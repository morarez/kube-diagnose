package llm

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const severityMedium = "medium"

// ---------------------------------------------------------------------------
// AnalysisCache
// ---------------------------------------------------------------------------

// cachedEntry holds a cached AnalysisResult with an expiration time.
type cachedEntry struct {
	result    *AnalysisResult
	expiresAt time.Time
}

// AnalysisCache is a thread-safe in-memory cache for LLM analysis results,
// keyed by incident fingerprint. Results are evicted after a configurable TTL.
type AnalysisCache struct {
	mu      sync.RWMutex
	entries map[string]*cachedEntry
	ttl     time.Duration
}

// newAnalysisCache creates a cache with the given TTL.
func newAnalysisCache(ttl time.Duration) *AnalysisCache {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &AnalysisCache{
		entries: make(map[string]*cachedEntry),
		ttl:     ttl,
	}
}

// get returns a cached result for key, or (nil, false) if absent / expired.
func (c *AnalysisCache) get(key string) (*AnalysisResult, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.result, true
}

// set stores result under key with the configured TTL.
func (c *AnalysisCache) set(key string, result *AnalysisResult) {
	c.mu.Lock()
	c.entries[key] = &cachedEntry{
		result:    result,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// Len returns the number of (possibly-expired) entries in the cache.
func (c *AnalysisCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Purge removes all expired entries. Call periodically to avoid memory growth.
func (c *AnalysisCache) Purge() {
	now := time.Now()
	c.mu.Lock()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

// Analyzer is the main orchestrator for AI incident analysis. It applies a
// cost-guard before invoking any LLM:
//
//  1. Check the in-memory cache — return cached result immediately.
//  2. If RAG confidence is high enough, return a RAG-only result (no LLM call).
//  3. Enforce an hourly rate limit to cap spending.
//  4. Try each configured LLM provider in order; return on first success.
//  5. Cache and return the result.
type Analyzer struct {
	providers                      []LLMProvider
	cache                          *AnalysisCache
	ragConfidenceThreshold         float64
	criticalRAGConfidenceThreshold float64
	maxCallsPerHour                int

	mu            sync.Mutex
	callsThisHour int
	hourResetAt   time.Time

	// stats for observability
	cacheHits    int64
	ragShortcuts int64
	llmCalls     int64

	logger *zap.Logger
}

// NewAnalyzer constructs an Analyzer.
//
//   - providers    – ordered list of LLM providers; tried in order on failure
//   - ragThreshold – RAG confidence score above which LLM is skipped (0–1)
//   - criticalThreshold – higher RAG threshold for critical-severity incidents
//   - maxCallsPerHour   – rolling window rate limit for LLM API calls
//   - cacheTTL    – how long to cache LLM results per fingerprint
//   - logger      – structured logger
func NewAnalyzer(
	providers []LLMProvider,
	ragThreshold, criticalThreshold float64,
	maxCallsPerHour int,
	cacheTTL time.Duration,
	logger *zap.Logger,
) *Analyzer {
	if ragThreshold <= 0 {
		ragThreshold = 0.75
	}
	if criticalThreshold <= 0 {
		criticalThreshold = 0.90
	}
	if maxCallsPerHour <= 0 {
		maxCallsPerHour = 60
	}
	return &Analyzer{
		providers:                      providers,
		cache:                          newAnalysisCache(cacheTTL),
		ragConfidenceThreshold:         ragThreshold,
		criticalRAGConfidenceThreshold: criticalThreshold,
		maxCallsPerHour:                maxCallsPerHour,
		hourResetAt:                    time.Now().Add(time.Hour),
		logger:                         logger.With(zap.String("component", "llm_analyzer")),
	}
}

// ShouldUseLLM returns true when the LLM must be invoked given the RAG
// confidence score and incident severity. This is the core cost-gate logic.
func (a *Analyzer) ShouldUseLLM(ragConfidence float64, severity string) bool {
	threshold := a.ragConfidenceThreshold
	if strings.EqualFold(severity, "critical") {
		threshold = a.criticalRAGConfidenceThreshold
	}
	return ragConfidence < threshold
}

// Analyze runs the full analysis pipeline for a single incident.
//
// ragContext is the pre-formatted string returned by RAGEngine.FormatContext.
// ragConfidence is the max similarity score from the RAG retrieval step.
// severity is the current assessed severity (used for threshold selection).
func (a *Analyzer) Analyze(
	ctx context.Context,
	req AnalysisRequest,
	ragContext string,
	ragConfidence float64,
	severity string,
) (*AnalysisResult, error) {
	cacheKey := req.Pattern + "|" + req.Namespace

	// 1. Cache lookup.
	if cached, ok := a.cache.get(cacheKey); ok {
		a.mu.Lock()
		a.cacheHits++
		a.mu.Unlock()

		a.logger.Info("returning cached analysis result",
			zap.String("pattern", req.Pattern),
			zap.String("cacheKey", cacheKey),
		)
		out := *cached
		out.AnalysisSource = "cache"
		return &out, nil
	}

	// 2. RAG shortcut — confidence is high enough, skip LLM.
	if !a.ShouldUseLLM(ragConfidence, severity) {
		a.mu.Lock()
		a.ragShortcuts++
		a.mu.Unlock()

		a.logger.Info("RAG confidence above threshold — skipping LLM",
			zap.Float64("confidence", ragConfidence),
			zap.String("severity", severity),
		)
		result := ragOnlyResult(ragContext, ragConfidence, severity)
		a.cache.set(cacheKey, result)
		return result, nil
	}

	// 3. Rate-limit check.
	a.mu.Lock()
	if time.Now().After(a.hourResetAt) {
		a.callsThisHour = 0
		a.hourResetAt = time.Now().Add(time.Hour)
	}
	if a.callsThisHour >= a.maxCallsPerHour {
		a.mu.Unlock()
		a.logger.Warn("LLM rate limit reached; returning degraded RAG result",
			zap.Int("callsThisHour", a.callsThisHour),
			zap.Int("maxCallsPerHour", a.maxCallsPerHour),
		)
		result := ragOnlyResult(ragContext, ragConfidence, severity)
		result.RootCause = "(Rate limit reached — using best available RAG context) " + result.RootCause
		return result, nil
	}
	a.mu.Unlock()

	// 4. Call LLM providers in order.
	prompt := BuildAnalysisPrompt(req, ragContext)
	var result *AnalysisResult
	var lastErr error

	for _, provider := range a.providers {
		a.logger.Info("invoking LLM provider",
			zap.String("provider", provider.Name()),
			zap.String("pattern", req.Pattern),
		)

		res, err := provider.Analyze(ctx, prompt)
		if err != nil {
			a.logger.Warn("LLM provider failed, trying next",
				zap.String("provider", provider.Name()),
				zap.Error(err),
			)
			lastErr = err
			continue
		}

		result = res
		a.mu.Lock()
		a.callsThisHour++
		a.llmCalls++
		a.mu.Unlock()

		a.logger.Info("LLM analysis complete",
			zap.String("provider", provider.Name()),
			zap.Float64("confidence", result.Confidence),
			zap.String("severity", result.Severity),
			zap.Int("tokensUsed", result.TokensUsed),
		)
		break
	}

	if result == nil {
		// All providers failed — return a degraded RAG result.
		a.logger.Error("all LLM providers failed; returning degraded RAG result", zap.Error(lastErr))
		result = ragOnlyResult(ragContext, ragConfidence, severity)
		result.RootCause = fmt.Sprintf("(LLM unavailable: %v) Using RAG context only.", lastErr)
		return result, nil
	}

	// 5. Cache and return.
	a.cache.set(cacheKey, result)
	return result, nil
}

// Stats returns a snapshot of key operational metrics for observability.
func (a *Analyzer) Stats() map[string]interface{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	return map[string]interface{}{
		"llm_calls_this_hour": a.callsThisHour,
		"max_calls_per_hour":  a.maxCallsPerHour,
		"cache_size":          a.cache.Len(),
		"cache_hits_total":    a.cacheHits,
		"rag_shortcuts_total": a.ragShortcuts,
		"llm_calls_total":     a.llmCalls,
	}
}

// StartCachePurger starts a background goroutine that purges expired cache
// entries every 15 minutes to prevent unbounded memory growth.
func (a *Analyzer) StartCachePurger(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.cache.Purge()
			}
		}
	}()
}

// ragOnlyResult builds an AnalysisResult entirely from RAG context,
// used when LLM is skipped or unavailable.
func ragOnlyResult(ragContext string, ragConfidence float64, severity string) *AnalysisResult {
	rootCause := "Analysis based on knowledge-base retrieval (no LLM call required)."
	if ragContext == "" {
		rootCause = "No matching runbooks found. Consider adding runbooks for this error pattern."
	}

	if severity == "" {
		severity = severityMedium
	}

	return &AnalysisResult{
		RootCause:          rootCause,
		Confidence:         ragConfidence,
		Impact:             "See retrieved runbook context for impact details.",
		Severity:           severity,
		RecommendedActions: []string{"Review the knowledge-base context attached to this incident for remediation steps."},
		RelatedRunbooks:    []string{},
		AnalysisSource:     "rag",
	}
}
