// Package llm provides a unified interface for interacting with multiple large
// language model providers (OpenAI, Anthropic) for Kubernetes incident
// analysis. It includes prompt engineering helpers, an in-memory cache with TTL,
// rate-limit controls, and a provider-fallback chain.
package llm

import "context"

// AnalysisResult holds the structured output produced by an LLM (or the RAG
// retrieval layer) after analysing a Kubernetes incident pattern.
type AnalysisResult struct {
	// RootCause is a human-readable explanation of the probable root cause.
	RootCause string `json:"root_cause"`

	// Confidence is a value in [0.0, 1.0] representing how confident the
	// provider is in its diagnosis.
	Confidence float64 `json:"confidence"`

	// Impact describes the user-visible or operational impact of the incident.
	Impact string `json:"impact"`

	// Severity is one of "critical", "high", "medium", or "low".
	Severity string `json:"severity"`

	// RecommendedActions is an ordered list of remediation steps the on-call
	// engineer should follow.
	RecommendedActions []string `json:"recommended_actions"`

	// RelatedRunbooks contains links or identifiers for runbooks that are
	// relevant to this incident.
	RelatedRunbooks []string `json:"related_runbooks"`

	// TokensUsed is the total number of tokens consumed by the LLM call
	// (prompt + completion). It is zero when the result came from cache or
	// the RAG layer without an LLM call.
	TokensUsed int `json:"tokens_used"`

	// AnalysisSource indicates where the result originated:
	//   "openai"    – OpenAI API
	//   "anthropic" – Anthropic API
	//   "rag"       – retrieval-augmented generation only (no LLM call)
	//   "cache"     – returned from the in-memory cache
	AnalysisSource string `json:"analysis_source"`
}

// LLMProvider is the minimal interface that every provider implementation must
// satisfy. Implementations are expected to be safe for concurrent use.
type LLMProvider interface {
	// Analyze sends prompt to the provider and returns a structured result.
	// Implementations must respect context cancellation / deadlines.
	Analyze(ctx context.Context, prompt string) (*AnalysisResult, error)

	// Name returns a short, stable identifier for the provider (e.g. "openai").
	Name() string
}

// AnalysisRequest captures all the incident metadata that is used to build the
// LLM prompt and the cache fingerprint.
type AnalysisRequest struct {
	// Pattern is the error or alert pattern identifier (e.g. "OOMKilled",
	// "CrashLoopBackOff").
	Pattern string

	// Namespace is the Kubernetes namespace where the incident was observed.
	Namespace string

	// SampleLog contains a representative excerpt from the affected workload's
	// log output. It should be truncated to a reasonable size before being
	// placed here (e.g. ≤ 2 000 characters).
	SampleLog string

	// Context provides additional free-form context gathered by the diagnoser
	// (e.g. recent events, resource quotas, HPA status).
	Context string

	// AffectedPods is the list of pod names currently exhibiting the pattern.
	AffectedPods []string

	// OccurrenceCount is the total number of times the pattern has been
	// observed in the monitoring window.
	OccurrenceCount int64
}
