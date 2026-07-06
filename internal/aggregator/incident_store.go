/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package aggregator

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/morarez/kube-diagnose/api/v1alpha1"
)

// ---------------------------------------------------------------------------
// IncidentRecord
// ---------------------------------------------------------------------------

// IncidentRecord holds the in-memory state for a single deduplicated incident.
// All mutations must be performed while the owning IncidentStore's write lock
// is held, or via atomic operations (Count only).
type IncidentRecord struct {
	// Fingerprint is the SimHash hex string that uniquely identifies this
	// error pattern.
	Fingerprint string

	// Pattern is a human-readable, normalised description of the error.
	Pattern string

	// SampleMessage is a representative raw log line from the incident.
	SampleMessage string

	// Namespace is the Kubernetes namespace where the incident was detected.
	Namespace string

	// PolicyName is the name of the LogWatchPolicy that triggered detection.
	PolicyName string

	// Count is the total number of times this pattern has been observed.
	// Use atomic loads/stores when reading outside the store's write lock.
	Count int64

	// AffectedPods is the set of pod names that have emitted this pattern.
	AffectedPods map[string]struct{}

	// FirstSeen is the wall-clock time of the first observed occurrence.
	FirstSeen time.Time

	// LastSeen is the wall-clock time of the most recent observed occurrence.
	LastSeen time.Time

	// Severity is the current assessed severity for this incident.
	Severity string

	// Resolved is true when the incident has been marked as resolved.
	Resolved bool

	// CRDName is the name of the corresponding Incident CRD object in
	// Kubernetes, set (and cached) on the first successful sync.
	CRDName string

	// FrequencyWindows records per-window event timestamps so that callers
	// can compute rates without re-reading the CRD.
	//   Key   → window label, e.g. "1m", "5m", "15m"
	//   Value → ordered slice of event timestamps (oldest first)
	FrequencyWindows map[string][]time.Time

	// Analysis holds the most recent LLM/RAG analysis result.
	Analysis *AnalysisResultData
}

// ---------------------------------------------------------------------------
// IncidentStore
// ---------------------------------------------------------------------------

// IncidentStore is a thread-safe in-memory store of IncidentRecords backed by
// Kubernetes Incident CRDs for persistence.
//
// Usage pattern
//
//	store := NewIncidentStore(k8sClient, fp, logger)
//	go store.StartPeriodicSync(ctx, 30*time.Second)
//
//	record, isNew := store.RecordEvent(ns, policy, fp, pattern, msg, pod)
type IncidentStore struct {
	mu          sync.RWMutex
	records     map[string]*IncidentRecord // key: fingerprint hex string
	k8sClient   client.Client
	fingerprint *Fingerprinter
	logger      *zap.Logger
}

// NewIncidentStore creates an empty IncidentStore.
// All parameters are required; passing nil will cause a panic at the first use.
func NewIncidentStore(k8sClient client.Client, fingerprinter *Fingerprinter, logger *zap.Logger) *IncidentStore {
	return &IncidentStore{
		records:     make(map[string]*IncidentRecord),
		k8sClient:   k8sClient,
		fingerprint: fingerprinter,
		logger:      logger,
	}
}

// RecordEvent creates or updates the IncidentRecord for the given fingerprint.
// It returns the (possibly new) record and a boolean that is true when this
// call created a brand-new incident.
//
// Thread-safe: the store write-lock is held for the duration of the update.
func (s *IncidentStore) RecordEvent(
	namespace, policyName, fingerprint, pattern, sampleMsg, podName string,
) (*IncidentRecord, bool) {
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, exists := s.records[fingerprint]
	isNew := !exists

	if isNew {
		rec = &IncidentRecord{
			Fingerprint:      fingerprint,
			Pattern:          pattern,
			SampleMessage:    sampleMsg,
			Namespace:        namespace,
			PolicyName:       policyName,
			Count:            0,
			AffectedPods:     make(map[string]struct{}),
			FirstSeen:        now,
			LastSeen:         now,
			Severity:         string(v1alpha1.IncidentSeverityLow),
			FrequencyWindows: make(map[string][]time.Time),
		}
		s.records[fingerprint] = rec

		s.logger.Info("new incident detected",
			zap.String("fingerprint", fingerprint),
			zap.String("pattern", pattern),
			zap.String("namespace", namespace),
			zap.String("policy", policyName),
		)
	}

	// Always update dynamic fields.
	atomic.AddInt64(&rec.Count, 1)
	rec.LastSeen = now

	if podName != "" {
		rec.AffectedPods[podName] = struct{}{}
	}

	// Record the event timestamp in every frequency window.
	for _, win := range []string{"1m", "5m", "15m"} {
		rec.FrequencyWindows[win] = append(rec.FrequencyWindows[win], now)
	}

	return rec, isNew
}

// GetOrCreate returns the existing IncidentRecord for fingerprint or creates a
// minimal placeholder record if none exists.  The placeholder will be
// populated fully the first time RecordEvent is called for the same fingerprint.
func (s *IncidentStore) GetOrCreate(fingerprint string) *IncidentRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rec, ok := s.records[fingerprint]; ok {
		return rec
	}

	now := time.Now().UTC()
	rec := &IncidentRecord{
		Fingerprint:      fingerprint,
		AffectedPods:     make(map[string]struct{}),
		FirstSeen:        now,
		LastSeen:         now,
		FrequencyWindows: make(map[string][]time.Time),
	}
	s.records[fingerprint] = rec
	return rec
}

// Get retrieves the IncidentRecord associated with fingerprint.
// The second return value is false if no record exists.
// The returned pointer is live; callers must not mutate it outside a lock.
func (s *IncidentStore) Get(fingerprint string) (*IncidentRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[fingerprint]
	return rec, ok
}

// List returns a snapshot of all IncidentRecords in insertion-stable order.
// Each element is a pointer to the live record; the slice itself is a new
// allocation.
func (s *IncidentStore) List() []*IncidentRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*IncidentRecord, 0, len(s.records))
	for _, rec := range s.records {
		out = append(out, rec)
	}
	return out
}

// AnalysisResultData holds LLM/RAG analysis output to be attached to a record.
// Using a plain struct here avoids a circular import with the llm package.
type AnalysisResultData struct {
	RootCause          string
	Confidence         float64
	Impact             string
	Severity           string
	RecommendedActions []string
	RelatedRunbooks    []string
	AnalysisSource     string
	TokensUsed         int
}

// UpdateSeverityAndAnalysis updates the severity and attaches analysis data to
// an existing IncidentRecord. Thread-safe.
func (s *IncidentStore) UpdateSeverityAndAnalysis(fingerprint, severity string, analysis *AnalysisResultData) {
	if analysis == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[fingerprint]
	if !ok {
		return
	}
	if severity != "" {
		rec.Severity = severity
	}
	rec.Analysis = analysis
}

// SyncToKubernetes creates or patches an Incident CRD for every in-memory
// record. It uses server-side apply semantics via controllerutil.CreateOrPatch
// so that concurrent controllers do not interfere.
//
// The CRD name is derived as:
//
//	<pattern-slug>-<first-8-chars-of-fingerprint>
//
// where pattern-slug is the pattern lowercased with all non-alphanumeric
// characters collapsed to dashes.
func (s *IncidentStore) SyncToKubernetes(ctx context.Context) error {
	records := s.List() // snapshot under read-lock; no lock held during K8s calls

	var firstErr error
	for _, rec := range records {
		if err := s.syncRecord(ctx, rec); err != nil {
			s.logger.Error("failed to sync incident to kubernetes",
				zap.String("fingerprint", rec.Fingerprint),
				zap.Error(err),
			)
			if firstErr == nil {
				firstErr = err
			}
			// Continue syncing remaining records even if one fails.
		}
	}
	return firstErr
}

// StartPeriodicSync launches a background goroutine that calls SyncToKubernetes
// every interval.  The goroutine exits when ctx is cancelled.
func (s *IncidentStore) StartPeriodicSync(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		s.logger.Info("incident store periodic sync started", zap.Duration("interval", interval))
		for {
			select {
			case <-ctx.Done():
				s.logger.Info("incident store periodic sync stopped")
				return
			case <-ticker.C:
				if err := s.SyncToKubernetes(ctx); err != nil {
					s.logger.Error("periodic sync encountered errors", zap.Error(err))
				}
			}
		}
	}()
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// syncRecord creates or patches a single Incident CRD for rec.
func (s *IncidentStore) syncRecord(ctx context.Context, rec *IncidentRecord) error {
	crdName := incidentCRDName(rec.Pattern, rec.Fingerprint)

	// Cache the derived CRD name to avoid recomputing it on every sync.
	s.mu.Lock()
	if rec.CRDName == "" {
		rec.CRDName = crdName
	}
	s.mu.Unlock()

	incident := &v1alpha1.Incident{}
	incident.Name = crdName
	incident.Namespace = rec.Namespace

	_, err := controllerutil.CreateOrPatch(ctx, s.k8sClient, incident, func() error {
		// Preserve any human-set spec fields (acknowledged, notes) by only
		// touching the status sub-resource through the dedicated status updater
		// below.  Here we only set labels and annotations on the object metadata.
		if incident.Labels == nil {
			incident.Labels = make(map[string]string)
		}
		incident.Labels["diagnose.diagnose.k8s.io/fingerprint"] = rec.Fingerprint
		incident.Labels["diagnose.diagnose.k8s.io/policy"] = rec.PolicyName
		incident.Labels["diagnose.diagnose.k8s.io/namespace"] = rec.Namespace

		return nil
	})
	if err != nil {
		return fmt.Errorf("CreateOrPatch incident %s/%s: %w", rec.Namespace, crdName, err)
	}

	// Status is a sub-resource; update it separately.
	return s.syncStatus(ctx, rec, crdName)
}

// syncStatus patches the status sub-resource of the named Incident CRD.
func (s *IncidentStore) syncStatus(ctx context.Context, rec *IncidentRecord, crdName string) error {
	s.mu.RLock()
	count := atomic.LoadInt64(&rec.Count)
	affectedResources := affectedPodsToResources(rec.Namespace, rec.AffectedPods)
	firstSeen := rec.FirstSeen
	lastSeen := rec.LastSeen
	severity := rec.Severity
	resolved := rec.Resolved
	pattern := rec.Pattern
	fingerprint := rec.Fingerprint
	sample := rec.SampleMessage
	policyRef := rec.PolicyName
	var analysis *AnalysisResultData
	if rec.Analysis != nil {
		analysis = &AnalysisResultData{
			RootCause:          rec.Analysis.RootCause,
			Confidence:         rec.Analysis.Confidence,
			Impact:             rec.Analysis.Impact,
			Severity:           rec.Analysis.Severity,
			RecommendedActions: rec.Analysis.RecommendedActions,
			RelatedRunbooks:    rec.Analysis.RelatedRunbooks,
			AnalysisSource:     rec.Analysis.AnalysisSource,
			TokensUsed:         rec.Analysis.TokensUsed,
		}
	}
	s.mu.RUnlock()

	// Determine phase from resolved flag and count.
	phase := v1alpha1.IncidentPhaseDetecting
	if resolved {
		phase = v1alpha1.IncidentPhaseResolved
	} else if count > 1 {
		phase = v1alpha1.IncidentPhaseAnalyzing
	}

	// Fetch the current object so we can build a patch against it.
	current := &v1alpha1.Incident{}
	if err := s.k8sClient.Get(ctx, types.NamespacedName{
		Namespace: rec.Namespace,
		Name:      crdName,
	}, current); err != nil {
		return fmt.Errorf("get incident for status patch: %w", err)
	}

	patch := client.MergeFrom(current.DeepCopy())

	current.Status.Phase = phase
	current.Status.Fingerprint = fingerprint
	current.Status.Pattern = pattern
	current.Status.Count = count
	current.Status.SampleLogMessage = sample
	current.Status.AffectedResources = affectedResources
	current.Status.FirstSeen = &metav1.Time{Time: firstSeen}
	current.Status.LastSeen = &metav1.Time{Time: lastSeen}
	current.Status.Severity = v1alpha1.IncidentSeverity(severity)
	current.Status.Resolved = resolved
	current.Status.PolicyRef = policyRef

	if analysis != nil {
		actions := make([]v1alpha1.RecommendedAction, len(analysis.RecommendedActions))
		for i, act := range analysis.RecommendedActions {
			actions[i] = v1alpha1.RecommendedAction{
				Step:   i + 1,
				Action: act,
			}
		}
		current.Status.Analysis = &v1alpha1.AIAnalysis{
			RootCause:          analysis.RootCause,
			Confidence:         analysis.Confidence,
			Impact:             analysis.Impact,
			Severity:           v1alpha1.IncidentSeverity(analysis.Severity),
			RecommendedActions: actions,
			RelatedRunbooks:    analysis.RelatedRunbooks,
			AnalysisSource:     analysis.AnalysisSource,
			TokensUsed:         analysis.TokensUsed,
		}
	} else {
		current.Status.Analysis = nil
	}

	if err := s.k8sClient.Status().Patch(ctx, current, patch); err != nil {
		return fmt.Errorf("status patch incident %s/%s: %w", rec.Namespace, crdName, err)
	}
	return nil
}

// incidentCRDName derives a valid Kubernetes name from a pattern and
// fingerprint. The result is at most 63 characters (DNS-label limit).
//
//	Format: <pattern-slug>-<fp8>
//	        where fp8 = first 8 chars of the fingerprint
func incidentCRDName(pattern, fingerprint string) string {
	slug := slugify(pattern)
	fp8 := fingerprint
	if len(fp8) > 8 {
		fp8 = fp8[:8]
	}

	name := slug + "-" + fp8
	// Kubernetes names must be <= 63 chars.
	if len(name) > 63 {
		// Trim slug to fit, keeping the mandatory fp8 suffix and dash separator.
		maxSlug := 63 - 1 - len(fp8) // 1 for the dash
		slug = slug[:maxSlug]
		// Remove any trailing dash left by the trim.
		slug = strings.TrimRight(slug, "-")
		name = slug + "-" + fp8
	}
	return name
}

// reSlugNonAlnum matches any character that is not a lowercase letter or digit.
var reSlugNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// slugify converts an arbitrary string into a lowercase, dash-separated
// DNS-compatible label segment.
func slugify(s string) string {
	s = strings.ToLower(s)
	s = reSlugNonAlnum.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 40 {
		s = s[:40]
		s = strings.TrimRight(s, "-")
	}
	if s == "" {
		s = "incident"
	}
	return s
}

// affectedPodsToResources converts the AffectedPods map into a slice of
// AffectedResource objects for the CRD status.
func affectedPodsToResources(namespace string, pods map[string]struct{}) []v1alpha1.AffectedResource {
	out := make([]v1alpha1.AffectedResource, 0, len(pods))
	for pod := range pods {
		out = append(out, v1alpha1.AffectedResource{
			Kind:      "Pod",
			Name:      pod,
			Namespace: namespace,
		})
	}
	return out
}

// LoadExistingIncidents fetches active (unresolved) Incidents from the Kubernetes API
// and populates the in-memory records map to recover store state after a restart.
func (s *IncidentStore) LoadExistingIncidents(ctx context.Context) error {
	var list v1alpha1.IncidentList
	if err := s.k8sClient.List(ctx, &list); err != nil {
		return fmt.Errorf("list existing incidents: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, item := range list.Items {
		if item.Status.Resolved {
			continue
		}

		fp := item.Status.Fingerprint
		if fp == "" {
			continue
		}

		affectedPods := make(map[string]struct{})
		for _, res := range item.Status.AffectedResources {
			if res.Kind == "Pod" {
				affectedPods[res.Name] = struct{}{}
			}
		}

		var analysis *AnalysisResultData
		if item.Status.Analysis != nil {
			var actions []string
			for _, act := range item.Status.Analysis.RecommendedActions {
				actions = append(actions, act.Action)
			}
			analysis = &AnalysisResultData{
				RootCause:          item.Status.Analysis.RootCause,
				Confidence:         item.Status.Analysis.Confidence,
				Impact:             item.Status.Analysis.Impact,
				Severity:           string(item.Status.Analysis.Severity),
				RecommendedActions: actions,
				RelatedRunbooks:    item.Status.Analysis.RelatedRunbooks,
				AnalysisSource:     item.Status.Analysis.AnalysisSource,
				TokensUsed:         item.Status.Analysis.TokensUsed,
			}
		}

		var firstSeen time.Time
		if item.Status.FirstSeen != nil {
			firstSeen = item.Status.FirstSeen.Time
		}
		var lastSeen time.Time
		if item.Status.LastSeen != nil {
			lastSeen = item.Status.LastSeen.Time
		}

		// FrequencyWindows is kept in-memory to calculate burst rates.
		// Since old log event timestamps are not persisted in standard CRD status,
		// we initialize an empty tracking map for the sliding windows.
		freqWindows := make(map[string][]time.Time)

		s.records[fp] = &IncidentRecord{
			Fingerprint:      fp,
			Pattern:          item.Status.Pattern,
			SampleMessage:    item.Status.SampleLogMessage,
			Namespace:        item.Namespace,
			PolicyName:       item.Status.PolicyRef,
			Count:            item.Status.Count,
			AffectedPods:     affectedPods,
			FirstSeen:        firstSeen,
			LastSeen:         lastSeen,
			Severity:         string(item.Status.Severity),
			Resolved:         item.Status.Resolved,
			CRDName:          item.Name,
			Analysis:         analysis,
			FrequencyWindows: freqWindows,
		}

		s.logger.Info("reconstructed in-memory state for active incident",
			zap.String("fingerprint", fp),
			zap.String("crd", item.Name),
			zap.Int64("count", item.Status.Count),
		)
	}

	return nil
}
