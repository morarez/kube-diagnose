/*
Copyright 2024.

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

package controller

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	diagnosev1alpha1 "github.com/morarez/kube-diagnose/api/v1alpha1"
	"github.com/morarez/kube-diagnose/internal/aggregator"
	"github.com/morarez/kube-diagnose/internal/dashboard"
	"github.com/morarez/kube-diagnose/internal/llm"
	"github.com/morarez/kube-diagnose/internal/logwatcher"
	"github.com/morarez/kube-diagnose/internal/rag"
)

// PlatformComponents holds all runtime components owned by the platform.
// This singleton is initialised by the LogIntelligencePlatformReconciler
// and shared with the other controllers via a package-level variable.
var platformComponents *PlatformComponents

// PlatformComponents groups the shared runtime objects for the platform.
type PlatformComponents struct {
	Watcher         *logwatcher.Watcher
	IncidentStore   *aggregator.IncidentStore
	PatternDetector *aggregator.PatternDetector
	Engine          *rag.Engine
	Analyzer        *llm.Analyzer
	Dashboard       *dashboard.Server
	LogCh           chan *logwatcher.LogEntry
	Logger          *zap.Logger
	cancel          context.CancelFunc
}

// LogIntelligencePlatformReconciler reconciles a LogIntelligencePlatform object.
// +kubebuilder:rbac:groups=diagnose.diagnose.k8s.io,resources=logintelligenceplatforms,verbs=get;list;watch
// +kubebuilder:rbac:groups=diagnose.diagnose.k8s.io,resources=logintelligenceplatforms,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=diagnose.diagnose.k8s.io,resources=logintelligenceplatforms/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=diagnose.diagnose.k8s.io,resources=logintelligenceplatforms/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;replicasets;statefulsets;daemonsets,verbs=get;list;watch
type LogIntelligencePlatformReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	K8sClient kubernetes.Interface
}

// Reconcile processes LogIntelligencePlatform changes, initialising or
// reconfiguring all platform components when the spec changes.
func (r *LogIntelligencePlatformReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	platform := &diagnosev1alpha1.LogIntelligencePlatform{}
	if err := r.Get(ctx, req.NamespacedName, platform); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	log.Info("Reconciling LogIntelligencePlatform", "name", platform.Name)

	// Resolve secrets and build components.
	if err := r.ensurePlatformComponents(ctx, platform); err != nil {
		log.Error(err, "failed to initialise platform components")
		return r.updateStatus(ctx, platform, false, err.Error()), err
	}

	return r.updateStatus(ctx, platform, true, ""), nil
}

// ensurePlatformComponents initialises all platform components from the spec.
// Calling it again on a subsequent reconcile tears down the old goroutines and
// starts fresh ones, making the platform hot-reloadable.
func (r *LogIntelligencePlatformReconciler) ensurePlatformComponents(
	ctx context.Context,
	platform *diagnosev1alpha1.LogIntelligencePlatform,
) error {
	// Tear down existing components if running.
	if platformComponents != nil && platformComponents.cancel != nil {
		platformComponents.cancel()
	}

	logger, _ := zap.NewProduction()
	childCtx, cancel := context.WithCancel(ctx)

	spec := platform.Spec

	// ── Embedder ──────────────────────────────────────────────────────────────
	embeddingProvider := "openai"
	embeddingModel := "text-embedding-3-small"
	embeddingEndpoint := ""
	embeddingAPIKey := ""
	if spec.Embedding != nil {
		embeddingProvider = string(spec.Embedding.Provider)
		if spec.Embedding.Model != "" {
			embeddingModel = spec.Embedding.Model
		}
		embeddingEndpoint = spec.Embedding.Endpoint
		if spec.Embedding.APIKeySecretRef != nil {
			key, err := r.resolveSecretKey(ctx, platform.Namespace, spec.Embedding.APIKeySecretRef)
			if err != nil {
				cancel()
				return fmt.Errorf("resolve embedding API key: %w", err)
			}
			embeddingAPIKey = key
		}
	}

	embedder, err := rag.NewEmbedder(embeddingProvider, embeddingAPIKey, embeddingModel, embeddingEndpoint, logger)
	if err != nil {
		cancel()
		return fmt.Errorf("create embedder: %w", err)
	}

	// ── Qdrant ────────────────────────────────────────────────────────────────
	qdrantHost := "qdrant"
	qdrantHTTPPort := 6333
	qdrantAPIKey := ""
	qdrantCollectionPrefix := "kube-diagnose"
	if spec.Qdrant != nil {
		if spec.Qdrant.Host != "" {
			qdrantHost = spec.Qdrant.Host
		}
		if spec.Qdrant.HTTPPort > 0 {
			qdrantHTTPPort = spec.Qdrant.HTTPPort
		}
		if spec.Qdrant.CollectionPrefix != "" {
			qdrantCollectionPrefix = spec.Qdrant.CollectionPrefix
		}
		if spec.Qdrant.APIKeySecretRef != nil {
			key, err := r.resolveSecretKey(ctx, platform.Namespace, spec.Qdrant.APIKeySecretRef)
			if err != nil {
				cancel()
				return fmt.Errorf("resolve Qdrant API key: %w", err)
			}
			qdrantAPIKey = key
		}
	}
	qdrantClient := rag.NewQdrantClient(qdrantHost, qdrantHTTPPort, qdrantAPIKey, qdrantCollectionPrefix, logger)

	// ── RAG Engine ────────────────────────────────────────────────────────────
	ragEngine := rag.NewEngine(embedder, qdrantClient, logger)
	if err := ragEngine.Initialize(childCtx, 0); err != nil {
		logger.Warn("RAG engine initialization failed (Qdrant may not be ready); continuing", zap.Error(err))
	}

	// Index knowledge-base documents in background.
	go r.indexKnowledgeBase(childCtx, platform, ragEngine, logger)

	// ── LLM Providers ─────────────────────────────────────────────────────────
	var providers []llm.Provider
	if spec.LLM != nil {
		provider, err := r.buildLLMProvider(ctx, platform.Namespace, spec.LLM, logger)
		if err != nil {
			logger.Warn("failed to build LLM provider; AI analysis will use RAG only", zap.Error(err))
		} else {
			providers = append(providers, provider)
		}
	}

	// ── Analyzer ──────────────────────────────────────────────────────────────
	ragThreshold := 0.75
	criticalThreshold := 0.90
	maxCallsPerHour := 60
	cacheTTL := 24 * time.Hour
	if spec.Analysis != nil {
		if v, err := strconv.ParseFloat(spec.Analysis.RAGConfidenceThreshold, 64); err == nil {
			ragThreshold = v
		}
		if v, err := strconv.ParseFloat(spec.Analysis.CriticalRAGConfidenceThreshold, 64); err == nil {
			criticalThreshold = v
		}
		if spec.Analysis.MaxLLMCallsPerHour > 0 {
			maxCallsPerHour = spec.Analysis.MaxLLMCallsPerHour
		}
		if d, err := time.ParseDuration(spec.Analysis.LLMCacheTTL); err == nil {
			cacheTTL = d
		}
	}
	analyzer := llm.NewAnalyzer(providers, ragThreshold, criticalThreshold, maxCallsPerHour, cacheTTL, logger)
	analyzer.StartCachePurger(childCtx)

	// ── Aggregator ────────────────────────────────────────────────────────────
	fingerprinter := aggregator.NewFingerprinter()
	incidentStore := aggregator.NewIncidentStore(r.Client, fingerprinter, logger)
	patternDetector := aggregator.NewPatternDetector(logger)
	go patternDetector.CleanupOldData(childCtx)
	incidentStore.StartPeriodicSync(childCtx, 30*time.Second)

	// ── Log Watcher ───────────────────────────────────────────────────────────
	logCh := make(chan *logwatcher.LogEntry, 4096)
	normalizer := logwatcher.NewNormalizer("", logger)
	filter, _ := logwatcher.NewFilter([]string{"ERROR", "FATAL", "CRITICAL", "PANIC"}, nil)
	watcher := logwatcher.NewWatcher(r.K8sClient, normalizer, filter, logCh, logger)

	// ── Dashboard ─────────────────────────────────────────────────────────────
	dashPort := 8080
	if spec.DashboardPort > 0 {
		dashPort = spec.DashboardPort
	}
	dash := dashboard.NewServer(dashPort, incidentStore, analyzer, logger)
	if spec.DashboardEnabled {
		go dash.Start(childCtx)
	}

	// ── Log processing pipeline ───────────────────────────────────────────────
	go r.runLogPipeline(childCtx, logCh, incidentStore, patternDetector, ragEngine, analyzer, logger)

	platformComponents = &PlatformComponents{
		Watcher:         watcher,
		IncidentStore:   incidentStore,
		PatternDetector: patternDetector,
		Engine:          ragEngine,
		Analyzer:        analyzer,
		Dashboard:       dash,
		LogCh:           logCh,
		Logger:          logger,
		cancel:          cancel,
	}

	logger.Info("platform components initialised successfully",
		zap.String("platform", platform.Name),
		zap.Int("llmProviders", len(providers)),
		zap.Int("dashboardPort", dashPort),
	)
	return nil
}

// runLogPipeline drains the log channel and processes each entry through the
// full pipeline: fingerprint → deduplicate → detect pattern → RAG → LLM → notify.
func (r *LogIntelligencePlatformReconciler) runLogPipeline(
	ctx context.Context,
	logCh <-chan *logwatcher.LogEntry,
	store *aggregator.IncidentStore,
	detector *aggregator.PatternDetector,
	ragEngine *rag.Engine,
	analyzer *llm.Analyzer,
	logger *zap.Logger,
) {
	fp := aggregator.NewFingerprinter()
	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-logCh:
			if !ok {
				return
			}
			fingerprint := fp.Fingerprint(entry.Message)
			detector.Record(fingerprint, time.Now())

			rec, isNew := store.RecordEvent(
				entry.Namespace,
				entry.PolicyName,
				fingerprint,
				entry.Message,
				entry.Message,
				entry.Pod,
			)

			if !isNew {
				continue
			}

			// New incident: run RAG + optional LLM analysis in a goroutine.
			go func(rec *aggregator.IncidentRecord) {
				analysisCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				defer cancel()

				affectedPods := make([]string, 0, len(rec.AffectedPods))
				for p := range rec.AffectedPods {
					affectedPods = append(affectedPods, p)
				}

				results, ragConfidence, err := ragEngine.Retrieve(analysisCtx, rec.Pattern, 5)
				ragContext := ""
				if err != nil {
					logger.Warn("RAG retrieval failed", zap.Error(err))
				} else {
					ragContext = ragEngine.FormatContext(results)
				}

				req := llm.AnalysisRequest{
					Pattern:         rec.Pattern,
					Namespace:       rec.Namespace,
					SampleLog:       rec.SampleMessage,
					AffectedPods:    affectedPods,
					OccurrenceCount: rec.Count,
				}

				result, err := analyzer.Analyze(analysisCtx, req, ragContext, ragConfidence, rec.Severity)
				if err != nil {
					logger.Error("analysis failed", zap.Error(err))
					return
				}

				// Update severity on the record.
				analysisData := &aggregator.AnalysisResultData{
					RootCause:          result.RootCause,
					Confidence:         result.Confidence,
					Impact:             result.Impact,
					Severity:           result.Severity,
					RecommendedActions: result.RecommendedActions,
					RelatedRunbooks:    result.RelatedRunbooks,
					AnalysisSource:     result.AnalysisSource,
					TokensUsed:         result.TokensUsed,
				}
				store.UpdateSeverityAndAnalysis(rec.Fingerprint, result.Severity, analysisData)
			}(rec)
		}
	}
}

// indexKnowledgeBase loads and indexes runbook documents from the configured path.
func (r *LogIntelligencePlatformReconciler) indexKnowledgeBase(
	ctx context.Context,
	platform *diagnosev1alpha1.LogIntelligencePlatform,
	ragEngine *rag.Engine,
	logger *zap.Logger,
) {
	runbooksPath := "/etc/kube-diagnose/runbooks"
	if platform.Spec.KnowledgeBase != nil && platform.Spec.KnowledgeBase.RunbooksPath != "" {
		runbooksPath = platform.Spec.KnowledgeBase.RunbooksPath
	}

	loader := rag.NewDocumentLoader(logger)
	docs, err := loader.LoadFromDirectory(runbooksPath)
	if err != nil {
		logger.Info("no runbooks directory found or empty; skipping initial indexing", zap.String("path", runbooksPath))
		return
	}

	var chunked []rag.Document
	for _, doc := range docs {
		chunked = append(chunked, loader.ChunkDocument(doc, 512, 50)...)
	}

	if err := ragEngine.IndexDocuments(ctx, chunked); err != nil {
		logger.Error("failed to index knowledge-base documents", zap.Error(err))
		return
	}
	logger.Info("knowledge-base indexed", zap.Int("documents", len(chunked)))
}

// buildLLMProvider constructs the appropriate LLM provider from the spec.
func (r *LogIntelligencePlatformReconciler) buildLLMProvider(
	ctx context.Context,
	namespace string,
	cfg *diagnosev1alpha1.LLMConfig,
	logger *zap.Logger,
) (llm.Provider, error) {
	apiKey := ""
	if cfg.APIKeySecretRef != nil {
		key, err := r.resolveSecretKey(ctx, namespace, cfg.APIKeySecretRef)
		if err != nil {
			return nil, fmt.Errorf("resolve LLM API key: %w", err)
		}
		apiKey = key
	}

	maxTokens := cfg.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 2048
	}
	model := cfg.Model

	switch cfg.Provider {
	case diagnosev1alpha1.LLMProviderOpenAI:
		if model == "" {
			model = "gpt-4o-mini"
		}
		return llm.NewOpenAIProvider(apiKey, model, maxTokens, logger), nil
	case diagnosev1alpha1.LLMProviderAnthropic:
		if model == "" {
			model = "claude-3-5-haiku-latest"
		}
		return llm.NewAnthropicProvider(apiKey, model, maxTokens, logger), nil
	case diagnosev1alpha1.LLMProviderVLLM:
		endpoint := cfg.Endpoint
		if endpoint == "" {
			endpoint = "http://vllm:8000"
		}
		return llm.NewOpenAIProviderWithEndpoint(apiKey, model, endpoint, maxTokens, logger), nil
	case diagnosev1alpha1.LLMProviderGoogle:
		if model == "" {
			model = "gemini-1.5-flash"
		}
		if apiKey == "" {
			return nil, fmt.Errorf("google gemini provider requires a non-empty apiKey")
		}
		return llm.NewGoogleProvider(apiKey, model, maxTokens, logger), nil
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %s", cfg.Provider)
	}
}

// resolveSecretKey fetches a secret key value from Kubernetes.
func (r *LogIntelligencePlatformReconciler) resolveSecretKey(
	ctx context.Context,
	namespace string,
	ref *diagnosev1alpha1.SecretKeyRef,
) (string, error) {
	if ref == nil {
		return "", nil
	}
	if namespace == "" {
		namespace = "default"
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, secret); err != nil {
		return "", fmt.Errorf("get secret %s/%s: %w", namespace, ref.Name, err)
	}
	val, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", ref.Key, namespace, ref.Name)
	}
	return string(val), nil
}

// updateStatus patches the platform status subresource and returns the requeue result.
func (r *LogIntelligencePlatformReconciler) updateStatus(
	ctx context.Context,
	platform *diagnosev1alpha1.LogIntelligencePlatform,
	ready bool,
	errMsg string,
) ctrl.Result {
	now := metav1.Now()
	platform.Status.Ready = ready
	platform.Status.LastReconcileTime = &now

	if ready {
		condition := metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			Reason:             "Reconciled",
			Message:            "Platform components initialised successfully",
			LastTransitionTime: now,
		}
		platform.Status.Conditions = []metav1.Condition{condition}
	} else {
		condition := metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "Error",
			Message:            errMsg,
			LastTransitionTime: now,
		}
		platform.Status.Conditions = []metav1.Condition{condition}
	}

	if err := r.Status().Update(ctx, platform); err != nil {
		logf.FromContext(ctx).Error(err, "failed to update LogIntelligencePlatform status")
	}

	if ready {
		return ctrl.Result{RequeueAfter: 5 * time.Minute}
	}
	return ctrl.Result{RequeueAfter: 30 * time.Second}
}

// SetupWithManager sets up the controller with the Manager.
func (r *LogIntelligencePlatformReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&diagnosev1alpha1.LogIntelligencePlatform{}).
		Named("logintelligenceplatform").
		Complete(r)
}
