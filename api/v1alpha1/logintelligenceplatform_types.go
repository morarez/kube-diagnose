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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LLMProvider defines the AI provider configuration.
// +kubebuilder:validation:Enum=openai;anthropic;vllm;google
type LLMProvider string

const (
	LLMProviderOpenAI    LLMProvider = "openai"
	LLMProviderAnthropic LLMProvider = "anthropic"
	LLMProviderVLLM      LLMProvider = "vllm"
	LLMProviderGoogle    LLMProvider = "google"
)

// EmbeddingProvider defines which service to use for vector embeddings.
// +kubebuilder:validation:Enum=openai
type EmbeddingProvider string

const (
	EmbeddingProviderOpenAI EmbeddingProvider = "openai"
)

// SecretKeyRef references a Kubernetes secret key.
type SecretKeyRef struct {
	// Name is the name of the secret.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// Key is the key within the secret.
	// +kubebuilder:validation:Required
	Key string `json:"key"`
}

// LLMConfig defines the configuration for an LLM provider.
type LLMConfig struct {
	// Provider is the LLM provider to use.
	// +kubebuilder:default=openai
	Provider LLMProvider `json:"provider"`

	// Model is the model name to use.
	// +optional
	// +kubebuilder:default="gpt-4o-mini"
	Model string `json:"model,omitempty"`

	// APIKeySecretRef references a secret containing the API key.
	// Not required for vLLM.
	// +optional
	APIKeySecretRef *SecretKeyRef `json:"apiKeySecretRef,omitempty"`

	// Endpoint is the API endpoint URL.
	// Required for vLLM.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// MaxTokens is the maximum tokens for LLM responses.
	// +optional
	// +kubebuilder:default=2048
	MaxTokens int `json:"maxTokens,omitempty"`

	// Temperature for LLM sampling.
	// +optional
	Temperature float64 `json:"temperature,omitempty"`
}

// EmbeddingConfig defines the configuration for embeddings.
type EmbeddingConfig struct {
	// Provider is the embedding provider.
	// +kubebuilder:default=openai
	Provider EmbeddingProvider `json:"provider"`

	// Model is the embedding model name.
	// +optional
	// +kubebuilder:default="text-embedding-3-small"
	Model string `json:"model,omitempty"`

	// APIKeySecretRef references a secret containing the API key.
	// +optional
	APIKeySecretRef *SecretKeyRef `json:"apiKeySecretRef,omitempty"`

	// Endpoint is the embedding API endpoint.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`
}

// QdrantConfig defines the Qdrant vector store configuration.
type QdrantConfig struct {
	// Host is the Qdrant server host.
	// +kubebuilder:default="qdrant"
	Host string `json:"host"`

	// Port is the Qdrant gRPC port.
	// +kubebuilder:default=6334
	Port int `json:"port,omitempty"`

	// HTTPPort is the Qdrant HTTP port.
	// +kubebuilder:default=6333
	HTTPPort int `json:"httpPort,omitempty"`

	// APIKeySecretRef references a secret containing the Qdrant API key.
	// +optional
	APIKeySecretRef *SecretKeyRef `json:"apiKeySecretRef,omitempty"`

	// TLSEnabled enables TLS for Qdrant connection.
	// +optional
	TLSEnabled bool `json:"tlsEnabled,omitempty"`

	// CollectionPrefix for all Qdrant collections.
	// +optional
	// +kubebuilder:default="kube-diagnose"
	CollectionPrefix string `json:"collectionPrefix,omitempty"`
}

// AnalysisConfig defines when and how AI analysis is triggered.
type AnalysisConfig struct {
	// RAGConfidenceThreshold is the minimum RAG similarity score to skip LLM analysis.
	// When RAG confidence is above this threshold, LLM is NOT invoked.
	// +optional
	// +kubebuilder:default="0.75"
	RAGConfidenceThreshold string `json:"ragConfidenceThreshold,omitempty"`

	// CriticalRAGConfidenceThreshold is the higher threshold for critical incidents.
	// +optional
	// +kubebuilder:default="0.90"
	CriticalRAGConfidenceThreshold string `json:"criticalRagConfidenceThreshold,omitempty"`

	// LLMCacheTTL is how long to cache LLM analysis results (e.g. "24h").
	// +optional
	// +kubebuilder:default="24h"
	LLMCacheTTL string `json:"llmCacheTTL,omitempty"`

	// MaxLLMCallsPerHour limits LLM API calls for cost control.
	// +optional
	// +kubebuilder:default=60
	MaxLLMCallsPerHour int `json:"maxLLMCallsPerHour,omitempty"`
}

// KnowledgeBaseConfig defines where runbooks and postmortems are loaded from.
type KnowledgeBaseConfig struct {
	// ConfigMapRef is a ConfigMap containing runbook documents.
	// Keys are document names, values are document content.
	// +optional
	ConfigMapRef *SecretKeyRef `json:"configMapRef,omitempty"`

	// RunbooksPath is a directory path mounted into the operator for runbooks.
	// +optional
	// +kubebuilder:default="/etc/kube-diagnose/runbooks"
	RunbooksPath string `json:"runbooksPath,omitempty"`

	// AutoReindexInterval is how often to re-index documents (e.g. "1h").
	// +optional
	// +kubebuilder:default="1h"
	AutoReindexInterval string `json:"autoReindexInterval,omitempty"`
}

// LogIntelligencePlatformSpec defines the desired state of LogIntelligencePlatform.
type LogIntelligencePlatformSpec struct {
	// LLM is the AI language model configuration.
	// +optional
	LLM *LLMConfig `json:"llm,omitempty"`

	// Embedding is the vector embedding configuration.
	// +optional
	Embedding *EmbeddingConfig `json:"embedding,omitempty"`

	// Qdrant is the vector store configuration.
	// +optional
	Qdrant *QdrantConfig `json:"qdrant,omitempty"`

	// Analysis configures AI analysis behavior and cost controls.
	// +optional
	Analysis *AnalysisConfig `json:"analysis,omitempty"`

	// KnowledgeBase configures runbook and postmortem indexing.
	// +optional
	KnowledgeBase *KnowledgeBaseConfig `json:"knowledgeBase,omitempty"`

	// Dashboard enables the built-in web dashboard.
	// +optional
	// +kubebuilder:default=true
	DashboardEnabled bool `json:"dashboardEnabled,omitempty"`

	// DashboardPort is the port for the dashboard HTTP server.
	// +optional
	// +kubebuilder:default=8080
	DashboardPort int `json:"dashboardPort,omitempty"`
}

// LogIntelligencePlatformStatus defines the observed state of LogIntelligencePlatform.
type LogIntelligencePlatformStatus struct {
	// Ready indicates whether the platform is fully initialized.
	Ready bool `json:"ready,omitempty"`

	// QdrantConnected indicates whether Qdrant is reachable.
	QdrantConnected bool `json:"qdrantConnected,omitempty"`

	// LLMReady indicates whether the configured LLM provider is reachable.
	LLMReady bool `json:"llmReady,omitempty"`

	// DocumentsIndexed is the number of knowledge base documents indexed.
	DocumentsIndexed int `json:"documentsIndexed,omitempty"`

	// WatchedNamespaces is the count of namespaces being watched.
	WatchedNamespaces int `json:"watchedNamespaces,omitempty"`

	// ActiveIncidents is the count of currently active incidents.
	ActiveIncidents int `json:"activeIncidents,omitempty"`

	// TotalIncidentsToday is the count of incidents created today.
	TotalIncidentsToday int `json:"totalIncidentsToday,omitempty"`

	// LLMCallsToday tracks LLM API calls for cost monitoring.
	LLMCallsToday int `json:"llmCallsToday,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastReconcileTime is when the platform was last reconciled.
	// +optional
	LastReconcileTime *metav1.Time `json:"lastReconcileTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=lip
// +kubebuilder:metadata:annotations="api-approved.kubernetes.io=https://github.com/kubernetes/kubernetes/pull/1111"
// +kubebuilder:printcolumn:name="Ready",type="boolean",JSONPath=".status.ready"
// +kubebuilder:printcolumn:name="LLM",type="string",JSONPath=".spec.llm.provider"
// +kubebuilder:printcolumn:name="Incidents",type="integer",JSONPath=".status.activeIncidents"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// LogIntelligencePlatform is the Schema for the logintelligenceplatforms API.
// It defines global configuration for the AI-powered log intelligence platform.
type LogIntelligencePlatform struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   LogIntelligencePlatformSpec   `json:"spec,omitempty"`
	Status LogIntelligencePlatformStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// LogIntelligencePlatformList contains a list of LogIntelligencePlatform.
type LogIntelligencePlatformList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LogIntelligencePlatform `json:"items"`
}

func init() {
	SchemeBuilder.Register(&LogIntelligencePlatform{}, &LogIntelligencePlatformList{})
}
