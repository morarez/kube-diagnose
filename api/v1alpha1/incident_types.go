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

// IncidentSeverity defines the severity level of an incident.
// +kubebuilder:validation:Enum=low;medium;high;critical
type IncidentSeverity string

const (
	IncidentSeverityLow      IncidentSeverity = "low"
	IncidentSeverityMedium   IncidentSeverity = "medium"
	IncidentSeverityHigh     IncidentSeverity = "high"
	IncidentSeverityCritical IncidentSeverity = "critical"
)

// IncidentPhase defines the lifecycle phase of an incident.
// +kubebuilder:validation:Enum=Detecting;Analyzing;Notified;Acknowledged;Resolved;Archived
type IncidentPhase string

const (
	IncidentPhaseDetecting    IncidentPhase = "Detecting"
	IncidentPhaseAnalyzing    IncidentPhase = "Analyzing"
	IncidentPhaseNotified     IncidentPhase = "Notified"
	IncidentPhaseAcknowledged IncidentPhase = "Acknowledged"
	IncidentPhaseResolved     IncidentPhase = "Resolved"
	IncidentPhaseArchived     IncidentPhase = "Archived"
)

// AffectedResource describes a Kubernetes resource involved in an incident.
type AffectedResource struct {
	// Kind is the resource kind (Pod, Deployment, StatefulSet, etc.)
	Kind string `json:"kind"`
	// Name is the resource name.
	Name string `json:"name"`
	// Namespace is the resource namespace.
	Namespace string `json:"namespace"`
	// Container is the container name (for pods).
	// +optional
	Container string `json:"container,omitempty"`
}

// PatternWindow captures frequency data over a time window.
type PatternWindow struct {
	// Window is the duration (e.g. "1m", "5m", "15m").
	Window string `json:"window"`
	// Count is the number of occurrences in this window.
	Count int64 `json:"count"`
	// Rate is occurrences per second.
	Rate float64 `json:"rate,omitempty"`
}

// RecommendedAction is a single actionable remediation step.
type RecommendedAction struct {
	// Step is the action number/order.
	Step int `json:"step"`
	// Action is the human-readable action description.
	Action string `json:"action"`
	// Command is an optional kubectl or shell command to run.
	// +optional
	Command string `json:"command,omitempty"`
	// Priority indicates urgency: immediate, short-term, long-term.
	// +optional
	Priority string `json:"priority,omitempty"`
}

// AIAnalysis holds the result of LLM analysis or RAG retrieval.
type AIAnalysis struct {
	// RootCause is the identified root cause of the incident.
	RootCause string `json:"rootCause,omitempty"`

	// Confidence is a 0.0–1.0 score indicating analysis certainty.
	Confidence float64 `json:"confidence,omitempty"`

	// Impact describes the business/service impact of the incident.
	Impact string `json:"impact,omitempty"`

	// Severity is the determined severity level.
	Severity IncidentSeverity `json:"severity,omitempty"`

	// RecommendedActions is the ordered list of remediation steps.
	// +optional
	RecommendedActions []RecommendedAction `json:"recommendedActions,omitempty"`

	// RelatedRunbooks is a list of relevant runbook references.
	// +optional
	RelatedRunbooks []string `json:"relatedRunbooks,omitempty"`

	// AnalysisSource indicates whether analysis came from RAG or LLM.
	// +kubebuilder:validation:Enum=rag;llm;cache;unknown
	AnalysisSource string `json:"analysisSource,omitempty"`

	// AnalyzedAt is when the analysis was performed.
	// +optional
	AnalyzedAt *metav1.Time `json:"analyzedAt,omitempty"`

	// TokensUsed is the LLM token count (for cost tracking).
	// +optional
	TokensUsed int `json:"tokensUsed,omitempty"`
}

// IncidentSpec defines the desired state of Incident.
// Note: Incidents are primarily system-managed; spec is intentionally minimal.
type IncidentSpec struct {
	// Acknowledged indicates the incident has been acknowledged by a human.
	// +optional
	Acknowledged bool `json:"acknowledged,omitempty"`

	// AcknowledgedBy is the user who acknowledged the incident.
	// +optional
	AcknowledgedBy string `json:"acknowledgedBy,omitempty"`

	// Notes are operator notes about this incident.
	// +optional
	Notes string `json:"notes,omitempty"`
}

// IncidentStatus defines the observed state of Incident.
type IncidentStatus struct {
	// Phase is the current lifecycle phase.
	Phase IncidentPhase `json:"phase,omitempty"`

	// Fingerprint is the SimHash fingerprint of the error pattern.
	Fingerprint string `json:"fingerprint,omitempty"`

	// Pattern is the normalized, human-readable error pattern.
	Pattern string `json:"pattern,omitempty"`

	// Count is the total number of occurrences.
	Count int64 `json:"count,omitempty"`

	// AffectedResources is the list of Kubernetes resources involved.
	// +optional
	AffectedResources []AffectedResource `json:"affectedResources,omitempty"`

	// SampleLogMessage is a representative log line for this incident.
	SampleLogMessage string `json:"sampleLogMessage,omitempty"`

	// FirstSeen is when the incident was first detected.
	// +optional
	FirstSeen *metav1.Time `json:"firstSeen,omitempty"`

	// LastSeen is when the incident was most recently observed.
	// +optional
	LastSeen *metav1.Time `json:"lastSeen,omitempty"`

	// FrequencyWindows captures occurrence rates across time windows.
	// +optional
	FrequencyWindows []PatternWindow `json:"frequencyWindows,omitempty"`

	// Analysis holds the AI/RAG analysis result.
	// +optional
	Analysis *AIAnalysis `json:"analysis,omitempty"`

	// Severity is the determined severity level.
	Severity IncidentSeverity `json:"severity,omitempty"`

	// Notified indicates whether notifications have been sent.
	Notified bool `json:"notified,omitempty"`

	// NotifiedAt is when notifications were last sent.
	// +optional
	NotifiedAt *metav1.Time `json:"notifiedAt,omitempty"`

	// Resolved indicates whether the incident is resolved.
	Resolved bool `json:"resolved,omitempty"`

	// ResolvedAt is when the incident was resolved.
	// +optional
	ResolvedAt *metav1.Time `json:"resolvedAt,omitempty"`

	// PolicyRef is the LogWatchPolicy that owns this incident.
	PolicyRef string `json:"policyRef,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=inc
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Severity",type="string",JSONPath=".status.severity"
// +kubebuilder:printcolumn:name="Count",type="integer",JSONPath=".status.count"
// +kubebuilder:printcolumn:name="Pattern",type="string",JSONPath=".status.pattern",priority=1
// +kubebuilder:printcolumn:name="First Seen",type="date",JSONPath=".status.firstSeen"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// Incident is the Schema for the incidents API.
// It represents a grouped, deduplicated error pattern with AI analysis.
type Incident struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IncidentSpec   `json:"spec,omitempty"`
	Status IncidentStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IncidentList contains a list of Incident.
type IncidentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Incident `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Incident{}, &IncidentList{})
}
