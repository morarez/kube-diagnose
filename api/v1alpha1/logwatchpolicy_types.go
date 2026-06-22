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

// LogLevel defines the log severity levels to watch.
// +kubebuilder:validation:Enum=DEBUG;INFO;WARNING;ERROR;FATAL;CRITICAL
type LogLevel string

const (
	LogLevelDebug    LogLevel = "DEBUG"
	LogLevelInfo     LogLevel = "INFO"
	LogLevelWarning  LogLevel = "WARNING"
	LogLevelError    LogLevel = "ERROR"
	LogLevelFatal    LogLevel = "FATAL"
	LogLevelCritical LogLevel = "CRITICAL"
)

// WorkloadSelector identifies a set of workloads to watch.
type WorkloadSelector struct {
	// Namespaces is the list of namespaces to watch.
	// An empty list means all namespaces.
	// +optional
	Namespaces []string `json:"namespaces,omitempty"`

	// ExcludeNamespaces is a list of namespaces to exclude.
	// +optional
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`

	// LabelSelector restricts log watching to pods matching these labels.
	// +optional
	LabelSelector *metav1.LabelSelector `json:"labelSelector,omitempty"`

	// DeploymentNames restricts watching to specific deployment names.
	// +optional
	DeploymentNames []string `json:"deploymentNames,omitempty"`
}

// ExclusionPattern defines a log pattern to exclude from processing.
type ExclusionPattern struct {
	// Name is a human-readable name for the exclusion rule.
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Pattern is a regex pattern. Logs matching this are ignored.
	// +kubebuilder:validation:Required
	Pattern string `json:"pattern"`

	// Reason is a human-readable explanation for the exclusion.
	// +optional
	Reason string `json:"reason,omitempty"`
}

// IncidentConfig defines how incidents are created and managed.
type IncidentConfig struct {
	// DedupWindow is the time window for deduplicating incidents.
	// Identical fingerprints within this window are merged.
	// +optional
	// +kubebuilder:default="1h"
	DedupWindow string `json:"dedupWindow,omitempty"`

	// BurstThreshold is the number of errors per minute that triggers a "burst" incident.
	// +optional
	// +kubebuilder:default=100
	BurstThreshold int `json:"burstThreshold,omitempty"`

	// AutoResolveAfter is the duration after which resolved incidents are archived.
	// +optional
	// +kubebuilder:default="24h"
	AutoResolveAfter string `json:"autoResolveAfter,omitempty"`

	// SLAWindow defines how long an incident can remain open before escalation.
	// +optional
	// +kubebuilder:default="4h"
	SLAWindow string `json:"slaWindow,omitempty"`

	// MaxAffectedPodsToTrack limits how many pod names are stored per incident.
	// +optional
	// +kubebuilder:default=20
	MaxAffectedPodsToTrack int `json:"maxAffectedPodsToTrack,omitempty"`
}

// LogWatchPolicySpec defines the desired state of LogWatchPolicy.
type LogWatchPolicySpec struct {
	// WorkloadSelector defines which workloads to watch.
	// +optional
	WorkloadSelector *WorkloadSelector `json:"workloadSelector,omitempty"`

	// LogLevels is the list of log levels to capture.
	// Defaults to ERROR and FATAL.
	// +optional
	// +kubebuilder:default={"ERROR","FATAL"}
	LogLevels []LogLevel `json:"logLevels,omitempty"`

	// ExclusionPatterns defines log patterns to ignore.
	// +optional
	ExclusionPatterns []ExclusionPattern `json:"exclusionPatterns,omitempty"`

	// IncidentConfig defines incident creation and management behavior.
	// +optional
	IncidentConfig *IncidentConfig `json:"incidentConfig,omitempty"`

	// NotificationOverride overrides the global notification config for this policy.
	// +optional
	NotificationOverride *NotificationConfig `json:"notificationOverride,omitempty"`

	// Enabled controls whether this policy is active.
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// LogIntelligencePlatformRef references the global platform config.
	// +optional
	// +kubebuilder:default="default"
	LogIntelligencePlatformRef string `json:"logIntelligencePlatformRef,omitempty"`
}

// LogWatchPolicyStatus defines the observed state of LogWatchPolicy.
type LogWatchPolicyStatus struct {
	// Ready indicates whether the policy is active and watching.
	Ready bool `json:"ready,omitempty"`

	// WatchedPods is the count of pods currently being watched.
	WatchedPods int `json:"watchedPods,omitempty"`

	// LogsProcessed is the total count of logs processed by this policy.
	LogsProcessed int64 `json:"logsProcessed,omitempty"`

	// ActiveIncidents is the count of active incidents for this policy.
	ActiveIncidents int `json:"activeIncidents,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastReconcileTime is when the policy was last reconciled.
	// +optional
	LastReconcileTime *metav1.Time `json:"lastReconcileTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=lwp
// +kubebuilder:metadata:annotations="api-approved.kubernetes.io=https://github.com/kubernetes/kubernetes/pull/1111"
// +kubebuilder:printcolumn:name="Ready",type="boolean",JSONPath=".status.ready"
// +kubebuilder:printcolumn:name="Pods",type="integer",JSONPath=".status.watchedPods"
// +kubebuilder:printcolumn:name="Incidents",type="integer",JSONPath=".status.activeIncidents"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// LogWatchPolicy is the Schema for the logwatchpolicies API.
// It defines per-namespace log watching configuration.
type LogWatchPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   LogWatchPolicySpec   `json:"spec,omitempty"`
	Status LogWatchPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// LogWatchPolicyList contains a list of LogWatchPolicy.
type LogWatchPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LogWatchPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&LogWatchPolicy{}, &LogWatchPolicyList{})
}
