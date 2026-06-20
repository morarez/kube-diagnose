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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	diagnosev1alpha1 "github.com/morarez/kube-diagnose/api/v1alpha1"
)

// LogWatchPolicyReconciler reconciles a LogWatchPolicy object.
//
// +kubebuilder:rbac:groups=diagnose.diagnose.k8s.io,resources=logwatchpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=diagnose.diagnose.k8s.io,resources=logwatchpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=diagnose.diagnose.k8s.io,resources=logwatchpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;replicasets;statefulsets;daemonsets,verbs=get;list;watch
type LogWatchPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile processes LogWatchPolicy changes, starting/stopping log watchers
// for pods matching the policy's workload selector.
func (r *LogWatchPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	policy := &diagnosev1alpha1.LogWatchPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			// Policy deleted — watcher goroutines are context-scoped and will exit.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !policy.Spec.Enabled {
		log.Info("LogWatchPolicy is disabled, skipping", "policy", req.Name)
		return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
	}

	// Platform components must be ready before we can watch pods.
	if platformComponents == nil {
		log.Info("Platform components not yet initialised; requeuing", "policy", req.Name)
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}

	watchedPods, err := r.syncWatchers(ctx, policy)
	if err != nil {
		log.Error(err, "failed to sync log watchers", "policy", req.Name)
		return r.updatePolicyStatus(ctx, policy, false, watchedPods, err.Error())
	}

	return r.updatePolicyStatus(ctx, policy, true, watchedPods, "")
}

// syncWatchers computes the desired set of (pod, container) watch targets from
// the policy's workload selector and reconciles with the current watcher state.
func (r *LogWatchPolicyReconciler) syncWatchers(
	ctx context.Context,
	policy *diagnosev1alpha1.LogWatchPolicy,
) (int, error) {
	// Build the list of namespaces to watch.
	namespacesToWatch := r.resolveNamespaces(ctx, policy)

	// Build the label selector (if any).
	var selector labels.Selector
	if policy.Spec.WorkloadSelector != nil && policy.Spec.WorkloadSelector.LabelSelector != nil {
		var err error
		selector, err = metav1.LabelSelectorAsSelector(policy.Spec.WorkloadSelector.LabelSelector)
		if err != nil {
			return 0, fmt.Errorf("parse label selector: %w", err)
		}
	}

	// Compile the exclusion filter for this policy.
	var exclusionPatterns []string
	if policy.Spec.ExclusionPatterns != nil {
		for _, ep := range policy.Spec.ExclusionPatterns {
			exclusionPatterns = append(exclusionPatterns, ep.Pattern)
		}
	}

	watcher := platformComponents.Watcher
	totalPods := 0

	for _, ns := range namespacesToWatch {
		podList := &corev1.PodList{}
		listOpts := []client.ListOption{client.InNamespace(ns)}
		if selector != nil {
			listOpts = append(listOpts, client.MatchingLabelsSelector{Selector: selector})
		}
		if err := r.List(ctx, podList, listOpts...); err != nil {
			return totalPods, fmt.Errorf("list pods in namespace %s: %w", ns, err)
		}

		for i := range podList.Items {
			pod := &podList.Items[i]

			// Only watch running pods.
			if pod.Status.Phase != corev1.PodRunning {
				continue
			}

			// Determine deployment name from owner references.
			deployment := ownerDeploymentName(pod)

			for _, cs := range pod.Spec.Containers {
				watcher.StartWatchingPod(
					ctx,
					pod.Namespace, pod.Name, cs.Name, deployment,
					policy.Namespace, policy.Name,
				)
				totalPods++
			}
		}
	}

	return totalPods, nil
}

// resolveNamespaces returns the list of namespaces to watch for the policy.
// If none are specified, it defaults to the policy's own namespace.
func (r *LogWatchPolicyReconciler) resolveNamespaces(ctx context.Context, policy *diagnosev1alpha1.LogWatchPolicy) []string {
	if policy.Spec.WorkloadSelector == nil || len(policy.Spec.WorkloadSelector.Namespaces) == 0 {
		return []string{policy.Namespace}
	}

	excluded := make(map[string]struct{})
	for _, ns := range policy.Spec.WorkloadSelector.ExcludeNamespaces {
		excluded[ns] = struct{}{}
	}

	var result []string
	for _, ns := range policy.Spec.WorkloadSelector.Namespaces {
		if _, skip := excluded[ns]; !skip {
			result = append(result, ns)
		}
	}
	return result
}

// ownerDeploymentName extracts the Deployment name from a Pod's owner references.
// Returns an empty string if the pod is not owned by a Deployment (via ReplicaSet).
func ownerDeploymentName(pod *corev1.Pod) string {
	for _, ref := range pod.OwnerReferences {
		if ref.Kind == "ReplicaSet" {
			// RS name is typically <deployment-name>-<hash>
			// Return the RS name as an approximation.
			return ref.Name
		}
		if ref.Kind == "StatefulSet" || ref.Kind == "DaemonSet" {
			return ref.Name
		}
	}
	return ""
}

// updatePolicyStatus patches the policy status subresource.
func (r *LogWatchPolicyReconciler) updatePolicyStatus(
	ctx context.Context,
	policy *diagnosev1alpha1.LogWatchPolicy,
	ready bool,
	watchedPods int,
	errMsg string,
) (ctrl.Result, error) {
	now := metav1.Now()
	policy.Status.Ready = ready
	policy.Status.WatchedPods = watchedPods
	policy.Status.LastReconcileTime = &now

	condStatus := metav1.ConditionTrue
	condReason := "Watching"
	condMsg := fmt.Sprintf("Watching %d pod containers", watchedPods)
	if !ready {
		condStatus = metav1.ConditionFalse
		condReason = "Error"
		condMsg = errMsg
	}
	policy.Status.Conditions = []metav1.Condition{{
		Type:               "Ready",
		Status:             condStatus,
		Reason:             condReason,
		Message:            condMsg,
		LastTransitionTime: now,
	}}

	if err := r.Status().Update(ctx, policy); err != nil {
		logf.FromContext(ctx).Error(err, "failed to update LogWatchPolicy status")
	}

	if !ready {
		return ctrl.Result{RequeueAfter: 30 * time.Second}, fmt.Errorf("%s", errMsg)
	}
	return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *LogWatchPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&diagnosev1alpha1.LogWatchPolicy{}).
		Named("logwatchpolicy").
		Complete(r)
}
