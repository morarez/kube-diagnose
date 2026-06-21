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
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	diagnosev1alpha1 "github.com/morarez/kube-diagnose/api/v1alpha1"
)

// IncidentReconciler reconciles Incident objects.
//
// Its primary responsibilities are:
//  1. Trigger notifications for newly created incidents (status.phase == Detecting).
//  2. Index resolved incidents into Qdrant for future RAG retrieval.
//  3. Auto-archive incidents that have been resolved beyond the configured window.
//
// +kubebuilder:rbac:groups=diagnose.diagnose.k8s.io,resources=incidents,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=diagnose.diagnose.k8s.io,resources=incidents/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=diagnose.diagnose.k8s.io,resources=incidents/finalizers,verbs=update
type IncidentReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile processes Incident state transitions.
func (r *IncidentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	incident := &diagnosev1alpha1.Incident{}
	if err := r.Get(ctx, req.NamespacedName, incident); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// ── Auto-archive resolved incidents ───────────────────────────────────────
	if incident.Status.Resolved && incident.Status.Phase != diagnosev1alpha1.IncidentPhaseArchived {
		if incident.Status.ResolvedAt != nil {
			archiveAfter := 24 * time.Hour
			if time.Since(incident.Status.ResolvedAt.Time) > archiveAfter {
				log.Info("archiving resolved incident", "incident", req.Name)
				return r.transitionPhase(ctx, incident, diagnosev1alpha1.IncidentPhaseArchived)
			}
		}
		return ctrl.Result{RequeueAfter: time.Hour}, nil
	}

	// ── Index resolved incidents in RAG ───────────────────────────────────────
	if incident.Status.Resolved && platformComponents != nil &&
		incident.Status.Analysis != nil &&
		incident.Status.Phase == diagnosev1alpha1.IncidentPhaseResolved {

		go func() {
			indexCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			rootCause := ""
			resolution := ""
			if incident.Status.Analysis != nil {
				rootCause = incident.Status.Analysis.RootCause
				var actions []string
				for _, act := range incident.Status.Analysis.RecommendedActions {
					if act.Command != "" {
						actions = append(actions, fmt.Sprintf("%s (Run: %s)", act.Action, act.Command))
					} else {
						actions = append(actions, act.Action)
					}
				}
				resolution = strings.Join(actions, "; ")
			}

			if err := platformComponents.RAGEngine.IndexResolvedIncident(
				indexCtx,
				incident.Status.Fingerprint,
				incident.Status.Pattern,
				rootCause,
				resolution,
				incident.Namespace,
			); err != nil {
				log.Error(err, "failed to index resolved incident in RAG", "incident", req.Name)
			} else {
				log.Info("indexed resolved incident in RAG", "incident", req.Name)
			}
		}()
	}

	// ── Phase progression for unresolved incidents ────────────────────────────
	switch incident.Status.Phase {
	case diagnosev1alpha1.IncidentPhaseDetecting:
		// Move to Analyzing if we have analysis data.
		if incident.Status.Analysis != nil {
			return r.transitionPhase(ctx, incident, diagnosev1alpha1.IncidentPhaseAnalyzing)
		}
	case diagnosev1alpha1.IncidentPhaseAnalyzing:
		// Move to Notified once notifications have been sent.
		if incident.Status.Notified {
			return r.transitionPhase(ctx, incident, diagnosev1alpha1.IncidentPhaseNotified)
		}
	case diagnosev1alpha1.IncidentPhaseNotified:
		// Check SLA breach: if the incident has been open too long, log a warning.
		if incident.Status.FirstSeen != nil {
			if time.Since(incident.Status.FirstSeen.Time) > 4*time.Hour {
				log.Info("incident SLA breach — unresolved after 4h",
					"incident", req.Name,
					"pattern", incident.Status.Pattern,
					"severity", incident.Status.Severity,
				)
			}
		}
	}

	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// transitionPhase patches the incident's phase in the status subresource.
func (r *IncidentReconciler) transitionPhase(
	ctx context.Context,
	incident *diagnosev1alpha1.Incident,
	phase diagnosev1alpha1.IncidentPhase,
) (ctrl.Result, error) {
	patch := client.MergeFrom(incident.DeepCopy())
	incident.Status.Phase = phase

	now := metav1.Now()
	incident.Status.Conditions = append(incident.Status.Conditions, metav1.Condition{
		Type:               string(phase),
		Status:             metav1.ConditionTrue,
		Reason:             "PhaseTransition",
		Message:            "Incident transitioned to " + string(phase),
		LastTransitionTime: now,
	})

	if err := r.Status().Patch(ctx, incident, patch); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: time.Minute}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IncidentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&diagnosev1alpha1.Incident{}).
		Named("incident").
		Complete(r)
}
