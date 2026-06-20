/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
you may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package notifier

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

const (
	pagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"
)

// PagerDutyNotifier sends incidents to PagerDuty via Events API v2.
type PagerDutyNotifier struct {
	integrationKey string
	minSeverity    string
	httpClient     *http.Client
	logger         *zap.Logger
}

// NewPagerDutyNotifier creates a new PagerDuty notifier.
func NewPagerDutyNotifier(integrationKey, minSeverity string, logger *zap.Logger) *PagerDutyNotifier {
	if minSeverity == "" {
		minSeverity = SeverityCritical
	}
	return &PagerDutyNotifier{
		integrationKey: integrationKey,
		minSeverity:    minSeverity,
		httpClient:     newHTTPClient(),
		logger:         logger,
	}
}

func (p *PagerDutyNotifier) Name() string        { return "pagerduty" }
func (p *PagerDutyNotifier) MinSeverity() string { return p.minSeverity }

// Send sends a PagerDuty v2 trigger event.
func (p *PagerDutyNotifier) Send(ctx context.Context, n *IncidentNotification) error {
	if p.integrationKey == "" {
		return fmt.Errorf("PagerDuty integration key is not configured")
	}

	pdSeverity := mapToPagerDutySeverity(n.Severity)

	summary := fmt.Sprintf("[%s] %s — %d occurrences in %s",
		strings.ToUpper(n.Severity), truncate(n.Pattern, 100), n.Count, n.Namespace)

	payload := map[string]interface{}{
		"routing_key":  p.integrationKey,
		"event_action": "trigger",
		"dedup_key":    n.IncidentName,
		"payload": map[string]interface{}{
			"summary":   summary,
			"severity":  pdSeverity,
			"source":    "kube-diagnose",
			"component": n.Namespace,
			"group":     n.Namespace,
			"class":     "kubernetes-incident",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"custom_details": map[string]interface{}{
				"incident_name":       n.IncidentName,
				"namespace":           n.Namespace,
				"pattern":             n.Pattern,
				"occurrence_count":    n.Count,
				"affected_pods":       strings.Join(n.AffectedPods, ", "),
				"root_cause":          n.RootCause,
				"recommended_actions": strings.Join(n.RecommendedActions, "; "),
				"first_seen":          n.FirstSeen.Format(time.RFC3339),
				"last_seen":           n.LastSeen.Format(time.RFC3339),
				"phase":               n.Phase,
				"dashboard_url":       n.DashboardURL,
			},
		},
		"links": []map[string]string{
			{
				"href": n.DashboardURL,
				"text": "View in Kube-Diagnose Dashboard",
			},
		},
	}

	return doHTTPPost(ctx, p.httpClient, pagerDutyEventsURL, map[string]string{
		"Accept": "application/vnd.pagerduty+json;version=2",
	}, payload)
}

// mapToPagerDutySeverity converts internal severity to PagerDuty severity levels.
func mapToPagerDutySeverity(severity string) string {
	switch severity {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "info"
	}
}
