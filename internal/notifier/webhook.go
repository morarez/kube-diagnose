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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// WebhookNotifier sends incident notifications to a generic HTTP webhook endpoint.
type WebhookNotifier struct {
	url         string
	method      string
	headers     map[string]string
	hmacSecret  string
	minSeverity string
	httpClient  *http.Client
	logger      *zap.Logger
}

// WebhookPayload is the JSON body sent to the webhook.
type WebhookPayload struct {
	EventType    string                 `json:"eventType"`
	Timestamp    string                 `json:"timestamp"`
	Source       string                 `json:"source"`
	IncidentName string                 `json:"incidentName"`
	Namespace    string                 `json:"namespace"`
	Pattern      string                 `json:"pattern"`
	Count        int64                  `json:"count"`
	Severity     string                 `json:"severity"`
	Phase        string                 `json:"phase"`
	AffectedPods []string               `json:"affectedPods"`
	Analysis     map[string]interface{} `json:"analysis"`
	DashboardURL string                 `json:"dashboardUrl"`
	FirstSeen    string                 `json:"firstSeen"`
	LastSeen     string                 `json:"lastSeen"`
}

// NewWebhookNotifier creates a new generic webhook notifier.
func NewWebhookNotifier(url, method, minSeverity, hmacSecret string, headers map[string]string, logger *zap.Logger) *WebhookNotifier {
	if method == "" {
		method = http.MethodPost
	}
	if minSeverity == "" {
		minSeverity = SeverityHigh
	}
	return &WebhookNotifier{
		url:         url,
		method:      method,
		headers:     headers,
		hmacSecret:  hmacSecret,
		minSeverity: minSeverity,
		httpClient:  newHTTPClient(),
		logger:      logger,
	}
}

func (w *WebhookNotifier) Name() string        { return "webhook" }
func (w *WebhookNotifier) MinSeverity() string { return w.minSeverity }

// Send sends a signed JSON payload to the webhook URL.
func (w *WebhookNotifier) Send(ctx context.Context, n *IncidentNotification) error {
	if w.url == "" {
		return fmt.Errorf("webhook URL is not configured")
	}

	payload := WebhookPayload{
		EventType:    "incident.created",
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Source:       "kube-diagnose",
		IncidentName: n.IncidentName,
		Namespace:    n.Namespace,
		Pattern:      n.Pattern,
		Count:        n.Count,
		Severity:     n.Severity,
		Phase:        n.Phase,
		AffectedPods: n.AffectedPods,
		Analysis: map[string]interface{}{
			"rootCause":          n.RootCause,
			"recommendedActions": n.RecommendedActions,
		},
		DashboardURL: n.DashboardURL,
		FirstSeen:    n.FirstSeen.Format(time.RFC3339),
		LastSeen:     n.LastSeen.Format(time.RFC3339),
	}

	headers := make(map[string]string)
	for k, v := range w.headers {
		headers[k] = v
	}

	// Add HMAC signature if secret is configured.
	if w.hmacSecret != "" {
		body, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal for signing: %w", err)
		}
		sig := computeHMACSHA256(body, w.hmacSecret)
		headers["X-Kube-Diagnose-Signature"] = "sha256=" + sig
		headers["X-Kube-Diagnose-Timestamp"] = time.Now().UTC().Format(time.RFC3339)
	}

	return doHTTPPost(ctx, w.httpClient, w.url, headers, payload)
}

// computeHMACSHA256 returns the HMAC-SHA256 hex digest of the payload.
func computeHMACSHA256(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
