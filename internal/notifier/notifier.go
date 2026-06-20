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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Severity level constants for notification filtering.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

var severityRank = map[string]int{
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// IncidentNotification is the data passed to all notifiers.
type IncidentNotification struct {
	// IncidentName is the Kubernetes resource name.
	IncidentName string
	// Namespace where the incident occurred.
	Namespace string
	// Pattern is the normalized error pattern.
	Pattern string
	// Count is the total occurrence count.
	Count int64
	// Severity is the determined severity level.
	Severity string
	// Phase is the incident lifecycle phase.
	Phase string
	// AffectedPods is a list of pod names involved.
	AffectedPods []string
	// RootCause from AI analysis.
	RootCause string
	// RecommendedActions from AI analysis.
	RecommendedActions []string
	// FirstSeen is when the incident started.
	FirstSeen time.Time
	// LastSeen is when the incident was last observed.
	LastSeen time.Time
	// DashboardURL is a link to the dashboard for this incident.
	DashboardURL string
}

// NotificationChannel defines the interface all notifiers must implement.
type NotificationChannel interface {
	// Send sends a notification about an incident.
	Send(ctx context.Context, n *IncidentNotification) error
	// Name returns the notifier name.
	Name() string
	// MinSeverity returns the minimum severity this channel handles.
	MinSeverity() string
}

// Notifier orchestrates multiple notification channels.
type Notifier struct {
	channels []NotificationChannel
	logger   *zap.Logger
}

// NewNotifier creates a new Notifier with the given channels.
func NewNotifier(channels []NotificationChannel, logger *zap.Logger) *Notifier {
	return &Notifier{
		channels: channels,
		logger:   logger,
	}
}

// Notify sends the incident notification to all eligible channels.
func (n *Notifier) Notify(ctx context.Context, notification *IncidentNotification) error {
	if notification == nil {
		return fmt.Errorf("notification is nil")
	}

	incidentRank := severityRank[notification.Severity]
	if incidentRank == 0 {
		incidentRank = 1
	}

	var errs []error
	for _, ch := range n.channels {
		minRank := severityRank[ch.MinSeverity()]
		if minRank == 0 {
			minRank = 1
		}
		if incidentRank < minRank {
			n.logger.Debug("Skipping notifier — incident severity below threshold",
				zap.String("notifier", ch.Name()),
				zap.String("incidentSeverity", notification.Severity),
				zap.String("minSeverity", ch.MinSeverity()),
			)
			continue
		}

		n.logger.Info("Sending notification",
			zap.String("channel", ch.Name()),
			zap.String("incident", notification.IncidentName),
			zap.String("severity", notification.Severity),
		)

		if err := ch.Send(ctx, notification); err != nil {
			n.logger.Error("Notification failed",
				zap.String("channel", ch.Name()),
				zap.Error(err),
			)
			errs = append(errs, fmt.Errorf("%s: %w", ch.Name(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("notification errors: %v", errs)
	}
	return nil
}

// doHTTPPost is a shared helper for sending HTTP POST requests.
func doHTTPPost(ctx context.Context, client *http.Client, url string, headers map[string]string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return nil
}

// newHTTPClient creates an HTTP client with sensible defaults.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
	}
}
