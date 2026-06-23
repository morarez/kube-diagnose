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

// SlackNotifier sends incident notifications to a Slack channel via webhook.
type SlackNotifier struct {
	webhookURL  string
	channel     string
	minSeverity string
	httpClient  *http.Client
	logger      *zap.Logger
}

// NewSlackNotifier creates a new Slack notifier.
func NewSlackNotifier(webhookURL, channel, minSeverity string, logger *zap.Logger) *SlackNotifier {
	if minSeverity == "" {
		minSeverity = SeverityHigh
	}
	return &SlackNotifier{
		webhookURL:  webhookURL,
		channel:     channel,
		minSeverity: minSeverity,
		httpClient:  newHTTPClient(),
		logger:      logger,
	}
}

func (s *SlackNotifier) Name() string        { return "slack" }
func (s *SlackNotifier) MinSeverity() string { return s.minSeverity }

// Send sends a Slack Block Kit message.
func (s *SlackNotifier) Send(ctx context.Context, n *IncidentNotification) error {
	if s.webhookURL == "" {
		return fmt.Errorf("slack webhook URL is not configured")
	}

	color := severityColor(n.Severity)
	emoji := severityEmoji(n.Severity)

	actionsText := ""
	if len(n.RecommendedActions) > 0 {
		var actions []string
		for i, a := range n.RecommendedActions {
			if i >= 3 {
				actions = append(actions, fmt.Sprintf("...and %d more", len(n.RecommendedActions)-3))
				break
			}
			actions = append(actions, fmt.Sprintf("• %s", a))
		}
		actionsText = strings.Join(actions, "\n")
	}

	var affectedText string
	if len(n.AffectedPods) <= 3 {
		affectedText = strings.Join(n.AffectedPods, ", ")
	} else {
		affectedText = fmt.Sprintf("%s (+%d more)", strings.Join(n.AffectedPods[:3], ", "), len(n.AffectedPods)-3)
	}

	payload := map[string]interface{}{
		"text": fmt.Sprintf("%s *New Incident: %s*", emoji, n.IncidentName),
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"blocks": []map[string]interface{}{
					{
						"type": "header",
						"text": map[string]string{
							"type": "plain_text",
							"text": fmt.Sprintf("%s Incident: %s", emoji, n.Severity),
						},
					},
					{
						"type": "section",
						"fields": []map[string]string{
							{"type": "mrkdwn", "text": fmt.Sprintf("*Pattern:*\n`%s`", truncate(n.Pattern, 80))},
							{"type": "mrkdwn", "text": fmt.Sprintf("*Namespace:*\n%s", n.Namespace)},
							{"type": "mrkdwn", "text": fmt.Sprintf("*Occurrences:*\n%d", n.Count)},
							{"type": "mrkdwn", "text": fmt.Sprintf("*Affected:*\n%s", affectedText)},
							{"type": "mrkdwn", "text": fmt.Sprintf("*First Seen:*\n%s", n.FirstSeen.Format(time.RFC3339))},
							{"type": "mrkdwn", "text": fmt.Sprintf("*Phase:*\n%s", n.Phase)},
						},
					},
					{
						"type": "section",
						"text": map[string]string{
							"type": "mrkdwn",
							"text": fmt.Sprintf("*Root Cause:*\n%s", truncate(n.RootCause, 300)),
						},
					},
					{
						"type": "section",
						"text": map[string]string{
							"type": "mrkdwn",
							"text": fmt.Sprintf("*Recommended Actions:*\n%s", actionsText),
						},
					},
					{
						"type": "actions",
						"elements": []map[string]interface{}{
							{
								"type": "button",
								"text": map[string]string{"type": "plain_text", "text": "View in Dashboard"},
								"url":  n.DashboardURL,
							},
						},
					},
				},
			},
		},
	}

	if s.channel != "" {
		payload["channel"] = s.channel
	}

	return doHTTPPost(ctx, s.httpClient, s.webhookURL, nil, payload)
}

func severityColor(severity string) string {
	switch severity {
	case SeverityCritical:
		return "#FF0000"
	case SeverityHigh:
		return "#FF8C00"
	case SeverityMedium:
		return "#FFD700"
	default:
		return "#36A64F"
	}
}

func severityEmoji(severity string) string {
	switch severity {
	case SeverityCritical:
		return "🚨"
	case SeverityHigh:
		return "🔴"
	case SeverityMedium:
		return "🟡"
	default:
		return "🟢"
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
