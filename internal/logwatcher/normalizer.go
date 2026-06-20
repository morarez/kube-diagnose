// Package logwatcher provides facilities for streaming, normalizing, and
// filtering Kubernetes pod logs in real time.
package logwatcher

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
)

// NormalizedLog is the canonical representation of a single log line
// regardless of whether it originated from a structured (JSON) or
// plain-text log stream.
type NormalizedLog struct {
	// Kubernetes coordinates
	Cluster    string
	Namespace  string
	Deployment string
	Pod        string
	Container  string

	// Log content
	Timestamp time.Time
	Level     string
	Message   string

	// Raw is the unmodified original log line.
	Raw string
}

// Normalizer converts raw log lines emitted by Kubernetes containers into
// NormalizedLog values. It attempts structured (JSON) parsing first and
// falls back to regex-based heuristics for plain-text logs.
type Normalizer struct {
	cluster string
	logger  *zap.Logger
}

// NewNormalizer constructs a Normalizer that annotates every produced
// NormalizedLog with the given cluster name.
func NewNormalizer(cluster string, logger *zap.Logger) *Normalizer {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Normalizer{
		cluster: cluster,
		logger:  logger.With(zap.String("component", "normalizer")),
	}
}

// Normalize converts a single raw log line into a NormalizedLog.
//
// The caller must supply the Kubernetes coordinates (namespace, pod,
// container, deployment) so they can be embedded into every log entry.
// The function never returns a nil *NormalizedLog together with a nil
// error — on parsing failures it still returns a best-effort entry.
func (n *Normalizer) Normalize(namespace, pod, container, deployment, raw string) (*NormalizedLog, error) {
	entry := &NormalizedLog{
		Cluster:    n.cluster,
		Namespace:  namespace,
		Deployment: deployment,
		Pod:        pod,
		Container:  container,
		Raw:        raw,
		// Sensible default so callers can always sort by Timestamp.
		Timestamp: time.Now().UTC(),
	}

	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return entry, nil
	}

	// ── 1. Attempt JSON parsing ──────────────────────────────────────────
	if strings.HasPrefix(trimmed, "{") {
		if err := parseJSON(trimmed, entry); err == nil {
			return entry, nil
		}
		// JSON parse failed — fall through to regex.
		n.logger.Debug("json parse failed, falling back to regex",
			zap.String("pod", pod),
			zap.String("container", container),
			zap.String("raw", raw),
		)
	}

	// ── 2. Regex-based fallback ──────────────────────────────────────────
	parseTextLine(trimmed, entry)
	return entry, nil
}

// ─── JSON parsing ───────────────────────────────────────────────────────────

// parseJSON extracts timestamp, level, and message from a JSON log line.
// It is tolerant of the many field-name conventions used across popular
// logging libraries (zerolog, zap, logrus, slog …).
func parseJSON(raw string, entry *NormalizedLog) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return fmt.Errorf("json unmarshal: %w", err)
	}

	// ── level ────────────────────────────────────────────────────────────
	for _, key := range []string{"level", "severity", "lvl", "log.level"} {
		if v, ok := m[key]; ok {
			var s string
			if err := json.Unmarshal(v, &s); err == nil {
				entry.Level = strings.ToUpper(strings.TrimSpace(s))
				break
			}
		}
	}

	// ── message ──────────────────────────────────────────────────────────
	for _, key := range []string{"msg", "message", "log", "body"} {
		if v, ok := m[key]; ok {
			var s string
			if err := json.Unmarshal(v, &s); err == nil {
				entry.Message = s
				break
			}
		}
	}

	// ── timestamp ────────────────────────────────────────────────────────
	for _, key := range []string{"time", "timestamp", "ts", "@timestamp", "date"} {
		if v, ok := m[key]; ok {
			if t, err := parseTimestampValue(v); err == nil {
				entry.Timestamp = t
				break
			}
		}
	}

	return nil
}

// parseTimestampValue handles the various timestamp representations found in
// the wild: RFC 3339 strings, Unix epoch integers, and Unix epoch floats.
func parseTimestampValue(raw json.RawMessage) (time.Time, error) {
	// Try string first (most common).
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		for _, layout := range []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05.999999999",
			"2006-01-02 15:04:05",
			"2006-01-02 15:04:05.999999999",
		} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.UTC(), nil
			}
		}
		return time.Time{}, fmt.Errorf("unrecognised timestamp string: %q", s)
	}

	// Try numeric (Unix seconds, possibly fractional).
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		sec := int64(f)
		nsec := int64((f - float64(sec)) * 1e9)
		return time.Unix(sec, nsec).UTC(), nil
	}

	return time.Time{}, fmt.Errorf("cannot parse timestamp from %s", string(raw))
}

// ─── Regex-based plain-text parsing ─────────────────────────────────────────

// rfc3339Re matches an ISO-8601 / RFC 3339 timestamp at the beginning or
// anywhere within a plain-text log line.
var rfc3339Re = regexp.MustCompile(
	`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?`,
)

// levelRe captures common log-level tokens in plain-text lines.
// It intentionally accepts both bracketed (e.g. [ERROR]) and bare forms.
var levelRe = regexp.MustCompile(
	`(?i)\b(TRACE|DEBUG|INFO(?:RMATION)?|WARN(?:ING)?|ERROR|FATAL|CRITICAL|PANIC|NOTICE)\b`,
)

// parseTextLine populates entry.Timestamp, entry.Level, and entry.Message
// via regular expression heuristics. entry.Raw is always used as Message
// when no better extraction is possible.
func parseTextLine(raw string, entry *NormalizedLog) {
	remainder := raw

	// ── timestamp ────────────────────────────────────────────────────────
	if loc := rfc3339Re.FindStringIndex(raw); loc != nil {
		ts := raw[loc[0]:loc[1]]
		for _, layout := range []string{
			"2006-01-02T15:04:05.999999999Z07:00",
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02T15:04:05.999999999",
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05.999999999",
			"2006-01-02 15:04:05",
		} {
			if t, err := time.Parse(layout, ts); err == nil {
				entry.Timestamp = t.UTC()
				// Strip the matched timestamp from the remainder so
				// level extraction is less likely to get confused.
				remainder = strings.TrimSpace(raw[:loc[0]] + raw[loc[1]:])
				break
			}
		}
	}

	// ── level ────────────────────────────────────────────────────────────
	if m := levelRe.FindString(remainder); m != "" {
		entry.Level = normalizeLevel(strings.ToUpper(m))
	}

	// ── message ──────────────────────────────────────────────────────────
	// Use the full raw line as the human-readable message so no context
	// is lost, even after we've extracted structured fields above.
	entry.Message = raw
}

// normalizeLevel maps variant spellings to a canonical form.
func normalizeLevel(l string) string {
	switch l {
	case "INFORMATION":
		return "INFO"
	case "WARNING":
		return "WARN"
	default:
		return l
	}
}
