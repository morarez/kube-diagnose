// Package logwatcher provides facilities for streaming, normalizing, and
// filtering Kubernetes pod logs in real time.
package logwatcher

import (
	"fmt"
	"regexp"
	"strings"
)

// defaultLevels are the severity levels accepted when no explicit list is
// provided to NewFilter. They represent actionable, high-severity signals.
var defaultLevels = []string{"ERROR", "FATAL", "CRITICAL", "PANIC"}

// criticalKeywordRe matches high-severity keywords anywhere inside a raw log
// line (case-insensitive). It is used as a secondary gate so that structured
// logs whose Level field is not populated still pass the filter when they
// clearly describe a serious event.
var criticalKeywordRe = regexp.MustCompile(`(?i)\b(error|fatal|critical|panic)\b`)

// Filter decides whether a NormalizedLog should be forwarded for further
// processing or silently discarded.
//
// A log entry passes the filter when ALL of the following conditions hold:
//  1. Its level (or raw content) matches at least one of the accepted levels.
//  2. Its raw line does NOT match any of the compiled exclusion patterns.
type Filter struct {
	// logLevels holds the upper-cased set of accepted severity levels.
	logLevels map[string]struct{}

	// rawLevels preserves the original slice for inspection / marshalling.
	rawLevels []string

	// ExclusionPatterns, when non-empty, cause matching log lines to be
	// dropped regardless of their severity level.
	ExclusionPatterns []*regexp.Regexp
}

// NewFilter constructs a Filter from human-readable level names and a list
// of Go regular expression strings used as exclusion patterns.
//
// If levels is nil or empty the default set (ERROR, FATAL, CRITICAL, PANIC)
// is used. Every pattern string is compiled and any compilation error is
// returned immediately so the caller receives a fully validated Filter or
// nothing at all.
func NewFilter(levels []string, exclusionPatterns []string) (*Filter, error) {
	if len(levels) == 0 {
		levels = defaultLevels
	}

	// Normalise and deduplicate accepted levels.
	levelSet := make(map[string]struct{}, len(levels))
	normalised := make([]string, 0, len(levels))
	for _, l := range levels {
		upper := strings.ToUpper(strings.TrimSpace(l))
		if upper == "" {
			continue
		}
		if _, dup := levelSet[upper]; !dup {
			levelSet[upper] = struct{}{}
			normalised = append(normalised, upper)
		}
	}

	// Pre-compile exclusion patterns so that errors surface at startup.
	compiled := make([]*regexp.Regexp, 0, len(exclusionPatterns))
	for _, pat := range exclusionPatterns {
		if strings.TrimSpace(pat) == "" {
			continue
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("logwatcher/filter: invalid exclusion pattern %q: %w", pat, err)
		}
		compiled = append(compiled, re)
	}

	return &Filter{
		logLevels:         levelSet,
		rawLevels:         normalised,
		ExclusionPatterns: compiled,
	}, nil
}

// ShouldProcess returns true when the supplied NormalizedLog should be
// forwarded to downstream consumers.
//
// Evaluation order:
//  1. If any exclusion pattern matches entry.Raw → reject immediately.
//  2. If entry.Level is in the accepted set → accept.
//  3. If entry.Raw contains any high-severity keyword (error/fatal/critical/panic)
//     AND that keyword maps to an accepted level → accept.
//  4. Otherwise → reject.
func (f *Filter) ShouldProcess(log *NormalizedLog) bool {
	if log == nil {
		return false
	}

	// ── 1. Exclusion check ───────────────────────────────────────────────
	for _, re := range f.ExclusionPatterns {
		if re.MatchString(log.Raw) {
			return false
		}
	}

	// ── 2. Structured level check ────────────────────────────────────────
	if log.Level != "" {
		if _, ok := f.logLevels[log.Level]; ok {
			return true
		}
	}

	// ── 3. Raw keyword scan ──────────────────────────────────────────────
	// This catches logs that carry no structured level field but whose
	// content clearly signals a high-severity event.
	matches := criticalKeywordRe.FindAllString(log.Raw, -1)
	for _, m := range matches {
		upper := strings.ToUpper(m)
		if _, ok := f.logLevels[upper]; ok {
			return true
		}
	}

	return false
}

// Levels returns the normalised list of accepted severity levels.
// The returned slice is a copy; mutations do not affect the filter.
func (f *Filter) Levels() []string {
	out := make([]string, len(f.rawLevels))
	copy(out, f.rawLevels)
	return out
}
