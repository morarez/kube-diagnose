/*
Copyright 2026.

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

package aggregator

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/morarez/kube-diagnose/api/v1alpha1"
)

// ---------------------------------------------------------------------------
// Window definitions
// ---------------------------------------------------------------------------

// window describes a named sliding time window used for frequency analysis.
type window struct {
	// name is the human-readable label used in PatternWindow.Window.
	name string
	// duration is the look-back period.
	duration time.Duration
}

// windows is the ordered set of sliding windows the detector tracks.
// Order is preserved in GetFrequency output.
var windows = []window{
	{name: "1m", duration: 1 * time.Minute},
	{name: "5m", duration: 5 * time.Minute},
	{name: "15m", duration: 15 * time.Minute},
}

// staleThreshold is the minimum period of inactivity after which a fingerprint
// is eligible for eviction by CleanupOldData.  Set to 2× the longest window
// so that IsRecurring results are accurate up until cleanup.
const staleThreshold = 30 * time.Minute

// cleanupInterval is the default ticker period for the background cleaner
// goroutine started by CleanupOldData.
const cleanupInterval = 5 * time.Minute

// ---------------------------------------------------------------------------
// fingerprintData — per-fingerprint time-series state
// ---------------------------------------------------------------------------

// fingerprintData holds the rolling timestamp slices for a single fingerprint.
// It is accessed only while the parent PatternDetector's lock is held.
type fingerprintData struct {
	// events maps window name → sorted (ascending) slice of event timestamps.
	// Timestamps outside the window's duration are pruned lazily during reads.
	events map[string][]time.Time

	// lastSeen is the wall-clock time of the most recent recorded event across
	// all windows.  Used by CleanupOldData to decide when a fingerprint has
	// gone idle.
	lastSeen time.Time
}

// newFingerprintData allocates a fresh fingerprintData for the given windows.
func newFingerprintData() *fingerprintData {
	d := &fingerprintData{
		events: make(map[string][]time.Time, len(windows)),
	}
	for _, w := range windows {
		d.events[w.name] = nil
	}
	return d
}

// ---------------------------------------------------------------------------
// PatternDetector
// ---------------------------------------------------------------------------

// PatternDetector tracks how often each fingerprint fires across three sliding
// time windows (1 m, 5 m, 15 m) and provides helpers to detect burst and
// recurring patterns.
//
// All public methods are safe for concurrent use.
//
// Typical usage:
//
//	det := NewPatternDetector(logger)
//	go det.CleanupOldData(ctx)
//
//	det.Record(fp, time.Now())
//	windows := det.GetFrequency(fp)
//	if det.IsBursting(fp, 10) { ... }
type PatternDetector struct {
	mu   sync.Mutex
	data map[string]*fingerprintData // key: fingerprint hex string
	log  *zap.Logger
}

// NewPatternDetector returns a PatternDetector ready for use.
func NewPatternDetector(logger *zap.Logger) *PatternDetector {
	return &PatternDetector{
		data: make(map[string]*fingerprintData),
		log:  logger,
	}
}

// Record appends event time t for fingerprint to every sliding window.
// Events must not be recorded out of chronological order (i.e. t should be
// close to time.Now()); the slices are appended-only and pruned lazily.
func (d *PatternDetector) Record(fingerprint string, t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	fd := d.getOrCreate(fingerprint)
	fd.lastSeen = t

	for _, w := range windows {
		fd.events[w.name] = append(fd.events[w.name], t)
	}
}

// GetFrequency returns a []v1alpha1.PatternWindow (one element per defined
// window) containing the count and rate for fingerprint in each window.
//
// Stale events (older than the window duration relative to now) are pruned
// in-place so that memory usage is bounded.
func (d *PatternDetector) GetFrequency(fingerprint string) []v1alpha1.PatternWindow {
	now := time.Now().UTC()

	d.mu.Lock()
	defer d.mu.Unlock()

	fd, ok := d.data[fingerprint]
	if !ok {
		// Return zeroed windows so callers don't need nil-checks.
		out := make([]v1alpha1.PatternWindow, len(windows))
		for i, w := range windows {
			out[i] = v1alpha1.PatternWindow{Window: w.name, Count: 0, Rate: 0}
		}
		return out
	}

	out := make([]v1alpha1.PatternWindow, len(windows))
	for i, w := range windows {
		pruned := pruneWindow(fd.events[w.name], now, w.duration)
		fd.events[w.name] = pruned

		count := int64(len(pruned))
		rate := 0.0
		if secs := w.duration.Seconds(); secs > 0 {
			rate = float64(count) / secs
		}
		out[i] = v1alpha1.PatternWindow{
			Window: w.name,
			Count:  count,
			Rate:   rate,
		}
	}
	return out
}

// IsBursting returns true when the number of events recorded in the 1-minute
// window strictly exceeds threshold.
func (d *PatternDetector) IsBursting(fingerprint string, threshold int) bool {
	now := time.Now().UTC()
	d.mu.Lock()
	defer d.mu.Unlock()

	fd, ok := d.data[fingerprint]
	if !ok {
		return false
	}

	pruned := pruneWindow(fd.events["1m"], now, 1*time.Minute)
	fd.events["1m"] = pruned
	return len(pruned) > threshold
}

// IsRecurring returns true when fingerprint has at least one event in each of
// the three windows (1m, 5m, 15m), indicating a pattern that has been active
// over the entire 15-minute observation horizon rather than being a single
// transient spike.
func (d *PatternDetector) IsRecurring(fingerprint string) bool {
	now := time.Now().UTC()
	d.mu.Lock()
	defer d.mu.Unlock()

	fd, ok := d.data[fingerprint]
	if !ok {
		return false
	}

	for _, w := range windows {
		pruned := pruneWindow(fd.events[w.name], now, w.duration)
		fd.events[w.name] = pruned
		if len(pruned) == 0 {
			return false
		}
	}
	return true
}

// CleanupOldData runs a background goroutine that periodically evicts
// fingerprints that have had no events for staleThreshold (30 minutes).
// The goroutine exits when ctx is cancelled.
//
// Call this once at startup:
//
//	go detector.CleanupOldData(ctx)
func (d *PatternDetector) CleanupOldData(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	d.log.Info("pattern detector cleanup goroutine started",
		zap.Duration("interval", cleanupInterval),
		zap.Duration("stale_threshold", staleThreshold),
	)

	for {
		select {
		case <-ctx.Done():
			d.log.Info("pattern detector cleanup goroutine stopped")
			return
		case <-ticker.C:
			d.cleanup()
		}
	}
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// getOrCreate returns the fingerprintData for fp, creating it if absent.
// Must be called with d.mu held.
func (d *PatternDetector) getOrCreate(fp string) *fingerprintData {
	if fd, ok := d.data[fp]; ok {
		return fd
	}
	fd := newFingerprintData()
	d.data[fp] = fd
	return fd
}

// cleanup evicts all fingerprints whose lastSeen is older than staleThreshold.
// Must NOT be called with d.mu held (it acquires the lock itself).
func (d *PatternDetector) cleanup() {
	cutoff := time.Now().UTC().Add(-staleThreshold)

	d.mu.Lock()
	defer d.mu.Unlock()

	evicted := 0
	for fp, fd := range d.data {
		if fd.lastSeen.Before(cutoff) {
			delete(d.data, fp)
			evicted++
		}
	}

	if evicted > 0 {
		d.log.Info("pattern detector pruned stale fingerprints",
			zap.Int("evicted", evicted),
			zap.Int("remaining", len(d.data)),
		)
	}
}

// pruneWindow removes events from the front of the slice that fall outside
// [now - duration, now] and returns the trimmed slice.
// The slice is assumed to be in ascending chronological order.
func pruneWindow(events []time.Time, now time.Time, duration time.Duration) []time.Time {
	cutoff := now.Add(-duration)

	// Binary search for the first event that is within the window.
	lo, hi := 0, len(events)
	for lo < hi {
		mid := (lo + hi) / 2
		if events[mid].Before(cutoff) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}

	if lo == 0 {
		// All events are still within the window — nothing to prune.
		return events
	}
	if lo == len(events) {
		// All events are stale — return an empty but re-usable slice.
		return events[:0]
	}
	// Shift surviving events to the front to reclaim memory for the dropped
	// entries rather than simply sub-slicing (which would retain the backing
	// array).
	n := copy(events, events[lo:])
	return events[:n]
}
