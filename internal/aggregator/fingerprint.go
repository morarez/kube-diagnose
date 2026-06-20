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

// Package aggregator implements log-event deduplication, fingerprinting,
// incident storage, and sliding-window pattern detection for kube-diagnose.
package aggregator

import (
	"crypto/md5" //nolint:gosec // MD5 is used for locality-sensitive hashing, not cryptographic security.
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"regexp"
	"strings"
	"unicode"
)

// ---------------------------------------------------------------------------
// Pre-compiled regular expressions for log normalization.
// ---------------------------------------------------------------------------

var (
	// reUUID matches standard UUID v4 strings (with or without braces).
	reUUID = regexp.MustCompile(
		`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
	)

	// reIP matches IPv4 addresses (e.g. 10.0.0.1) and IPv4:port combos.
	reIP = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b`)

	// reLargeNumber matches standalone numeric IDs that are 8 or more digits
	// long — these are almost always ephemeral identifiers (PIDs, inode
	// numbers, object IDs) that should not affect fingerprint similarity.
	reLargeNumber = regexp.MustCompile(`\b\d{8,}\b`)

	// rePodSuffix strips the two-segment random suffix Kubernetes appends to
	// ReplicaSet/Deployment pod names (e.g. "-abc12-xyz99").
	rePodSuffix = regexp.MustCompile(`-[a-z0-9]{5,10}-[a-z0-9]{5}\b`)

	// reTimestamp matches common log timestamp formats:
	//   • ISO-8601 / RFC-3339        2006-01-02T15:04:05Z
	//   • Syslog-style date-time     Jan  2 15:04:05
	//   • Epoch seconds / ms         1718123456 / 1718123456789
	reTimestamp = regexp.MustCompile(
		`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?` +
			`|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}` +
			`|\b\d{10,13}\b`,
	)

	// reNonWord collapses sequences of non-alphabetic, non-digit characters
	// into a single space for tokenization.
	reNonWord = regexp.MustCompile(`[^a-zA-Z0-9]+`)
)

// stopWords is the set of common English and Kubernetes-log words that carry
// no discriminating signal for fingerprinting.
var stopWords = map[string]struct{}{
	"a": {}, "an": {}, "the": {}, "and": {}, "or": {}, "but": {},
	"in": {}, "on": {}, "at": {}, "to": {}, "for": {}, "of": {},
	"with": {}, "by": {}, "from": {}, "is": {}, "are": {}, "was": {},
	"were": {}, "be": {}, "been": {}, "being": {}, "have": {}, "has": {},
	"had": {}, "do": {}, "does": {}, "did": {}, "will": {}, "would": {},
	"could": {}, "should": {}, "may": {}, "might": {}, "can": {},
	"not": {}, "no": {}, "nor": {}, "so": {}, "yet": {}, "both": {},
	"either": {}, "neither": {}, "this": {}, "that": {}, "these": {},
	"those": {}, "it": {}, "its": {},
	// Kubernetes / container runtime common words
	"error": {}, "err": {}, "warn": {}, "warning": {}, "info": {},
	"debug": {}, "level": {}, "msg": {}, "message": {}, "log": {},
	"time": {}, "ts": {}, "caller": {}, "source": {}, "line": {},
	"pod": {}, "container": {}, "namespace": {}, "node": {},
}

// ---------------------------------------------------------------------------
// Fingerprinter
// ---------------------------------------------------------------------------

// Fingerprinter computes SimHash fingerprints for log messages, enabling
// fast similarity detection across large volumes of log events.
//
// A SimHash is a locality-sensitive hash: similar messages produce fingerprints
// that differ in only a few bits, making Hamming distance an accurate proxy
// for semantic similarity without storing full message text.
type Fingerprinter struct{}

// NewFingerprinter returns a ready-to-use Fingerprinter.
// The struct carries no mutable state; multiple goroutines may call its methods
// concurrently without synchronisation.
func NewFingerprinter() *Fingerprinter {
	return &Fingerprinter{}
}

// Fingerprint normalises msg and returns its 64-bit SimHash as a 16-character
// lowercase hexadecimal string.
//
// Algorithm
//  1. Normalise  – lower-case, strip timestamps, UUIDs, IPs, large numeric
//     IDs, and Kubernetes pod-name suffixes.
//  2. Tokenise   – split on non-word boundaries, remove stop words and
//     tokens that are purely numeric or single characters.
//  3. SimHash    – for each surviving token compute MD5; use the first 8
//     bytes as a uint64 feature hash.  For every bit position 0-63 increment
//     a signed counter by +1 if the bit is set, -1 otherwise.  The final
//     fingerprint sets bit i to 1 iff counter[i] > 0.
//  4. Encode     – return the 64-bit result as a 16-char hex string.
func (f *Fingerprinter) Fingerprint(message string) string {
	tokens := f.tokenize(f.normalize(message))

	// v[i] accumulates the "vote" for bit position i across all tokens.
	// Using a fixed-size array avoids heap allocation.
	var v [64]int

	for _, tok := range tokens {
		// MD5 is cheap, deterministic, and produces well-distributed output.
		// We only need the first 8 bytes (64 bits) for the feature hash.
		//nolint:gosec
		sum := md5.Sum([]byte(tok))
		h := binary.LittleEndian.Uint64(sum[:8])

		for i := range 64 {
			if (h>>uint(i))&1 == 1 {
				v[i]++
			} else {
				v[i]--
			}
		}
	}

	// Build the final fingerprint bit-by-bit.
	var fp uint64
	for i := range 64 {
		if v[i] > 0 {
			fp |= 1 << uint(i)
		}
	}

	return fmt.Sprintf("%016x", fp)
}

// Similarity returns a value in [0.0, 1.0] representing how similar two
// fingerprint hex strings are. 1.0 means identical; 0.0 means maximally
// different (all 64 bits differ).
//
// It parses each argument with [ParseFingerprint] and computes:
//
//	1.0 - HammingDistance(a, b) / 64.0
//
// If either argument is not a valid 16-character hex string the function
// returns 0.0.
func (f *Fingerprinter) Similarity(a, b string) float64 {
	ua, err := parseFingerprint(a)
	if err != nil {
		return 0.0
	}
	ub, err := parseFingerprint(b)
	if err != nil {
		return 0.0
	}
	dist := HammingDistance(ua, ub)
	return 1.0 - float64(dist)/64.0
}

// HammingDistance returns the number of bit positions at which a and b differ.
// It uses the standard popcount trick via bits.OnesCount64.
func HammingDistance(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// normalize strips the ephemeral, high-cardinality parts of a log message that
// would prevent similar messages from being grouped together.
func (f *Fingerprinter) normalize(msg string) string {
	// Work in lower-case throughout.
	s := strings.Map(unicode.ToLower, msg)

	// Order matters: remove more-specific patterns before broader ones so that
	// UUIDs are not partially mangled by the IP or number regexes.
	s = reTimestamp.ReplaceAllString(s, " ")
	s = reUUID.ReplaceAllString(s, " ")
	s = reIP.ReplaceAllString(s, " ")
	s = rePodSuffix.ReplaceAllString(s, " ")
	s = reLargeNumber.ReplaceAllString(s, " ")

	return s
}

// tokenize splits a normalised string into significant lower-case words,
// discarding stop words, pure-numeric tokens, and single-character tokens.
func (f *Fingerprinter) tokenize(normalized string) []string {
	// Collapse punctuation/whitespace into spaces then split.
	parts := strings.Fields(reNonWord.ReplaceAllString(normalized, " "))

	tokens := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) <= 1 {
			continue
		}
		if _, isStop := stopWords[p]; isStop {
			continue
		}
		// Skip purely numeric tokens (port numbers, small counters, etc.).
		if isAllDigits(p) {
			continue
		}
		tokens = append(tokens, p)
	}
	return tokens
}

// isAllDigits returns true if every rune in s is a decimal digit.
func isAllDigits(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// parseFingerprint decodes a 16-character hex string into a uint64.
// It is a package-private helper used by Similarity.
func parseFingerprint(h string) (uint64, error) {
	if len(h) != 16 {
		return 0, fmt.Errorf("fingerprint %q: expected 16 hex chars, got %d", h, len(h))
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return 0, fmt.Errorf("fingerprint %q: %w", h, err)
	}
	return binary.LittleEndian.Uint64(b), nil
}
