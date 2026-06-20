// Package logwatcher provides facilities for streaming, normalizing, and
// filtering Kubernetes pod logs in real time.
package logwatcher

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ─── Public types ────────────────────────────────────────────────────────────

// LogEntry wraps a NormalizedLog with additional policy-routing metadata
// added by the controller layer.
type LogEntry struct {
	*NormalizedLog

	// PolicyNamespace and PolicyName identify the DiagnosePolicy resource
	// that caused this pod to be watched.
	PolicyNamespace string
	PolicyName      string
}

// watcherKey is the map key that uniquely identifies a watched
// (namespace, pod, container) triple.
type watcherKey struct {
	namespace string
	pod       string
	container string
}

func (k watcherKey) String() string {
	return fmt.Sprintf("%s/%s/%s", k.namespace, k.pod, k.container)
}

// ─── Watcher ─────────────────────────────────────────────────────────────────

// Watcher streams log lines from Kubernetes containers, normalises and
// filters them, and forwards matching entries onto a channel.
//
// Each (namespace, pod, container) triple is tracked independently;
// a dedicated goroutine drives the Kubernetes log-follow stream and
// reconnects with exponential back-off when the stream is interrupted.
type Watcher struct {
	client     kubernetes.Interface
	normalizer *Normalizer
	filter     *Filter
	logCh      chan<- *LogEntry
	logger     *zap.Logger

	mu       sync.RWMutex
	watchers map[watcherKey]context.CancelFunc
}

// NewWatcher constructs a Watcher.
//
// logCh must be a buffered channel whose consumer keeps up with the
// rate of log production; a stalled consumer will block individual
// streaming goroutines but will not affect other watched containers.
func NewWatcher(
	client kubernetes.Interface,
	normalizer *Normalizer,
	filter *Filter,
	logCh chan<- *LogEntry,
	logger *zap.Logger,
) *Watcher {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Watcher{
		client:     client,
		normalizer: normalizer,
		filter:     filter,
		logCh:      logCh,
		logger:     logger.With(zap.String("component", "logwatcher")),
		watchers:   make(map[watcherKey]context.CancelFunc),
	}
}

// ─── Public API ──────────────────────────────────────────────────────────────

// StartWatchingPod begins streaming logs from a specific container.
//
// If the same (namespace, pod, container) triple is already being watched
// the call is a no-op. The goroutine owns its own child context derived
// from ctx; cancelling ctx or calling StopWatchingPod will cleanly
// terminate it.
//
// deployment, policyNamespace and policyName are metadata forwarded
// verbatim into every LogEntry emitted for this stream.
func (w *Watcher) StartWatchingPod(
	ctx context.Context,
	namespace, pod, container, deployment, policyNamespace, policyName string,
) {
	key := watcherKey{namespace: namespace, pod: pod, container: container}

	w.mu.Lock()
	if _, exists := w.watchers[key]; exists {
		w.mu.Unlock()
		w.logger.Debug("already watching pod container — ignoring duplicate start",
			zap.String("key", key.String()),
		)
		return
	}

	childCtx, cancel := context.WithCancel(ctx)
	w.watchers[key] = cancel
	w.mu.Unlock()

	w.logger.Info("starting pod log watcher",
		zap.String("namespace", namespace),
		zap.String("pod", pod),
		zap.String("container", container),
		zap.String("policyNamespace", policyNamespace),
		zap.String("policyName", policyName),
	)

	go w.streamLoop(childCtx, key, deployment, policyNamespace, policyName)
}

// StopWatchingPod cancels the streaming goroutine for the given container.
// The goroutine will terminate asynchronously; this call returns immediately.
func (w *Watcher) StopWatchingPod(namespace, pod, container string) {
	key := watcherKey{namespace: namespace, pod: pod, container: container}

	w.mu.Lock()
	cancel, ok := w.watchers[key]
	if ok {
		delete(w.watchers, key)
	}
	w.mu.Unlock()

	if !ok {
		w.logger.Debug("StopWatchingPod called for unknown key — ignoring",
			zap.String("key", key.String()),
		)
		return
	}

	w.logger.Info("stopping pod log watcher",
		zap.String("namespace", namespace),
		zap.String("pod", pod),
		zap.String("container", container),
	)
	cancel()
}

// StopAll cancels every active streaming goroutine.
// It blocks briefly to acquire the write lock but does not wait for goroutines
// to drain.
func (w *Watcher) StopAll() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.logger.Info("stopping all pod log watchers", zap.Int("count", len(w.watchers)))
	for key, cancel := range w.watchers {
		cancel()
		delete(w.watchers, key)
	}
}

// WatchedCount returns the number of (namespace, pod, container) triples
// currently being streamed.
func (w *Watcher) WatchedCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.watchers)
}

// ─── Internal streaming logic ─────────────────────────────────────────────────

// backoffConfig holds the parameters for the reconnection back-off strategy.
const (
	backoffBase    = 1 * time.Second
	backoffMax     = 30 * time.Second
	backoffFactor  = 2.0
	tailLines      = int64(100)
)

// streamLoop is the goroutine body. It repeatedly opens a log stream and reads
// lines until the context is cancelled or the pod terminates permanently.
func (w *Watcher) streamLoop(
	ctx context.Context,
	key watcherKey,
	deployment, policyNamespace, policyName string,
) {
	defer func() {
		// Always clean up the watcher map entry when the goroutine exits,
		// even when the exit is unplanned (e.g. panic recovery is not here,
		// but defensive clean-up prevents map leaks on graceful exits).
		w.mu.Lock()
		delete(w.watchers, key)
		w.mu.Unlock()

		w.logger.Info("pod log stream goroutine exited",
			zap.String("namespace", key.namespace),
			zap.String("pod", key.pod),
			zap.String("container", key.container),
		)
	}()

	attempt := 0

	for {
		// ── Check context before every attempt ──────────────────────────
		if ctx.Err() != nil {
			return
		}

		// ── Exponential back-off on retries ─────────────────────────────
		if attempt > 0 {
			delay := backoffDuration(attempt)
			w.logger.Info("reconnecting log stream after back-off",
				zap.String("key", key.String()),
				zap.Int("attempt", attempt),
				zap.Duration("delay", delay),
			)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}

		// ── Open the log stream ──────────────────────────────────────────
		done, permanent := w.streamOnce(ctx, key, deployment, policyNamespace, policyName)
		if done {
			// Context was cancelled — exit the loop cleanly.
			return
		}
		if permanent {
			// Pod has terminated — no point reconnecting.
			w.logger.Info("pod container has terminated; not reconnecting",
				zap.String("key", key.String()),
			)
			return
		}

		// Transient error — increment attempt counter and retry.
		attempt++
	}
}

// streamOnce opens a single log stream for the container and reads from it
// until the stream closes or the context is cancelled.
//
// Returns:
//   - done=true  → caller should exit the retry loop (context cancelled).
//   - permanent=true → caller should exit the retry loop (pod is gone/done).
//   - both false → transient error; caller should back off and retry.
func (w *Watcher) streamOnce(
	ctx context.Context,
	key watcherKey,
	deployment, policyNamespace, policyName string,
) (done bool, permanent bool) {
	tail := tailLines
	opts := &corev1.PodLogOptions{
		Container: key.container,
		Follow:    true,
		TailLines: &tail,
	}

	req := w.client.CoreV1().
		Pods(key.namespace).
		GetLogs(key.pod, opts)

	stream, err := req.Stream(ctx)
	if err != nil {
		// If the context was already cancelled we treat it as a clean exit.
		if ctx.Err() != nil {
			return true, false
		}
		w.logger.Warn("failed to open log stream",
			zap.String("key", key.String()),
			zap.Error(err),
		)
		return false, false
	}
	defer stream.Close()

	scanner := bufio.NewScanner(stream)
	// Increase the scanner buffer to handle very long log lines (e.g. stack traces).
	const maxTokenSize = 512 * 1024 // 512 KiB
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, maxTokenSize)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return true, false
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		entry, err := w.normalizer.Normalize(key.namespace, key.pod, key.container, deployment, line)
		if err != nil {
			w.logger.Debug("normalize error",
				zap.String("key", key.String()),
				zap.Error(err),
			)
			continue
		}

		if !w.filter.ShouldProcess(entry) {
			continue
		}

		logEntry := &LogEntry{
			NormalizedLog:   entry,
			PolicyNamespace: policyNamespace,
			PolicyName:      policyName,
		}

		// Non-blocking send: if the channel is full we log and drop to
		// prevent the streaming goroutine from stalling.
		select {
		case w.logCh <- logEntry:
		case <-ctx.Done():
			return true, false
		default:
			w.logger.Warn("logCh is full; dropping log entry",
				zap.String("key", key.String()),
				zap.String("message", entry.Message),
			)
		}
	}

	if scanErr := scanner.Err(); scanErr != nil {
		if ctx.Err() != nil {
			return true, false
		}
		w.logger.Warn("log stream scanner error",
			zap.String("key", key.String()),
			zap.Error(scanErr),
		)
		return false, false
	}

	// Scanner finished without error — stream was closed by the server.
	// Check whether the pod is still running; if not, there is nothing to
	// reconnect to.
	if ctx.Err() != nil {
		return true, false
	}

	running, checkErr := w.isPodStillRunning(ctx, key.namespace, key.pod)
	if checkErr != nil {
		w.logger.Warn("could not determine pod phase; will retry",
			zap.String("key", key.String()),
			zap.Error(checkErr),
		)
		return false, false
	}

	if !running {
		return false, true // permanent termination
	}

	// Pod is still running — log stream was interrupted transiently.
	w.logger.Debug("log stream ended but pod is still running; will reconnect",
		zap.String("key", key.String()),
	)
	return false, false
}

// isPodStillRunning returns true when the pod exists and its phase is
// Running or Pending (i.e. it may still emit logs in the future).
func (w *Watcher) isPodStillRunning(ctx context.Context, namespace, name string) (bool, error) {
	pod, err := w.client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("get pod %s/%s: %w", namespace, name, err)
	}

	switch pod.Status.Phase {
	case corev1.PodRunning, corev1.PodPending:
		return true, nil
	default:
		// Succeeded, Failed, Unknown — treat as terminal.
		return false, nil
	}
}

// backoffDuration computes the delay before the nth reconnection attempt
// using truncated exponential back-off.
//
//	delay = min(backoffBase * backoffFactor^(attempt-1), backoffMax)
func backoffDuration(attempt int) time.Duration {
	exp := math.Pow(backoffFactor, float64(attempt-1))
	d := time.Duration(float64(backoffBase) * exp)
	if d > backoffMax {
		d = backoffMax
	}
	return d
}

// int64Ptr is a small helper that returns a pointer to an int64 value.
// It is kept unexported because it is only used internally.
func int64Ptr(v int64) *int64 { return &v }

// Ensure int64Ptr is used (avoids "declared and not used" if the compiler
// inlines tailLines as a constant literal above).
var _ = int64Ptr
