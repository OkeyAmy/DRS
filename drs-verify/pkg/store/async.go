package store

import (
	"context"
	"sync"
	"time"
)

// AsyncConfig configures the AsyncStore write pipeline.
type AsyncConfig struct {
	QueueSize      int                          // bounded queue depth; 0 -> 4096
	Workers        int                          // flush worker goroutines; 0 -> 4
	MaxRetries     int                          // per-item flush retries; 0 -> 5
	RetryBackoff   time.Duration                // base backoff between retries; 0 -> 100ms
	OnDrop         func(hash string)            // called when Put is rejected (queue full)
	OnFlushError   func(hash string, err error) // called when a flush ultimately fails
	OnFlushSuccess func(hash string)            // called after each successful inner.Put; used for metrics
}

func (c *AsyncConfig) applyDefaults() {
	if c.QueueSize <= 0 {
		c.QueueSize = 4096
	}
	if c.Workers <= 0 {
		c.Workers = 4
	}
	if c.MaxRetries <= 0 {
		c.MaxRetries = 5
	}
	if c.RetryBackoff <= 0 {
		c.RetryBackoff = 100 * time.Millisecond
	}
}

// queuedWrite carries both the hash and its value through the queue so the
// worker can flush without re-loading from pending. This is what makes flushes
// independent of concurrent pending mutations and prevents silent lost writes.
type queuedWrite struct{ hash, value string }

// AsyncStore decorates a Store so that Put does not block the caller on the
// inner backend. Writes are buffered in memory and flushed by a worker pool.
// Get is read-after-write consistent: values not yet flushed are served from
// the in-flight buffer, then from the inner store. Reads and Deletes are
// synchronous (a Delete also drops any in-flight copy).
//
// Known residuals (production behaviour is correct; documented constraints):
//
// Residual 1 — Transient read miss on same-key queue-full rejection.
// A Put rejected by queue-full or after Close removes only its own pending
// entry via CompareAndDelete. When another in-flight Put holds an identical
// value under the same key, this briefly clears the shared read-after-write
// entry, so Get may miss the value until the queued write flushes.
// Self-healing; because keys are content-addressed, a read never returns
// wrong bytes.
//
// Residual 2 — Delete is undone by a queued write for the same key.
// A Delete followed by an already-queued write for the same key is undone
// when that write flushes. Safe for content-addressed storage (identical
// bytes); do not rely on Delete for evidence expiry/GC on an AsyncStore.
type AsyncStore struct {
	inner   Store
	cfg     AsyncConfig
	queue   chan queuedWrite
	pending sync.Map // hash -> string (in-flight, not yet durably flushed)
	wg      sync.WaitGroup
	mu      sync.RWMutex // guards closed; held (read) across Put's enqueue
	closed  bool
}

// NewAsyncStore starts the worker pool and returns a ready AsyncStore.
func NewAsyncStore(inner Store, cfg AsyncConfig) *AsyncStore {
	cfg.applyDefaults()
	a := &AsyncStore{
		inner: inner,
		cfg:   cfg,
		queue: make(chan queuedWrite, cfg.QueueSize),
	}
	for i := 0; i < cfg.Workers; i++ {
		a.wg.Add(1)
		go a.worker()
	}
	return a
}

// Put buffers the value and enqueues it for durable flush. Non-blocking:
// returns ErrQueueFull immediately if the queue is saturated, so the caller
// can surface an evidence gap instead of stalling the verify path. Returns
// ErrStoreClosed if the store is already closed.
//
// The read lock is held across both the closed-check and the send so that
// Close (which needs the write lock) cannot close the channel mid-send. It is
// released before any user callback to avoid deadlocking a callback that calls
// back into Put while Close is parked waiting for the write lock.
func (a *AsyncStore) Put(hash, jwt string) error {
	a.pending.Store(hash, jwt)

	a.mu.RLock()
	if a.closed {
		a.mu.RUnlock()
		a.pending.CompareAndDelete(hash, jwt)
		return ErrStoreClosed
	}
	select {
	case a.queue <- queuedWrite{hash: hash, value: jwt}:
		a.mu.RUnlock()
		return nil
	default:
		a.mu.RUnlock()
		a.pending.CompareAndDelete(hash, jwt)
		if a.cfg.OnDrop != nil {
			a.cfg.OnDrop(hash)
		}
		return ErrQueueFull
	}
}

// Get returns the in-flight value if present, otherwise delegates to inner.
func (a *AsyncStore) Get(hash string) (string, error) {
	if v, ok := a.pending.Load(hash); ok {
		return v.(string), nil
	}
	return a.inner.Get(hash)
}

// Delete removes any in-flight copy and deletes from the inner store.
func (a *AsyncStore) Delete(hash string) error {
	a.pending.Delete(hash)
	return a.inner.Delete(hash)
}

func (a *AsyncStore) worker() {
	defer a.wg.Done()
	for q := range a.queue {
		a.flush(q.hash, q.value)
	}
}

func (a *AsyncStore) flush(hash, jwt string) {
	var err error
	for attempt := 0; attempt <= a.cfg.MaxRetries; attempt++ {
		if err = a.inner.Put(hash, jwt); err == nil {
			// Remove only our own value; a concurrent newer Put's value stays.
			a.pending.CompareAndDelete(hash, jwt)
			if a.cfg.OnFlushSuccess != nil {
				a.cfg.OnFlushSuccess(hash)
			}
			return
		}
		if attempt < a.cfg.MaxRetries {
			time.Sleep(a.cfg.RetryBackoff * time.Duration(attempt+1))
		}
	}
	// Give up: keep the value in pending (still readable) and surface the error.
	if a.cfg.OnFlushError != nil {
		a.cfg.OnFlushError(hash, err)
	}
}

// Close stops accepting new work and drains the queue until empty or ctx
// expires. Safe to call more than once; subsequent calls are no-ops.
func (a *AsyncStore) Close(ctx context.Context) error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	close(a.queue)
	a.mu.Unlock()

	done := make(chan struct{})
	go func() { a.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
