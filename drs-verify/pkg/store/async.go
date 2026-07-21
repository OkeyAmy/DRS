package store

import (
	"context"
	"sync"
	"time"
)

// AsyncConfig configures the AsyncStore write pipeline.
type AsyncConfig struct {
	QueueSize    int                          // bounded queue depth; 0 -> 4096
	Workers      int                          // flush worker goroutines; 0 -> 4
	MaxRetries   int                          // per-item flush retries; 0 -> 5
	RetryBackoff time.Duration                // base backoff between retries; 0 -> 100ms
	OnDrop       func(hash string)            // called when Put is rejected (queue full)
	OnFlushError func(hash string, err error) // called when a flush ultimately fails
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

// AsyncStore decorates a Store so that Put does not block the caller on the
// inner backend. Writes are buffered in memory and flushed by a worker pool.
// Get is read-after-write consistent: values not yet flushed are served from
// the in-flight buffer, then from the inner store. Reads and Deletes are
// synchronous (a Delete also drops any in-flight copy).
type AsyncStore struct {
	inner   Store
	cfg     AsyncConfig
	queue   chan string
	pending sync.Map // hash -> string (in-flight, not yet durably flushed)
	wg      sync.WaitGroup
	closed  chan struct{}
	once    sync.Once
}

// NewAsyncStore starts the worker pool and returns a ready AsyncStore.
func NewAsyncStore(inner Store, cfg AsyncConfig) *AsyncStore {
	cfg.applyDefaults()
	a := &AsyncStore{
		inner:  inner,
		cfg:    cfg,
		queue:  make(chan string, cfg.QueueSize),
		closed: make(chan struct{}),
	}
	for i := 0; i < cfg.Workers; i++ {
		a.wg.Add(1)
		go a.worker()
	}
	return a
}

// Put buffers the value and enqueues it for durable flush. Non-blocking:
// returns ErrQueueFull immediately if the queue is saturated, so the caller
// can surface an evidence gap instead of stalling the verify path.
func (a *AsyncStore) Put(hash, jwt string) error {
	a.pending.Store(hash, jwt)
	select {
	case a.queue <- hash:
		return nil
	default:
		a.pending.Delete(hash)
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
	for hash := range a.queue {
		v, ok := a.pending.Load(hash)
		if !ok {
			continue // deleted before flush
		}
		a.flush(hash, v.(string))
	}
}

func (a *AsyncStore) flush(hash, jwt string) {
	var err error
	for attempt := 0; attempt <= a.cfg.MaxRetries; attempt++ {
		if err = a.inner.Put(hash, jwt); err == nil {
			a.pending.Delete(hash)
			return
		}
		time.Sleep(a.cfg.RetryBackoff * time.Duration(attempt+1))
	}
	// Give up: keep the value in pending (still readable) and surface the error.
	if a.cfg.OnFlushError != nil {
		a.cfg.OnFlushError(hash, err)
	}
}

// Close stops accepting new work and drains the queue until empty or ctx
// expires. Safe to call once; subsequent calls are no-ops.
func (a *AsyncStore) Close(ctx context.Context) error {
	a.once.Do(func() { close(a.queue) })
	done := make(chan struct{})
	go func() { a.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
