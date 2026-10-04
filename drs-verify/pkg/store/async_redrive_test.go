package store

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// outageStore is a durable-backend stand-in whose availability the test
// controls. Writes that succeed are really kept, so tests can assert what
// reached "durable" storage.
type outageStore struct {
	down atomic.Bool
	mu   sync.Mutex
	data map[string]string
}

func newOutageStore(down bool) *outageStore {
	o := &outageStore{data: map[string]string{}}
	o.down.Store(down)
	return o
}

func (o *outageStore) Put(hash, jwt string) error {
	if o.down.Load() {
		return fmt.Errorf("backend unavailable")
	}
	o.mu.Lock()
	o.data[hash] = jwt
	o.mu.Unlock()
	return nil
}

func (o *outageStore) Get(hash string) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	v, ok := o.data[hash]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (o *outageStore) Delete(string) error { return nil }

func (o *outageStore) durable() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.data)
}

func key(i int) string { return fmt.Sprintf("sha256:%064x", i) }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func fastConfig() AsyncConfig {
	return AsyncConfig{Workers: 2, MaxRetries: 1, RetryBackoff: time.Millisecond, RedriveInterval: 10 * time.Millisecond}
}

func TestAsyncRedrivesReceiptsAfterBackendRecovers(t *testing.T) {
	inner := newOutageStore(true)
	var flushErrors atomic.Int64
	cfg := fastConfig()
	cfg.OnFlushError = func(string, error) { flushErrors.Add(1) }
	a := NewAsyncStore(inner, cfg)
	defer func() { _ = a.Close(context.Background()) }()

	const n = 20
	for i := 0; i < n; i++ {
		if err := a.Put(key(i), fmt.Sprintf("jwt-%d", i)); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}
	waitFor(t, "all writes to be marked failed", func() bool { return a.FailedCount() == n })
	// blindfold: invariant — every receipt that failed to flush is counted exactly once, and a failed receipt is still readable.
	if got, err := a.Get(key(3)); err != nil || got != "jwt-3" {
		t.Fatalf("a failed-to-flush receipt must stay readable during the outage, got %q, %v", got, err)
	}
	if flushErrors.Load() != n {
		t.Fatalf("OnFlushError must fire once per failed receipt, got %d", flushErrors.Load())
	}

	inner.down.Store(false)
	waitFor(t, "redrive to flush every receipt", func() bool { return inner.durable() == n && a.FailedCount() == 0 })
	for i := 0; i < n; i++ {
		got, err := inner.Get(key(i))
		// blindfold: invariant — the redriven value is byte-identical to what was Put.
		if err != nil || got != fmt.Sprintf("jwt-%d", i) {
			t.Fatalf("receipt %d not durable after recovery: %q, %v", i, got, err)
		}
	}
}

func TestAsyncFailedBufferIsBounded(t *testing.T) {
	inner := newOutageStore(true)
	var dropped atomic.Int64
	cfg := fastConfig()
	cfg.Workers = 4
	cfg.MaxFailed = 5
	cfg.RedriveInterval = time.Hour // keep entries failed for the whole test
	cfg.OnDrop = func(string) { dropped.Add(1) }
	a := NewAsyncStore(inner, cfg)
	defer func() { _ = a.Close(context.Background()) }()

	const n = 40
	for i := 0; i < n; i++ {
		if err := a.Put(key(i), "jwt"); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}
	waitFor(t, "every write to settle as failed or dropped", func() bool {
		return int64(a.FailedCount())+dropped.Load() == n
	})
	// blindfold: contract — AsyncConfig.MaxFailed is a hard cap on receipts held for redrive; the rest are dropped loudly via OnDrop.
	if a.FailedCount() != 5 || dropped.Load() != n-5 {
		t.Fatalf("want exactly 5 held and %d dropped, got held=%d dropped=%d", n-5, a.FailedCount(), dropped.Load())
	}
}

func TestAsyncSameKeyFailureIsCountedOnce(t *testing.T) {
	inner := newOutageStore(true)
	cfg := fastConfig()
	cfg.RedriveInterval = time.Hour
	a := NewAsyncStore(inner, cfg)
	defer func() { _ = a.Close(context.Background()) }()

	// Content-addressed: identical receipts arrive repeatedly under one key.
	for i := 0; i < 10; i++ {
		if err := a.Put(key(7), "same-jwt"); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "the key to be marked failed", func() bool { return a.FailedCount() >= 1 })
	time.Sleep(50 * time.Millisecond)
	// blindfold: invariant — one key is one failed receipt, however many Puts raced.
	if a.FailedCount() != 1 {
		t.Fatalf("one key must occupy exactly one failed slot, got %d", a.FailedCount())
	}
}

func TestAsyncCloseMakesFinalAttemptToPersistFailedReceipts(t *testing.T) {
	inner := newOutageStore(true)
	cfg := fastConfig()
	cfg.RedriveInterval = time.Hour // only Close's final pass can save these
	a := NewAsyncStore(inner, cfg)

	for i := 0; i < 5; i++ {
		_ = a.Put(key(i), "jwt")
	}
	waitFor(t, "writes to be marked failed", func() bool { return a.FailedCount() == 5 })
	inner.down.Store(false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// blindfold: contract — Close's final redrive pass persists failed receipts once the backend is healthy.
	if inner.durable() != 5 || a.FailedCount() != 0 {
		t.Fatalf("Close must persist failed receipts after recovery: durable=%d failed=%d", inner.durable(), a.FailedCount())
	}
}

func TestAsyncRedriveForgetsReceiptsDeletedDuringOutage(t *testing.T) {
	inner := newOutageStore(true)
	cfg := fastConfig()
	a := NewAsyncStore(inner, cfg)
	defer func() { _ = a.Close(context.Background()) }()

	_ = a.Put(key(1), "jwt")
	waitFor(t, "write to be marked failed", func() bool { return a.FailedCount() == 1 })
	if err := a.Delete(key(1)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "redrive to forget the deleted receipt", func() bool { return a.FailedCount() == 0 })
	inner.down.Store(false)
	time.Sleep(50 * time.Millisecond)
	if inner.durable() != 0 {
		t.Fatal("a receipt deleted during the outage must not be resurrected by the redrive")
	}
}

// gatedStore blocks every Put until released, modelling a slow backend.
type gatedStore struct {
	outageStore
	gate chan struct{}
}

func (g *gatedStore) Put(hash, jwt string) error {
	<-g.gate
	return g.outageStore.Put(hash, jwt)
}

func TestAsyncPendingCountCoversQueuedAndInFlightReceipts(t *testing.T) {
	inner := &gatedStore{outageStore: *newOutageStore(false), gate: make(chan struct{})}
	cfg := fastConfig()
	cfg.Workers = 1
	a := NewAsyncStore(inner, cfg)
	defer func() { _ = a.Close(context.Background()) }()

	const n = 6
	for i := 0; i < n; i++ {
		if err := a.Put(key(i), "jwt"); err != nil {
			t.Fatal(err)
		}
	}
	// blindfold: contract — PendingCount is every receipt not yet durable (queued + in flight), visible before any failure.
	if a.PendingCount() != n || a.FailedCount() != 0 {
		t.Fatalf("want pending=%d failed=0 while the backend is slow, got pending=%d failed=%d", n, a.PendingCount(), a.FailedCount())
	}
	close(inner.gate)
	waitFor(t, "backend to drain", func() bool { return a.PendingCount() == 0 })
}
