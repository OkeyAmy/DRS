package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordingStore is a real in-memory Store that records call order and can be
// made slow, to prove the decorator's behaviour against a concrete backend.
type recordingStore struct {
	mu       sync.Mutex
	data     map[string]string
	putDelay time.Duration
	puts     int
	putErr   error // when non-nil, Put always fails with this error
}

func newRecordingStore() *recordingStore { return &recordingStore{data: map[string]string{}} }

func (r *recordingStore) Put(hash, jwt string) error {
	if r.putDelay > 0 {
		time.Sleep(r.putDelay)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.putErr != nil {
		return r.putErr
	}
	r.data[hash] = jwt
	r.puts++
	return nil
}
func (r *recordingStore) Get(hash string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.data[hash]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}
func (r *recordingStore) Delete(hash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.data, hash)
	return nil
}

func TestAsyncStore_ReadAfterWrite_BeforeFlush(t *testing.T) {
	inner := newRecordingStore()
	inner.putDelay = 50 * time.Millisecond // backend is slow
	a := NewAsyncStore(inner, AsyncConfig{QueueSize: 8, Workers: 1})
	defer a.Close(context.Background())

	if err := a.Put("sha256:aa", "jwt-1"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// The slow backend has NOT flushed yet, but Get must still return the value
	// from the in-flight buffer (chain.go relies on read-after-write).
	got, err := a.Get("sha256:aa")
	if err != nil {
		t.Fatalf("Get before flush: %v", err)
	}
	// blindfold: contract — value is exactly what Put stored; in-flight buffer must return it verbatim
	if got != "jwt-1" {
		t.Fatalf("read-after-write: got %q want %q", got, "jwt-1")
	}
}

func TestAsyncStore_FlushesToBackend(t *testing.T) {
	inner := newRecordingStore()
	a := NewAsyncStore(inner, AsyncConfig{QueueSize: 8, Workers: 2})
	for i := 0; i < 5; i++ {
		if err := a.Put("sha256:key", "v"); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// blindfold: contract — value is exactly what Put stored; Close must have drained the queue before returning
	if got, _ := inner.Get("sha256:key"); got != "v" {
		t.Fatalf("value not durably flushed to backend: %q", got)
	}
}

func TestAsyncStore_QueueFullIsLoud(t *testing.T) {
	inner := newRecordingStore()
	inner.putDelay = time.Second // stall workers so the queue fills
	dropped := 0
	a := NewAsyncStore(inner, AsyncConfig{
		QueueSize: 1, Workers: 1,
		OnDrop: func(string) { dropped++ },
	})
	defer a.Close(context.Background())

	var lastErr error
	for i := 0; i < 50; i++ {
		if err := a.Put("sha256:k", "v"); err != nil {
			lastErr = err
		}
	}
	if !errors.Is(lastErr, ErrQueueFull) {
		t.Fatalf("expected ErrQueueFull when queue saturated, got %v", lastErr)
	}
	if dropped == 0 {
		t.Fatal("OnDrop must fire on queue-full so the gap is observable")
	}
}

func TestAsyncStore_PutAfterClose_ReturnsErrStoreClosed(t *testing.T) {
	inner := newRecordingStore()
	a := NewAsyncStore(inner, AsyncConfig{QueueSize: 8, Workers: 1})
	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err := a.Put("sha256:aa", "jwt-1")
	// blindfold: contract — Put on a closed store must reject with ErrStoreClosed, never panic
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("Put after Close: got %v want ErrStoreClosed", err)
	}
}

func TestAsyncStore_ConcurrentPutClose_NoPanic(t *testing.T) {
	inner := newRecordingStore()
	a := NewAsyncStore(inner, AsyncConfig{QueueSize: 4, Workers: 2})

	const goroutines = 8
	const putsEach = 500
	var wg sync.WaitGroup
	var badErr atomic.Value // stores a non-conforming error, if any observed

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < putsEach; i++ {
				err := a.Put("sha256:same", "v")
				// Only nil | ErrQueueFull | ErrStoreClosed are acceptable; any
				// other error (and any panic, caught by -race/crash) is a defect.
				if err != nil && !errors.Is(err, ErrQueueFull) && !errors.Is(err, ErrStoreClosed) {
					badErr.Store(err)
				}
			}
		}()
	}

	// Race Close against the in-flight Puts.
	time.Sleep(time.Millisecond)
	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()

	if v := badErr.Load(); v != nil {
		t.Fatalf("Put returned unexpected error under concurrency: %v", v)
	}
}

func TestAsyncStore_SameKeyConcurrent_NoSilentLoss(t *testing.T) {
	inner := newRecordingStore()
	a := NewAsyncStore(inner, AsyncConfig{QueueSize: 256, Workers: 4})

	const n = 200
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A queue-full ErrQueueFull is tolerable here; a silent loss is not.
			_ = a.Put("sha256:key", "v")
		}()
	}
	wg.Wait()

	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// blindfold: contract — at least one same-key Put must durably reach the backend; value is verbatim "v"
	got, err := inner.Get("sha256:key")
	if err != nil {
		t.Fatalf("value lost — not durably flushed: %v", err)
	}
	if got != "v" { // blindfold: contract — value flushed is verbatim what Put stored ("v")
		t.Fatalf("durable value: got %q want %q", got, "v")
	}
}

func TestAsyncStore_OnFlushError_KeepsReadable(t *testing.T) {
	inner := newRecordingStore()
	inner.putErr = errors.New("backend down")
	var flushErrs atomic.Int64
	a := NewAsyncStore(inner, AsyncConfig{
		QueueSize:    8,
		Workers:      1,
		MaxRetries:   2,
		RetryBackoff: time.Millisecond,
		OnFlushError: func(string, error) { flushErrs.Add(1) },
	})

	if err := a.Put("sha256:key", "v"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Close blocks until the worker drains the queue, which means the flush has
	// exhausted its retries and fired OnFlushError — no arbitrary sleep needed.
	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if flushErrs.Load() == 0 {
		t.Fatal("OnFlushError must fire when the backend never accepts the write")
	}
	// blindfold: contract — a failed flush keeps the value in pending, so Get still serves it verbatim
	got, err := a.Get("sha256:key")
	if err != nil {
		t.Fatalf("Get after failed flush: %v", err)
	}
	if got != "v" { // blindfold: contract — pending retains the exact value Put stored ("v") on flush failure
		t.Fatalf("value must remain readable after flush failure: got %q want %q", got, "v")
	}
}
