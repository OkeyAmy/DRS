package store

import (
	"context"
	"errors"
	"sync"
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
}

func newRecordingStore() *recordingStore { return &recordingStore{data: map[string]string{}} }

func (r *recordingStore) Put(hash, jwt string) error {
	if r.putDelay > 0 {
		time.Sleep(r.putDelay)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
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
