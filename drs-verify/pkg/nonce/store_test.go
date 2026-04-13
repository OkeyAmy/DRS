package nonce

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCheck_FirstCallSucceeds(t *testing.T) {
	s := New(100, time.Hour)
	if err := s.Check("inv:abc123"); err != nil {
		t.Fatalf("first Check should succeed, got: %v", err)
	}
}

func TestCheck_ReplayDetected(t *testing.T) {
	s := New(100, time.Hour)
	if err := s.Check("inv:abc123"); err != nil {
		t.Fatalf("first Check should succeed, got: %v", err)
	}
	err := s.Check("inv:abc123")
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("second Check should return ErrReplayDetected, got: %v", err)
	}
}

func TestCheck_TTLExpiry(t *testing.T) {
	s := New(100, 2*time.Second)
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.nowFunc = func() time.Time { return baseTime }

	if err := s.Check("inv:expire-me"); err != nil {
		t.Fatalf("first Check should succeed, got: %v", err)
	}

	s.nowFunc = func() time.Time { return baseTime.Add(3 * time.Second) }

	if err := s.Check("inv:expire-me"); err != nil {
		t.Fatalf("Check after TTL should succeed (expired entry), got: %v", err)
	}
}

func TestCheck_CapacityEviction(t *testing.T) {
	s := New(2, 2*time.Second)
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.nowFunc = func() time.Time { return baseTime }

	if err := s.Check("inv:a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Check("inv:b"); err != nil {
		t.Fatal(err)
	}

	s.nowFunc = func() time.Time { return baseTime.Add(3 * time.Second) }

	if err := s.Check("inv:c"); err != nil {
		t.Fatalf("Check should succeed after eviction of expired entries, got: %v", err)
	}
}

func TestCheck_StoreExhausted(t *testing.T) {
	s := New(2, time.Hour)

	if err := s.Check("inv:a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Check("inv:b"); err != nil {
		t.Fatal(err)
	}

	err := s.Check("inv:c")
	if !errors.Is(err, ErrStoreExhausted) {
		t.Fatalf("expected ErrStoreExhausted, got: %v", err)
	}
}

func TestCheck_ConcurrentSafety(t *testing.T) {
	s := New(10_000, time.Hour)
	const goroutines = 100
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				jti := fmt.Sprintf("inv:%d-%d", id, i)
				_ = s.Check(jti)
			}
		}(g)
	}
	wg.Wait()
}
