package nonce

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// TestRedisStore_RejectsReplay uses a real Redis instance. Run via:
//
//	docker run --rm -p 6379:6379 redis:7-alpine
//	REDIS_TEST_URL=redis://localhost:6379/15 go test ./pkg/nonce/...
//
// Skipped when REDIS_TEST_URL is unset — the check is an integration test
// and must exercise real SETNX + EX semantics, not a local reimplementation.
func TestRedisStore_RejectsReplay(t *testing.T) {
	url := os.Getenv("REDIS_TEST_URL")
	if url == "" {
		t.Skip("REDIS_TEST_URL not set — skipping integration test. See test doc for how to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s, err := NewRedisStore(ctx, RedisConfig{
		URL:       url,
		KeyPrefix: "drs-test:nonce:",
		TTL:       5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewRedisStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	jti := "test-jti-" + time.Now().Format("20060102150405.000000000")

	// First claim succeeds.
	if err := s.Check(jti); err != nil {
		t.Fatalf("first Check: %v", err)
	}
	// Replay — same jti — must return ErrReplayDetected.
	err = s.Check(jti)
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("replay Check: want ErrReplayDetected, got %v", err)
	}
	// A different jti must still succeed.
	other := jti + ":other"
	if err := s.Check(other); err != nil {
		t.Errorf("different jti: %v", err)
	}
}

func TestRedisStore_DifferentInstancesShareState(t *testing.T) {
	// The entire point of Redis-backed replay is replica-sharing: two
	// independent RedisStore values pointing at the same Redis must see
	// each other's claims.
	url := os.Getenv("REDIS_TEST_URL")
	if url == "" {
		t.Skip("REDIS_TEST_URL not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s1, err := NewRedisStore(ctx, RedisConfig{URL: url, KeyPrefix: "drs-test2:nonce:", TTL: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewRedisStore 1: %v", err)
	}
	defer func() { _ = s1.Close() }()

	s2, err := NewRedisStore(ctx, RedisConfig{URL: url, KeyPrefix: "drs-test2:nonce:", TTL: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewRedisStore 2: %v", err)
	}
	defer func() { _ = s2.Close() }()

	jti := "shared-test-jti-" + time.Now().Format("20060102150405.000000000")
	if err := s1.Check(jti); err != nil {
		t.Fatalf("s1 Check: %v", err)
	}
	// Replica 2 must now see the same jti as consumed.
	if err := s2.Check(jti); !errors.Is(err, ErrReplayDetected) {
		t.Errorf("s2 Check: want ErrReplayDetected, got %v", err)
	}
}

func TestRedisStore_RejectsEmptyURL(t *testing.T) {
	_, err := NewRedisStore(context.Background(), RedisConfig{TTL: time.Minute})
	if err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestRedisStore_RejectsZeroTTL(t *testing.T) {
	_, err := NewRedisStore(context.Background(), RedisConfig{URL: "redis://localhost:6379", TTL: 0})
	if err == nil {
		t.Error("expected error for zero TTL")
	}
}

func TestRedisStore_SatisfiesCheckerInterface(t *testing.T) {
	var _ Checker = (*RedisStore)(nil)
	var _ Checker = (*Store)(nil)
}
