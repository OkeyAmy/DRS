package nonce

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore is a distributed nonce store backed by Redis SET with NX+EX.
//
// Atomicity: Check uses SET key value NX EX ttl, which Redis guarantees
// is atomic. Multiple replicas issuing Check(same-jti) in parallel will
// see exactly one success and the rest ErrReplayDetected.
//
// Durability: the JTI survives process restart and is shared across
// replicas, fixing the process-local limitation of the in-memory Store.
// The trade-off is an extra network hop per Check. For most deployments
// this is ~1 ms on a local Redis or ~5 ms across AZ.
//
// Failure policy: if Redis is unreachable, Check returns an error (not
// ErrReplayDetected, not ErrStoreExhausted) so callers can distinguish
// an operational failure from a real replay. Middleware treats any
// error as "abort the request"; that fails closed.
type RedisStore struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
	// ctxTimeout bounds how long a single Check may block on Redis.
	// Request-path tolerance; don't set this longer than your outer HTTP
	// timeout or verifications will outlive their caller.
	ctxTimeout time.Duration
}

// RedisConfig controls RedisStore construction.
type RedisConfig struct {
	// URL is the Redis connection URL (e.g. redis://:pw@host:6379/0).
	// Parsed via redis.ParseURL — supports TLS (rediss://), user/pass, db.
	URL string

	// KeyPrefix is prepended to every JTI before storage. Default: "drs:nonce:".
	// Change if multiple DRS deployments share a Redis instance.
	KeyPrefix string

	// TTL is how long a claimed JTI remains reserved. Must match or exceed
	// the invocation exp window; usually 900s (15 min).
	TTL time.Duration

	// CheckTimeout bounds a single Check's Redis round-trip. Default: 250ms.
	CheckTimeout time.Duration
}

// NewRedisStore builds a RedisStore. It pings the server once to fail fast
// on misconfiguration; the caller should exit non-zero if this returns error.
func NewRedisStore(ctx context.Context, cfg RedisConfig) (*RedisStore, error) {
	if cfg.URL == "" {
		return nil, errors.New("nonce: RedisConfig.URL is required")
	}
	if cfg.TTL <= 0 {
		return nil, errors.New("nonce: RedisConfig.TTL must be > 0")
	}
	opts, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("nonce: parse redis URL: %w", err)
	}
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = "drs:nonce:"
	}
	timeout := cfg.CheckTimeout
	if timeout <= 0 {
		timeout = 250 * time.Millisecond
	}

	client := redis.NewClient(opts)
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("nonce: redis ping: %w", err)
	}

	return &RedisStore{
		client:     client,
		prefix:     prefix,
		ttl:        cfg.TTL,
		ctxTimeout: timeout,
	}, nil
}

// Check uses SET key sentinel NX EX ttl: returns OK on new, nil (redis.Nil)
// when the key already exists — which we map to ErrReplayDetected.
//
// The value "1" is a placeholder sentinel — we never read it, we only care
// whether the SET succeeded.
func (s *RedisStore) Check(jti string) error {
	if jti == "" {
		// Matches the contract of Store.Check indirectly: middleware rejects
		// empty JTIs before reaching the store, but defence in depth.
		return errors.New("nonce: empty jti")
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.ctxTimeout)
	defer cancel()

	ok, err := s.client.SetNX(ctx, s.prefix+jti, "1", s.ttl).Result()
	if err != nil {
		return fmt.Errorf("nonce: redis SETNX: %w", err)
	}
	if !ok {
		return ErrReplayDetected
	}
	return nil
}

// Close releases the Redis client connections.
func (s *RedisStore) Close() error {
	return s.client.Close()
}
