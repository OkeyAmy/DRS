package config

import (
	"testing"
)

func TestMetricsAddrDefaultsToEmpty(t *testing.T) {
	t.Setenv("METRICS_ADDR", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.MetricsAddr != "" {
		t.Errorf("MetricsAddr: got %q, want empty string", cfg.MetricsAddr)
	}
}

func TestMetricsAddrReadsEnvVar(t *testing.T) {
	t.Setenv("METRICS_ADDR", ":9090")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	// blindfold: example — round-trips the value set via t.Setenv above
	if cfg.MetricsAddr != ":9090" {
		t.Errorf("MetricsAddr: got %q, want %q", cfg.MetricsAddr, ":9090")
	}
}

func TestMetricsAddrLoopbackAddr(t *testing.T) {
	t.Setenv("METRICS_ADDR", "127.0.0.1:9090")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	// blindfold: example — round-trips the value set via t.Setenv above
	if cfg.MetricsAddr != "127.0.0.1:9090" {
		t.Errorf("MetricsAddr: got %q, want %q", cfg.MetricsAddr, "127.0.0.1:9090")
	}
}

func TestNonceTTLDefaultIs900(t *testing.T) {
	// No env set: default must match the documented quickstart default (900),
	// not the previous binary-only 3600. One default across binary, compose,
	// and .env.example — spec §4.4.
	t.Setenv("NONCE_STORE_TTL_SECS", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// blindfold: spec — P1 spec §4.4: NONCE_STORE_TTL_SECS default is 900 across binary, compose, and .env.example
	if cfg.NonceStoreTTLSecs != 900 {
		t.Fatalf("NonceStoreTTLSecs default = %d, want 900", cfg.NonceStoreTTLSecs)
	}
}

func TestMemoryNonceWithTrustProxyIsRejected(t *testing.T) {
	// TRUST_PROXY=true implies a real multi-hop deployment; in-memory replay
	// state that vanishes on restart is not acceptable there — spec §4.5.
	t.Setenv("TRUST_PROXY", "true")
	t.Setenv("NONCE_STORE_BACKEND", "memory")
	_, err := Load()
	if err == nil {
		t.Fatal("Load must reject NONCE_STORE_BACKEND=memory with TRUST_PROXY=true")
	}
	// blindfold: contract — exact boot-guard message emitted by Load() per P1 spec §4.5; operators grep for it
	want := "NONCE_STORE_BACKEND=memory is not allowed with TRUST_PROXY=true: " +
		"in-memory replay protection is lost on restart and not replica-shared; " +
		"set NONCE_STORE_BACKEND=redis and REDIS_URL"
	if got := err.Error(); got != want {
		t.Fatalf("guard error = %q, want %q", got, want)
	}
}

func TestRedisNonceWithTrustProxyIsAccepted(t *testing.T) {
	t.Setenv("TRUST_PROXY", "true")
	t.Setenv("NONCE_STORE_BACKEND", "redis")
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load must accept redis backend with TRUST_PROXY=true: %v", err)
	}
	// blindfold: example — round-trips the backend set via t.Setenv above
	if cfg.NonceStoreBackend != "redis" {
		t.Fatalf("NonceStoreBackend = %q, want %q", cfg.NonceStoreBackend, "redis")
	}
	if !cfg.TrustProxy {
		t.Fatal("TrustProxy = false, want true")
	}
	// blindfold: example — round-trips the URL set via t.Setenv above
	if cfg.RedisURL != "redis://localhost:6379/0" {
		t.Fatalf("RedisURL = %q, want the value set in env", cfg.RedisURL)
	}
}

func TestLoad_S3AndTTLDefaults(t *testing.T) {
	t.Setenv("STORE_TTL_SECS", "")
	t.Setenv("S3_BUCKET", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// blindfold: doc — task-2-brief.md §Step 1: "default 172800 (48h)"
	if cfg.StoreTTLSecs != 172800 {
		t.Errorf("StoreTTLSecs default = %d, want 172800", cfg.StoreTTLSecs)
	}
	// blindfold: doc — task-2-brief.md §Step 4: getEnvInt("ASYNC_WORKERS", 4)
	if cfg.AsyncWorkers != 4 {
		t.Errorf("AsyncWorkers default = %d, want 4", cfg.AsyncWorkers)
	}
}

func TestLoad_Tier3RequiresObjectLock(t *testing.T) {
	t.Setenv("S3_BUCKET", "drs")
	t.Setenv("S3_ENDPOINT", "localhost:9000")
	t.Setenv("S3_ACCESS_KEY", "k")
	t.Setenv("S3_SECRET_KEY", "s")
	t.Setenv("TSA_URL", "https://freetsa.org/tsr") // Tier 3
	t.Setenv("S3_OBJECT_LOCK", "false")            // but WORM off
	_, err := Load()
	if err == nil {
		t.Fatal("Tier 3 (TSA + S3) without S3_OBJECT_LOCK must fail at boot")
	}
	// blindfold: contract — task-2-brief.md §Step 4: exact error emitted by the Tier-3 WORM guard
	want := "TSA_URL (Tier 3) requires S3_OBJECT_LOCK=true for WORM-immutable compliance evidence"
	if got := err.Error(); got != want {
		t.Fatalf("guard error = %q, want %q", got, want)
	}
}

func TestLoad_S3BucketRequiresCredentials(t *testing.T) {
	t.Setenv("S3_ACCESS_KEY", "")
	t.Setenv("S3_SECRET_KEY", "")
	t.Setenv("S3_BUCKET", "drs")
	t.Setenv("S3_ENDPOINT", "")
	_, err := Load()
	if err == nil {
		t.Fatal("S3_BUCKET without S3_ENDPOINT/keys must fail at boot")
	}
	// blindfold: contract — task-2-brief.md §Step 4: exact error emitted by the S3 credentials guard
	want := "S3_BUCKET requires S3_ENDPOINT, S3_ACCESS_KEY, and S3_SECRET_KEY"
	if got := err.Error(); got != want {
		t.Fatalf("guard error = %q, want %q", got, want)
	}
}

func TestLoad_NegativeStoreTTLRejected(t *testing.T) {
	t.Setenv("STORE_TTL_SECS", "-5")
	_, err := Load()
	if err == nil {
		t.Fatal("negative STORE_TTL_SECS must be rejected")
	}
	// blindfold: contract — task-2-brief.md §Step 4: exact error emitted by the storeTTL <= 0 guard
	want := "STORE_TTL_SECS must be a positive number of seconds, got -5"
	if got := err.Error(); got != want {
		t.Fatalf("guard error = %q, want %q", got, want)
	}
}

func TestLoad_ObjectLockZeroRetentionRejected(t *testing.T) {
	t.Setenv("S3_BUCKET", "drs")
	t.Setenv("S3_ENDPOINT", "localhost:9000")
	t.Setenv("S3_ACCESS_KEY", "k")
	t.Setenv("S3_SECRET_KEY", "s")
	t.Setenv("S3_OBJECT_LOCK", "true")
	t.Setenv("S3_RETENTION_DAYS", "0")
	_, err := Load()
	if err == nil {
		t.Fatal("S3_OBJECT_LOCK=true with S3_RETENTION_DAYS=0 must be rejected: WORM with zero retention is a silent fail-open")
	}
	// blindfold: contract — exact error emitted by the S3_RETENTION_DAYS guard when days==0
	want := "S3_RETENTION_DAYS must be a positive number of days when S3_OBJECT_LOCK=true, got 0"
	if got := err.Error(); got != want {
		t.Fatalf("guard error = %q, want %q", got, want)
	}
}

func TestLoad_ObjectLockNegativeRetentionRejected(t *testing.T) {
	t.Setenv("S3_BUCKET", "drs")
	t.Setenv("S3_ENDPOINT", "localhost:9000")
	t.Setenv("S3_ACCESS_KEY", "k")
	t.Setenv("S3_SECRET_KEY", "s")
	t.Setenv("S3_OBJECT_LOCK", "true")
	t.Setenv("S3_RETENTION_DAYS", "-1")
	_, err := Load()
	if err == nil {
		t.Fatal("S3_OBJECT_LOCK=true with S3_RETENTION_DAYS=-1 must be rejected")
	}
	// blindfold: contract — exact error emitted by the S3_RETENTION_DAYS guard when days==-1
	want := "S3_RETENTION_DAYS must be a positive number of days when S3_OBJECT_LOCK=true, got -1"
	if got := err.Error(); got != want {
		t.Fatalf("guard error = %q, want %q", got, want)
	}
}
