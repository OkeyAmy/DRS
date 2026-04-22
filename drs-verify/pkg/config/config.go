// Package config loads all service configuration from environment variables.
// No hard-coded defaults for security-sensitive values (keys, URLs).
// Non-sensitive defaults are documented inline.
package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds all runtime configuration for drs-verify.
type Config struct {
	// HTTP listen address, e.g. ":8080"
	ListenAddr string

	// Maximum entries in the DID resolver LRU cache (hard cap ~640 KB at 10 000 entries)
	DidCacheSize int

	// DID cache entry TTL in seconds
	DidCacheTTLSecs int64

	// Status list cache TTL in seconds
	StatusListCacheTTLSecs int64

	// Bitstring Status List endpoint base URL
	StatusListBaseURL string

	// Maximum request body size in bytes for the /verify endpoint (default 1 MiB)
	MaxBodyBytes int64

	// LOG_LEVEL: "debug" | "info" | "warn" | "error"
	LogLevel string

	// LogFormat controls output format: "text" (default) or "json".
	// Set via LOG_FORMAT env var. Use "json" in production for log aggregators.
	LogFormat string

	// Bearer token required to call POST /admin/revoke.
	// Empty means the admin endpoint is disabled (responds 503).
	// Set via DRS_ADMIN_TOKEN — no default.
	AdminToken string

	// TSAURL is the RFC 3161 Timestamp Authority endpoint URL.
	// If empty, Tier 3 timestamping is disabled.
	// Example values:
	//   FreeTSA (free):   https://freetsa.org/tsr
	//   DigiCert:         https://timestamp.digicert.com
	//   GlobalSign:       http://timestamp.globalsign.com/tsa/r6advanced1
	TSAURL string

	// StoreDir is the base directory for the filesystem store.
	// Required if TSAURL is set. Default: empty (in-memory store used).
	StoreDir string

	// ServerIdentity is this server's identity string (e.g. a DID or URL).
	// When set, the verifier enforces that invocation.tool_server matches this
	// value, binding invocations to the intended target server.
	// Set via SERVER_IDENTITY — empty disables the check.
	ServerIdentity string

	// NonceStoreMaxEntries is the maximum number of JTIs held in the replay
	// protection store. Default: 100000.
	NonceStoreMaxEntries int

	// NonceStoreTTLSecs is the TTL in seconds for nonce store entries.
	// Should match or exceed the maximum expected exp window. Default: 3600 (1 hour).
	NonceStoreTTLSecs int64

	// TSARootCertPEM is the PEM-encoded root CA certificate(s) trusted for
	// RFC 3161 timestamp verification. Empty means system roots are used.
	// Set via TSA_ROOT_CERT_PEM env var.
	TSARootCertPEM string

	// RateLimitPerIP is the sustained requests/second allowed per source IP.
	// Default: 100. Set via RATE_LIMIT_PER_IP.
	RateLimitPerIP float64

	// RateLimitGlobal is the sustained requests/second allowed across all IPs.
	// Default: 1000. Set via RATE_LIMIT_GLOBAL.
	RateLimitGlobal float64

	// TrustProxy controls whether X-Forwarded-For is trusted for IP extraction.
	// When false (default), r.RemoteAddr is always used for rate limiting.
	// Set to true only when the service runs behind a trusted reverse proxy
	// that appends client IPs to X-Forwarded-For.
	// Set via TRUST_PROXY=true.
	TrustProxy bool

	// CircuitBreakerThreshold is the number of consecutive did:web failures before
	// the circuit opens for that DID. Default: 5. Set via CIRCUIT_BREAKER_THRESHOLD.
	CircuitBreakerThreshold int

	// CircuitBreakerCooldownSecs is the number of seconds to wait before allowing
	// a probe request through an open circuit. Default: 60.
	// Set via CIRCUIT_BREAKER_COOLDOWN_SECS.
	CircuitBreakerCooldownSecs int64

	// RevocationStorePath is the filesystem path for the file-backed local
	// revocation store. When set, POST /admin/revoke persists to this file
	// and revocations survive process restart. Empty (default) uses the
	// in-memory store — fastest, but /admin/revoke calls are lost on restart.
	// Set via REVOCATION_STORE_PATH. Typical value: /var/lib/drs-verify/revoked.log
	RevocationStorePath string

	// NonceStoreBackend selects the replay-protection backend:
	//   "memory" — in-process map (default). Lost on restart; not replica-shared.
	//   "redis"  — redis-backed. Survives restart; shared across replicas.
	// Set via NONCE_STORE_BACKEND.
	NonceStoreBackend string

	// RedisURL is the Redis connection URL for the redis nonce backend.
	// Required when NONCE_STORE_BACKEND=redis. Example:
	//   redis://localhost:6379/0
	//   rediss://user:pw@redis.internal:6379/0  (TLS)
	// Set via REDIS_URL.
	RedisURL string

	// MetricsAddr is the listen address for the Prometheus /metrics endpoint,
	// served on a separate listener so it can be firewalled independently of
	// the main API port. Empty (default) disables the metrics endpoint.
	// Set via METRICS_ADDR.
	// Examples:
	//   :9090               — all interfaces (dev)
	//   127.0.0.1:9090      — loopback only (production / Kubernetes sidecar)
	MetricsAddr string

	// BindingMode selects enforcement level for the request-body binding check.
	// The check compares JCS(request body) with JCS(invocation.args) after the
	// bundle verifies, closing the gap where a caller signs policy-compliant
	// args but sends a different body that the tool server actually executes.
	//   "off"      — check disabled (NOT recommended in production)
	//   "lenient"  — mismatches logged + metered, request passes through (default)
	//   "enforced" — mismatches return 403 Forbidden
	// Roll out lenient first; flip to enforced once
	// drs_binding_checks_total{result="mismatch_lenient"} stays at zero.
	// Set via DRS_BINDING_MODE.
	BindingMode string
}

// Load reads all configuration from environment variables.
// Returns an error if required variables are absent or invalid.
func Load() (Config, error) {
	listenAddr := getEnvOrDefault("LISTEN_ADDR", ":8080")

	didCacheSize, err := getEnvInt("DID_CACHE_SIZE", 10_000)
	if err != nil {
		return Config{}, fmt.Errorf("DID_CACHE_SIZE: %w", err)
	}

	didCacheTTL, err := getEnvInt64("DID_CACHE_TTL_SECS", 3600)
	if err != nil {
		return Config{}, fmt.Errorf("DID_CACHE_TTL_SECS: %w", err)
	}

	statusCacheTTL, err := getEnvInt64("STATUS_CACHE_TTL_SECS", 300)
	if err != nil {
		return Config{}, fmt.Errorf("STATUS_CACHE_TTL_SECS: %w", err)
	}

	statusBaseURL := os.Getenv("STATUS_LIST_BASE_URL")

	maxBodyBytes, err := getEnvInt64("MAX_BODY_BYTES", 1_048_576)
	if err != nil {
		return Config{}, fmt.Errorf("MAX_BODY_BYTES: %w", err)
	}

	logLevel := getEnvOrDefault("LOG_LEVEL", "info")
	logFormat := getEnvOrDefault("LOG_FORMAT", "text")
	adminToken := os.Getenv("DRS_ADMIN_TOKEN")
	tsaURL := os.Getenv("TSA_URL")
	storeDir := os.Getenv("STORE_DIR")
	serverIdentity := os.Getenv("SERVER_IDENTITY")

	nonceMax, err := getEnvInt("NONCE_STORE_MAX_ENTRIES", 100_000)
	if err != nil {
		return Config{}, fmt.Errorf("NONCE_STORE_MAX_ENTRIES: %w", err)
	}

	nonceTTL, err := getEnvInt64("NONCE_STORE_TTL_SECS", 3600)
	if err != nil {
		return Config{}, fmt.Errorf("NONCE_STORE_TTL_SECS: %w", err)
	}

	tsaRootCertPEM := os.Getenv("TSA_ROOT_CERT_PEM")

	rateLimitPerIP, err := getEnvFloat64("RATE_LIMIT_PER_IP", 100)
	if err != nil {
		return Config{}, fmt.Errorf("RATE_LIMIT_PER_IP: %w", err)
	}
	rateLimitGlobal, err := getEnvFloat64("RATE_LIMIT_GLOBAL", 1000)
	if err != nil {
		return Config{}, fmt.Errorf("RATE_LIMIT_GLOBAL: %w", err)
	}
	trustProxy := os.Getenv("TRUST_PROXY") == "true"

	cbThreshold, err := getEnvInt("CIRCUIT_BREAKER_THRESHOLD", 5)
	if err != nil {
		return Config{}, fmt.Errorf("CIRCUIT_BREAKER_THRESHOLD: %w", err)
	}
	cbCooldown, err := getEnvInt64("CIRCUIT_BREAKER_COOLDOWN_SECS", 60)
	if err != nil {
		return Config{}, fmt.Errorf("CIRCUIT_BREAKER_COOLDOWN_SECS: %w", err)
	}
	revocationStorePath := os.Getenv("REVOCATION_STORE_PATH")
	nonceBackend := getEnvOrDefault("NONCE_STORE_BACKEND", "memory")
	redisURL := os.Getenv("REDIS_URL")
	metricsAddr := os.Getenv("METRICS_ADDR")

	bindingMode := getEnvOrDefault("DRS_BINDING_MODE", "lenient")
	switch bindingMode {
	case "off", "lenient", "enforced":
		// ok
	default:
		return Config{}, fmt.Errorf("DRS_BINDING_MODE: unknown mode %q (want off, lenient, or enforced)", bindingMode)
	}

	// Fail fast if redis backend is requested without a URL — surfaces
	// misconfiguration at boot instead of at first /verify call.
	if nonceBackend == "redis" && redisURL == "" {
		return Config{}, fmt.Errorf("NONCE_STORE_BACKEND=redis requires REDIS_URL to be set")
	}
	if nonceBackend != "memory" && nonceBackend != "redis" {
		return Config{}, fmt.Errorf("NONCE_STORE_BACKEND: unknown backend %q (want memory or redis)", nonceBackend)
	}

	return Config{
		ListenAddr:                 listenAddr,
		DidCacheSize:               didCacheSize,
		DidCacheTTLSecs:            didCacheTTL,
		StatusListCacheTTLSecs:     statusCacheTTL,
		StatusListBaseURL:          statusBaseURL,
		MaxBodyBytes:               maxBodyBytes,
		LogLevel:                   logLevel,
		LogFormat:                  logFormat,
		AdminToken:                 adminToken,
		TSAURL:                     tsaURL,
		StoreDir:                   storeDir,
		ServerIdentity:             serverIdentity,
		NonceStoreMaxEntries:       nonceMax,
		NonceStoreTTLSecs:          nonceTTL,
		TSARootCertPEM:             tsaRootCertPEM,
		RateLimitPerIP:             rateLimitPerIP,
		RateLimitGlobal:            rateLimitGlobal,
		TrustProxy:                 trustProxy,
		CircuitBreakerThreshold:    cbThreshold,
		CircuitBreakerCooldownSecs: cbCooldown,
		RevocationStorePath:        revocationStorePath,
		NonceStoreBackend:          nonceBackend,
		RedisURL:                   redisURL,
		MetricsAddr:                metricsAddr,
		BindingMode:                bindingMode,
	}, nil
}

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("must be an integer, got %q", v)
	}
	return n, nil
}

func getEnvInt64(key string, def int64) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("must be an integer, got %q", v)
	}
	return n, nil
}

func getEnvFloat64(key string, def float64) (float64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("must be a number, got %q", v)
	}
	return n, nil
}
