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

	return Config{
		ListenAddr:             listenAddr,
		DidCacheSize:           didCacheSize,
		DidCacheTTLSecs:        didCacheTTL,
		StatusListCacheTTLSecs: statusCacheTTL,
		StatusListBaseURL:      statusBaseURL,
		MaxBodyBytes:           maxBodyBytes,
		LogLevel:               logLevel,
		LogFormat:              logFormat,
		AdminToken:             adminToken,
		TSAURL:                 tsaURL,
		StoreDir:               storeDir,
		ServerIdentity:         serverIdentity,
		NonceStoreMaxEntries:   nonceMax,
		NonceStoreTTLSecs:      nonceTTL,
		TSARootCertPEM:         tsaRootCertPEM,
		RateLimitPerIP:         rateLimitPerIP,
		RateLimitGlobal:        rateLimitGlobal,
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
