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

	// LOG_LEVEL: "debug" | "info" | "warn" | "error"
	LogLevel string
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

	logLevel := getEnvOrDefault("LOG_LEVEL", "info")

	return Config{
		ListenAddr:             listenAddr,
		DidCacheSize:           didCacheSize,
		DidCacheTTLSecs:        didCacheTTL,
		StatusListCacheTTLSecs: statusCacheTTL,
		StatusListBaseURL:      statusBaseURL,
		LogLevel:               logLevel,
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
