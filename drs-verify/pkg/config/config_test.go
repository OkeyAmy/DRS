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
	if cfg.MetricsAddr != "127.0.0.1:9090" {
		t.Errorf("MetricsAddr: got %q, want %q", cfg.MetricsAddr, "127.0.0.1:9090")
	}
}
