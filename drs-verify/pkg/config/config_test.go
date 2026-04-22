package config

import (
	"strings"
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

func TestBindingModeDefaultsToLenient(t *testing.T) {
	t.Setenv("DRS_BINDING_MODE", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.BindingMode != "lenient" {
		t.Errorf("default BindingMode = %q, want \"lenient\"", cfg.BindingMode)
	}
}

func TestBindingModeReadsEnvVar(t *testing.T) {
	for _, mode := range []string{"off", "lenient", "enforced"} {
		t.Setenv("DRS_BINDING_MODE", mode)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("mode %q: Load() error: %v", mode, err)
		}
		if cfg.BindingMode != mode {
			t.Errorf("mode %q: got %q", mode, cfg.BindingMode)
		}
	}
}

func TestBindingModeRejectsInvalid(t *testing.T) {
	t.Setenv("DRS_BINDING_MODE", "strict")
	_, err := Load()
	if err == nil {
		t.Fatal("invalid binding mode should return error")
	}
	if !strings.Contains(err.Error(), "strict") {
		t.Errorf("error should mention the invalid value, got: %v", err)
	}
}
