# `/metrics` Security Fix — Design Spec

**Date:** 2026-04-21
**Status:** Approved — ready for implementation plan
**Closes:** Security comment in `drs-verify/cmd/server/main.go:210-212`
**Touches:** `drs-verify/pkg/config/config.go`, `drs-verify/cmd/server/main.go`, `drs-verify/pkg/middleware/ratelimit.go`, `docker-compose.yml`, `.env.example`

---

## 1. Problem

`/metrics` is registered on the main API mux (port `8080`) with no authentication:

```go
// drs-verify/cmd/server/main.go:210-212
// Prometheus metrics endpoint (no auth required, rate-limit exempt).
// Production operators should firewall /metrics to their monitoring network.
mux.Handle("/metrics", metrics.Handler())
```

The comment delegates the security control to the operator — a "should" that is not enforced. Any caller who can reach port `8080` can read:

- Verification rates and outcomes (`drs_verify_verifications_total`)
- Nonce replay counts and exhaustion state (`drs_nonce_checks_total`)
- DID resolution cache hit/miss rates (`drs_resolver_resolutions_total`)
- Circuit breaker open/close transitions (inferred from `miss_error` spikes)
- Request durations per endpoint (`drs_http_request_duration_seconds`)

This is sufficient for traffic analysis, replay-attack planning, and service reconnaissance.

---

## 2. Why Not Bearer Token (Option B)

Bearer token auth was considered and rejected for scale reasons:

- Token rotation requires simultaneous update of every Prometheus scraper replica — no graceful rotation window
- Single shared secret: one leak means rotate everywhere
- No per-scraper identity in logs
- Token distribution at scale (Kubernetes Secrets, rolling restarts) adds operational overhead that grows with deployment size

---

## 3. Chosen Fix: Separate Metrics Listener (`METRICS_ADDR`)

Remove `/metrics` from the main mux. Start an independent `http.Server` on `METRICS_ADDR` serving only `/metrics`.

- If `METRICS_ADDR` is unset (empty string): metrics are **disabled**. Startup log says so. This is the safe production default.
- If `METRICS_ADDR` is set: a second listener starts on that address. No auth, no middleware — access control is at the infra layer (NetworkPolicy, firewall).

### Default values by context

| Context | `METRICS_ADDR` | Result |
|---|---|---|
| Unset (production safe default) | `""` | Metrics disabled; startup log warns |
| Dev quickstart | `:9090` | All-interfaces; expose port in compose |
| Production bare-metal | `127.0.0.1:9090` | Loopback only; firewall port 9090 to monitoring VLAN |
| Kubernetes | `127.0.0.1:9090` | NetworkPolicy allows only monitoring namespace to reach pod port 9090 |

### Why this scales

- No secret to distribute, rotate, or leak across replicas
- In Kubernetes: one `NetworkPolicy` covers all replicas automatically — no per-pod config
- Prometheus Operator, kube-prometheus-stack, Grafana Agent all expect a separate metrics port — works with service discovery out of the box
- Co-located sidecar agents reach `127.0.0.1:9090` natively

---

## 4. Developer Onboarding Impact

The fix is **invisible to first-time users**:

- They run `docker compose up -d`, hit `/verify` and `/healthz` on port `8080` as before
- `METRICS_ADDR` is unset in the default `.env.example` → metrics quietly absent on port `8080`
- No friction added to the `pnpm add @okeyamy/drs-sdk` → `docker compose up` quickstart path

Operators who want monitoring set `METRICS_ADDR=:9090` and expose port `9090`.

---

## 5. Files Changed

### `drs-verify/pkg/config/config.go`

Add one field:

```go
// MetricsAddr is the listen address for the Prometheus /metrics endpoint.
// Served on a separate listener so it can be firewalled independently of
// the main API port. Empty (default) disables the metrics endpoint entirely.
// Set via METRICS_ADDR. Example values:
//   :9090               — all interfaces (dev)
//   127.0.0.1:9090      — loopback only (production sidecar / K8s)
MetricsAddr string
```

Load it in `Load()`:

```go
metricsAddr := os.Getenv("METRICS_ADDR")
```

No default — empty means disabled.

### `drs-verify/cmd/server/main.go`

**Remove** from main mux:
```go
// DELETE these three lines:
// Prometheus metrics endpoint (no auth required, rate-limit exempt).
// Production operators should firewall /metrics to their monitoring network.
mux.Handle("/metrics", metrics.Handler())
```

**Add** after the main server starts (or before — in its own goroutine):

```go
if cfg.MetricsAddr != "" {
    metricsMux := http.NewServeMux()
    metricsMux.Handle("/metrics", metrics.Handler())
    metricsServer := &http.Server{
        Addr:    cfg.MetricsAddr,
        Handler: metricsMux,
    }
    go func() {
        slog.Info("metrics server listening", "addr", cfg.MetricsAddr)
        if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
            slog.Error("metrics server failed", "err", err)
            os.Exit(1)
        }
    }()
} else {
    slog.Warn("metrics endpoint disabled — set METRICS_ADDR to enable (e.g. METRICS_ADDR=127.0.0.1:9090)")
}
```

The metrics server must be shut down gracefully alongside the main server. The existing shutdown goroutine in `main.go` calls `server.Shutdown(ctx)` — add a second `metricsServer.Shutdown(ctx)` call in the same block so both drain before the process exits.

### `drs-verify/pkg/middleware/ratelimit.go`

Remove `/metrics` from the rate-limit exemption — it no longer hits the main mux:

```go
// BEFORE:
if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/metrics" {

// AFTER:
if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
```

### `docker-compose.yml`

Add `METRICS_ADDR` env passthrough and a commented-out port mapping:

```yaml
environment:
  # ... existing vars ...
  # Metrics listener address. Empty = metrics disabled (safe default).
  # Uncomment the port mapping below and set this to :9090 to expose
  # metrics for a local Prometheus scraper.
  METRICS_ADDR: "${METRICS_ADDR:-}"

ports:
  - "${DRS_VERIFY_PORT:-8080}:8080"
  # Metrics port — uncomment when METRICS_ADDR=:9090 is set in .env.
  # In production, leave this commented out and use a NetworkPolicy or
  # firewall to restrict port 9090 to your monitoring network.
  # - "${DRS_METRICS_PORT:-9090}:9090"
```

### `.env.example`

Add a documented section:

```bash
# -- Metrics ------------------------------------------------------------------

# Address for the Prometheus /metrics listener (served on a SEPARATE port
# from the main API so it can be independently firewalled).
# Leave blank to disable metrics entirely (production safe default).
# Dev:        METRICS_ADDR=:9090    (expose port 9090 in docker-compose too)
# Production: METRICS_ADDR=127.0.0.1:9090  (loopback; scraper is a sidecar)
# Kubernetes: METRICS_ADDR=127.0.0.1:9090  (NetworkPolicy controls port 9090)
METRICS_ADDR=
```

### `docker-compose.monitoring.yml` (new file)

Optional overlay for operators who want local Prometheus + Grafana:

```yaml
# Optional monitoring overlay.
# Usage: docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d
#
# Prerequisites: set METRICS_ADDR=:9090 in your .env and uncomment the
# 9090 port mapping in docker-compose.yml.

services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    ports:
      - "9091:9090"
    depends_on:
      - drs-verify

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
    volumes:
      - grafana-data:/var/lib/grafana
    depends_on:
      - prometheus

volumes:
  grafana-data:
```

With a minimal `monitoring/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: drs-verify
    static_configs:
      - targets: ["drs-verify:9090"]
```

---

## 6. Graceful Shutdown

The metrics server must be included in the shutdown sequence alongside the main server. Both servers receive `context.WithTimeout` and are shut down concurrently via `errgroup` or sequential `Shutdown()` calls.

---

## 7. Test Plan

### Unit

- `config_test.go`: `METRICS_ADDR` parses correctly; empty string stored as empty (not defaulted)
- `ratelimit_test.go`: `/metrics` path is **no longer** exempt from rate limiting on the main mux (verify the exemption list shrank)

### Integration

- Server starts with `METRICS_ADDR=` (empty): `GET /metrics` on main port returns `404`; startup log contains "metrics endpoint disabled"
- Server starts with `METRICS_ADDR=:9090`: `GET /metrics` on port `9090` returns `200` with Prometheus text format; `GET /metrics` on main port returns `404`
- Graceful shutdown: both servers drain and exit cleanly on `SIGTERM`

### Existing tests

- `pkg/metrics/metrics_test.go` tests the handler directly — unaffected (tests `Handler()` not the routing)

---

## 8. Migration / Backward Compatibility

Operators who were previously scraping `http://<host>:8080/metrics` must update their Prometheus scrape target to `http://<host>:9090/metrics` (or wherever they set `METRICS_ADDR`).

This is a **breaking change** to the scrape endpoint. It should be:
1. Documented in the release notes
2. Called out in the operator upgrade guide
3. Listed in the production-readiness checklist (§8 — add a `METRICS_ADDR` row)

---

## 9. References

- `drs-verify/cmd/server/main.go` — current `/metrics` registration
- `drs-verify/pkg/config/config.go` — env-driven config pattern
- `drs-verify/pkg/middleware/ratelimit.go` — exemption list to shrink
- `docker-compose.yml` — quickstart compose file
- `.env.example` — operator config reference
- `docs/production-readiness-checklist.md` §8 — needs `METRICS_ADDR` added
