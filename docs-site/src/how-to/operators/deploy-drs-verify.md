# Deploy drs-verify

drs-verify is a single static Go binary with no runtime dependencies. It compiles with `CGO_ENABLED=0` and runs in a distroless container.

## Docker (recommended for production)

```bash
docker pull ghcr.io/yourorg/drs-verify:latest

docker run -d \
  --name drs-verify \
  -p 8080:8080 \
  -e DRS_LISTEN_ADDR=:8080 \
  -e DRS_CACHE_SIZE=10000 \
  -e DRS_CACHE_TTL=1h \
  -e DRS_STATUS_CACHE_TTL=5m \
  -e DRS_REQUIRE_BUNDLE=true \
  ghcr.io/yourorg/drs-verify:latest
```

## Build from source

```bash
cd drs-verify
CGO_ENABLED=0 GOOS=linux go build -o drs-verify ./cmd/server
./drs-verify
# drs-verify listening on :8080
```

## Health checks

```bash
# Liveness
curl http://localhost:8080/healthz
# {"status":"ok"}

# Readiness (includes cache state)
curl http://localhost:8080/readyz
# {"status":"ok","cache_size":0,"uptime_seconds":12}
```

Configure your load balancer or Kubernetes probe to use `/readyz` — it only returns `ok` when the server is fully initialised.

## Kubernetes deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: drs-verify
  labels:
    app: drs-verify
spec:
  replicas: 3
  selector:
    matchLabels:
      app: drs-verify
  template:
    metadata:
      labels:
        app: drs-verify
    spec:
      containers:
      - name: drs-verify
        image: ghcr.io/yourorg/drs-verify:latest
        ports:
        - containerPort: 8080
        env:
        - name: DRS_LISTEN_ADDR
          value: ":8080"
        - name: DRS_CACHE_SIZE
          value: "10000"
        - name: DRS_CACHE_TTL
          value: "1h"
        - name: DRS_REQUIRE_BUNDLE
          value: "true"
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8080
          initialDelaySeconds: 3
          periodSeconds: 5
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "500m"
```

## Sidecar pattern

To add DRS to an existing MCP server without modifying it, run drs-verify as a sidecar that proxies to the upstream server:

```yaml
containers:
- name: drs-verify
  image: ghcr.io/yourorg/drs-verify:latest
  env:
  - name: DRS_LISTEN_ADDR
    value: ":8081"
  - name: DRS_UPSTREAM
    value: "http://localhost:8080"   # your MCP server
  - name: DRS_REQUIRE_BUNDLE
    value: "true"
- name: your-mcp-server
  # ... your existing container
```

Clients connect to port `8081`. Your server on `8080` only receives verified requests.
