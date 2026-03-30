# Deploy drs-verify

drs-verify is a single static Go binary with no runtime dependencies. It compiles with `CGO_ENABLED=0` and runs in a distroless container.

## Docker (recommended for production)

```bash
docker pull ghcr.io/yourorg/drs-verify:latest

docker run -d \
  --name drs-verify \
  -p 8080:8080 \
  -e LISTEN_ADDR=:8080 \
  -e DID_CACHE_SIZE=10000 \
  -e DID_CACHE_TTL_SECS=3600 \
  -e STATUS_LIST_BASE_URL=https://status.example.com \
  -e STATUS_CACHE_TTL_SECS=300 \
  -e DRS_ADMIN_TOKEN=your-secret-token \
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
        - name: LISTEN_ADDR
          value: ":8080"
        - name: DID_CACHE_SIZE
          value: "10000"
        - name: DID_CACHE_TTL_SECS
          value: "3600"
        - name: STATUS_LIST_BASE_URL
          value: "https://status.example.com"
        - name: STATUS_CACHE_TTL_SECS
          value: "300"
        - name: DRS_ADMIN_TOKEN
          valueFrom:
            secretKeyRef:
              name: drs-secrets
              key: admin-token
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

Running drs-verify as a sidecar that proxies requests to an upstream MCP server is a planned deployment mode. It is not implemented in the current release. For now, configure your MCP server to call `POST /verify` directly before accepting tool-call requests.
