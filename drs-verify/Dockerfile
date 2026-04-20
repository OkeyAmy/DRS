# Build stage — compile a static binary with CGO disabled.
# Go 1.23+ is required because the Prometheus client_golang dependency
# targets that toolchain.
FROM golang:1.23-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# GOARCH is not pinned: the publish workflow builds linux/amd64 and linux/arm64
# via BuildKit cross-compile, and `go build` picks GOARCH up from the
# TARGETARCH build-arg injected by buildx.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w" \
    -o drs-verify \
    ./cmd/server

# Runtime stage — distroless for minimal attack surface.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/drs-verify /drs-verify

EXPOSE 8080

ENTRYPOINT ["/drs-verify"]
