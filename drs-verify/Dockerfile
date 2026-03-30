# Build stage — compile a static binary with CGO disabled
FROM golang:1.22-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o drs-verify \
    ./cmd/server

# Runtime stage — distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/drs-verify /drs-verify

EXPOSE 8080

ENTRYPOINT ["/drs-verify"]
