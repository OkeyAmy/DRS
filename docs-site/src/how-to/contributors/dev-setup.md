# Development Setup

## Prerequisites

Install all three language toolchains:

```bash
# Rust 1.77+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install stable

# Go 1.22+
# Download from https://go.dev/dl/ or via your package manager

# Node.js 20+ and pnpm
# Node: https://nodejs.org or nvm
npm install -g pnpm

# wasm-pack (for WASM builds)
cargo install wasm-pack
```

## Clone and build

```bash
git clone https://github.com/yourorg/drs
cd drs

# Rust core
cd drs-core
cargo build
cargo test
cd ..

# Go middleware
cd drs-verify
go build ./...
go test ./... -race
cd ..

# TypeScript SDK
cd drs-sdk
pnpm install
pnpm test
pnpm typecheck
cd ..
```

## Optional: WASM build

```bash
cd drs-core
wasm-pack build --target web --features wasm
# Output: drs-core/pkg/
```

## Run all tests

```bash
# Rust
cd drs-core && cargo test

# Go (with race detector and coverage)
cd drs-verify && go test ./... -race -coverprofile=coverage.out
go tool cover -html=coverage.out

# TypeScript
cd drs-sdk && pnpm test
cd drs-sdk && pnpm typecheck
```

## Formatting and linting

```bash
# Rust
cd drs-core && cargo fmt && cargo clippy

# Go
cd drs-verify && gofmt -w . && go vet ./...

# TypeScript
cd drs-sdk && pnpm prettier --write .
```

CI enforces all formatters. `cargo fmt --check`, `gofmt -l .`, and `pnpm prettier --check .` must all pass.

## Running drs-verify locally

```bash
cd drs-verify
go run ./cmd/server
# drs-verify listening on :8080

# In another terminal:
curl http://localhost:8080/healthz
# {"status":"ok"}
```

## IDE setup

**VS Code:** Install the `rust-analyzer`, `Go`, and `TypeScript` extensions. The project includes workspace settings that configure formatters.

**IntelliJ / GoLand:** The Go module layout is standard — open `drs-verify/` as a Go module.
