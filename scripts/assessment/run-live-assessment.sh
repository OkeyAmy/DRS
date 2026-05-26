#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/.local/drs-assessment/live-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT/responses" "$OUT/logs" "$OUT/benchmarks"

echo "DRS assessment output: $OUT"

cd "$ROOT"
pnpm typecheck | tee "$OUT/logs/typescript-typecheck.log"
pnpm test | tee "$OUT/logs/typescript-tests.log"
pnpm --filter @okeyamy/drs-sdk build | tee "$OUT/logs/sdk-build.log"
pnpm --filter @drs/mcp-server build | tee "$OUT/logs/mcp-server-build.log"
node scripts/assessment/run-live-scenarios.mjs --out="$OUT" | tee "$OUT/logs/live-scenarios.log"
pnpm --filter drs-persona-walkthrough test | tee "$OUT/logs/persona-tests.log"
pnpm --filter drs-persona-walkthrough capture -- "$OUT/responses" | tee "$OUT/logs/persona-capture.log"
pnpm --filter drs-persona-walkthrough start | tee "$OUT/logs/persona-start.log"
(cd "$ROOT/drs-verify" && go test ./...) | tee "$OUT/logs/go-tests.log"
(cd "$ROOT/drs-core" && cargo test) | tee "$OUT/logs/rust-tests.log"

echo "Assessment evidence captured under $OUT"
