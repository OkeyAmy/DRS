#!/usr/bin/env bash
# End-to-end test runner for DRS.
#
# Brings up the verifier + Redis via Docker Compose, waits for /readyz,
# runs the Node test suite against the HTTP surface, and tears everything
# down regardless of test outcome.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

VERIFY_PORT="${DRS_VERIFY_PORT:-18080}"
VERIFY_URL="http://localhost:${VERIFY_PORT}"
READY_TIMEOUT_SECS="${READY_TIMEOUT_SECS:-60}"

# Resolve the image reference here (not inside the compose file) so nested
# ${} substitution works reliably on docker-compose v1. Precedence:
#   1. $DRS_VERIFY_IMAGE — explicit full reference (e.g. "drs-verify:local")
#   2. ghcr.io/okeyamy/drs-verify:$DRS_VERIFY_TAG (defaults to :latest)
if [ -z "${DRS_VERIFY_IMAGE:-}" ]; then
  DRS_VERIFY_IMAGE="ghcr.io/okeyamy/drs-verify:${DRS_VERIFY_TAG:-latest}"
fi
export DRS_VERIFY_IMAGE DRS_VERIFY_PORT

# Support both modern `docker compose` (plugin, v2) and legacy `docker-compose`
# (standalone, v1). Pick whichever is available.
if docker compose version > /dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose > /dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
  exit 1
fi

cleanup() {
  echo "--- tearing down ---"
  "${COMPOSE[@]}" -f docker-compose.test.yml down -v --remove-orphans || true
}
trap cleanup EXIT

echo "--- pulling and starting services (via ${COMPOSE[*]}) ---"
"${COMPOSE[@]}" -f docker-compose.test.yml pull --ignore-pull-failures 2>/dev/null || true
"${COMPOSE[@]}" -f docker-compose.test.yml up -d

echo "--- waiting for /readyz (up to ${READY_TIMEOUT_SECS}s) ---"
elapsed=0
until curl -sf "${VERIFY_URL}/readyz" > /dev/null; do
  if [ "$elapsed" -ge "$READY_TIMEOUT_SECS" ]; then
    echo "verifier did not become ready in time" >&2
    "${COMPOSE[@]}" -f docker-compose.test.yml logs drs-verify || true
    exit 1
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done
echo "verifier is ready after ${elapsed}s"

echo "--- running Node test suite ---"
DRS_VERIFY_URL="$VERIFY_URL" node --test tests/
