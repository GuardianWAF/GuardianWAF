#!/usr/bin/env bash
# dashboard-e2e.sh - Build and exercise the dashboard in a real browser.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="$(mktemp -d)"
SERVER_PID=""

cleanup() {
  if [[ -n "${SERVER_PID}" ]]; then
    kill -TERM "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${TMPDIR}"
}
trap cleanup EXIT

BIN="${TMPDIR}/guardianwaf"
CONFIG="${TMPDIR}/guardianwaf.yaml"
LOG="${TMPDIR}/guardianwaf.log"
API_KEY="${DASHBOARD_E2E_API_KEY:-dashboard-e2e-secret}"
ADMIN_KEY="${DASHBOARD_E2E_ADMIN_KEY:-dashboard-e2e-admin-secret}"
BASE_URL="${DASHBOARD_E2E_BASE_URL:-http://127.0.0.1:19443}"

"${ROOT_DIR}/scripts/build-dashboard.sh"
go build -o "${BIN}" "${ROOT_DIR}/cmd/guardianwaf"

cat > "${CONFIG}" <<YAML
mode: enforce
listen: ":19088"
dashboard:
  enabled: true
  listen: ":19443"
  api_key: "${API_KEY}"
  admin_key: "${ADMIN_KEY}"
  tls: false
mcp:
  enabled: false
events:
  max_events: 1000
YAML

"${BIN}" serve -c "${CONFIG}" >"${LOG}" 2>&1 &
SERVER_PID=$!

for _ in {1..50}; do
  if curl -fsS "${BASE_URL}/api/v1/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    cat "${LOG}"
    echo "GuardianWAF exited before dashboard became ready" >&2
    exit 1
  fi
  sleep 0.2
done

curl -fsS "${BASE_URL}/api/v1/health" >/dev/null

(
  cd "${ROOT_DIR}/internal/dashboard/ui"
  if [[ -z "${PLAYWRIGHT_CHROMIUM_EXECUTABLE:-}" ]]; then
    for browser in google-chrome google-chrome-stable chromium chromium-browser; do
      if command -v "${browser}" >/dev/null 2>&1; then
        export PLAYWRIGHT_CHROMIUM_EXECUTABLE="$(command -v "${browser}")"
        break
      fi
    done
  fi
  DASHBOARD_E2E_BASE_URL="${BASE_URL}" DASHBOARD_E2E_API_KEY="${API_KEY}" DASHBOARD_E2E_ADMIN_KEY="${ADMIN_KEY}" E2E_ADMIN_KEY="${ADMIN_KEY}" npm run test:e2e
)
