#!/usr/bin/env bash
# release-rollback-smoke.sh - verifies a candidate binary can upgrade from a
# previous binary's state, then a rollback binary can boot the same state.
#
# Usage:
#   ./scripts/release-rollback-smoke.sh ./dist/guardianwaf-linux-amd64 [./previous/guardianwaf]
#
# If the previous/rollback binary is omitted, the candidate binary is reused.
# Release operators should pass the previously released binary to prove
# cross-version upgrade and rollback compatibility before publishing a release.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

CANDIDATE="${1:-}"
PREVIOUS="${2:-${CANDIDATE}}"

if [ -z "${CANDIDATE}" ]; then
    echo -e "${RED}usage: $0 <candidate-binary> [rollback-binary]${NC}" >&2
    exit 2
fi
if [ ! -x "${CANDIDATE}" ]; then
    echo -e "${RED}candidate binary is not executable: ${CANDIDATE}${NC}" >&2
    exit 2
fi
if [ ! -x "${PREVIOUS}" ]; then
    echo -e "${RED}previous/rollback binary is not executable: ${PREVIOUS}${NC}" >&2
    exit 2
fi

TMPDIR="$(mktemp -d)"
BACKEND_PID=""
GWAF_PID=""

cleanup_pid() {
    local pid="$1"
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
        kill -TERM "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
    fi
}

cleanup() {
    cleanup_pid "${GWAF_PID}"
    cleanup_pid "${BACKEND_PID}"
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

pass() {
    echo -e "  ${GREEN}PASS${NC} $1"
}

fail() {
    echo -e "  ${RED}FAIL${NC} $1: $2" >&2
    exit 1
}

section() {
    echo -e "\n${YELLOW}=== $1 ===${NC}"
}

wait_http() {
    local url="$1"
    local want="${2:-200}"
    local code="000"
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        code="$(curl -s -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || true)"
        if [ "${code}" = "${want}" ]; then
            return 0
        fi
        sleep 1
    done
    echo "${code}"
    return 1
}

BACKEND_PORT=19181
GWAF_PORT=19182
STATE_DIR="${TMPDIR}/state"
CONFIG="${TMPDIR}/guardianwaf.yaml"
mkdir -p "${STATE_DIR}/events"

cat > "${TMPDIR}/backend.go" <<'GO'
package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	addr := os.Args[1]
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "rollback-backend %s\n", r.URL.Path)
	})
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
GO

cat > "${CONFIG}" <<YAML
mode: enforce
listen: "127.0.0.1:${GWAF_PORT}"
allow_private_upstreams: true

upstreams:
  - name: rollback-backend
    targets:
      - url: "http://127.0.0.1:${BACKEND_PORT}"
        weight: 1

routes:
  - path: /
    upstream: rollback-backend

waf:
  detection:
    enabled: true
    threshold:
      block: 50
      log: 25
  sanitizer:
    enabled: true
  response:
    security_headers:
      enabled: true

dashboard:
  enabled: false

mcp:
  enabled: false

events:
  storage: file
  max_events: 1000
  file_path: "${STATE_DIR}/events/events.jsonl"
YAML

start_backend() {
    go run "${TMPDIR}/backend.go" "127.0.0.1:${BACKEND_PORT}" &
    BACKEND_PID=$!
    if ! code="$(wait_http "http://127.0.0.1:${BACKEND_PORT}/healthz" 200)"; then
        fail "backend startup" "got HTTP ${code}"
    fi
    pass "backend starts"
}

start_guardianwaf() {
    local binary="$1"
    local label="$2"
    "${binary}" validate -config "${CONFIG}" >/dev/null
    pass "${label} validates rollback config"

    "${binary}" serve -config "${CONFIG}" &
    GWAF_PID=$!
    if ! code="$(wait_http "http://127.0.0.1:${GWAF_PORT}/readyz" 200)"; then
        fail "${label} readiness" "got HTTP ${code}"
    fi
    pass "${label} /readyz returns 200"
}

stop_guardianwaf() {
    cleanup_pid "${GWAF_PID}"
    GWAF_PID=""
}

proxy_request() {
    local label="$1"
    local body
    body="$(curl -s "http://127.0.0.1:${GWAF_PORT}/rollback-check" -H "User-Agent: Mozilla/5.0 Chrome/120.0" 2>/dev/null || true)"
    if echo "${body}" | grep -q "rollback-backend /rollback-check"; then
        pass "${label} proxies traffic"
    else
        fail "${label} proxy traffic" "unexpected body: ${body}"
    fi
}

section "Rollback Smoke Setup"
start_backend

section "Previous Runtime"
start_guardianwaf "${PREVIOUS}" "previous"
proxy_request "previous"
stop_guardianwaf
pass "previous stops cleanly"

if [ ! -s "${STATE_DIR}/events/events.jsonl" ]; then
    fail "previous event persistence" "expected non-empty ${STATE_DIR}/events/events.jsonl"
fi
pass "previous writes persistent events"

section "Candidate Upgrade Runtime"
start_guardianwaf "${CANDIDATE}" "candidate upgrade"
proxy_request "candidate upgrade"
stop_guardianwaf
pass "candidate upgrade stops cleanly"

section "Rollback Runtime"
start_guardianwaf "${PREVIOUS}" "rollback"
proxy_request "rollback"
stop_guardianwaf
pass "rollback stops cleanly"

section "Summary"
echo -e "${GREEN}Upgrade and rollback smoke passed${NC}"
