#!/usr/bin/env bash
# One-command local developer workflow for GuardianWAF.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTDIR="${ROOT_DIR}/dist"
BINARY="${OUTDIR}/guardianwaf-dev"
RUN_DEMO=0
RUN_SMOKE=0
SKIP_DASHBOARD=0
SKIP_TESTS=0

usage() {
    cat <<'EOF'
Usage: ./scripts/dev.sh [options]

Build a local developer binary through the same prerequisite and dashboard
asset path used by production builds, then run Go tests.

Options:
  --demo             Start a temporary backend and GuardianWAF after the build.
  --smoke            Run scripts/smoke-test.sh with the built binary.
  --skip-dashboard   Skip dashboard asset build for fast backend-only iteration.
  --skip-tests       Skip go test ./... for fast compile-only iteration.
  -h, --help         Show this help.

Demo endpoints:
  Backend:      http://127.0.0.1:18080
  GuardianWAF:  http://127.0.0.1:18088
  Dashboard:    http://127.0.0.1:19443
  API key:      dev-local-api-key-1234567890
EOF
}

log() {
    printf '\n==> %s\n' "$1"
}

for arg in "$@"; do
    case "$arg" in
        --demo)
            RUN_DEMO=1
            ;;
        --smoke)
            RUN_SMOKE=1
            ;;
        --skip-dashboard)
            SKIP_DASHBOARD=1
            ;;
        --skip-tests)
            SKIP_TESTS=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $arg" >&2
            usage >&2
            exit 2
            ;;
    esac
done

log "Checking prerequisites"
"${ROOT_DIR}/scripts/check-prereqs.sh"

if [ "$SKIP_DASHBOARD" -eq 0 ]; then
    log "Building dashboard assets"
    "${ROOT_DIR}/scripts/build-dashboard.sh"
else
    log "Skipping dashboard asset build"
fi

if [ "$SKIP_TESTS" -eq 0 ]; then
    log "Running Go tests"
    (cd "$ROOT_DIR" && go test ./...)
else
    log "Skipping Go tests"
fi

log "Building local developer binary"
mkdir -p "$OUTDIR"
(cd "$ROOT_DIR" && go build -o "$BINARY" ./cmd/guardianwaf)
printf 'Built %s\n' "$BINARY"

if [ "$RUN_SMOKE" -eq 1 ]; then
    log "Running smoke test"
    "${ROOT_DIR}/scripts/smoke-test.sh" "$BINARY"
fi

if [ "$RUN_DEMO" -eq 0 ]; then
    log "Developer workflow complete"
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required for --demo backend" >&2
    exit 1
fi

TMPDIR="$(mktemp -d)"
BACKEND_PID=""
GWAF_PID=""

cleanup() {
    if [ -n "$GWAF_PID" ] && kill -0 "$GWAF_PID" 2>/dev/null; then
        kill -TERM "$GWAF_PID" 2>/dev/null || true
        wait "$GWAF_PID" 2>/dev/null || true
    fi
    if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill -TERM "$BACKEND_PID" 2>/dev/null || true
        wait "$BACKEND_PID" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

cat >"${TMPDIR}/backend.py" <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/healthz", "/readyz"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"service":"guardianwaf-demo","status":"ok"}')

    def log_message(self, fmt, *args):
        return

ThreadingHTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
PY

cat >"${TMPDIR}/guardianwaf.yaml" <<'YAML'
mode: enforce
listen: "127.0.0.1:18088"
allow_private_upstreams: true
upstreams:
  - name: demo
    targets:
      - url: "http://127.0.0.1:18080"
        weight: 1
    health_check:
      enabled: true
      interval: 2s
      timeout: 1s
      path: /healthz
routes:
  - path: /
    upstream: demo
waf:
  detection:
    enabled: true
    threshold:
      block: 50
      log: 25
dashboard:
  enabled: true
  listen: "127.0.0.1:19443"
  api_key: "dev-local-api-key-1234567890"
  admin_key: ""
  tls: false
mcp:
  enabled: false
events:
  storage: memory
  max_events: 1000
YAML

log "Starting demo backend"
python3 "${TMPDIR}/backend.py" &
BACKEND_PID=$!

log "Starting GuardianWAF demo"
"$BINARY" serve -config "${TMPDIR}/guardianwaf.yaml" &
GWAF_PID=$!

printf '\nDemo running. Press Ctrl+C to stop.\n'
printf 'Backend:      http://127.0.0.1:18080\n'
printf 'GuardianWAF:  http://127.0.0.1:18088\n'
printf 'Dashboard:    http://127.0.0.1:19443\n'
printf 'API key:      dev-local-api-key-1234567890\n\n'

wait "$GWAF_PID"
