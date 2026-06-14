#!/usr/bin/env bash
# Measure standalone and sidecar proxy latency against a local backend.
# Usage: REQUESTS=1000 CONCURRENCY=20 ./scripts/proxy-load-test.sh [path-to-binary]
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="${1:-}"
REQUESTS="${REQUESTS:-1000}"
CONCURRENCY="${CONCURRENCY:-20}"
WARMUP="${WARMUP:-50}"
OUTFILE="${OUTFILE:-proxy_load_results.txt}"
TMPDIR="$(mktemp -d)"

BACKEND_PID=""
SERVE_PID=""
SIDECAR_PID=""

kill_process() {
    local pid="$1"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}

cleanup() {
    kill_process "$SIDECAR_PID"
    kill_process "$SERVE_PID"
    kill_process "$BACKEND_PID"
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

free_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

wait_url() {
    local url="$1"
    local name="$2"
    for _ in $(seq 1 100); do
        if curl -fsS "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    echo "$name did not become ready at $url" >&2
    return 1
}

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required" >&2
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required" >&2
    exit 1
fi

if [ -z "$BINARY" ]; then
    BINARY="$TMPDIR/guardianwaf"
    (cd "$ROOT_DIR" && go build -o "$BINARY" ./cmd/guardianwaf)
fi
if [ ! -x "$BINARY" ]; then
    echo "binary is not executable: $BINARY" >&2
    exit 1
fi

BACKEND_PORT="$(free_port)"
SERVE_PORT="$(free_port)"
SIDECAR_PORT="$(free_port)"

cat >"$TMPDIR/backend.py" <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sys

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path in ("/healthz", "/readyz"):
            body = b"ok"
            self.send_response(200)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps({"service": "guardianwaf-load", "path": self.path}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return

class Server(ThreadingHTTPServer):
    request_queue_size = 128
    daemon_threads = True

Server(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY

python3 "$TMPDIR/backend.py" "$BACKEND_PORT" &
BACKEND_PID=$!
wait_url "http://127.0.0.1:$BACKEND_PORT/healthz" "backend"

cat >"$TMPDIR/standalone.yaml" <<YAML
mode: enforce
listen: "127.0.0.1:$SERVE_PORT"
allow_private_upstreams: true
upstreams:
  - name: load-backend
    targets:
      - url: "http://127.0.0.1:$BACKEND_PORT"
        weight: 1
    health_check:
      enabled: true
      interval: 2s
      timeout: 1s
      path: /healthz
routes:
  - path: /
    upstream: load-backend
waf:
  ip_acl:
    enabled: false
  rate_limit:
    enabled: false
  detection:
    enabled: true
    threshold:
      block: 50
      log: 25
  sanitizer:
    enabled: true
    max_body_size: 10485760
  bot_detection:
    enabled: false
dashboard:
  enabled: false
mcp:
  enabled: false
events:
  storage: memory
  max_events: 1000
YAML

cat >"$TMPDIR/sidecar.yaml" <<YAML
mode: enforce
listen: "127.0.0.1:$SIDECAR_PORT"
allow_private_upstreams: true
upstreams:
  - name: load-backend
    targets:
      - url: "http://127.0.0.1:$BACKEND_PORT"
        weight: 1
    health_check:
      enabled: true
      interval: 2s
      timeout: 1s
      path: /healthz
routes:
  - path: /
    upstream: load-backend
waf:
  ip_acl:
    enabled: false
  rate_limit:
    enabled: false
  detection:
    enabled: true
    threshold:
      block: 50
      log: 25
  sanitizer:
    enabled: true
    max_body_size: 10485760
  bot_detection:
    enabled: false
dashboard:
  enabled: false
mcp:
  enabled: false
events:
  storage: memory
  max_events: 1000
YAML

"$BINARY" serve -config "$TMPDIR/standalone.yaml" >"$TMPDIR/serve.log" 2>&1 &
SERVE_PID=$!
wait_url "http://127.0.0.1:$SERVE_PORT/livez" "standalone"

"$BINARY" sidecar -config "$TMPDIR/sidecar.yaml" >"$TMPDIR/sidecar.log" 2>&1 &
SIDECAR_PID=$!
wait_url "http://127.0.0.1:$SIDECAR_PORT/livez" "sidecar"

{
    echo "# GuardianWAF proxy load test"
    echo "timestamp_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "go_version=$(go version)"
    echo "goos=$(go env GOOS)"
    echo "goarch=$(go env GOARCH)"
    echo "cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"
    echo "kernel=$(uname -srmo 2>/dev/null || uname -a)"
    echo "requests=${REQUESTS}"
    echo "concurrency=${CONCURRENCY}"
    echo "warmup=${WARMUP}"
    echo "backend_url=http://127.0.0.1:${BACKEND_PORT}"
    echo ""
    python3 - "$REQUESTS" "$CONCURRENCY" "$WARMUP" \
        "backend=http://127.0.0.1:$BACKEND_PORT/" \
        "standalone=http://127.0.0.1:$SERVE_PORT/" \
        "sidecar=http://127.0.0.1:$SIDECAR_PORT/" <<'PY'
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.client import HTTPConnection
from urllib.parse import urlparse
import statistics
import sys
import time

requests = int(sys.argv[1])
concurrency = int(sys.argv[2])
warmup = int(sys.argv[3])
targets = [arg.split("=", 1) for arg in sys.argv[4:]]

def hit(conn, path):
    start = time.perf_counter()
    try:
        conn.request("GET", path, headers={"User-Agent": "GuardianWAF proxy-load-test"})
        response = conn.getresponse()
        response.read()
        status = response.status
    except Exception:
        status = 0
    elapsed_ms = (time.perf_counter() - start) * 1000
    return status, elapsed_ms

def make_conn(parsed):
    return HTTPConnection(parsed.hostname, parsed.port, timeout=5)

def run_worker(parsed, path, count):
    conn = make_conn(parsed)
    worker_results = []
    try:
        for _ in range(count):
            status, elapsed = hit(conn, path)
            if status == 0:
                conn.close()
                conn = make_conn(parsed)
            worker_results.append((status, elapsed))
    finally:
        conn.close()
    return worker_results

def percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((pct / 100.0) * len(ordered) + 0.999999) - 1))
    return ordered[index]

baseline = {}

for name, url in targets:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    warm_conn = make_conn(parsed)
    for _ in range(warmup):
        status, _ = hit(warm_conn, path)
        if status != 200:
            raise SystemExit(f"{name} warmup failed with status {status}")
    warm_conn.close()

    started = time.perf_counter()
    results = []
    base = requests // concurrency
    remainder = requests % concurrency
    worker_counts = [base + (1 if i < remainder else 0) for i in range(concurrency)]
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(run_worker, parsed, path, count) for count in worker_counts if count > 0]
        for future in as_completed(futures):
            results.extend(future.result())
    duration = time.perf_counter() - started

    statuses = [status for status, _ in results]
    latencies = [elapsed for status, elapsed in results if status == 200]
    errors = sum(1 for status in statuses if status != 200)
    rps = requests / duration if duration > 0 else 0
    avg = statistics.mean(latencies) if latencies else 0.0
    p95 = percentile(latencies, 95)
    p99 = percentile(latencies, 99)

    print(f"## {name}")
    print(f"url={url}")
    print(f"requests={requests}")
    print(f"concurrency={concurrency}")
    print(f"errors={errors}")
    print(f"rps={rps:.2f}")
    print(f"latency_avg_ms={avg:.3f}")
    print(f"latency_p50_ms={percentile(latencies, 50):.3f}")
    print(f"latency_p95_ms={p95:.3f}")
    print(f"latency_p99_ms={p99:.3f}")
    print(f"latency_max_ms={max(latencies) if latencies else 0.0:.3f}")
    if name == "backend":
        baseline["p95"] = p95
        baseline["p99"] = p99
    elif "p95" in baseline and "p99" in baseline:
        print(f"overhead_p95_ms={max(0.0, p95 - baseline['p95']):.3f}")
        print(f"overhead_p99_ms={max(0.0, p99 - baseline['p99']):.3f}")
    print("")
    if errors:
        raise SystemExit(f"{name} load test had {errors} non-200 responses")
PY
} | tee "$OUTFILE"

echo "Proxy load results saved to $OUTFILE"
