#!/usr/bin/env bash
# Measure GuardianWAF proxy latency in a real target environment.
# Usage:
#   TARGET_BACKEND_URL=https://backend.example.com/healthz \
#   TARGET_STANDALONE_URL=https://waf.example.com/healthz \
#   REQUESTS=1000 CONCURRENCY=20 ./scripts/target-load-evidence.sh
set -euo pipefail

REQUESTS="${REQUESTS:-1000}"
CONCURRENCY="${CONCURRENCY:-20}"
WARMUP="${WARMUP:-50}"
OUTFILE="${OUTFILE:-target_load_results.txt}"
TARGET_BACKEND_URL="${TARGET_BACKEND_URL:-}"
TARGET_STANDALONE_URL="${TARGET_STANDALONE_URL:-}"
TARGET_SIDECAR_URL="${TARGET_SIDECAR_URL:-}"
TARGET_LABEL="${TARGET_LABEL:-target}"

require_positive_integer() {
    local name="$1"
    local value="$2"
    if ! [[ "${value}" =~ ^[1-9][0-9]*$ ]]; then
        echo "${name} must be a positive integer, got: ${value}" >&2
        exit 2
    fi
}

require_http_url() {
    local name="$1"
    local value="$2"
    local authority
    if ! [[ "${value}" =~ ^https?:// ]]; then
        echo "${name} must start with http:// or https://, got: ${value}" >&2
        exit 2
    fi
    if [[ "${value}" =~ [[:space:]] ]]; then
        echo "${name} must not contain whitespace, got: ${value}" >&2
        exit 2
    fi
    authority="${value#*://}"
    authority="${authority%%[/?#]*}"
    if [ -z "${authority}" ]; then
        echo "${name} must include a host, got: ${value}" >&2
        exit 2
    fi
    if [[ "${authority}" == *"@"* ]]; then
        echo "${name} must not include URL userinfo or credentials, got: ${value}" >&2
        exit 2
    fi
    if [[ "${value}" == *"#"* ]]; then
        echo "${name} must not include a URL fragment, got: ${value}" >&2
        exit 2
    fi
}

require_positive_integer REQUESTS "${REQUESTS}"
require_positive_integer CONCURRENCY "${CONCURRENCY}"
require_positive_integer WARMUP "${WARMUP}"
case "${TARGET_LABEL}" in
    target|test|default|unknown)
        echo "TARGET_LABEL must identify the measured target environment, not generic value: ${TARGET_LABEL}" >&2
        exit 2
        ;;
esac
if [ "${REQUESTS}" -lt 1000 ] || [ "${CONCURRENCY}" -lt 10 ] || [ "${WARMUP}" -lt 50 ]; then
    echo "REQUESTS, CONCURRENCY, and WARMUP must satisfy release evidence minimums: REQUESTS>=1000 CONCURRENCY>=10 WARMUP>=50" >&2
    exit 2
fi

if [ -z "${TARGET_BACKEND_URL}" ]; then
    echo "TARGET_BACKEND_URL is required" >&2
    exit 2
fi
require_http_url TARGET_BACKEND_URL "${TARGET_BACKEND_URL}"
if [ -z "${TARGET_STANDALONE_URL}" ] && [ -z "${TARGET_SIDECAR_URL}" ]; then
    echo "set TARGET_STANDALONE_URL or TARGET_SIDECAR_URL" >&2
    exit 2
fi
if [ -n "${TARGET_STANDALONE_URL}" ]; then
    require_http_url TARGET_STANDALONE_URL "${TARGET_STANDALONE_URL}"
fi
if [ -n "${TARGET_SIDECAR_URL}" ]; then
    require_http_url TARGET_SIDECAR_URL "${TARGET_SIDECAR_URL}"
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required" >&2
    exit 1
fi

targets=("backend=${TARGET_BACKEND_URL}")
if [ -n "${TARGET_STANDALONE_URL}" ]; then
    targets+=("standalone=${TARGET_STANDALONE_URL}")
fi
if [ -n "${TARGET_SIDECAR_URL}" ]; then
    targets+=("sidecar=${TARGET_SIDECAR_URL}")
fi

{
    echo "# GuardianWAF target environment load evidence"
    echo "timestamp_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "target_label=${TARGET_LABEL}"
    echo "requests=${REQUESTS}"
    echo "concurrency=${CONCURRENCY}"
    echo "warmup=${WARMUP}"
    echo "backend_url=${TARGET_BACKEND_URL}"
    if [ -n "${TARGET_STANDALONE_URL}" ]; then
        echo "standalone_url=${TARGET_STANDALONE_URL}"
    fi
    if [ -n "${TARGET_SIDECAR_URL}" ]; then
        echo "sidecar_url=${TARGET_SIDECAR_URL}"
    fi
    echo "cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"
    echo "kernel=$(uname -srmo 2>/dev/null || uname -a)"
    echo ""
    python3 - "$REQUESTS" "$CONCURRENCY" "$WARMUP" "${targets[@]}" <<'PY'
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlparse
import statistics
import sys
import time

requests = int(sys.argv[1])
concurrency = int(sys.argv[2])
warmup = int(sys.argv[3])
targets = [arg.split("=", 1) for arg in sys.argv[4:]]

def make_conn(parsed):
    if parsed.scheme == "https":
        return HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=10)
    if parsed.scheme == "http":
        return HTTPConnection(parsed.hostname, parsed.port or 80, timeout=10)
    raise SystemExit(f"unsupported URL scheme for {parsed.geturl()}")

def request_path(parsed):
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return path

def hit(conn, host, path):
    start = time.perf_counter()
    try:
        conn.request("GET", path, headers={"Host": host, "User-Agent": "GuardianWAF target-load-evidence"})
        response = conn.getresponse()
        response.read()
        status = response.status
    except Exception:
        status = 0
    elapsed_ms = (time.perf_counter() - start) * 1000
    return status, elapsed_ms

def run_worker(parsed, path, count):
    host = parsed.netloc
    conn = make_conn(parsed)
    worker_results = []
    try:
        for _ in range(count):
            status, elapsed = hit(conn, host, path)
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
    path = request_path(parsed)

    warm_conn = make_conn(parsed)
    for _ in range(warmup):
        status, _ = hit(warm_conn, parsed.netloc, path)
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
    p95 = percentile(latencies, 95)
    p99 = percentile(latencies, 99)

    print(f"## {name}")
    print(f"url={url}")
    print(f"requests={requests}")
    print(f"concurrency={concurrency}")
    print(f"errors={errors}")
    print(f"rps={rps:.2f}")
    print(f"latency_avg_ms={statistics.mean(latencies) if latencies else 0.0:.3f}")
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
} | tee "${OUTFILE}"

echo "Target load evidence saved to ${OUTFILE}"
