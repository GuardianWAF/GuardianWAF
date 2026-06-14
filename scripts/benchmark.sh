#!/usr/bin/env bash
# Run all benchmarks for GuardianWAF.
# Usage: ./scripts/benchmark.sh [count]
set -euo pipefail

COUNT="${1:-3}"
BENCH="${BENCH:-.}"
BENCHTIME="${BENCHTIME:-1s}"
PACKAGES="${PACKAGES:-./...}"
OUTFILE="${OUTFILE:-benchmark_results.txt}"

echo "Running GuardianWAF benchmarks (count=${COUNT})..."
echo "Benchmark pattern: ${BENCH}"
echo "Benchmark time: ${BENCHTIME}"
echo "Packages: ${PACKAGES}"
echo "Results will be saved to ${OUTFILE}"
echo ""

{
    echo "# GuardianWAF benchmark run"
    echo "timestamp_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "go_version=$(go version)"
    echo "goos=$(go env GOOS)"
    echo "goarch=$(go env GOARCH)"
    echo "cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"
    echo "kernel=$(uname -srmo 2>/dev/null || uname -a)"
    echo "bench_pattern=${BENCH}"
    echo "benchtime=${BENCHTIME}"
    echo "count=${COUNT}"
    echo "packages=${PACKAGES}"
    echo ""
    go test -bench="${BENCH}" -benchmem -benchtime="${BENCHTIME}" -run='^$' -count="${COUNT}" ${PACKAGES}
} | tee "${OUTFILE}"

echo ""
echo "Benchmark results saved to ${OUTFILE}"
