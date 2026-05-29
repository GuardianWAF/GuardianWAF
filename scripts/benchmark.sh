#!/usr/bin/env bash
# Run all benchmarks for GuardianWAF.
# Usage: ./scripts/benchmark.sh [count]
set -euo pipefail

COUNT="${1:-3}"
OUTFILE="benchmark_results.txt"

echo "Running GuardianWAF benchmarks (count=${COUNT})..."
echo "Results will be saved to ${OUTFILE}"
echo ""

go test -bench=. -benchmem -run='^$' -count="${COUNT}" ./... | tee "${OUTFILE}"

echo ""
echo "Benchmark results saved to ${OUTFILE}"
