#!/usr/bin/env bash
# fuzz-smoke.sh — bounded fuzz smoke checks for CI/nightly gates.

set -euo pipefail

FUZZTIME="${FUZZTIME:-5s}"

targets=(
  "./internal/config FuzzYAMLParserWithValidation"
  "./internal/layers/sanitizer FuzzNormalizeAll"
  "./internal/layers/detection/sqli FuzzSQLiDetector"
  "./internal/layers/detection/xss FuzzXSSDetector"
  "./internal/layers/ipacl FuzzRadixTreeLookup"
  "./internal/layers/ratelimit FuzzTokenBucket"
  "./internal/layers/botdetect FuzzJA3Fingerprint"
  "./internal/layers/apisecurity FuzzJWTValidateInput"
)

echo "Running fuzz smoke checks with FUZZTIME=${FUZZTIME}"

for target in "${targets[@]}"; do
  read -r pkg fuzz <<<"${target}"
  echo
  echo "==> ${pkg} ${fuzz}"
  go test -run='^$' -fuzz="^${fuzz}$" -fuzztime="${FUZZTIME}" "${pkg}"
done

echo
echo "Fuzz smoke checks passed"
