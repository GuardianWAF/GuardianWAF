#!/usr/bin/env bash
# fuzz-smoke.sh — bounded fuzz smoke checks for CI/nightly gates.

set -euo pipefail

FUZZTIME="${FUZZTIME:-5s}"

targets=(
  "./internal/config FuzzYAMLParserWithValidation"
  "./internal/layers/sanitizer FuzzNormalizeAll"
  "./internal/layers/detection/sqli FuzzSQLiDetector"
  "./internal/layers/detection/xss FuzzXSSDetector"
  "./internal/layers/detection/lfi FuzzLFIDetector"
  "./internal/layers/detection/cmdi FuzzCMDiDetector"
  "./internal/layers/detection/ssrf FuzzSSRFDetector"
  "./internal/layers/detection/ssti FuzzSSTIDetector"
  "./internal/engine FuzzRecoverDroppedQueryParams"
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
  # Retry once on failure. A real crash is written to testdata/fuzz/ and so fails
  # deterministically on the retry too; only the known short-fuzztime timing flake
  # ("context deadline exceeded", no crash file) clears on a second attempt.
  if ! go test -run='^$' -fuzz="^${fuzz}$" -fuzztime="${FUZZTIME}" "${pkg}"; then
    echo "    (first attempt failed; retrying once)"
    go test -run='^$' -fuzz="^${fuzz}$" -fuzztime="${FUZZTIME}" "${pkg}"
  fi
done

echo
echo "Fuzz smoke checks passed"
