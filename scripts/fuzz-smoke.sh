#!/usr/bin/env bash
# fuzz-smoke.sh — bounded fuzz smoke checks for CI/nightly gates.
#
# Targets are DISCOVERED from the tree, never hand-listed. Two hand-maintained
# lists previously drifted from reality: the Makefile named FuzzParseFrame in
# ./internal/layers/websocket, which does not exist — `go test -fuzz` treats an
# unmatched target as "no fuzz tests to fuzz" and exits 0, so that gate reported
# green while fuzzing nothing. Between them the two lists also skipped 20 of the
# 33 real targets. Discovery keeps a new `func FuzzX` covered the day it lands.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

FUZZTIME="${FUZZTIME:-5s}"

# "<pkg> <FuzzName>" pairs, sorted and deduplicated.
mapfile -t targets < <(
  grep -rEl --include='*_test.go' '^func Fuzz[A-Za-z0-9_]*\(' . |
    while read -r file; do
      pkg="./$(dirname "${file#./}")"
      grep -oE '^func Fuzz[A-Za-z0-9_]+' "$file" | sed 's/^func //' |
        while read -r fn; do printf '%s %s\n' "$pkg" "$fn"; done
    done | sort -u
)

if [ "${#targets[@]}" -eq 0 ]; then
  echo "no fuzz targets discovered — discovery is broken, refusing to pass" >&2
  exit 1
fi

echo "Running fuzz smoke checks with FUZZTIME=${FUZZTIME} over ${#targets[@]} targets"

for target in "${targets[@]}"; do
  read -r pkg fuzz <<<"${target}"
  echo
  echo "==> ${pkg} ${fuzz}"
  # Confirm the target actually exists before fuzzing it, so a rename can never
  # silently degrade into a no-op pass the way FuzzParseFrame did.
  if ! go test -run="^${fuzz}$" -count=1 "${pkg}" >/dev/null 2>&1; then
    echo "    fuzz target ${fuzz} not found in ${pkg}" >&2
    exit 1
  fi
  # Retry once on failure. A real crash is written to testdata/fuzz/ and so fails
  # deterministically on the retry too; only the known short-fuzztime timing flake
  # ("context deadline exceeded", no crash file) clears on a second attempt.
  if ! go test -run='^$' -fuzz="^${fuzz}$" -fuzztime="${FUZZTIME}" "${pkg}"; then
    echo "    (first attempt failed; retrying once)"
    go test -run='^$' -fuzz="^${fuzz}$" -fuzztime="${FUZZTIME}" "${pkg}"
  fi
done

echo
echo "Fuzz smoke checks passed (${#targets[@]} targets)"
