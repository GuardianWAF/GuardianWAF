#!/usr/bin/env bash
# go-test-packages.sh — run Go tests package-by-package with per-package timeouts.
# Usage: [GO_TEST_PACKAGE_TIMEOUT=180s] [GO_TEST_ARGS='-count=1'] ./scripts/go-test-packages.sh [packages...]

set -euo pipefail

PACKAGE_TIMEOUT="${GO_TEST_PACKAGE_TIMEOUT:-180s}"
GO_TEST_ARGS_STRING="${GO_TEST_ARGS:--count=1}"

packages=("$@")
if [ "${#packages[@]}" -eq 0 ]; then
  mapfile -t packages < <(go list ./...)
fi

if [ "${#packages[@]}" -eq 0 ]; then
  echo "No Go packages found" >&2
  exit 1
fi

# Split GO_TEST_ARGS like normal shell words so callers can pass flags such as
# GO_TEST_ARGS='-count=1 -run TestWorkflow'. Keep package names separate so they
# are never interpreted as shell syntax.
read -r -a go_test_args <<<"${GO_TEST_ARGS_STRING}"

printf 'Running go test package-by-package: packages=%d timeout=%s args=%q\n' "${#packages[@]}" "${PACKAGE_TIMEOUT}" "${GO_TEST_ARGS_STRING}"

for pkg in "${packages[@]}"; do
  printf '\n==> %s\n' "${pkg}"
  start=$(date +%s)
  set +e
  timeout "${PACKAGE_TIMEOUT}" go test "${go_test_args[@]}" "${pkg}"
  rc=$?
  set -e
  if [ "${rc}" -ne 0 ]; then
    if [ "${rc}" -eq 124 ]; then
      echo "Package timed out after ${PACKAGE_TIMEOUT}: ${pkg}" >&2
    else
      echo "Package failed with exit code ${rc}: ${pkg}" >&2
    fi
    exit "${rc}"
  fi
  end=$(date +%s)
  printf 'ok package=%s seconds=%s\n' "${pkg}" "$((end - start))"
done

echo
printf 'All package-by-package Go tests passed: packages=%d\n' "${#packages[@]}"
