#!/usr/bin/env bash
# Build and run the complete Playwright/API suite against a real local binary.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="$(mktemp -d)"
BACKEND_PID=""
WAF_PID=""

cleanup() {
  if [[ -n "${WAF_PID}" ]]; then
    kill -TERM "${WAF_PID}" 2>/dev/null || true
    wait "${WAF_PID}" 2>/dev/null || true
  fi
  if [[ -n "${BACKEND_PID}" ]]; then
    kill -TERM "${BACKEND_PID}" 2>/dev/null || true
    wait "${BACKEND_PID}" 2>/dev/null || true
  fi
  rm -rf "${TMPDIR}"
}
trap cleanup EXIT

BIN="${TMPDIR}/guardianwaf"
BACKEND_BIN="${TMPDIR}/backend"
CONFIG="${TMPDIR}/guardianwaf.yaml"
WAF_LOG="${TMPDIR}/guardianwaf.log"
BACKEND_LOG="${TMPDIR}/backend.log"
BASE_URL="${E2E_BASE_URL:-http://127.0.0.1:9443}"
WAF_URL="${E2E_WAF_URL:-http://127.0.0.1:8088}"
API_KEY="${E2E_API_KEY:-guardianwaf-full-e2e-api-key}"
ADMIN_KEY="${E2E_ADMIN_KEY:-guardianwaf-full-e2e-admin-key}"
E2E_PROJECTS="${E2E_PROJECTS:-chromium}"
E2E_PLAYWRIGHT_DOCKER="${E2E_PLAYWRIGHT_DOCKER:-false}"
PLAYWRIGHT_DOCKER_IMAGE="${PLAYWRIGHT_DOCKER_IMAGE:-mcr.microsoft.com/playwright:v1.60.0-noble@sha256:9bd26ad900bb5e0f4dee75839e957a89ae89c2b7ab1e76050e559790e946b948}"

case "${E2E_PLAYWRIGHT_DOCKER}" in
  true|false) ;;
  *)
    echo "E2E_PLAYWRIGHT_DOCKER must be true or false" >&2
    exit 2
    ;;
esac

IFS=',' read -r -a requested_projects <<<"${E2E_PROJECTS}"
project_args=()
bundled_projects=()
needs_chromium=false
for project in "${requested_projects[@]}"; do
  project="${project//[[:space:]]/}"
  case "${project}" in
    chromium|firefox|webkit)
      project_args+=("--project=${project}")
      if [[ "${project}" == "chromium" ]]; then
        needs_chromium=true
      else
        bundled_projects+=("${project}")
      fi
      ;;
    *)
      echo "Unsupported E2E project ${project@Q}; expected chromium, firefox, or webkit" >&2
      exit 2
      ;;
  esac
done
if [[ ${#project_args[@]} -eq 0 ]]; then
  echo "E2E_PROJECTS must select at least one browser project" >&2
  exit 2
fi
grep_args=()
if [[ -n "${E2E_GREP:-}" ]]; then
  grep_args+=("--grep=${E2E_GREP}")
fi

"${ROOT_DIR}/scripts/build-dashboard.sh"
go build -o "${BIN}" "${ROOT_DIR}/cmd/guardianwaf"
go build -o "${BACKEND_BIN}" "${ROOT_DIR}/examples/backend"
cp "${ROOT_DIR}/testdata/realtest.yaml" "${CONFIG}"

(
  cd "${TMPDIR}"
  exec "${BACKEND_BIN}" >"${BACKEND_LOG}" 2>&1
) &
BACKEND_PID=$!

for _ in {1..50}; do
  if curl -fsS "http://127.0.0.1:3000/healthz" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${BACKEND_PID}" 2>/dev/null; then
    cat "${BACKEND_LOG}"
    echo "E2E backend exited before becoming ready" >&2
    exit 1
  fi
  sleep 0.2
done
if ! kill -0 "${BACKEND_PID}" 2>/dev/null; then
  cat "${BACKEND_LOG}"
  echo "E2E backend is not running after readiness check" >&2
  exit 1
fi
curl -fsS "http://127.0.0.1:3000/healthz" >/dev/null

(
  cd "${TMPDIR}"
  GWAF_DASHBOARD_API_KEY="${API_KEY}" \
  GWAF_DASHBOARD_ADMIN_KEY="${ADMIN_KEY}" \
  GWAF_MCP_ENABLED=true \
  GWAF_MCP_TRANSPORT=stdio \
  GWAF_DOCKER_ENABLED=false \
  GWAF_WAF_AI_ANALYSIS_ENABLED=false \
    exec "${BIN}" serve -c "${CONFIG}" >"${WAF_LOG}" 2>&1
) &
WAF_PID=$!

for _ in {1..100}; do
  if curl -fsS "${BASE_URL}/api/v1/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${WAF_PID}" 2>/dev/null; then
    cat "${WAF_LOG}"
    echo "GuardianWAF exited before the full E2E suite became ready" >&2
    exit 1
  fi
  sleep 0.2
done
if ! kill -0 "${WAF_PID}" 2>/dev/null; then
  cat "${WAF_LOG}"
  echo "GuardianWAF is not running after readiness check" >&2
  exit 1
fi
curl -fsS "${BASE_URL}/api/v1/health" >/dev/null

(
  cd "${ROOT_DIR}/tests/e2e/playwright"
  npm ci --no-audit --no-fund
)

if [[ "${E2E_PLAYWRIGHT_DOCKER}" != "true" && "${needs_chromium}" == "true" && -z "${PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH:-}" ]]; then
  for browser in google-chrome google-chrome-stable chromium chromium-browser; do
    if command -v "${browser}" >/dev/null 2>&1; then
      export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$(command -v "${browser}")"
      break
    fi
  done
fi

if [[ "${E2E_PLAYWRIGHT_DOCKER}" != "true" && "${needs_chromium}" == "true" && -z "${PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH:-}" ]]; then
  (
    cd "${ROOT_DIR}/tests/e2e/playwright"
    npx playwright install chromium
  )
fi

if [[ "${E2E_PLAYWRIGHT_DOCKER}" != "true" && ${#bundled_projects[@]} -gt 0 ]]; then
  (
    cd "${ROOT_DIR}/tests/e2e/playwright"
    npx playwright install "${bundled_projects[@]}"
  )
fi

run_playwright() {
  if [[ "${E2E_PLAYWRIGHT_DOCKER}" == "true" ]]; then
    if ! command -v docker >/dev/null 2>&1; then
      echo "Docker is required when E2E_PLAYWRIGHT_DOCKER=true" >&2
      return 1
    fi
    docker run --rm --init --ipc=host --network host \
      --volume "${ROOT_DIR}/tests/e2e/playwright:/work:ro" \
      --workdir /work \
      --env "E2E_BASE_URL=${BASE_URL}" \
      --env "E2E_WAF_URL=${WAF_URL}" \
      --env "E2E_API_KEY=${API_KEY}" \
      --env "E2E_ADMIN_KEY=${ADMIN_KEY}" \
      "${PLAYWRIGHT_DOCKER_IMAGE}" \
      npx playwright test "${project_args[@]}" "${grep_args[@]}" --workers="${E2E_WORKERS:-1}" --reporter=list --output=/tmp/test-results
    return
  fi

  (
    cd "${ROOT_DIR}/tests/e2e/playwright"
    E2E_BASE_URL="${BASE_URL}" \
    E2E_WAF_URL="${WAF_URL}" \
    E2E_API_KEY="${API_KEY}" \
    E2E_ADMIN_KEY="${ADMIN_KEY}" \
      npx playwright test "${project_args[@]}" "${grep_args[@]}" --workers="${E2E_WORKERS:-1}"
  )
}

if ! run_playwright; then
  echo "Full E2E suite failed; GuardianWAF log tail:" >&2
  tail -n 200 "${WAF_LOG}" >&2
  echo "Backend log tail:" >&2
  tail -n 100 "${BACKEND_LOG}" >&2
  exit 1
fi
