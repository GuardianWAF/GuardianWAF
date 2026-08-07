#!/usr/bin/env bash
# Collect release-readiness evidence into a single auditable directory.
# Usage: RELEASE_EVIDENCE_HEAVY=1 ./scripts/release-evidence.sh v1.x.x [previous-release-binary]
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-local}"
PREVIOUS_BINARY="${2:-}"
HEAVY="${RELEASE_EVIDENCE_HEAVY:-0}"
TIMESTAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
OUT_DIR="${RELEASE_EVIDENCE_DIR:-${ROOT_DIR}/dist/release-evidence/${VERSION}-${TIMESTAMP}}"
LOG_DIR="${OUT_DIR}/logs"
DOC_DIR="${OUT_DIR}/docs"
PENDING_DIR="${OUT_DIR}/pending"
SUPPLY_CHAIN_DIR="${OUT_DIR}/supply-chain"

mkdir -p "${LOG_DIR}" "${DOC_DIR}" "${PENDING_DIR}"

run_step() {
    local name="$1"
    shift
    local log="${LOG_DIR}/${name}.log"
    {
        echo "# ${name}"
        echo "timestamp_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo "command=$*"
        echo
    } >"${log}"

    set +e
    "$@" 2>&1 | tee -a "${log}"
    local status=${PIPESTATUS[0]}
    set -e
    if [ "${status}" -ne 0 ]; then
        echo "::error::release evidence step '${name}' failed; see ${log}" >&2
        return "${status}"
    fi
}

record_pending() {
    local name="$1"
    local reason="$2"
    printf '%s\n' "${reason}" >"${PENDING_DIR}/${name}.txt"
}

cd "${ROOT_DIR}"

{
    echo "# GuardianWAF release evidence bundle"
    echo "version=${VERSION}"
    echo "timestamp_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "git_commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "git_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
    echo "go_version=$(go version 2>/dev/null || echo unavailable)"
    echo "goos=$(go env GOOS 2>/dev/null || echo unavailable)"
    echo "goarch=$(go env GOARCH 2>/dev/null || echo unavailable)"
    echo "node_version=$(node --version 2>/dev/null || echo unavailable)"
    echo "npm_version=$(npm --version 2>/dev/null || echo unavailable)"
    echo "docker_version=$(docker --version 2>/dev/null || echo unavailable)"
    echo "heavy=${HEAVY}"
} >"${OUT_DIR}/manifest.txt"

git status --short >"${OUT_DIR}/git-status.txt" || true
git diff --stat >"${OUT_DIR}/git-diff-stat.txt" || true
git diff --check >"${OUT_DIR}/git-diff-check.txt"

for doc in \
    docs/release-checklist.md \
    docs/release-performance-evidence.md \
    docs/detection-quality.md \
    docs/threat-model.md \
    docs/security-review-scope.md \
    docs/performance-budget.md; do
    if [ -f "${doc}" ]; then
        cp "${doc}" "${DOC_DIR}/$(basename "${doc}")"
    fi
done

run_step check-prereqs ./scripts/check-prereqs.sh
# Use the same package set as .github/workflows/ci.yml:95 so the runner
# does not pick up `.temp_files/*` scratch directories, vendored copies,
# or `examples/*` modules that are not part of the production codebase.
GO_TEST_PACKAGES="$(go list ./... 2>/dev/null | grep -v '/examples/' | grep -v '/scripts/attack-simulation' || true)"
# `-count=1` forces a fresh test run; without it `go test` happily replays
# cached results from a previous workflow run on the same runner image,
# which masks real failures. The main `test` job already uses `-count=1`
# (see .github/workflows/ci.yml:95).
run_step go-test go test -count=1 ${GO_TEST_PACKAGES}
run_step go-vet go vet ${GO_TEST_PACKAGES}
run_step http3-build-tag go test -tags http3 ./cmd/guardianwaf -count=1
run_step detection-quality go test ./internal/layers/detection -run TestDetectionLayer_CorpusQualityBaseline -count=1 -v
run_step validate-k8s ./scripts/validate-k8s.sh
run_step validate-helm ./scripts/validate-helm.sh

if [ "${HEAVY}" = "1" ]; then
    run_step go-race go test -race -count=1 ${GO_TEST_PACKAGES}
    run_step build-dashboard ./scripts/build-dashboard.sh
    run_step release-build ./scripts/build.sh "${VERSION}"
    if [ -x "${ROOT_DIR}/dist/guardianwaf-linux-amd64" ]; then
        run_step smoke ./scripts/smoke-test.sh ./dist/guardianwaf-linux-amd64
        if [ -n "${PREVIOUS_BINARY}" ]; then
            run_step release-rollback ./scripts/release-rollback-smoke.sh ./dist/guardianwaf-linux-amd64 "${PREVIOUS_BINARY}"
        else
            record_pending release-rollback "Previous release binary was not provided; run ./scripts/release-rollback-smoke.sh with the candidate and previous release binary before tagging."
        fi
        OUTFILE="${OUT_DIR}/proxy_load_results.txt" run_step proxy-load ./scripts/proxy-load-test.sh ./dist/guardianwaf-linux-amd64
    else
        record_pending binary-smoke "dist/guardianwaf-linux-amd64 was not produced; build logs must be inspected before release."
    fi
    OUTFILE="${OUT_DIR}/benchmark_results.txt" \
        BENCH='BenchmarkEngine_(BenignRequest|AttackRequest|LargeHeaders|LargeBody|GzipBody|DeflateBody|FullPipeline_MultiParam|Parallel)$|BenchmarkRouteLookup_ManyRoutes$|BenchmarkTenantResolve_ManyTenants$|BenchmarkEventStore_HighEventRate$' \
        PACKAGES='./tests/integration ./internal/tenant' \
        run_step focused-benchmark ./scripts/benchmark.sh 5
    if command -v docker >/dev/null 2>&1; then
        SUPPLY_CHAIN_OUT_DIR="${SUPPLY_CHAIN_DIR}" run_step supply-chain-smoke ./scripts/supply-chain-smoke.sh
    else
        record_pending supply-chain-smoke "Docker is unavailable; SBOM and vulnerability scan evidence must be collected on a Docker-capable runner."
    fi
else
    record_pending go-race "Set RELEASE_EVIDENCE_HEAVY=1 to collect full-repository race evidence."
    record_pending build-smoke "Set RELEASE_EVIDENCE_HEAVY=1 to build dashboard/release artifacts and run binary smoke tests."
    record_pending performance-load "Set RELEASE_EVIDENCE_HEAVY=1 to collect focused benchmark and local proxy load evidence."
    record_pending supply-chain-smoke "Set RELEASE_EVIDENCE_HEAVY=1 on a Docker-capable host to collect local SBOM and vulnerability scan evidence."
fi

record_pending hosted-ci "Attach GitHub-hosted CI run URL and status for the exact commit before release."
record_pending external-security-review "Attach completed external security review report or explicit risk acceptance before stable production tagging."
record_pending target-environment-load "Attach target deployment environment load/performance evidence before stable production tagging."
record_pending release-artifact-checksums "Attach GoReleaser checksums.txt from the GitHub Release page or release-binary-checksums artifact before stable production tagging."
record_pending image-digest-signature-provenance "After the tag workflow publishes the image, record image digest, cosign verification, SLSA provenance attestation, SPDX attestation, uploaded SBOM, and Trivy result."

{
    echo "# Release Evidence Index"
    echo
    echo "- Manifest: manifest.txt"
    echo "- Git status: git-status.txt"
    echo "- Git diff stat: git-diff-stat.txt"
    echo "- Logs: logs/"
    echo "- Copied docs: docs/"
    echo "- Supply-chain artifacts: supply-chain/ when RELEASE_EVIDENCE_HEAVY=1 runs on a Docker-capable host"
    echo "- Pending external/tag-time evidence: pending/"
    echo
    echo "Pending files are intentional blockers for a stable production release until replaced with real evidence."
} >"${OUT_DIR}/README.md"

echo "Release evidence bundle written to ${OUT_DIR}"
