#!/usr/bin/env bash
# Copy external release evidence into an existing release evidence bundle.
# Usage:
#   CI_RUN_URL=... CI_COMMIT=... CI_RESULT=passed \
#   TARGET_LOAD_FILE=target_load_results.txt \
#   RELEASE_CHECKSUM_FILE=checksums.txt \
#   RELEASE_SUPPLY_CHAIN_DIR=release-supply-chain-evidence/supply-chain \
#   SECURITY_REVIEW_REPORT=security-review-report.md \
#   ./scripts/assemble-release-evidence.sh dist/release-evidence/v1.x.x-...
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE="${1:-}"
if [ -z "${BUNDLE}" ]; then
    echo "usage: $0 <release-evidence-dir>" >&2
    exit 2
fi
if [ ! -d "${BUNDLE}" ]; then
    echo "release evidence directory not found: ${BUNDLE}" >&2
    exit 1
fi

STAGING_DIRS=()
cleanup_staging_dirs() {
    local dir
    for dir in "${STAGING_DIRS[@]}"; do
        rm -rf "${dir}"
    done
}
trap cleanup_staging_dirs EXIT

copy_file() {
    local source="$1"
    local dest="$2"
    if [ ! -s "${source}" ]; then
        echo "missing or empty evidence source: ${source}" >&2
        exit 1
    fi
    mkdir -p "$(dirname "${dest}")"
    cp "${source}" "${dest}"
}

stage_bundle() {
    local stage
    stage="$(mktemp -d "${TMPDIR:-/tmp}/guardianwaf-release-evidence.XXXXXX")"
    STAGING_DIRS+=("${stage}")
    cp -a "${BUNDLE}/." "${stage}/"
    printf '%s\n' "${stage}"
}

commit_staged_file() {
    local stage="$1"
    local rel="$2"
    copy_file "${stage}/${rel}" "${BUNDLE}/${rel}"
}

clear_pending() {
    local name="$1"
    rm -f "${BUNDLE}/pending/${name}.txt"
}

if [ -n "${CI_RUN_FILE:-}" ]; then
    stage="$(stage_bundle)"
    copy_file "${CI_RUN_FILE}" "${stage}/hosted-ci/ci-run.txt"
    "${ROOT_DIR}/scripts/verify-release-evidence.sh" --check-hosted-ci "${stage}"
    commit_staged_file "${stage}" hosted-ci/ci-run.txt
    clear_pending hosted-ci
elif [ -n "${CI_RUN_URL:-}" ] || [ -n "${CI_COMMIT:-}" ] || [ -n "${CI_RESULT:-}" ]; then
    if [ -z "${CI_RUN_URL:-}" ] || [ -z "${CI_COMMIT:-}" ] || [ -z "${CI_RESULT:-}" ]; then
        echo "CI_RUN_URL, CI_COMMIT, and CI_RESULT must be set together" >&2
        exit 2
    fi
    stage="$(stage_bundle)"
    mkdir -p "${stage}/hosted-ci"
    {
        echo "url: ${CI_RUN_URL}"
        echo "commit: ${CI_COMMIT}"
        echo "result: ${CI_RESULT}"
    } >"${stage}/hosted-ci/ci-run.txt"
    "${ROOT_DIR}/scripts/verify-release-evidence.sh" --check-hosted-ci "${stage}"
    commit_staged_file "${stage}" hosted-ci/ci-run.txt
    clear_pending hosted-ci
fi

if [ -n "${TARGET_LOAD_FILE:-}" ]; then
    stage="$(stage_bundle)"
    copy_file "${TARGET_LOAD_FILE}" "${stage}/target-load/target_load_results.txt"
    "${ROOT_DIR}/scripts/verify-release-evidence.sh" --check-target-load "${stage}"
    commit_staged_file "${stage}" target-load/target_load_results.txt
    clear_pending target-environment-load
fi

if [ -n "${RELEASE_CHECKSUM_FILE:-}" ]; then
    stage="$(stage_bundle)"
    copy_file "${RELEASE_CHECKSUM_FILE}" "${stage}/release-artifacts/checksums.txt"
    "${ROOT_DIR}/scripts/verify-release-evidence.sh" --check-release-checksums "${stage}"
    commit_staged_file "${stage}" release-artifacts/checksums.txt
    clear_pending release-artifact-checksums
fi

if [ -n "${RELEASE_SUPPLY_CHAIN_DIR:-}" ]; then
    if [ -d "${RELEASE_SUPPLY_CHAIN_DIR}/supply-chain" ]; then
        RELEASE_SUPPLY_CHAIN_DIR="${RELEASE_SUPPLY_CHAIN_DIR}/supply-chain"
    fi
    stage="$(stage_bundle)"
    for file in image-digest.txt imagetools.txt cosign-verify.txt provenance-verify.txt sbom-attestation-verify.txt sbom.spdx.json trivy.txt; do
        copy_file "${RELEASE_SUPPLY_CHAIN_DIR}/${file}" "${stage}/supply-chain/${file}"
    done
    "${ROOT_DIR}/scripts/verify-release-evidence.sh" --check-supply-chain "${stage}"
    for file in image-digest.txt imagetools.txt cosign-verify.txt provenance-verify.txt sbom-attestation-verify.txt sbom.spdx.json trivy.txt; do
        commit_staged_file "${stage}" "supply-chain/${file}"
    done
    clear_pending image-digest-signature-provenance
    clear_pending supply-chain-smoke
fi

if [ -n "${SECURITY_REVIEW_REPORT:-}" ] && [ -n "${SECURITY_RISK_ACCEPTANCE:-}" ]; then
    echo "set only one of SECURITY_REVIEW_REPORT or SECURITY_RISK_ACCEPTANCE" >&2
    exit 2
fi
if [ -n "${SECURITY_REVIEW_REPORT:-}" ]; then
    stage="$(stage_bundle)"
    copy_file "${SECURITY_REVIEW_REPORT}" "${stage}/external-security-review/report.md"
    "${ROOT_DIR}/scripts/verify-release-evidence.sh" --check-external-review "${stage}"
    commit_staged_file "${stage}" external-security-review/report.md
    clear_pending external-security-review
fi
if [ -n "${SECURITY_RISK_ACCEPTANCE:-}" ]; then
    stage="$(stage_bundle)"
    copy_file "${SECURITY_RISK_ACCEPTANCE}" "${stage}/external-security-review/risk-acceptance.md"
    "${ROOT_DIR}/scripts/verify-release-evidence.sh" --check-external-review "${stage}"
    commit_staged_file "${stage}" external-security-review/risk-acceptance.md
    clear_pending external-security-review
fi

echo "Release evidence bundle updated: ${BUNDLE}"
