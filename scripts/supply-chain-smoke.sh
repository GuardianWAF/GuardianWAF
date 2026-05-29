#!/usr/bin/env bash
# Build the runtime image, generate an SBOM, and run a container vulnerability scan.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_NAME="${SUPPLY_CHAIN_IMAGE:-guardianwaf:supply-chain-smoke}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:v1.38.0}"
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.68.1}"
TMPDIR="$(mktemp -d)"

cleanup() {
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required" >&2
    exit 1
fi

cd "${ROOT_DIR}"

echo "Building ${IMAGE_NAME}..."
docker build -t "${IMAGE_NAME}" .

echo "Generating SPDX SBOM..."
docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "${TMPDIR}:/out" \
    "${SYFT_IMAGE}" \
    "${IMAGE_NAME}" \
    -o spdx-json=/out/sbom.spdx.json >/dev/null

if [ ! -s "${TMPDIR}/sbom.spdx.json" ]; then
    echo "SBOM was not generated" >&2
    exit 1
fi
if ! grep -q '"spdxVersion"' "${TMPDIR}/sbom.spdx.json"; then
    echo "SBOM does not look like SPDX JSON" >&2
    exit 1
fi

echo "Scanning image for HIGH/CRITICAL vulnerabilities..."
docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    "${TRIVY_IMAGE}" image \
    --severity HIGH,CRITICAL \
    --exit-code 1 \
    --no-progress \
    "${IMAGE_NAME}"

echo "Supply-chain smoke passed"
