#!/usr/bin/env bash
# Cross-platform build script for GuardianWAF.
# Usage: ./scripts/build.sh [version]
set -euo pipefail

VERSION="${1:-dev}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo "none")"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}"
OUTDIR="dist"

mkdir -p "${OUTDIR}"

PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
)

echo "Building GuardianWAF ${VERSION} (${COMMIT})..."
echo ""

for platform in "${PLATFORMS[@]}"; do
    GOOS="${platform%/*}"
    GOARCH="${platform#*/}"

    output="${OUTDIR}/guardianwaf-${GOOS}-${GOARCH}"
    if [ "${GOOS}" = "windows" ]; then
        output="${output}.exe"
    fi

    echo "  -> ${GOOS}/${GOARCH}"
    CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
        go build -ldflags="${LDFLAGS}" -o "${output}" ./cmd/guardianwaf
done

echo ""
echo "Generating checksums..."
cd "${OUTDIR}"
sha256sum guardianwaf-* > checksums.txt 2>/dev/null || shasum -a 256 guardianwaf-* > checksums.txt
cd ..

echo ""
echo "Build complete. Binaries in ${OUTDIR}/:"
ls -lh "${OUTDIR}/"
