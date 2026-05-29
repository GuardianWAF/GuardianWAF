#!/usr/bin/env bash
# Build the embedded GuardianWAF dashboard assets without requiring make.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UI_DIR="${ROOT_DIR}/internal/dashboard/ui"
EMBED_DIR="${ROOT_DIR}/internal/dashboard/dist"

if ! command -v npm >/dev/null 2>&1; then
    echo "npm is required to build the dashboard UI" >&2
    exit 1
fi

cd "${UI_DIR}"
if [ -f package-lock.json ]; then
    npm ci --no-audit --no-fund
else
    npm install --no-audit --no-fund
fi
npm run build

rm -rf "${EMBED_DIR}"
cp -R "${UI_DIR}/dist" "${EMBED_DIR}"

echo "Dashboard assets built at ${EMBED_DIR}"
