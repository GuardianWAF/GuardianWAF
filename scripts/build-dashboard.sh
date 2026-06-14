#!/usr/bin/env bash
# Build the embedded GuardianWAF dashboard assets without requiring make.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UI_DIR="${ROOT_DIR}/internal/dashboard/ui"
EMBED_DIR="${ROOT_DIR}/internal/dashboard/dist"

if [ "${GWAF_SKIP_PREREQ_CHECK:-0}" != "1" ]; then
    "${ROOT_DIR}/scripts/check-prereqs.sh"
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
cat > "${EMBED_DIR}/placeholder.txt" <<'EOF'
This placeholder keeps the embedded dashboard dist directory present in clean
checkouts. Run scripts/build-dashboard.sh or scripts/build.sh to replace this
directory with the production React dashboard assets.
EOF

echo "Dashboard assets built at ${EMBED_DIR}"
