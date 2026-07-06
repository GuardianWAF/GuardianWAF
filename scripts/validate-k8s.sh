#!/usr/bin/env bash
# Validate checked-in Kubernetes manifests against Kubernetes schemas.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if command -v kubeconform >/dev/null 2>&1; then
    KUBECONFORM_BIN="$(command -v kubeconform)"
elif command -v go >/dev/null 2>&1 && [ -x "$(go env GOPATH)/bin/kubeconform" ]; then
    KUBECONFORM_BIN="$(go env GOPATH)/bin/kubeconform"
else
    echo "kubeconform is required. Install with: go install github.com/yannh/kubeconform/cmd/kubeconform@v0.8.0" >&2
    exit 1
fi

cd "${ROOT_DIR}"
"${KUBECONFORM_BIN}" \
    -strict \
    -ignore-missing-schemas \
    -summary \
    contrib/k8s/*.yaml \
    examples/kubernetes/*.yaml
