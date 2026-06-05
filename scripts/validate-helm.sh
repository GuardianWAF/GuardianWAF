#!/usr/bin/env bash
# Render and validate the GuardianWAF Helm chart.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART_DIR="contrib/k8s/helm"
mkdir -p "${ROOT_DIR}/tmp"
TMPDIR="$(mktemp -d "${ROOT_DIR}/tmp/helm-validate.XXXXXX")"

cleanup() {
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

if command -v kubeconform >/dev/null 2>&1; then
    KUBECONFORM_BIN="$(command -v kubeconform)"
elif command -v go >/dev/null 2>&1 && [ -x "$(go env GOPATH)/bin/kubeconform" ]; then
    KUBECONFORM_BIN="$(go env GOPATH)/bin/kubeconform"
else
    echo "kubeconform is required. Install with: go install github.com/yannh/kubeconform/cmd/kubeconform@latest" >&2
    exit 1
fi

helm_cmd() {
    if command -v helm >/dev/null 2>&1; then
        helm "$@"
        return
    fi
    if command -v docker >/dev/null 2>&1; then
        docker run --rm \
            -v "${ROOT_DIR}:/work" \
            -w /work \
            alpine/helm:3.18.6 "$@"
        return
    fi
    echo "helm or docker is required to render Helm charts" >&2
    exit 1
}

extract_config() {
    local rendered="$1"
    local output="$2"
    # The config block is indented 4 spaces under "  guardianwaf.yaml: |".
    # Stop at the first non-blank line indented fewer than 4 spaces — this covers
    # a sibling ConfigMap key ("  other: ...") AND the "---" document separator
    # when guardianwaf.yaml is the last key (otherwise the separator leaks into
    # the extracted config and `guardianwaf validate` rejects the stray "---").
    awk '
        /^  guardianwaf\.ya?ml: \|$/ { in_config = 1; next }
        in_config && /^ {0,3}[^ ]/ { exit }
        in_config {
            sub(/^    /, "")
            print
        }
    ' "${rendered}" > "${output}"
    if [ ! -s "${output}" ]; then
        echo "failed to extract embedded GuardianWAF config from Helm render" >&2
        exit 1
    fi
}

validate_guardianwaf_config() {
    local config_file="$1"
    if [ -n "${GUARDIANWAF_BIN:-}" ]; then
        "${GUARDIANWAF_BIN}" validate -c "${config_file}"
        return
    fi
    if [ -x "${ROOT_DIR}/dist/guardianwaf-linux-amd64" ]; then
        "${ROOT_DIR}/dist/guardianwaf-linux-amd64" validate -c "${config_file}"
        return
    fi
    if command -v go >/dev/null 2>&1 && [ -d "${ROOT_DIR}/internal/dashboard/dist" ]; then
        (cd "${ROOT_DIR}" && go run ./cmd/guardianwaf validate -c "${config_file}")
        return
    fi
    echo "guardianwaf binary, Go with dashboard assets, or GUARDIANWAF_BIN is required to validate rendered config" >&2
    exit 1
}

cat > "${TMPDIR}/production-values.yaml" <<'YAML'
apiKey:
  existingSecret: guardianwaf-dashboard-auth
config:
  events:
    storage: file
    maxEvents: 100000
    filePath: /var/log/guardianwaf/events.jsonl
persistence:
  enabled: true
  accessModes:
    - ReadWriteMany
  size: 10Gi
upstreams:
  - name: backend
    strategy: weighted
    targets:
      - url: http://backend.default.svc.cluster.local:3000
        weight: 1
    healthCheck:
      enabled: true
      path: /healthz
      interval: 10s
routes:
  - path: /
    upstream: backend
    stripPrefix: false
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: waf.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: waf-example-tls
      hosts:
        - waf.example.com
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 5
  targetCPUUtilizationPercentage: 70
podDisruptionBudget:
  enabled: true
  minAvailable: 1
istio:
  enabled: true
  virtualService:
    enabled: true
    gateways:
      - mesh
    hosts:
      - waf.example.com
  destinationRule:
    enabled: true
YAML

cd "${ROOT_DIR}"

helm_cmd lint contrib/k8s/helm

helm_cmd template guardianwaf "${CHART_DIR}" > "${TMPDIR}/default.yaml"
helm_cmd template guardianwaf "${CHART_DIR}" -f "${TMPDIR#${ROOT_DIR}/}/production-values.yaml" > "${TMPDIR}/production.yaml"

"${KUBECONFORM_BIN}" -strict -ignore-missing-schemas -summary "${TMPDIR}/default.yaml" "${TMPDIR}/production.yaml"

extract_config "${TMPDIR}/default.yaml" "${TMPDIR}/default-guardianwaf.yaml"
extract_config "${TMPDIR}/production.yaml" "${TMPDIR}/production-guardianwaf.yaml"
validate_guardianwaf_config "${TMPDIR}/default-guardianwaf.yaml" >/dev/null
validate_guardianwaf_config "${TMPDIR}/production-guardianwaf.yaml" >/dev/null

echo "Helm chart validation passed"
