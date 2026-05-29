#!/usr/bin/env bash
# Build GuardianWAF, deploy it into a KinD cluster, and verify proxy/dashboard health.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${KIND_CLUSTER_NAME:-guardianwaf-smoke-$$}"
NAMESPACE="${KIND_SMOKE_NAMESPACE:-guardianwaf-smoke}"
IMAGE_NAME="${KIND_SMOKE_IMAGE:-guardianwaf:kind-smoke}"
HTTP_PORT="${KIND_SMOKE_HTTP_PORT:-18088}"
DASHBOARD_PORT="${KIND_SMOKE_DASHBOARD_PORT:-19443}"
API_KEY="${KIND_SMOKE_API_KEY:-kind-smoke-secret-1234567890}"
TMPDIR="$(mktemp -d)"
PF_HTTP_PID=""
PF_DASH_PID=""

cleanup() {
    if [[ -n "${PF_HTTP_PID}" ]]; then
        kill "${PF_HTTP_PID}" 2>/dev/null || true
        wait "${PF_HTTP_PID}" 2>/dev/null || true
    fi
    if [[ -n "${PF_DASH_PID}" ]]; then
        kill "${PF_DASH_PID}" 2>/dev/null || true
        wait "${PF_DASH_PID}" 2>/dev/null || true
    fi
    if [[ "${KIND_SMOKE_KEEP_CLUSTER:-}" != "1" ]]; then
        kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
    fi
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

require() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "$1 is required" >&2
        exit 1
    fi
}

wait_url() {
    local url="$1"
    for _ in {1..80}; do
        if curl -fsS "${url}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    echo "timed out waiting for ${url}" >&2
    return 1
}

require docker
require kind
require kubectl
require curl

cd "${ROOT_DIR}"

echo "Building ${IMAGE_NAME}..."
docker build -t "${IMAGE_NAME}" .

echo "Creating KinD cluster ${CLUSTER_NAME}..."
kind create cluster --name "${CLUSTER_NAME}" --wait 120s
kind load docker-image "${IMAGE_NAME}" --name "${CLUSTER_NAME}"

kubectl create namespace "${NAMESPACE}"
kubectl -n "${NAMESPACE}" create secret generic guardianwaf-dashboard-auth \
    "--from-literal=api-key=${API_KEY}"

cat > "${TMPDIR}/manifest.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  labels:
    app: backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
        - name: backend
          image: nginx:1.27-alpine
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: backend
spec:
  selector:
    app: backend
  ports:
    - name: http
      port: 3000
      targetPort: 80
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: guardianwaf-config
data:
  guardianwaf.yaml: |
    mode: enforce
    listen: ":8088"
    allow_private_upstreams: true
    tls:
      enabled: false
    dashboard:
      enabled: true
      listen: ":9443"
      api_key: "${GWAF_DASHBOARD_API_KEY}"
      tls: false
    mcp:
      enabled: false
    upstreams:
      - name: backend
        targets:
          - url: "http://backend:3000"
        health_check:
          enabled: true
          interval: 2s
          timeout: 1s
          path: /
    routes:
      - path: /
        upstream: backend
    waf:
      detection:
        enabled: true
        threshold:
          block: 50
          log: 25
        detectors:
          sqli:
            enabled: true
            multiplier: 1.0
          xss:
            enabled: true
            multiplier: 1.0
          lfi:
            enabled: true
            multiplier: 1.0
          cmdi:
            enabled: true
            multiplier: 1.0
          xxe:
            enabled: true
            multiplier: 1.0
          ssrf:
            enabled: true
            multiplier: 1.0
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: guardianwaf
  labels:
    app: guardianwaf
spec:
  replicas: 1
  selector:
    matchLabels:
      app: guardianwaf
  template:
    metadata:
      labels:
        app: guardianwaf
    spec:
      containers:
        - name: guardianwaf
          image: guardianwaf:kind-smoke
          imagePullPolicy: Never
          args: ["serve", "-c", "/etc/guardianwaf/guardianwaf.yaml"]
          ports:
            - name: http
              containerPort: 8088
            - name: dashboard
              containerPort: 9443
          env:
            - name: GWAF_DASHBOARD_API_KEY
              valueFrom:
                secretKeyRef:
                  name: guardianwaf-dashboard-auth
                  key: api-key
          livenessProbe:
            httpGet:
              path: /livez
              port: http
            initialDelaySeconds: 3
            periodSeconds: 5
          readinessProbe:
            httpGet:
              path: /readyz
              port: http
            initialDelaySeconds: 3
            periodSeconds: 5
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          volumeMounts:
            - name: config
              mountPath: /etc/guardianwaf
              readOnly: true
            - name: state
              mountPath: /var/lib/guardianwaf
            - name: cache
              mountPath: /var/cache/guardianwaf
      volumes:
        - name: config
          configMap:
            name: guardianwaf-config
        - name: state
          emptyDir: {}
        - name: cache
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: guardianwaf
spec:
  selector:
    app: guardianwaf
  ports:
    - name: http
      port: 80
      targetPort: 8088
    - name: dashboard
      port: 9443
      targetPort: 9443
YAML

sed -i "s|image: guardianwaf:kind-smoke|image: ${IMAGE_NAME}|g" "${TMPDIR}/manifest.yaml"

kubectl -n "${NAMESPACE}" apply -f "${TMPDIR}/manifest.yaml"
kubectl -n "${NAMESPACE}" rollout status deployment/backend --timeout=180s
kubectl -n "${NAMESPACE}" rollout status deployment/guardianwaf --timeout=180s

kubectl -n "${NAMESPACE}" port-forward svc/guardianwaf "${HTTP_PORT}:80" >"${TMPDIR}/http-port-forward.log" 2>&1 &
PF_HTTP_PID=$!
kubectl -n "${NAMESPACE}" port-forward svc/guardianwaf "${DASHBOARD_PORT}:9443" >"${TMPDIR}/dashboard-port-forward.log" 2>&1 &
PF_DASH_PID=$!

wait_url "http://127.0.0.1:${HTTP_PORT}/livez"
wait_url "http://127.0.0.1:${HTTP_PORT}/readyz"
wait_url "http://127.0.0.1:${HTTP_PORT}/"

attack_code="$(curl -sS -o /dev/null -w '%{http_code}' -H 'User-Agent: Mozilla/5.0' "http://127.0.0.1:${HTTP_PORT}/search?q=%27%20OR%201%3D1--")"
if [[ "${attack_code}" != "403" ]]; then
    echo "expected SQLi request to be blocked with 403, got ${attack_code}" >&2
    exit 1
fi

unauth_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${DASHBOARD_PORT}/api/v1/stats")"
if [[ "${unauth_code}" != "401" ]]; then
    echo "expected dashboard stats without API key to return 401, got ${unauth_code}" >&2
    exit 1
fi

auth_code="$(curl -sS -o /dev/null -w '%{http_code}' -H "X-API-Key: ${API_KEY}" "http://127.0.0.1:${DASHBOARD_PORT}/api/v1/stats")"
if [[ "${auth_code}" != "200" ]]; then
    echo "expected dashboard stats with API key to return 200, got ${auth_code}" >&2
    exit 1
fi

echo "KinD smoke test passed"
