# Kubernetes and Helm Deployment

This guide shows the production Kubernetes pieces that must be explicit before rollout: managed secrets, persistent state, and ingress exposure for both the proxy and dashboard.

Use the checked-in manifests in `contrib/k8s/` for a static starting point, or the Helm chart in `contrib/k8s/helm/` when you need repeatable environment-specific values.

## Secret Management

Create dashboard credentials through Kubernetes Secrets or your external secret controller. Do not put dashboard keys directly in a ConfigMap, Helm `values.yaml`, or rendered Pod spec.

```bash
kubectl create secret generic guardianwaf-dashboard-auth \
  --namespace guardianwaf \
  --from-literal=api-key="$(openssl rand -base64 32)" \
  --from-literal=admin-key="$(openssl rand -base64 32)"
```

Helm values:

```yaml
apiKey:
  existingSecret: guardianwaf-dashboard-auth
  existingSecretKey: api-key

adminKey:
  existingSecret: guardianwaf-dashboard-auth
  existingSecretKey: admin-key

The checked-in static manifests and Helm defaults keep Kubernetes service account token automounting disabled for GuardianWAF pods. Keep this unless you add a feature that explicitly calls the Kubernetes API.

```yaml
automountServiceAccountToken: false
```
```

For cert-manager-managed TLS, reference the certificate Secret from ingress. For manually managed listener certificates, create a TLS Secret and set `tls.enabled: true` plus `tls.secretName`.

```bash
kubectl create secret tls guardianwaf-tls \
  --namespace guardianwaf \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key
```

## Persistent State

Use persistent storage whenever you enable file-backed events, ACME cache, replay captures, tenant data, remediation state, analytics, or compliance audit persistence. The Helm chart mounts one state volume at both `/var/lib/guardianwaf` and `/var/log/guardianwaf`.

Single-replica or per-pod state:

```yaml
replicaCount: 1

config:
  events:
    storage: file
    filePath: /var/log/guardianwaf/events.jsonl

persistence:
  enabled: true
  accessModes:
    - ReadWriteOnce
  size: 10Gi
```

Shared multi-replica file-backed state requires storage that supports `ReadWriteMany`, or a topology where each pod owns its own durable path.

```yaml
replicaCount: 2

persistence:
  enabled: true
  accessModes:
    - ReadWriteMany
  storageClass: rwx-storage
  size: 20Gi
```

If you manage PVCs separately, keep the chart from creating one:

```yaml
persistence:
  enabled: true
  existingClaim: guardianwaf-state
```

## Proxy and Dashboard Ingress

Expose the proxy path publicly and keep the dashboard on a separate host with stronger access controls. The dashboard still requires `X-API-Key` or a dashboard session; ingress auth is an additional gate, not a replacement.

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  hosts:
    - host: waf.example.com
      paths:
        - path: /
          pathType: Prefix
    - host: dashboard.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: guardianwaf-public-tls
      hosts:
        - waf.example.com
        - dashboard.example.com
```

When using a shared ingress controller, configure `trusted_proxies` or `GWAF_TRUSTED_PROXIES` for the ingress controller source CIDRs so client IP extraction is explicit.

## Network Policy

The static production manifests include `contrib/k8s/networkpolicy.yaml`, which creates a `guardianwaf-ingress` NetworkPolicy for the proxy and dashboard ports. It allows traffic from the `ingress-nginx` namespace and same-namespace pods by default; adjust the selectors to match your ingress controller, service mesh, Prometheus scraper, or admin jump namespace before applying it in a different cluster layout.

Helm keeps NetworkPolicy disabled by default to avoid breaking existing clusters that have not selected an ingress namespace. Enable it in production values after setting the controller namespace selector:

```yaml
networkPolicy:
  enabled: true
  ingress:
    from:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ingress-nginx
      - podSelector: {}
    ports:
      - protocol: TCP
        port: 8088
      - protocol: TCP
        port: 9443
```

## Validation

Render, schema-check, and validate the embedded GuardianWAF config before rollout:

```bash
./scripts/validate-k8s.sh
./scripts/validate-helm.sh
```

For a cluster smoke test with a locally built runtime image:

```bash
./scripts/kind-smoke.sh
```

Before routing production traffic, verify:

- `/livez` returns 200.
- `/readyz` returns 200 only after every configured upstream group has at least one healthy target.
- Dashboard requests without an API key are rejected.
- Dashboard requests with the Secret-backed API key succeed.
- File-backed event storage survives a pod restart when persistence is enabled.
