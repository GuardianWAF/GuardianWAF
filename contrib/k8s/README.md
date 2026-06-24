# GuardianWAF Kubernetes Deployment

This directory contains Kubernetes manifests for deploying GuardianWAF in production.

For Helm values covering Secret-backed dashboard keys, persistent state, and proxy/dashboard ingress, see [Kubernetes and Helm Deployment](../../docs/kubernetes-helm.md).

## Quick Start

```bash
# Apply all manifests
kubectl apply -f contrib/k8s/

# Verify deployment
kubectl get pods -l app=guardianwaf

# Check logs
kubectl logs -l app=guardianwaf
```

## Components

### deployment.yaml
- Replicas: 2 (configurable)
- Resources: 64Mi/256Mi memory, 100m/500m CPU
- Security context: non-root, read-only filesystem
- Health checks: `/livez` for process liveness and `/readyz` for upstream readiness
- Volumes: ConfigMap (config), Secret (certs), EmptyDir (cache), EmptyDir state/log paths for read-only-root compatibility

### configmap.yaml
- WAF mode: enforce
- Detection thresholds: block=50, log=25
- All 6 detectors enabled
- Rate limiting enabled
- Security headers enabled

### service.yaml
- ClusterIP for internal traffic
- Separate service for dashboard

### ingress.yaml
- Ingress for API traffic
- Separate ingress for dashboard with basic auth

### networkpolicy.yaml
- Optional ingress isolation for GuardianWAF pods
- Allows proxy and dashboard traffic from the `ingress-nginx` namespace and same-namespace pods by default
- Adjust selectors for your ingress controller, service mesh, monitoring, or admin namespace before applying to production clusters

## Configuration

### Required Secrets

```bash
# Dashboard API key used by GuardianWAF itself
kubectl create secret generic guardianwaf-dashboard-auth \
  --from-literal=api-key=$(openssl rand -base64 32)

# Optional NGINX Ingress basic-auth guard for the dashboard ingress
kubectl create secret generic guardianwaf-dashboard-basic-auth \
  --from-literal=auth="$(htpasswd -nb admin "$(openssl rand -base64 24)")"

# TLS certificates (optional)
kubectl create secret tls guardianwaf-certs \
  --cert=path/to/cert.crt \
  --key=path/to/cert.key
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| GWAF_MODE | WAF mode (enforce/monitor/disabled) | enforce |
| GWAF_LISTEN | HTTP listen address | :8088 |
| GWAF_DASHBOARD_LISTEN | Dashboard listen address | :9443 |

### Custom Configuration

Edit `configmap.yaml` or create your own:

```bash
# Create custom config
kubectl create configmap guardianwaf-config \
  --from-file=guardianwaf.yaml=your-config.yaml
```

### Persistent State

The checked-in static manifests use `emptyDir` for `/var/lib/guardianwaf` and `/var/log/guardianwaf` so the pod can run with `readOnlyRootFilesystem: true`. This is suitable for examples and stateless deployments.

For durable event history, ACME cache, tenant stores, replay captures, analytics, or remediation state, replace the `state` `emptyDir` with a `persistentVolumeClaim`. If `events.storage: file` is enabled, keep `events.file_path` under `/var/log/guardianwaf` and mount that path on persistent storage.

For the Helm chart, enable:

```yaml
config:
  events:
    storage: file
    filePath: /var/log/guardianwaf/events.jsonl
persistence:
  enabled: true
  size: 10Gi
```

Use `ReadWriteMany` storage or one replica when multiple pods need the same file-backed state. With the default `ReadWriteOnce` access mode, keep `replicaCount: 1` or provide separate per-pod storage.

## Scaling

```bash
# Scale to 5 replicas
kubectl scale deployment guardianwaf --replicas=5

# Horizontal Pod Autoscaler
kubectl apply -f - <<EOF
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: guardianwaf
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: guardianwaf
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
EOF
```

## Monitoring

### Prometheus Metrics

GuardianWAF exposes Prometheus metrics at `/metrics`. Configure Prometheus to scrape:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: guardianwaf
spec:
  selector:
    matchLabels:
      app: guardianwaf
  endpoints:
    - port: http
      path: /metrics
      interval: 15s
```

### Health Checks

- **Liveness**: `/livez` - Restart if the process stops serving
- **Readiness**: `/readyz` - Remove from service if configured upstreams have no healthy targets

## Production Checklist

- [ ] Configure TLS certificates
- [ ] Set dashboard API key
- [ ] Tune detection thresholds
- [ ] Configure rate limits
- [ ] Set resource limits
- [ ] Enable PodDisruptionBudget
- [ ] Configure and apply NetworkPolicy selectors for ingress, monitoring, and admin access
- [ ] Set up monitoring
- [ ] Configure backups (if using file event storage)

## Troubleshooting

### Check pod status
```bash
kubectl get pods -l app=guardianwaf -o wide
kubectl describe pod <pod-name>
```

### View logs
```bash
kubectl logs -l app=guardianwaf --tail=100 -f
```

### Debug configuration
```bash
kubectl exec -it <pod-name> -- cat /etc/guardianwaf/guardianwaf.yaml
```

## Sidecar Mode

For sidecar deployment alongside your application:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
        - name: my-app
          image: my-app:latest
        - name: guardianwaf
          image: guardianwaf/guardianwaf:latest
          args: ["sidecar", "-u", "http://localhost:8080"]
          ports:
            - containerPort: 8088
```
