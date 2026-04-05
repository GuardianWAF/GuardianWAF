# GuardianWAF Kubernetes Deployment

This directory contains Kubernetes manifests for deploying GuardianWAF in production.

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
- Health checks: /healthz endpoint
- Volumes: ConfigMap (config), Secret (certs), EmptyDir (cache)

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

## Configuration

### Required Secrets

```bash
# Dashboard API key
kubectl create secret generic guardianwaf-dashboard-auth \
  --from-literal=username=admin \
  --from-literal=password=$(openssl rand -base64 32)

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

- **Liveness**: `/healthz` - Restart if failing
- **Readiness**: `/healthz` - Remove from service if failing

## Production Checklist

- [ ] Configure TLS certificates
- [ ] Set dashboard API key
- [ ] Tune detection thresholds
- [ ] Configure rate limits
- [ ] Set resource limits
- [ ] Enable PodDisruptionBudget
- [ ] Configure network policies
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
