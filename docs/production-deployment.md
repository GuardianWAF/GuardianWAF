# GuardianWAF Production Deployment Guide

This guide covers production deployment best practices for GuardianWAF v0.4.0.

## Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Deployment Methods](#deployment-methods)
3. [Configuration](#configuration)
4. [Security Hardening](#security-hardening)
5. [Monitoring & Alerting](#monitoring--alerting)
6. [Backup & Recovery](#backup--recovery)
7. [Troubleshooting](#troubleshooting)

---

## Pre-Deployment Checklist

### Constraints to plan around

Two limits shape the topology and are easier to design for than to retrofit.

**The dashboard does not terminate TLS.** There is no built-in HTTPS listener for
the dashboard/API port. Setting `dashboard.tls: true` is rejected by config
validation and the process refuses to start — deliberately, so it can never
fall back to serving the dashboard, its API keys, and the config editor over
plaintext. Terminate TLS in front of it:

- bind the dashboard to loopback (`dashboard.listen: "127.0.0.1:9443"`) and put
  nginx/Caddy/HAProxy in front, or
- in Kubernetes, keep the dashboard Service `ClusterIP` and expose it through an
  ingress that holds the certificate.

Never publish the dashboard port directly to an untrusted network.

**Every replica must share the dashboard API key.** When `dashboard.api_key` is
empty, each process generates its own random key at startup, and the session
signing secret is derived from that key. Two replicas with different keys reject
each other's API keys and session cookies, so users are bounced back to the
login page at random. Set `GWAF_DASHBOARD_API_KEY` (and `GWAF_DASHBOARD_ADMIN_KEY`)
from one shared secret across all replicas. The Helm chart does this for you:
it generates a single Secret for the release, or you can point it at your own
with `apiKey.existingSecret`.

### System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 2 GB | 4+ GB |
| Disk | 10 GB SSD | 50 GB SSD |
| Network | 100 Mbps | 1 Gbps |
| OS | Linux kernel 5.x+ | Ubuntu 22.04 LTS |

### Prerequisites

- [ ] Domain name with DNS access
- [ ] Valid TLS certificate (Let's Encrypt or custom)
- [ ] SMTP server for alerts (optional)
- [ ] Webhook endpoints for notifications (optional)
- [ ] Reverse proxy (nginx/traefik/caddy) - **recommended**
- [ ] Source builds only: Go 1.26.5 or newer, Node.js 20.19.0 or newer, npm 10.x or newer, and `git`

For source builds, validate the local toolchain before building:

```bash
./scripts/check-prereqs.sh
./scripts/build.sh
```

### Network Requirements

```
Inbound:
  80/tcp    - HTTP (ACME challenge, redirects to HTTPS)
  443/tcp   - HTTPS (main traffic)
  9443/tcp  - Dashboard (optional, restrict to internal)

Outbound:
  53/tcp+udp    - DNS resolution
  443/tcp       - ACME, Threat Intel, GeoIP, NVD, AI providers, webhooks
  587/tcp       - SMTP for alerts (optional)
  cluster port  - Cluster sync peers, if enabled; restrict to known peer nodes
```

---

## Deployment Methods

### Method 1: Docker (Recommended)

```yaml
# docker-compose.yml
version: '3.8'

services:
  guardianwaf:
    image: ghcr.io/guardianwaf/guardianwaf:v0.4.0
    container_name: guardianwaf
    restart: unless-stopped
    ports:
      - "80:8080"
      - "443:8443"
    volumes:
      - ./config.yaml:/etc/guardianwaf/config.yaml:ro
      - ./certs:/etc/guardianwaf/certs:ro
      - ./data:/var/lib/guardianwaf
      - ./logs:/var/log/guardianwaf
    environment:
      - GWAF_LOGGING_LEVEL=info
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    healthcheck:
      test: ["CMD", "/app/guardianwaf", "healthcheck"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

**Start:**
```bash
docker-compose up -d
```

### Method 2: Binary

```bash
# Download latest release
curl -LO https://github.com/GuardianWAF/GuardianWAF/releases/latest/download/guardianwaf_linux_amd64.tar.gz
tar -xzf guardianwaf_linux_amd64.tar.gz
sudo mv guardianwaf /usr/local/bin/
sudo chmod +x /usr/local/bin/guardianwaf

# Create directories
sudo mkdir -p /etc/guardianwaf /var/lib/guardianwaf /var/log/guardianwaf

# Create systemd service
sudo tee /etc/systemd/system/guardianwaf.service << 'EOF'
[Unit]
Description=GuardianWAF - Web Application Firewall
After=network.target

[Service]
Type=simple
User=guardianwaf
Group=guardianwaf
ExecStart=/usr/local/bin/guardianwaf serve --config /etc/guardianwaf/config.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=guardianwaf

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/guardianwaf /var/log/guardianwaf

[Install]
WantedBy=multi-user.target
EOF

# Create user
sudo useradd -r -s /bin/false guardianwaf
sudo chown -R guardianwaf:guardianwaf /var/lib/guardianwaf /var/log/guardianwaf

# Start service
sudo systemctl daemon-reload
sudo systemctl enable guardianwaf
sudo systemctl start guardianwaf
```

### Method 3: Kubernetes

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: guardianwaf
  namespace: guardianwaf
spec:
  replicas: 1  # Note: HA not supported yet, keep 1
  selector:
    matchLabels:
      app: guardianwaf
  template:
    metadata:
      labels:
        app: guardianwaf
    spec:
      serviceAccountName: guardianwaf
      containers:
      - name: guardianwaf
        image: ghcr.io/guardianwaf/guardianwaf:v0.4.0
        ports:
        - name: http
          containerPort: 8080
        - name: https
          containerPort: 8443
        - name: dashboard
          containerPort: 9443
        volumeMounts:
        - name: config
          mountPath: /etc/guardianwaf
          readOnly: true
        - name: data
          mountPath: /var/lib/guardianwaf
        - name: logs
          mountPath: /var/log/guardianwaf
        - name: certs
          mountPath: /etc/guardianwaf/certs
          readOnly: true
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /livez
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 65534
          capabilities:
            drop:
            - ALL
      volumes:
      - name: config
        configMap:
          name: guardianwaf-config
      - name: data
        persistentVolumeClaim:
          claimName: guardianwaf-data
      - name: logs
        persistentVolumeClaim:
          claimName: guardianwaf-logs
      - name: certs
        secret:
          secretName: guardianwaf-certs
---
apiVersion: v1
kind: Service
metadata:
  name: guardianwaf
  namespace: guardianwaf
spec:
  selector:
    app: guardianwaf
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: https
    port: 443
    targetPort: 8443
  - name: dashboard
    port: 9443
    targetPort: 9443
```

---

## Configuration

### Minimal Production Config

<!-- guardianwaf-config:validate -->
```yaml
# /etc/guardianwaf/guardianwaf.yaml
mode: enforce
listen: ":8080"
allowed_upstream_cidrs:
  - "10.0.1.0/24"

tls:
  enabled: true
  listen: ":8443"
  acme:
    enabled: true
    email: "admin@example.com"
    domains:
      - "waf.example.com"
      - "api.example.com"

waf:
  detection:
    threshold:
      block: 50
      log: 25
  rate_limit:
    enabled: true
    rules:
      - id: global
        scope: ip
        limit: 1000
        window: 1m
        burst: 100
        action: block
  ip_acl:
    enabled: true
    whitelist:
      # Internal network and localhost
      - "10.0.0.0/8"
      - "127.0.0.1/32"
    blacklist: []

alerting:
  enabled: false
  webhooks:
    - name: "security-alerts"
      url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
      type: "slack"
      events: ["block"]
      min_score: 50

  emails:
    - name: "security-email"
      smtp_host: "smtp.gmail.com"
      smtp_port: 587
      username: "alerts@example.com"
      password: "${SMTP_PASSWORD}"  # Use env var
      from: "alerts@example.com"
      to:
        - "security@example.com"
      use_tls: true
      events: ["block"]

logging:
  level: "info"
  format: "json"
  output: "/var/log/guardianwaf/guardianwaf.log"
  log_blocked: true
  log_allowed: false

dashboard:
  enabled: true
  listen: "127.0.0.1:9443"  # Restrict to localhost
  api_key: "${GWAF_DASHBOARD_API_KEY}"
  admin_key: "${GWAF_DASHBOARD_ADMIN_KEY}"

# Upstreams (your backend services)
upstreams:
  - name: "api-backend"
    targets:
      - url: "http://10.0.1.10:8080"
      - url: "http://10.0.1.11:8080"
    health_check:
      enabled: true
      path: "/health"
      interval: 10s

routes:
  - path: "/api"
    upstream: "api-backend"
    strip_prefix: false
```

### Environment Variables

```bash
# .env file (don't commit this!)
GWAF_LOGGING_LEVEL=info
GWAF_ALLOWED_UPSTREAM_CIDRS=10.0.1.0/24
SMTP_PASSWORD=your-secret-password
ACME_ACCEPT_TOS=true
```

---

## Security Hardening

### 1. Network Security

```bash
# Firewall rules (ufw)
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow from 10.0.0.0/8 to any port 9443  # Dashboard only internal
ufw enable
```

### 2. Dashboard Access Control

<!-- guardianwaf-config:validate -->
```yaml
# Require API key for dashboard
dashboard:
  listen: "127.0.0.1:9443"
  api_key: "${GWAF_DASHBOARD_API_KEY}"      # Strong random string
  admin_key: "${GWAF_DASHBOARD_ADMIN_KEY}"  # Required only for tenant-admin endpoints
```

Access via SSH tunnel:
```bash
ssh -L 9443:localhost:9443 user@waf-server
# Then open http://localhost:9443 in browser
```

### 3. TLS Configuration

<!-- guardianwaf-config:validate -->
```yaml
tls:
  enabled: true
  listen: ":8443"
  cert_file: "/etc/guardianwaf/certs/cert.pem"
  key_file: "/etc/guardianwaf/certs/key.pem"

waf:
  response:
    security_headers:
      enabled: true
      hsts:
        enabled: true
        max_age: 31536000
        include_subdomains: true
```

### 4. File Permissions

```bash
# Restrict config file
chmod 600 /etc/guardianwaf/config.yaml
chown root:guardianwaf /etc/guardianwaf/config.yaml

# Logs
chmod 755 /var/log/guardianwaf
chown guardianwaf:guardianwaf /var/log/guardianwaf

# Data
chmod 700 /var/lib/guardianwaf
chown guardianwaf:guardianwaf /var/lib/guardianwaf
```

---

## Monitoring & Alerting

### Prometheus Metrics

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'guardianwaf'
    static_configs:
      - targets: ['guardianwaf:8080']
    metrics_path: '/metrics'
```

See [Metrics Contract](metrics.md) for stable metric names, types, and baseline PromQL queries.

### Health Checks

```bash
# Liveness probe
curl -f http://localhost:8080/livez || exit 1

# Readiness probe
curl -f http://localhost:8080/readyz || exit 1
```

### Log Aggregation (Loki/ELK)

```yaml
# Example fluent-bit config
[INPUT]
    Name tail
    Path /var/log/guardianwaf/*.log
    Parser json
    Tag guardianwaf

[OUTPUT]
    Name loki
    Match guardianwaf
    Host loki.example.com
    Port 3100
```

---

## Backup & Recovery

### Backup contract

GuardianWAF's standard production contract is **RPO ≤ 1 hour** and **RTO ≤ 5 minutes**. Stop/quiesce the process before copying append-only JSONL stores, and copy the resulting archive plus `.sha256` sidecar to encrypted off-host storage.

```bash
sudo systemctl stop guardianwaf
sudo ./scripts/backup-state.sh \
  --config /etc/guardianwaf/guardianwaf.yaml \
  --state-dir /var/lib/guardianwaf \
  --event-file /var/log/guardianwaf/events.jsonl \
  --output /backups/guardianwaf/state-$(date -u +%Y%m%dT%H%M%SZ).tar.gz \
  --metrics-file /var/lib/node_exporter/textfile_collector/guardianwaf-backup.prom \
  --rpo-seconds 3600 \
  --confirm-quiesced
sudo systemctl start guardianwaf
```

Schedule this at least hourly, retain multiple generations according to the organization's incident/compliance policy, and alert on backup age. See [State Persistence](state-persistence.md#backup-and-restore) for path coverage and sensitive-state handling.

### Recovery procedure

```bash
# Service must remain stopped through restore.
sudo systemctl stop guardianwaf
sudo ./scripts/restore-state.sh \
  --archive /backups/guardianwaf/state-YYYYmmddTHHMMSSZ.tar.gz \
  --config /etc/guardianwaf/guardianwaf.yaml \
  --state-dir /var/lib/guardianwaf \
  --event-file /var/log/guardianwaf/events.jsonl \
  --guardianwaf /usr/local/bin/guardianwaf \
  --confirm-stopped
sudo chown -R guardianwaf:guardianwaf /var/lib/guardianwaf /var/log/guardianwaf
sudo systemctl start guardianwaf
curl --fail http://127.0.0.1:8088/livez
curl --fail http://127.0.0.1:8088/readyz
```

Before accepting traffic, verify event history, tenants, ACME material, compliance audit-chain continuity, and dashboard mutation audit replay. Record elapsed recovery time and attach the drill evidence to the release/operations record. `make backup-restore-smoke` validates integrity, tamper rejection, config validation, restore equality, cleanup, and the 300-second RTO budget locally; it does not replace a target-environment restore drill.

---

## Troubleshooting

### Common Issues

#### 1. Service Won't Start

```bash
# Check logs
sudo journalctl -u guardianwaf -f

# Validate config
guardianwaf validate --config /etc/guardianwaf/config.yaml

# Check permissions
ls -la /var/lib/guardianwaf /var/log/guardianwaf
```

#### 2. High Memory Usage

```bash
# Check goroutines
curl http://localhost:9443/api/v1/stats | jq

# Enable memory profiling (if needed)
# Add to config:
# debug:
#   mem_profile: "/tmp/mem.prof"
```

#### 3. False Positives

```yaml
# Add exclusions for legitimate traffic
rules:
  exclusions:
    - path: "/api/health"
      detectors: []  # Skip all
    - path: "/api/webhook/*"
      detectors: ["sqli", "xss"]  # Skip specific
```

#### 4. Dashboard Not Accessible

```bash
# Check if listening
ss -tlnp | grep 9443

# Check firewall
sudo ufw status

# Check from local
curl http://localhost:9443/api/v1/stats
```

### Performance Tuning

```yaml
# For high traffic (>1000 RPS)
engine:
  workers: 16
  queue_size: 10000

rate_limit:
  requests_per_minute: 5000
  
geoip:
  cache_size: 100000  # Increase cache
```

---

## Migration from v0.2.x

### Breaking Changes

1. **Dashboard Port**: Changed from `:8080/dashboard` to `:9443`
2. **Alerting Config**: New format required
3. **TLS Auto**: Now uses `tls.auto: true` instead of `acme.enabled`

### Migration Script

```bash
# Backup old config
cp config.yaml config.yaml.v0.2.backup

# Update config
guardianwaf migrate-config --from 0.2 --to 0.3 --config config.yaml
```

---

## Support

- **Documentation**: https://guardianwaf.io/docs
- **GitHub Issues**: https://github.com/GuardianWAF/GuardianWAF/issues
- **Security**: security@guardianwaf.io

---

*Last updated: 2026-04-15 for GuardianWAF v0.4.0*
