# GuardianWAF Security Best Practices

This guide covers security hardening for GuardianWAF deployments.

## Table of Contents

1. [Deployment Security](#deployment-security)
2. [Network Security](#network-security)
3. [Authentication & Authorization](#authentication--authorization)
4. [TLS Configuration](#tls-configuration)
5. [Secrets Management](#secrets-management)
6. [Monitoring & Alerting](#monitoring--alerting)
7. [Incident Response](#incident-response)

---

## Deployment Security

### Container Security

```yaml
# docker-compose.yml - Security Hardened Version
version: '3.8'

services:
  guardianwaf:
    image: ghcr.io/guardianwaf/guardianwaf:v0.4.0
    container_name: guardianwaf
    restart: unless-stopped
    
    # Security options
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # Only needed for ports < 1024
    
    # User (non-root)
    user: "65534:65534"  # nobody:nobody
    
    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
    
    # Tmpfs for writable directories
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
      - /var/run:noexec,nosuid,size=10m
    
    volumes:
      # Read-only configs
      - ./config.yaml:/etc/guardianwaf/config.yaml:ro
      - ./certs:/etc/guardianwaf/certs:ro
      
      # Persistent data
      - type: bind
        source: ./data
        target: /var/lib/guardianwaf
        read_only: false
      
      # Logs (optional - can use stdout)
      - type: bind
        source: ./logs
        target: /var/log/guardianwaf
        read_only: false
    
    environment:
      - GWAF_LOG_LEVEL=info
      - GWAF_CONFIG_PATH=/etc/guardianwaf/config.yaml
    
    ports:
      - "80:8080"
      - "443:8443"
    
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:8080/healthz || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    
    networks:
      - waf-network
    
    # Don't expose to external directly
    # Use reverse proxy for dashboard

networks:
  waf-network:
    driver: bridge
    internal: false
```

### Kubernetes Security

```yaml
# security-context.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: guardianwaf
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        runAsGroup: 65534
        fsGroup: 65534
        seccompProfile:
          type: RuntimeDefault
      
      containers:
      - name: guardianwaf
        image: ghcr.io/guardianwaf/guardianwaf:v0.4.0
        
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
          seccompProfile:
            type: RuntimeDefault
        
        resources:
          limits:
            cpu: "2000m"
            memory: "2Gi"
          requests:
            cpu: "500m"
            memory: "512Mi"
```

### Pod Security Policy

```yaml
# psp.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: guardianwaf-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'secret'
    - 'emptyDir'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: true
```

---

## Network Security

### Firewall Rules

#### iptables

```bash
#!/bin/bash
# firewall-setup.sh

# Flush existing rules
iptables -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (from specific IPs only)
iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT

# Allow HTTP/HTTPS to GuardianWAF
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow dashboard from internal network only
iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 9443 -j ACCEPT
iptables -A INPUT -p tcp --dport 9443 -j DROP

# Rate limit new connections (anti-DDoS)
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# Log and drop everything else
iptables -A INPUT -j LOG --log-prefix "IPTABLES DROP: "
iptables -A INPUT -j DROP
```

#### ufw (Ubuntu)

```bash
# ufw-setup.sh
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH from specific IP
ufw allow from 10.0.0.0/8 to any port 22

# Allow HTTP/HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Allow dashboard from internal only
ufw allow from 10.0.0.0/8 to any port 9443

# Enable
ufw --force enable

# Check status
ufw status verbose
```

### Reverse Proxy (nginx)

```nginx
# /etc/nginx/sites-available/guardianwaf
upstream guardianwaf {
    server 127.0.0.1:8080;
    keepalive 32;
}

upstream guardianwaf-secure {
    server 127.0.0.1:8443;
    keepalive 32;
}

# Rate limiting zones
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;

# Block bad user agents
map $http_user_agent $bad_agent {
    default 0;
    ~*(sqlmap|nikto|nmap|masscan) 1;
    ~*(bot|crawler|spider) 0;
}

server {
    listen 80;
    server_name _;
    
    # Redirect to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;
    
    # SSL configuration
    ssl_certificate /etc/ssl/certs/api.example.com.crt;
    ssl_certificate_key /etc/ssl/private/api.example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Block bad agents
    if ($bad_agent) {
        return 403;
    }
    
    # Rate limiting
    limit_req zone=general burst=20 nodelay;
    
    # Proxy to GuardianWAF
    location / {
        proxy_pass http://guardianwaf;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
}

# Dashboard server (internal only)
server {
    listen 9443 ssl http2;
    server_name dashboard.internal;
    
    # Internal network only
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    allow 192.168.0.0/16;
    deny all;
    
    ssl_certificate /etc/ssl/certs/dashboard.crt;
    ssl_certificate_key /etc/ssl/private/dashboard.key;
    
    location / {
        proxy_pass http://127.0.0.1:9443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Authentication & Authorization

### Dashboard API Key

```yaml
# config.yaml
server:
  dashboard_listen: "127.0.0.1:9443"
  dashboard_api_key: "${DASHBOARD_API_KEY}"  # From env var

# Generate strong key
# openssl rand -base64 32
```

### Basic Auth (nginx)

```nginx
# Protect dashboard with basic auth
location / {
    auth_basic "GuardianWAF Dashboard";
    auth_basic_user_file /etc/nginx/.htpasswd;
    
    proxy_pass http://127.0.0.1:9443;
}

# Create htpasswd file
# htpasswd -c /etc/nginx/.htpasswd admin
```

### OAuth2 Proxy (Advanced)

```yaml
# oauth2-proxy.yaml
- name: oauth2-proxy
  image: quay.io/oauth2-proxy/oauth2-proxy:latest
  args:
    - --provider=github
    - --github-org=your-org
    - --email-domain=*
    - --upstream=http://guardianwaf:9443
    - --http-address=0.0.0.0:4180
    - --cookie-secure=true
    - --cookie-secret=${COOKIE_SECRET}
    - --client-id=${GITHUB_CLIENT_ID}
    - --client-secret=${GITHUB_CLIENT_SECRET}
```

---

## TLS Configuration

### Strong TLS Settings

```yaml
# config.yaml
tls:
  enabled: true
  listen: ":8443"
  
  # Minimum TLS version
  min_version: "1.2"
  
  # Modern cipher suites
  cipher_suites:
    - "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    - "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    - "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
    - "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
    - "TLS_AES_128_GCM_SHA256"
    - "TLS_AES_256_GCM_SHA384"
    - "TLS_CHACHA20_POLY1305_SHA256"
  
  # HSTS
  hsts: true
  hsts_max_age: 31536000
  hsts_include_subdomains: true
  
  # OCSP Stapling
  ocsp_stapling: true
  
  # Certificate files
  cert_file: "/etc/guardianwaf/certs/cert.pem"
  key_file: "/etc/guardianwaf/certs/key.pem"
  
  # ACME (Let's Encrypt)
  auto: true
  email: "security@example.com"
  domains:
    - "api.example.com"
    - "www.example.com"
```

### Certificate Permissions

```bash
# Proper certificate file permissions
chmod 600 /etc/guardianwaf/certs/*.pem
chmod 700 /etc/guardianwaf/certs
chown -R guardianwaf:guardianwaf /etc/guardianwaf/certs

# For ACME certs
chmod 750 /var/lib/guardianwaf/acme
chown -R guardianwaf:guardianwaf /var/lib/guardianwaf/acme
```

---

## Secrets Management

### Environment Variables

```bash
# .env file (DO NOT COMMIT!)
DASHBOARD_API_KEY=$(openssl rand -base64 32)
SMTP_PASSWORD=your-smtp-password
ACME_EMAIL=admin@example.com
WEBHOOK_SECRET=another-secret

# Load in systemd service
# /etc/systemd/system/guardianwaf.service
[Service]
EnvironmentFile=/etc/guardianwaf/secrets.env
```

### Docker Secrets

```yaml
# docker-compose.yml
version: '3.8'

services:
  guardianwaf:
    image: ghcr.io/guardianwaf/guardianwaf:v0.4.0
    secrets:
      - api_key
      - smtp_password
    environment:
      - DASHBOARD_API_KEY_FILE=/run/secrets/api_key
      - SMTP_PASSWORD_FILE=/run/secrets/smtp_password

secrets:
  api_key:
    file: ./secrets/api_key.txt
  smtp_password:
    file: ./secrets/smtp_password.txt
```

### Kubernetes Secrets

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: guardianwaf-secrets
type: Opaque
stringData:
  api-key: "your-secret-key"
  smtp-password: "your-smtp-password"

---
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: guardianwaf
        env:
        - name: DASHBOARD_API_KEY
          valueFrom:
            secretKeyRef:
              name: guardianwaf-secrets
              key: api-key
```

### HashiCorp Vault (Enterprise)

```go
// vault.go
package main

import (
    "github.com/hashicorp/vault/api"
)

func loadSecretsFromVault() (map[string]string, error) {
    config := api.DefaultConfig()
    config.Address = "https://vault.example.com:8200"
    
    client, err := api.NewClient(config)
    if err != nil {
        return nil, err
    }
    
    client.SetToken("your-vault-token")
    
    secret, err := client.Logical().Read("secret/guardianwaf")
    if err != nil {
        return nil, err
    }
    
    return secret.Data, nil
}
```

---

## Monitoring & Alerting

### Security Event Monitoring

```yaml
# config.yaml
alerting:
  webhooks:
    - name: "security-alerts"
      url: "https://hooks.slack.com/services/..."
      events: ["block"]
      min_score: 50
      
    - name: "pagerduty-critical"
      url: "https://events.pagerduty.com/v2/enqueue"
      events: ["block"]
      min_score: 80
      
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    username: "alerts@example.com"
    password: "${SMTP_PASSWORD}"
    from: "alerts@example.com"
    to:
      - "security@example.com"
      - "oncall@example.com"
    use_tls: true
    events: ["block"]
    min_score: 70
```

### Audit Logging

```yaml
logging:
  level: "info"
  format: "json"
  file: "/var/log/guardianwaf/audit.log"
  
  # Include sensitive fields (careful!)
  mask_headers:
    - "Authorization"
    - "Cookie"
    - "X-API-Key"
```

### Failed Login Detection

```yaml
layers:
  ato:
    enabled: true
    brute_force:
      enabled: true
      threshold: 5
      window: "5m"
      ban_duration: "1h"
```

---

## Incident Response

### Common Attack Patterns

#### DDoS Attack

```bash
# Check rate limit status
curl http://localhost:9443/api/v1/stats | jq '.rate_limit'

# View top IPs
curl http://localhost:9443/api/v1/stats | jq '.top_ips'

# Block IP immediately
curl -X POST http://localhost:9443/api/v1/acl/blacklist \
  -H "X-API-Key: secret" \
  -d '{"ip": "192.0.2.1", "comment": "DDoS attack"}'

# Check if IP is blocked
curl "http://localhost:9443/api/v1/acl?ip=192.0.2.1"
```

#### SQL Injection Attempt

```yaml
# Increase detection sensitivity for SQLi
layers:
  detection:
    sqli:
      enabled: true
      score_multiplier: 2.0  # Double the score
      patterns:
        - "union.*select"
        - "1\s*=\s*1"
```

#### False Positive

```yaml
# Add exclusion for legitimate traffic
rules:
  exclusions:
    - path: "/api/internal/*"
      source_ips: ["10.0.0.0/8"]
      detectors: []  # Skip all
      
    - path: "/webhook/*"
      detectors: ["sqli"]  # Skip SQLi only
      methods: ["POST"]
```

### Emergency Response Playbook

```bash
#!/bin/bash
# emergency-response.sh

API_KEY="your-api-key"
API_URL="http://localhost:9443/api/v1"

# 1. Get current status
echo "=== Current Status ==="
curl -s -H "X-API-Key: $API_KEY" "$API_URL/stats" | jq

# 2. List top attackers
echo "=== Top Blocked IPs ==="
curl -s -H "X-API-Key: $API_KEY" "$API_URL/events?action=block&limit=20" | \
  jq -r '.[].client_ip' | sort | uniq -c | sort -rn | head -10

# 3. Emergency block (CIDR range)
block_ip() {
    local ip=$1
    local comment=$2
    curl -s -X POST "$API_URL/acl/blacklist" \
      -H "X-API-Key: $API_KEY" \
      -H "Content-Type: application/json" \
      -d "{\"ip\": \"$ip\", \"comment\": \"$comment\"}"
    echo "Blocked: $ip"
}

# 4. Enable strict mode
echo "=== Enabling Strict Mode ==="
curl -s -X POST "$API_URL/config" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"mode": "enforce", "block_threshold": 30}'

# 5. Export events for analysis
echo "=== Exporting Events ==="
curl -s -H "X-API-Key: $API_KEY" \
  "$API_URL/events/export?format=json&since=1h" > incident-$(date +%Y%m%d-%H%M).json

echo "Response complete. Check incident-*.json for details."
```

### Backup During Incident

```bash
#!/bin/bash
# backup-before-changes.sh

BACKUP_DIR="/backups/incident-$(date +%Y%m%d-%H%M)"
mkdir -p "$BACKUP_DIR"

# Backup config
cp /etc/guardianwaf/config.yaml "$BACKUP_DIR/"

# Backup ACLs
curl -s http://localhost:9443/api/v1/acl > "$BACKUP_DIR/acl.json"

# Backup events (last hour)
curl -s "http://localhost:9443/api/v1/events/export?since=1h" > "$BACKUP_DIR/events.json"

# Backup rate limits
curl -s http://localhost:9443/api/v1/ratelimits > "$BACKUP_DIR/ratelimits.json"

tar -czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR"
rm -rf "$BACKUP_DIR"

echo "Backup complete: $BACKUP_DIR.tar.gz"
```

---

## Security Checklist

### Pre-Deployment

- [ ] Dashboard API key generated (32+ chars random)
- [ ] TLS certificates valid and from trusted CA
- [ ] Secrets stored securely (not in git)
- [ ] Container runs as non-root user
- [ ] Read-only root filesystem enabled
- [ ] All capabilities dropped
- [ ] Resource limits configured
- [ ] Health checks configured
- [ ] Firewall rules applied

### Post-Deployment

- [ ] Dashboard access restricted to internal network
- [ ] HTTPS redirect enabled
- [ ] HSTS headers configured
- [ ] Security headers present
- [ ] Rate limiting active
- [ ] IP ACL configured (whitelist internal)
- [ ] Alerting configured (Slack/email)
- [ ] Logging enabled (JSON format)
- [ ] Metrics endpoint accessible (internal only)

### Regular Maintenance

- [ ] Review logs weekly
- [ ] Update GeoIP database monthly
- [ ] Rotate TLS certificates before expiry
- [ ] Review and update IP ACLs
- [ ] Test alerting channels monthly
- [ ] Review false positives
- [ ] Update to latest version
- [ ] Security audit (quarterly)

---

*Last updated: 2026-04-04*
