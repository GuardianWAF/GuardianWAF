# GuardianWAF Troubleshooting FAQ

Common issues and solutions for GuardianWAF deployments.

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Configuration Issues](#configuration-issues)
3. [Performance Issues](#performance-issues)
4. [Security Issues](#security-issues)
5. [Alerting Issues](#alerting-issues)
6. [Docker Issues](#docker-issues)
7. [Dashboard Issues](#dashboard-issues)

---

## Installation Issues

### Q: Binary won't execute (permission denied)

**A:**
```bash
# Make executable
chmod +x guardianwaf

# Or install system-wide
sudo mv guardianwaf /usr/local/bin/
sudo chmod +x /usr/local/bin/guardianwaf
```

### Q: "command not found" after installation

**A:**
```bash
# Check if in PATH
echo $PATH | grep /usr/local/bin

# If not, add to PATH
export PATH=$PATH:/usr/local/bin

# Or use full path
/usr/local/bin/guardianwaf serve
```

### Q: Docker image pull fails

**A:**
```bash
# Check image exists
docker pull ghcr.io/guardianwaf/guardianwaf:v0.3.0

# If auth required
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Use specific version
docker pull ghcr.io/guardianwaf/guardianwaf:v0.3.0
```

---

## Configuration Issues

### Q: Config validation fails

**A:**
```bash
# Validate config
guardianwaf validate --config config.yaml

# Check YAML syntax
cat config.yaml | yq

# Check for required fields
# - server.listen
# - upstreams
# - routes
```

### Q: "listen address already in use"

**A:**
```bash
# Find process using port
sudo lsof -i :8080
# or
sudo netstat -tlnp | grep 8080

# Kill process
sudo kill -9 <PID>

# Or use different port
# config.yaml:
# server:
#   listen: ":8081"
```

### Q: TLS certificate not loading

**A:**
```bash
# Check file permissions
ls -la /etc/guardianwaf/certs/

# Fix permissions
sudo chmod 600 /etc/guardianwaf/certs/*.pem
sudo chown guardianwaf:guardianwaf /etc/guardianwaf/certs/*.pem

# Verify certificate
openssl x509 -in /etc/guardianwaf/certs/cert.pem -text -noout

# Check certificate chain
openssl verify -CAfile /etc/guardianwaf/certs/ca.pem /etc/guardianwaf/certs/cert.pem
```

### Q: ACME certificate not generated

**A:**
```bash
# Check DNS resolution
nslookup your-domain.com

# Check port 80 is accessible
sudo lsof -i :80

# Check firewall allows port 80
sudo ufw status

# Verify email is set
cat config.yaml | grep email

# Check logs
journalctl -u guardianwaf | grep -i acme
```

---

## Performance Issues

### Q: High CPU usage

**A:**
```bash
# Check what process is using CPU
top -p $(pgrep guardianwaf)

# Enable profiling
curl http://localhost:9443/debug/pprof/profile > cpu.prof

# Reduce workers in config
# engine:
#   workers: 4  # Reduce from default

# Disable unnecessary layers
layers:
  ai:
    enabled: false  # If not needed
```

### Q: High memory usage

**A:**
```bash
# Check memory profile
curl http://localhost:9443/debug/pprof/heap > heap.prof

# Reduce cache sizes
geoip:
  cache_size: 50000  # Default: 100000

threat_intel:
  cache_size: 10000  # Default: 50000

# Limit event storage
events:
  max_events: 50000  # Default: 100000
```

### Q: Slow response times

**A:**
```bash
# Check backend health
curl http://localhost:9443/api/v1/upstreams

# Test backend directly
curl -w "@curl-format.txt" -o /dev/null -s http://backend:8080/

# Increase timeouts
proxy:
  timeout: 30s
  
# Enable connection pooling
proxy:
  max_connections: 1000
```

### Q: "too many open files"

**A:**
```bash
# Check current limit
ulimit -n

# Increase limit
sudo sysctl -w fs.file-max=100000
ulimit -n 65535

# Or in systemd
# /etc/systemd/system/guardianwaf.service
[Service]
LimitNOFILE=65535
```

---

## Security Issues

### Q: Legitimate requests being blocked

**A:**
```yaml
# Add IP to whitelist
ip_acl:
  whitelist:
    - "192.168.1.0/24"  # Your office
    - "10.0.0.0/8"      # Internal network

# Or add exclusion
rules:
  exclusions:
    - path: "/api/internal/*"
      source_ips: ["10.0.0.0/8"]
      detectors: []

# Increase threshold temporarily
server:
  block_threshold: 70  # Default: 50
```

### Q: Dashboard API key not working

**A:**
```bash
# Check API key is set
echo $DASHBOARD_API_KEY

# Verify in config
grep -i api_key config.yaml

# Test manually
curl -H "X-API-Key: your-key" http://localhost:9443/api/v1/stats

# Check logs
journalctl -u guardianwaf | grep -i "unauthorized"
```

### Q: Cannot access dashboard

**A:**
```bash
# Check if listening
ss -tlnp | grep 9443

# Check from local
curl http://localhost:9443/api/v1/stats

# If using Docker, check port mapping
docker ps | grep guardianwaf

# Check firewall
sudo iptables -L | grep 9443
```

---

## Alerting Issues

### Q: Webhooks not firing

**A:**
```bash
# Test webhook manually
curl -X POST https://hooks.slack.com/... \
  -d '{"text": "Test message"}'

# Check webhook config
curl http://localhost:9443/api/v1/alerting/webhooks

# Check min_score threshold
# Must be >= min_score to trigger

# Check logs
journalctl -u guardianwaf | grep -i webhook
```

### Q: Email alerts not sending

**A:**
```bash
# Test SMTP manually
telnet smtp.gmail.com 587

# Check config
grep -A 10 "email:" config.yaml

# Verify credentials
echo $SMTP_PASSWORD

# Check TLS setting
# Some providers require TLS, others don't

# Check logs
journalctl -u guardianwaf | grep -i "failed.*email"
```

### Q: Events not appearing in dashboard

**A:**
```bash
# Check events API
curl http://localhost:9443/api/v1/events

# Check if events are being logged
ls -la /var/lib/guardianwaf/events/

# Check log level
grep -i "log_level" config.yaml

# Increase log level temporarily
# logging:
#   level: debug
```

---

## Docker Issues

### Q: Container keeps restarting

**A:**
```bash
# Check logs
docker logs guardianwaf --tail 100

# Check config mounted correctly
docker exec guardianwaf cat /etc/guardianwaf/config.yaml

# Check permissions on host
ls -la /path/to/data

# Run with debug
docker run -it --rm \
  -v $(pwd)/config.yaml:/etc/guardianwaf/config.yaml \
  ghcr.io/guardianwaf/guardianwaf:v0.3.0 \
  serve -c /etc/guardianwaf/config.yaml
```

### Q: Cannot access backend services

**A:**
```bash
# Check network
docker network ls
docker network inspect guardianwaf_waf-network

# Test connectivity from container
docker exec guardianwaf ping backend

# Check if on same network
# docker-compose.yml:
# networks:
#   - waf-network

# Check DNS resolution
docker exec guardianwaf nslookup backend
```

### Q: Volume permissions issues

**A:**
```bash
# Check ownership
ls -la data/

# Fix ownership
sudo chown -R 65534:65534 data/
sudo chown -R 65534:65534 logs/

# Or use named volumes
docker volume create guardianwaf-data

# In docker-compose:
# volumes:
#   - guardianwaf-data:/var/lib/guardianwaf
```

---

## Dashboard Issues

### Q: Dashboard shows "No data"

**A:**
```bash
# Check SSE connection
# Open browser dev tools -> Network -> SSE

# Check if events are flowing
curl http://localhost:9443/api/v1/events/stream

# Check CORS settings
# server:
#   dashboard_cors_origins: ["http://localhost:5173"]

# Clear browser cache
# Ctrl+Shift+R (hard reload)
```

### Q: Cannot add whitelist/blacklist

**A:**
```bash
# Check API key permissions
curl -H "X-API-Key: your-key" http://localhost:9443/api/v1/acl

# Check IP format
curl -X POST http://localhost:9443/api/v1/acl/whitelist \
  -H "X-API-Key: key" \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.1"}'  # Not CIDR

# Use CIDR format
curl -X POST http://localhost:9443/api/v1/acl/whitelist \
  -H "X-API-Key: key" \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.0/24"}'
```

### Q: Graph not rendering

**A:**
```bash
# Check if topology endpoint works
curl http://localhost:9443/api/v1/topology

# Check browser console for errors
# Open F12 -> Console

# Check if React loaded correctly
# Sources tab -> webpack://

# Clear localStorage
localStorage.clear()
```

---

## Common Error Messages

### "bind: address already in use"

```bash
# Find and kill process
sudo lsof -i :8080 | grep LISTEN
sudo kill -9 <PID>
```

### "permission denied" on config file

```bash
# Fix permissions
sudo chmod 644 config.yaml
sudo chown $(whoami):$(whoami) config.yaml
```

### "certificate file not found"

```bash
# Check path
ls -la /etc/guardianwaf/certs/

# Create directory
sudo mkdir -p /etc/guardianwaf/certs
sudo cp certs/* /etc/guardianwaf/certs/
sudo chown -R guardianwaf:guardianwaf /etc/guardianwaf/certs
```

### "unauthorized" on API calls

```bash
# Verify API key
curl -v -H "X-API-Key: wrong-key" http://localhost:9443/api/v1/stats

# Use correct key
curl -H "X-API-Key: correct-key" http://localhost:9443/api/v1/stats
```

### "rate limit exceeded"

```bash
# Wait and retry
sleep 60

# Or check current limits
curl http://localhost:9443/api/v1/ratelimits
```

---

## Debug Mode

### Enable Debug Logging

```yaml
# config.yaml
logging:
  level: debug
  format: json
  file: "/var/log/guardianwaf/debug.log"
```

### Verbose Mode

```bash
# Run with verbose output
guardianwaf serve -v

# Or with trace
guardianwaf serve --log-level=trace
```

### Request Testing

```bash
# Test request scoring
guardianwaf check --method GET --url "http://example.com/test?id=1"

# With custom headers
guardianwaf check \
  --method POST \
  --url "http://example.com/api" \
  --header "Content-Type: application/json" \
  --body '{"query": "SELECT * FROM users"}'
```

---

## Getting Help

### Collect Debug Info

```bash
#!/bin/bash
# collect-debug-info.sh

echo "=== GuardianWAF Debug Info ===" > debug-info.txt
date >> debug-info.txt

echo -e "\n=== Version ===" >> debug-info.txt
guardianwaf version >> debug-info.txt 2>&1 || echo "version command failed"

echo -e "\n=== Config ===" >> debug-info.txt
guardianwaf validate --config config.yaml >> debug-info.txt 2>&1

echo -e "\n=== Process ===" >> debug-info.txt
ps aux | grep guardianwaf >> debug-info.txt

echo -e "\n=== Ports ===" >> debug-info.txt
ss -tlnp | grep guardianwaf >> debug-info.txt

echo -e "\n=== Logs (last 100) ===" >> debug-info.txt
journalctl -u guardianwaf --no-pager -n 100 >> debug-info.txt 2>&1 || \
  tail -100 /var/log/guardianwaf/guardianwaf.log >> debug-info.txt 2>&1

echo -e "\n=== System Info ===" >> debug-info.txt
uname -a >> debug-info.txt
free -h >> debug-info.txt
df -h >> debug-info.txt

echo "Debug info collected: debug-info.txt"
```

### Submit Issue

When reporting issues, include:

1. GuardianWAF version
2. Operating system
3. Config (sanitized)
4. Debug logs
5. Steps to reproduce
6. Expected vs actual behavior

**GitHub Issues:** https://github.com/GuardianWAF/GuardianWAF/issues

---

*Last updated: 2026-04-04*

## Log Rotation

GuardianWAF writes structured logs to stdout/stderr. For production deployments, use external log rotation:

- **Docker:** Configure log drivers (`json-file` with max-size/max-file, or `local` driver)
  ```yaml
  services:
    guardianwaf:
      logging:
        driver: json-file
        options:
          max-size: "50m"
          max-file: "5"
  ```
- **Kubernetes:** Container logs are rotated by kubelet (configure `--container-log-max-size` and `--container-log-max-files`)
- **systemd:** Use `journal` with `SystemMaxUse=` and `SystemMaxFileSize=` settings
- **Bare metal:** Pipe to `logrotate` or use `slog` JSON output with file rotation

Event JSONL files are rotated automatically at 100MB. No external configuration needed.

