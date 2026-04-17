# GuardianWAF Troubleshooting Runbook

## Quick Diagnostics

```bash
# Check health
curl -s http://localhost:9443/healthz | jq .

# Check metrics
curl -s http://localhost:9443/metrics | grep guardianwaf_

# View recent logs
kubectl logs -l app=guardianwaf --tail=100

# Check config validity
guardianwaf validate -config /path/to/guardianwaf.yaml
```

## Common Issues

### 1. High False Positive Rate

**Symptoms**: Legitimate requests blocked (403 responses), high block count.

**Diagnosis**:
```bash
# Check which detectors are firing
curl -s http://localhost:9443/api/stats | jq '.findings_by_detector'

# Review recent blocked events
curl -s "http://localhost:9443/api/events?action=block&limit=20"
```

**Resolution**:
- Lower `block_threshold` in config (default: 50)
- Add path exclusions for specific detectors:
  ```yaml
  waf:
    detection:
      exclusions:
        - path: /api/webhook
          detectors: [sqli, xss]
  ```
- Per-detector multipliers can reduce sensitivity:
  ```yaml
  waf:
    detection:
      multipliers:
        sqli: 0.7
  ```

### 2. Backend Upstream Unreachable

**Symptoms**: 502 Bad Gateway, upstream health checks failing.

**Diagnosis**:
```bash
# Check upstream health
curl -s http://localhost:9443/api/upstreams | jq '.[].targets[] | {url, healthy}'

# Check circuit breaker state
curl -s http://localhost:9443/api/proxy/status
```

**Resolution**:
- Verify backend is running and accessible from WAF node
- Check firewall rules between WAF and upstream
- If circuit breaker is open, wait for half-open probe (30s default) or restart WAF
- Adjust health check settings:
  ```yaml
  upstreams:
    - name: backend
      health_check:
        interval: 10s
        timeout: 5s
        path: /healthz
  ```

### 3. TLS Certificate Errors

**Symptoms**: Browser shows certificate warnings, ACME enrollment fails.

**Diagnosis**:
```bash
# Check TLS config
guardianwaf validate -config guardianwaf.yaml 2>&1 | grep -i tls

# Test certificate
openssl s_client -connect localhost:9443 -servername example.com < /dev/null 2>/dev/null | openssl x509 -noout -dates
```

**Resolution**:
- Verify cert/key file paths and permissions
- For ACME: ensure port 80 is reachable from the internet for HTTP-01 challenge
- Check `acme.cache_dir` is writable

### 4. Memory Growth

**Symptoms**: Increasing RSS over time, OOM kills.

**Diagnosis**:
```bash
# Check pprof
curl -s http://localhost:9443/debug/pprof/heap > heap.pprof
go tool pprof heap.pprof

# Check event buffer size
curl -s http://localhost:9443/api/stats | jq '.events_stored'
```

**Resolution**:
- Reduce `events.max_events` (default: 10000)
- Enable file-based event storage:
  ```yaml
  events:
    storage: file
    file_path: /var/log/guardianwaf/events.jsonl
  ```
- Check for oversized request bodies: reduce `waf.sanitizer.max_body_size`

### 5. Cluster Node Not Syncing

**Symptoms**: IP bans not propagating to other nodes, stale config.

**Diagnosis**:
```bash
# Check cluster state
curl -s http://localhost:9443/api/cluster/status | jq .

# Check node connectivity
curl -s https://peer-node:9443/api/cluster/health
```

**Resolution**:
- Verify `X-Cluster-Auth` secret matches across nodes
- Check network connectivity between nodes (port 9443)
- Ensure all nodes use the same `cluster.node_id`

### 6. Rate Limiting Too Aggressive

**Symptoms**: Legitimate users getting 429 responses.

**Diagnosis**:
```bash
# Check rate limit stats
curl -s http://localhost:9443/api/stats | jq '.rate_limits'
```

**Resolution**:
- Increase `requests_per_second` in rate limit rules
- Increase `auto_ban.threshold` (violations before ban)
- Add trusted proxy CIDRs so real IPs are used:
  ```yaml
  trusted_proxies:
    - 10.0.0.0/8
    - 172.16.0.0/12
  ```

### 7. Dashboard Not Loading

**Symptoms**: Blank page, API errors in browser console.

**Diagnosis**:
```bash
# Check dashboard health
curl -s http://localhost:9443/api/health

# Check if dashboard is enabled
grep dashboard guardianwaf.yaml
```

**Resolution**:
- Ensure `dashboard.enabled: true`
- Verify `dashboard.api_key` is set
- Check CORS settings if accessing from a different origin

### 8. Performance Degradation

**Symptoms**: High latency, slow responses.

**Diagnosis**:
```bash
# Check p50/p90/p99 latency
curl -s http://localhost:9443/metrics | grep guardianwaf_request_duration

# Check per-layer timing
curl -s http://localhost:9443/debug/pprof/profile?seconds=10 > cpu.pprof
go tool pprof cpu.pprof
```

**Resolution**:
- Disable unused layers (e.g., ML anomaly, DLP) if not needed
- Reduce `waf.sanitizer.max_body_size` to limit body scanning
- Enable response caching:
  ```yaml
  waf:
    cache:
      enabled: true
      backend: memory
      ttl: 60s
  ```

## Emergency Procedures

### Disable WAF (Pass-Through Mode)

```yaml
# Set mode to "disabled" — all requests pass through without inspection
mode: disabled
```

Or via environment variable:
```bash
export GWAF_MODE=disabled
```

### Clear All Auto-Bans

```bash
curl -X DELETE http://localhost:9443/api/ipacl/auto-ban \
  -H "Authorization: Bearer YOUR_API_KEY"
```

### Force Config Reload

```bash
# Send SIGHUP to reload config (if supported)
kill -HUP $(pidof guardianwaf)
```
