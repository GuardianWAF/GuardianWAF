# GuardianWAF Troubleshooting Runbook

## Quick Diagnostics

```bash
# Check process liveness
curl -s http://localhost:9443/livez | jq .

# Check traffic readiness
curl -s http://localhost:9443/readyz | jq .

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
curl -s http://localhost:9443/api/v1/stats | jq '.findings_by_detector'

# Review recent blocked events
curl -s "http://localhost:9443/api/v1/events?action=block&limit=20"
```

**Resolution**:
- Move to `monitor` mode or raise the block threshold while triaging:
  <!-- guardianwaf-config:validate -->
  ```yaml
  mode: monitor
  waf:
    detection:
      threshold:
        block: 80
        log: 25
  ```
- Add path exclusions for specific detectors:
  <!-- guardianwaf-config:validate -->
  ```yaml
  waf:
    detection:
      exclusions:
        - path: /api/webhook
          detectors: [sqli, xss]
          reason: trusted webhook payloads
  ```
- Per-detector multipliers can reduce sensitivity:
  <!-- guardianwaf-config:validate -->
  ```yaml
  waf:
    detection:
      detectors:
        sqli:
          enabled: true
          multiplier: 0.7
  ```

### 2. Backend Upstream Unreachable

**Symptoms**: 502 Bad Gateway, upstream health checks failing.

**Diagnosis**:
```bash
# Check upstream health
curl -s http://localhost:9443/api/v1/upstreams | jq '.[].targets[] | {url, healthy}'

# Check circuit breaker state
curl -s http://localhost:9443/api/v1/routing
```

**Resolution**:
- Verify backend is running and accessible from WAF node
- Check firewall rules between WAF and upstream
- If circuit breaker is open, wait for half-open probe (30s default) or restart WAF
- Adjust health check settings:
  <!-- guardianwaf-config:validate -->
  ```yaml
  upstreams:
    - name: backend
      targets:
        - url: http://app:3000
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
curl -s http://localhost:9443/api/v1/stats | jq '.events_stored'
```

**Resolution**:
- Reduce `events.max_events` (default: 10000)
- Enable file-based event storage:
  <!-- guardianwaf-config:validate -->
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
curl -s http://localhost:9443/api/v1/cluster/status | jq .

# Check node connectivity
curl -s https://peer-node:9443/api/v1/cluster/health
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
curl -s http://localhost:9443/api/v1/stats | jq '.rate_limits'
```

**Resolution**:
- Increase the relevant rule `limit`, `window`, or `burst`:
  <!-- guardianwaf-config:validate -->
  ```yaml
  waf:
    rate_limit:
      rules:
        - id: global
          scope: ip
          limit: 1000
          window: 1m
          burst: 100
          action: block
  ```
- Increase `auto_ban_after` on path-specific rules when automatic bans are too aggressive.
- Add trusted proxy CIDRs so real IPs are used. These must be the direct proxy,
  load balancer, or ingress addresses that connect to GuardianWAF, not the
  public client address range:
  <!-- guardianwaf-config:validate -->
  ```yaml
  trusted_proxies:
    - 10.0.0.10
    - 10.0.1.0/24
  ```
- Leave `trusted_proxies` empty for direct internet exposure so spoofed
  `X-Forwarded-For` and `X-Real-IP` headers are ignored.

### 7. Dashboard Not Loading

**Symptoms**: Blank page, API errors in browser console.

**Diagnosis**:
```bash
# Check dashboard health
curl -s http://localhost:9443/api/v1/health

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
# Check average WAF processing latency
curl -s http://localhost:9443/metrics | grep guardianwaf_latency_avg_microseconds

# Check per-layer timing
curl -s http://localhost:9443/debug/pprof/profile?seconds=10 > cpu.pprof
go tool pprof cpu.pprof
```

**Resolution**:
- Disable unused detectors via per-detector multipliers or `waf.detection.exclusions` if not needed
- Reduce `waf.sanitizer.max_body_size` to limit body scanning
- Add path exclusions for hot, trusted endpoints so detectors skip them:
  <!-- guardianwaf-config:validate -->
  ```yaml
  waf:
    detection:
      exclusions:
        - path: /api/health
          detectors: [sqli, xss, lfi, cmdi]
          reason: high-volume internal health endpoint
  ```

### 9. High Block Spike

**Symptoms**: `guardianwaf_requests_blocked_total` rate rises sharply, users report 403s, upstream traffic drops.

**Diagnosis**:
```bash
# Compare block rate to total request rate
curl -s http://localhost:9443/metrics | egrep 'guardianwaf_requests_(total|blocked)_total'

# Inspect recent blocked events
curl -s "http://localhost:9443/api/v1/events?action=block&limit=50" \
  -H "Authorization: Bearer $GWAF_DASHBOARD_API_KEY" | jq '.events[] | {path, score, findings}'

# Check recent deploy/config changes
guardianwaf validate -config /etc/guardianwaf/guardianwaf.yaml
kubectl rollout history deploy/guardianwaf
```

**Resolution**:
- If the spike is a real attack, keep `mode: enforce`, confirm upstream capacity, and export incident evidence.
- If likely false positive, switch to `mode: monitor` or raise `waf.detection.threshold.block` while collecting samples.
- Add the narrowest path/detector exclusion needed and record the reason.
- Verify recovery with `guardianwaf_requests_blocked_total` rate and a known-good user workflow.

### 10. False Positive Rollback

**Symptoms**: A rule/config change blocks valid traffic after rollout.

**Diagnosis**:
```bash
# Identify current config and blocked evidence
guardianwaf validate -config /etc/guardianwaf/guardianwaf.yaml
curl -s "http://localhost:9443/api/v1/events?action=block&limit=20" \
  -H "Authorization: Bearer $GWAF_DASHBOARD_API_KEY" | jq .
```

**Resolution**:
- Roll back to the last known-good config from version control or your config store.
- If rollback is slow, temporarily set `mode: monitor` and reload/restart GuardianWAF.
- Re-apply only the smallest safe exclusion or detector multiplier after reproducing with `guardianwaf check`.
- Verify that clean traffic passes and the original attack sample still blocks before returning to `enforce`.

### 11. Dashboard Lockout

**Symptoms**: Dashboard API returns 401/403, tenant-admin APIs unavailable, or operators lost the API/admin key.

**Diagnosis**:
```bash
# Health does not require an API key
curl -i http://localhost:9443/api/v1/health

# Stats should reject missing key and accept the configured key
curl -i http://localhost:9443/api/v1/stats
curl -i http://localhost:9443/api/v1/stats -H "Authorization: Bearer $GWAF_DASHBOARD_API_KEY"
```

**Resolution**:
- Rotate `GWAF_DASHBOARD_API_KEY` in the secret manager and restart/reload the deployment.
- Set `GWAF_DASHBOARD_ADMIN_KEY` only when tenant-admin APIs are required.
- Keep dashboard bound to loopback or an internal network and expose it through an authenticated TLS proxy.
- Confirm the startup log no longer says tenant admin APIs are disabled if admin APIs are expected.

### 12. Event Store Full or Dropping Events

**Symptoms**: Missing dashboard events, file event store write errors, disk pressure, or increasing memory use.

**Diagnosis**:
```bash
# Check event config and current event count
guardianwaf validate -config /etc/guardianwaf/guardianwaf.yaml
curl -s http://localhost:9443/api/v1/stats -H "Authorization: Bearer $GWAF_DASHBOARD_API_KEY" | jq '.events_stored'

# Check bounded overload signals
curl -s http://localhost:8088/metrics | grep -E 'guardianwaf_event_store_dropped_total|guardianwaf_event_bus_dropped_total|guardianwaf_event_bus_rejected_subscriptions_total|guardianwaf_alert_manager_dropped_total|guardianwaf_ai_pending_events'

# Check disk usage for file-backed events
df -h /var/log/guardianwaf
du -sh /var/log/guardianwaf/events.jsonl
```

**Resolution**:
- For durable production events, use `events.storage: file` with a persistent volume.
- Increase disk capacity or reduce `events.max_events` to bound replay/load time.
- If `guardianwaf_event_bus_dropped_total` rises, identify slow dashboard/SSE or alerting consumers and reduce subscriber work or scale the instance.
- If `guardianwaf_event_bus_rejected_subscriptions_total` rises, the event fan-out subscriber cap has been reached; reduce duplicate consumers or split traffic across instances.
- If `guardianwaf_alert_manager_dropped_total` rises, reduce alert fan-out, fix slow webhook/SMTP targets, or temporarily disable non-critical alert targets.
- If `guardianwaf_ai_pending_events` remains near the configured batch size while AI requests are capped, raise approved provider limits or disable AI analysis until capacity is available.
- Archive or rotate old JSONL files according to retention policy.
- Verify new events appear in the dashboard after cleanup.

### 13. AI Provider Cost Cap Hit

**Symptoms**: AI analysis stops, analysis queue remains low but events no longer receive AI verdicts, logs mention token/request budget limits.

**Diagnosis**:
```bash
# Inspect AI config
guardianwaf validate -config /etc/guardianwaf/guardianwaf.yaml
grep -n "ai_analysis" -A20 /etc/guardianwaf/guardianwaf.yaml

# Review recent logs
kubectl logs -l app=guardianwaf --tail=200 | grep -i 'ai\\|token\\|budget\\|cost'
```

**Resolution**:
- Confirm the cap was intentional and no provider key leaked.
- Raise `waf.ai_analysis.max_tokens_per_hour`, `max_tokens_per_day`, or `max_requests_per_hour` only after approval.
- Disable `auto_block` if AI verdict volume is uncertain.
- Verify logs show analysis resumed and provider credentials remain masked in dashboard/API responses.

### 14. ACME Renewal Failure

**Symptoms**: Certificate near expiry, ACME errors in logs, HTTPS clients report expired or invalid certificate.

**Diagnosis**:
```bash
guardianwaf validate -config /etc/guardianwaf/guardianwaf.yaml
openssl s_client -connect app.example.com:443 -servername app.example.com < /dev/null 2>/dev/null \
  | openssl x509 -noout -dates -issuer -subject
kubectl logs -l app=guardianwaf --tail=200 | grep -i acme
```

**Resolution**:
- Ensure HTTP-01 traffic can reach the GuardianWAF ACME listener and no ingress blocks challenge paths.
- Check `tls.acme.email`, `tls.acme.domains`, and writable `tls.acme.cache_dir`.
- If expiry is imminent, deploy a manually issued cert via `tls.cert_file` and `tls.key_file`, then restore ACME.
- Confirm renewal by checking certificate dates and startup logs.

### 15. Docker Discovery Failure

**Symptoms**: Docker-labeled services do not appear, fallback route is used, or discovered routes disappear.

**Diagnosis**:
```bash
# Verify Docker config
grep -n "docker:" -A10 /etc/guardianwaf/guardianwaf.yaml

# Check socket access from the GuardianWAF container/host
docker ps --format '{{.Names}} {{.Labels}}' | grep gwaf
kubectl logs -l app=guardianwaf --tail=200 | grep -i docker
```

**Resolution**:
- Verify `docker.enabled: true`, `docker.socket_path`, `docker.label_prefix`, and container labels.
- Confirm the GuardianWAF process can read the Docker socket.
- Keep a validated fallback upstream/route so traffic has a deterministic failure mode.
- Restart GuardianWAF only after confirming labels and socket permissions.

### 16. Suspected WAF Bypass

**Symptoms**: Malicious payload reaches the application, but GuardianWAF logs show pass/log instead of block.

**Diagnosis**:
```bash
# Reproduce through the CLI with the production config
guardianwaf check -config /etc/guardianwaf/guardianwaf.yaml \
  -url '/suspect/path?payload=...' \
  -H 'User-Agent: reproduction'

# Export recent related events
curl -s "http://localhost:9443/api/v1/events?limit=100" \
  -H "Authorization: Bearer $GWAF_DASHBOARD_API_KEY" > bypass-events.json
```

**Resolution**:
- Preserve payload, headers, route, upstream response, and request ID as incident evidence.
- Add a temporary custom rule or virtual patch scoped to the affected path.
- Add the sample to the attack corpus/regression tests before broad detector changes.
- Keep the deployment in `enforce` after confirming the compensating rule blocks the sample.

### 17. Incident Export for Compliance

**Symptoms**: Security, audit, or compliance team requests evidence for a time window.

**Procedure**:
```bash
mkdir -p incident-export

# Metrics snapshot
curl -s http://localhost:9443/metrics > incident-export/metrics.prom

# Event export
curl -s "http://localhost:9443/api/v1/events?limit=1000" \
  -H "Authorization: Bearer $GWAF_DASHBOARD_API_KEY" > incident-export/events.json

# Config snapshot with secrets redacted manually before sharing
cp /etc/guardianwaf/guardianwaf.yaml incident-export/guardianwaf.yaml

# Runtime logs
kubectl logs -l app=guardianwaf --since=24h > incident-export/guardianwaf.log

# Audit-chain integrity snapshot for external anchoring
curl -s http://localhost:9443/api/v1/compliance/audit-chain \
  -H "Authorization: Bearer $GWAF_DASHBOARD_API_KEY" > incident-export/audit-chain.json
```

**Verification**:
- Confirm exported events have request IDs and redacted sensitive fields.
- Record the GuardianWAF version and image digest.
- Confirm `audit-chain.json` has `"integrity": true` and store its `head_hash` in the approved write-once evidence system for later truncation/tamper checks.
- Store the export in the approved evidence repository with retention tags.

### 18. Backup Stale or Restore Required

**Symptoms:** `guardianwaf_backup_last_success_timestamp_seconds` is missing or older than 3600 seconds, snapshot verification fails, persistent state is lost/corrupt, or a node/PVC must be replaced.

**Owners:** primary on-call SRE executes backup/restore; GuardianWAF service owner validates security state before traffic returns. Escalate failed integrity verification immediately; never bypass a failed hash/config check.

```bash
# Backup freshness (node-exporter textfile metric)
now=$(date +%s)
last=$(awk '$1 == "guardianwaf_backup_last_success_timestamp_seconds" {print $2}' \
  /var/lib/node_exporter/textfile_collector/guardianwaf-backup.prom)
test "$((now-last))" -le 3600

# Verify the selected off-host snapshot without mutation.
./scripts/restore-state.sh \
  --archive /backups/guardianwaf/state-YYYYmmddTHHMMSSZ.tar.gz \
  --guardianwaf /usr/local/bin/guardianwaf \
  --verify-only
```

Restore procedure and exact paths are in [State Persistence](state-persistence.md#backup-and-restore). Start the RTO clock when the restore is approved; service must remain stopped until restore completes. After start, require `/livez`, `/readyz`, event history, tenants, ACME material, compliance chain, and dashboard mutation audit replay before accepting traffic. Record the selected snapshot time (RPO), elapsed restore time (RTO), operator, incident/ticket, and validation results. Target: **RPO ≤ 3600s; RTO ≤ 300s**.

### 19. Dashboard Audit Persistence Failure

**Symptoms:** `increase(guardianwaf_dashboard_audit_persistence_failures_total[5m]) > 0`, log message `dashboard audit persistence failed`, or missing management mutations in the JSONL audit store.

**Owners:** primary GuardianWAF on-call pages the service owner/security incident lead because management evidence may be incomplete.

```bash
curl -s http://127.0.0.1:8088/metrics | grep guardianwaf_dashboard_audit_persistence_failures_total
grep -n 'audit_path' /etc/guardianwaf/guardianwaf.yaml
df -h /var/lib/guardianwaf
namei -l /var/lib/guardianwaf/audit/dashboard.jsonl
```

Stop privileged dashboard mutations until persistence is restored. Check disk/inode pressure and directory ownership; do not truncate or replace the JSONL file while GuardianWAF is running. Restart only after fixing the storage problem, then perform a controlled mutation and confirm the counter no longer rises and the new JSONL record survives restart. Preserve logs and the last valid audit file as incident evidence; document the potentially missing time window.

### 20. Service or Scrape Unavailable

**Symptoms:** `up{job="guardianwaf"} == 0`, availability error-budget burn, failed `/livez` or `/readyz`, or missing metrics for an intended instance.

**Owners:** primary GuardianWAF on-call; involve the platform/cluster owner when scheduling, networking, or Prometheus service discovery is responsible.

```bash
systemctl status guardianwaf --no-pager
journalctl -u guardianwaf --since '15 minutes ago'
curl --fail http://127.0.0.1:8088/livez
curl --fail http://127.0.0.1:8088/readyz
curl --fail http://127.0.0.1:8088/metrics >/dev/null
```

Distinguish process failure from scrape-path failure: if local health and metrics pass, inspect Prometheus target discovery, Service/NetworkPolicy, TLS/auth, and DNS. If the process is unhealthy, validate the active config, check disk/memory pressure and recent deployment changes, then roll back to the last known-good image/config when repair cannot fit the error budget. Confirm all intended instances are `up == 1` and burn alerts resolve before closing the incident.

### 21. Alert Delivery Failure

**Symptoms:** increases in `guardianwaf_alert_manager_failed_total`, `guardianwaf_alert_manager_dropped_total`, or `guardianwaf_alert_email_failed_total`; expected security notifications are absent.

**Owners:** GuardianWAF on-call plus the notification-system owner. Treat the interval as degraded incident detection and use the secondary paging path.

```bash
curl -s http://127.0.0.1:8088/metrics | grep -E 'guardianwaf_alert_(manager|email)_(failed|dropped)_total'
journalctl -u guardianwaf --since '15 minutes ago' | grep -i alert
/usr/local/bin/guardianwaf test-alert -c /etc/guardianwaf/guardianwaf.yaml
```

Check target configuration, DNS/TLS, SMTP/webhook credentials, quotas, and queue capacity without printing secrets. Route security events manually through the approved secondary channel until a test alert reaches the real destination. Preserve failed-delivery logs and record the notification gap; confirm counters stop increasing before closing.

## Emergency Procedures

### Disable WAF (Pass-Through Mode)

<!-- guardianwaf-config:validate -->
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
curl -X DELETE http://localhost:9443/api/v1/bans \
  -H "Authorization: Bearer YOUR_API_KEY"
```

### Force Config Reload

```bash
# Re-apply the current in-memory config and rebuild routing when configured
curl -X POST http://localhost:9443/api/v1/config/reload \
  -H "X-API-Key: YOUR_API_KEY"
```

This does not reread the YAML file from disk. For listener, storage, TLS/ACME, Docker watcher, AI, alerting, tenant, MCP, tracing, compliance, SIEM, cluster, or other startup-owned service changes, update the config through your deployment system and perform a rolling restart. See [Runtime Reload Contract](runtime-reload.md).
