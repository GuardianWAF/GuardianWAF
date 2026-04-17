# GuardianWAF Incident Response Guide

## Incident Classification

| Severity | Description | Example | Response Time |
|----------|-------------|---------|---------------|
| P1 - Critical | WAF down, all traffic affected | Process crash, OOM kill | < 15 min |
| P2 - High | Significant feature degraded | False positive spike, upstream down | < 1 hour |
| P3 - Medium | Limited impact, workaround available | Single tenant affected, slow dashboard | < 4 hours |
| P4 - Low | Minor issue, no user impact | Config warning, log noise | Next business day |

## P1: WAF Process Crash

1. **Triage** — Check if process is running:
   ```bash
   kubectl get pods -l app=guardianwaf
   # or
   systemctl status guardianwaf
   ```

2. **Recover** — Restart the service:
   ```bash
   kubectl rollout restart deployment/guardianwaf
   # or
   systemctl restart guardianwaf
   ```

3. **Investigate** — Check crash logs:
   ```bash
   kubectl logs -l app=guardianwaf --previous --tail=200
   # Look for: PANIC recovered, fatal error, out of memory
   ```

4. **Mitigate** — If recurring:
   - Increase memory limits in deployment config
   - Disable problematic layer temporarily via config
   - Enable `mode: monitor` to reduce processing overhead

## P2: Active Attack / False Positive Spike

### Coordinated Attack Response

1. **Identify** — Check attack patterns:
   ```bash
   curl -s "http://localhost:9443/api/events?action=block&limit=50" | \
     jq -r '.[].client_ip' | sort | uniq -c | sort -rn | head -20
   ```

2. **Contain** — Block attacking IPs:
   ```bash
   # Add to blacklist
   curl -X POST http://localhost:9443/api/ipacl/blacklist \
     -H "Authorization: Bearer $API_KEY" \
     -d '{"cidr": "192.0.2.0/24"}'
   ```

3. **Monitor** — Track block rate:
   ```bash
   curl -s http://localhost:9443/metrics | grep guardianwaf_requests_blocked
   ```

### False Positive Surge

1. **Identify** — Find the detector/layer causing blocks:
   ```bash
   curl -s "http://localhost:9443/api/events?action=block&limit=20" | \
     jq -r '.[].findings[]?.detector_name' | sort | uniq -c | sort -rn
   ```

2. **Mitigate** — Add exclusion for affected path:
   ```yaml
   waf:
     detection:
       exclusions:
         - path: /api/legitimate-endpoint
           detectors: [sqli]
   ```

3. **Switch mode** — If widespread, switch to monitor mode:
   ```bash
   export GWAF_MODE=monitor
   ```

## P3: Tenant Isolation Failure

1. **Verify** — Check tenant context in events:
   ```bash
   curl -s "http://localhost:9443/api/events?tenant_id=TENANT_ID&limit=10"
   ```

2. **Check** — Ensure tenant config is isolated:
   ```bash
   curl -s http://localhost:9443/api/tenants | jq '.[].id'
   ```

3. **Escalate** — If tenant data leakage suspected, immediately:
   - Isolate the affected tenant's virtual host
   - Review access logs for cross-tenant requests
   - Check proxy routing configuration

## Forensic Data Collection

When investigating a security incident, collect:

```bash
# 1. Recent events (JSON)
curl -s "http://localhost:9443/api/events?limit=1000" > events.json

# 2. Current configuration
curl -s http://localhost:9443/api/config > config_snapshot.json

# 3. IP ACL state
curl -s http://localhost:9443/api/ipacl/auto-ban > autobans.json

# 4. Rate limit state
curl -s http://localhost:9443/api/stats > stats.json

# 5. Metrics snapshot
curl -s http://localhost:9443/metrics > metrics.txt

# 6. Application logs
kubectl logs -l app=guardianwaf --since=1h > guardianwaf.log
```

## Post-Incident Checklist

- [ ] Root cause identified and documented
- [ ] Affected requests/users identified
- [ ] Configuration changes reverted or hardened
- [ ] New detection rules added if attack was novel
- [ ] Runbook updated if new failure mode discovered
- [ ] Incident report filed with timeline and actions taken
