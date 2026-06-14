# Tuning Guide

This guide covers reducing false positives, adjusting thresholds, and configuring GuardianWAF for your specific application.

---

## Start in Monitor Mode

Before enforcing, run in monitor mode to observe traffic patterns without blocking anything:

<!-- guardianwaf-config:validate -->
```yaml
mode: monitor
```

Or via environment variable:

```bash
GWAF_MODE=monitor guardianwaf serve
```

In monitor mode, all detection runs normally and events are logged, but no requests are blocked. Review the events to understand your traffic baseline.

---

## Adjusting Thresholds

The two main thresholds control when requests are logged and blocked:

<!-- guardianwaf-config:validate -->
```yaml
waf:
  detection:
    threshold:
      block: 50    # Score >= 50 → blocked
      log: 25      # Score >= 25 → logged (but not blocked)
```

**Lowering the block threshold** (e.g., to 40) makes the WAF more aggressive -- more requests will be blocked. Use this if you're seeing attacks slip through.

**Raising the block threshold** (e.g., to 70) makes the WAF more permissive -- only high-confidence attacks are blocked. Use this if you have too many false positives.

Common configurations:

| Scenario | Block | Log |
|---|---|---|
| High security (financial, healthcare) | 40 | 20 |
| Standard web application | 50 | 25 |
| API with rich text input | 70 | 35 |
| Permissive / learning | 100 | 25 |

Override via environment:

```bash
GWAF_WAF_DETECTION_THRESHOLD_BLOCK=70 GWAF_WAF_DETECTION_THRESHOLD_LOG=35 guardianwaf serve
```

---

## Detector Multipliers

Each detector has a score multiplier that scales all its findings:

<!-- guardianwaf-config:validate -->
```yaml
waf:
  detection:
    detectors:
      sqli:
        enabled: true
        multiplier: 1.0    # Default: no scaling
      xss:
        enabled: true
        multiplier: 0.5    # Half sensitivity
      lfi:
        enabled: true
        multiplier: 1.5    # 50% more sensitive
```

**When to adjust multipliers:**

| Situation | Action |
|---|---|
| Application handles SQL-like input (e.g., query builder) | Lower `sqli` multiplier to 0.5–0.7 |
| Application accepts HTML/Markdown | Lower `xss` multiplier to 0.3–0.5 |
| API receives file paths as parameters | Lower `lfi` multiplier to 0.5 |
| Application has no XML processing | Set `xxe` multiplier to 0 or disable |
| No outbound HTTP requests from user input | Set `ssrf` multiplier to 0 or disable |
| High-security login endpoint | Raise `sqli` multiplier to 1.5–2.0 |

Multiplier math: a UNION SELECT finding with base score 90 and multiplier 0.5 produces score 45 (below the default block threshold of 50).

---

## Path Exclusions

When specific endpoints legitimately contain content that triggers detectors, use exclusions instead of lowering global thresholds:

<!-- guardianwaf-config:validate -->
```yaml
waf:
  detection:
    exclusions:
      # Webhook endpoint receives arbitrary JSON payloads
      - path: /api/webhook
        detectors: [sqli, xss]
        reason: "Webhook receives arbitrary payloads"

      # CMS editor allows HTML content
      - path: /api/content
        detectors: [xss]
        reason: "CMS editor allows rich HTML"

      # Search endpoint uses SQL-like syntax
      - path: /api/search
        detectors: [sqli]
        reason: "Search query language uses SQL keywords"

      # File management API uses file paths
      - path: /api/files
        detectors: [lfi]
        reason: "File browser API handles path parameters"
```

Exclusions match by path prefix. `/api/webhook/github` matches the `/api/webhook` exclusion.

Apply exclusion changes through configuration management and reload the dashboard configuration when needed:

```bash
curl -X POST http://localhost:9443/api/v1/config/reload \
  -H "X-API-Key: your-key"
```

For the exact runtime update boundary, see [Runtime Reload Contract](runtime-reload.md).

---

## Disabling Individual Detectors

If a detector is not relevant to your application:

<!-- guardianwaf-config:validate -->
```yaml
waf:
  detection:
    detectors:
      xxe:
        enabled: false     # Disable XXE (no XML processing)
      ssrf:
        enabled: false     # Disable SSRF (no user-controlled URLs)
```

---

## Monitor vs Enforce Mode

| Mode | Behavior | Use Case |
|---|---|---|
| `monitor` | All detection runs, events are logged, nothing is blocked | Initial deployment, threshold tuning, testing |
| `enforce` | Requests exceeding block threshold are blocked with 403 | Production protection |
| `disabled` | No inspection, all traffic passes through | Emergency bypass |

**Recommended workflow:**

1. Deploy in `monitor` mode.
2. Observe events for 1–7 days.
3. Review logged events -- identify false positives.
4. Add exclusions or adjust thresholds for false positives.
5. Switch to `enforce` mode.
6. Continue monitoring events and refining.

Switch modes without restart:

```bash
# Via MCP tool
guardianwaf_set_mode {"mode": "enforce"}

# Via REST API
curl -X PUT http://localhost:9443/api/v1/config \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"mode": "enforce"}'

# Via CLI flag
guardianwaf serve --mode enforce
```

---

## Common Scenarios

### Scenario 1: API Receiving SQL-Like Query Language

Your API has a search endpoint that accepts queries like `SELECT name FROM products WHERE price > 100`.

**Problem:** The SQLi detector flags these as attacks.

**Solution:**

<!-- guardianwaf-config:validate -->
```yaml
waf:
  detection:
    exclusions:
      - path: /api/search
        detectors: [sqli]
        reason: "Custom query language uses SQL keywords"
```

### Scenario 2: Rich Text Editor (HTML Content)

Your CMS allows users to input HTML content.

**Problem:** The XSS detector flags `<h1>`, `<a href=...>`, etc.

**Solution:**

<!-- guardianwaf-config:validate -->
```yaml
waf:
  detection:
    detectors:
      xss:
        multiplier: 0.3      # Reduce global XSS sensitivity
    exclusions:
      - path: /api/content
        detectors: [xss]
        reason: "CMS editor handles HTML content"
```

### Scenario 3: File Upload Endpoint

Your API handles large file uploads that may contain various content.

**Solution:**

<!-- guardianwaf-config:validate -->
```yaml
waf:
  sanitizer:
    path_overrides:
      - path: /api/upload
        max_body_size: 104857600   # 100MB
  detection:
    exclusions:
      - path: /api/upload
        detectors: [sqli, xss, cmdi]
        reason: "File upload content is not interpreted"
```

### Scenario 4: Internal Microservice Communication

Internal services communicate with each other and should not be blocked.

**Solution:**

<!-- guardianwaf-config:validate -->
```yaml
waf:
  ip_acl:
    whitelist:
      # Internal network
      - 10.0.0.0/8
      # Docker network
      - 172.16.0.0/12
```

Whitelisted IPs bypass all checks entirely.

### Scenario 5: High-Security Login Endpoint

Your login endpoint should have extra protection.

**Solution:** Use rate limiting combined with higher detection sensitivity:

<!-- guardianwaf-config:validate -->
```yaml
waf:
  rate_limit:
    rules:
      - id: login
        scope: ip+path
        paths: ["/api/login", "/api/auth"]
        limit: 5
        window: 1m
        burst: 2
        action: block
        auto_ban_after: 10   # Auto-ban IP after 10 rate limit violations
  detection:
    detectors:
      sqli:
        multiplier: 1.5      # More aggressive SQL injection detection
```

### Scenario 6: Too Many False Positives Overall

If you're seeing widespread false positives after deploying:

1. **Raise the block threshold:**
   ```yaml
   waf:
     detection:
       threshold:
         block: 70    # Only block high-confidence attacks
         log: 30      # Still log suspicious activity
   ```

2. **Review logged events** to identify specific patterns causing false positives.

3. **Add targeted exclusions** for specific paths.

4. **Lower multipliers** for the detectors causing the most false positives.

5. **Gradually lower the block threshold** as you refine exclusions.

---

## Using the Check Command for Tuning

Test specific inputs without running the full server:

```bash
# Test a URL your users might send
guardianwaf check --url "/search?q=SELECT brand FROM products" --verbose

# Test with custom config
guardianwaf check -c guardianwaf.yaml --url "/api/content" \
  --method POST \
  --body '<h1>Hello World</h1>' \
  --verbose
```

The verbose output shows exactly which detectors triggered and why, making it straightforward to decide whether to add an exclusion or adjust a threshold.

---

## Rate Limit Tuning

Rate limits prevent abuse without affecting normal traffic:

<!-- guardianwaf-config:validate -->
```yaml
waf:
  rate_limit:
    rules:
      # Global: generous limit for normal browsing
      - id: global
        scope: ip
        limit: 1000
        window: 1m
        burst: 50
        action: block

      # API: moderate limit
      - id: api
        scope: ip+path
        paths: ["/api/"]
        limit: 100
        window: 1m
        burst: 20
        action: block

      # Authentication: strict limit
      - id: auth
        scope: ip+path
        paths: ["/api/login", "/api/register"]
        limit: 5
        window: 1m
        burst: 2
        action: block
        auto_ban_after: 10
```

---

## Monitoring After Tuning

After adjusting thresholds and exclusions, continuously monitor:

1. **Block rate:** `blocked_requests / total_requests` should be low (< 1% for most applications).
2. **Logged events:** Review periodically for new attack patterns or false positives.
3. **Average latency:** Should remain under 1ms. If detection adds noticeable overhead, check if any detectors can be disabled.

Use the dashboard API or MCP tools for ongoing monitoring:

```bash
# Check stats
curl http://localhost:9443/api/v1/stats -H "X-API-Key: your-key"

# Review recent blocks
curl "http://localhost:9443/api/v1/events?action=blocked&limit=20" -H "X-API-Key: your-key"
```
