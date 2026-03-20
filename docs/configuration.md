# Configuration Reference

GuardianWAF uses a layered configuration system: defaults, then YAML file, then environment variables, then CLI flags.

---

## Configuration Layering

```
Defaults → YAML file → Environment variables → CLI flags
```

Each layer overrides the previous. If you set `mode: monitor` in the YAML file and pass `--mode enforce` on the CLI, the mode will be `enforce`.

---

## Full YAML Schema

```yaml
# ─────────────────────────────────────────────────────────────────────────────
# Top-level settings
# ─────────────────────────────────────────────────────────────────────────────

# WAF operation mode.
#   enforce  — block requests that exceed the block threshold
#   monitor  — log everything, block nothing (learning mode)
#   disabled — pass all traffic without inspection
mode: enforce                    # Default: enforce

# HTTP listen address.
listen: ":8088"                  # Default: :8088

# ─────────────────────────────────────────────────────────────────────────────
# TLS
# ─────────────────────────────────────────────────────────────────────────────

tls:
  enabled: false                 # Default: false
  listen: ":8443"                # Default: :8443
  cert_file: ""                  # Required if enabled and ACME is off
  key_file: ""                   # Required if enabled and ACME is off

  acme:
    enabled: false               # Enable automatic certificate provisioning
    email: ""                    # Required when ACME is enabled
    domains: []                  # Required when ACME is enabled
    cache_dir: "/var/lib/guardianwaf/acme"

# ─────────────────────────────────────────────────────────────────────────────
# Upstreams (backend targets)
# ─────────────────────────────────────────────────────────────────────────────

upstreams:
  - name: backend                # Unique name referenced by routes
    targets:
      - url: "http://localhost:3000"
        weight: 1                # Default: 1 (for weighted load balancing)
    load_balancer: round_robin   # Options: round_robin, weighted, least_conn, ip_hash
    health_check:
      enabled: true
      interval: 10s
      timeout: 5s
      path: /healthz

# ─────────────────────────────────────────────────────────────────────────────
# Routes (path → upstream mapping)
# ─────────────────────────────────────────────────────────────────────────────

routes:
  - path: /                      # Path prefix to match
    upstream: backend            # Name of upstream defined above
    strip_prefix: false          # Strip the path prefix before forwarding
    methods: []                  # Allowed methods (empty = all methods)

  - path: /api
    upstream: backend
    strip_prefix: true
    methods: [GET, POST, PUT, DELETE]

# ─────────────────────────────────────────────────────────────────────────────
# WAF settings
# ─────────────────────────────────────────────────────────────────────────────

waf:

  # ── IP Access Control ───────────────────────────────────────────────────
  ip_acl:
    enabled: true                # Default: true
    whitelist: []                # IPs/CIDRs that bypass all checks
      # - "10.0.0.0/8"
      # - "192.168.1.100"
    blacklist: []                # IPs/CIDRs that are always blocked
      # - "203.0.113.0/24"
    auto_ban:
      enabled: true              # Default: true
      default_ttl: 1h           # Default ban duration
      max_ttl: 24h              # Maximum ban duration (escalation)

  # ── Rate Limiting ───────────────────────────────────────────────────────
  rate_limit:
    enabled: true                # Default: true
    rules:
      - id: global               # Unique rule ID
        scope: ip                # Scope: "ip" or "ip+path"
        limit: 1000              # Max requests per window
        window: 1m               # Time window
        burst: 50                # Burst allowance
        action: block            # "block" or "log"
        # paths: ["/api/"]       # Optional path filter (empty = all paths)
        # auto_ban_after: 5      # Auto-ban after N violations

      - id: login
        scope: ip+path
        paths: ["/api/login"]
        limit: 5
        window: 1m
        burst: 2
        action: block
        auto_ban_after: 10

  # ── Request Sanitizer ───────────────────────────────────────────────────
  sanitizer:
    enabled: true                # Default: true
    max_url_length: 8192         # Default: 8192 bytes
    max_header_size: 8192        # Default: 8192 bytes (total headers)
    max_header_count: 100        # Default: 100 headers
    max_body_size: 10485760      # Default: 10MB (10 * 1024 * 1024)
    max_cookie_size: 4096        # Default: 4096 bytes
    block_null_bytes: true       # Default: true
    normalize_encoding: true     # Default: true (URL-decode, normalize)
    strip_hop_by_hop: true       # Default: true
    allowed_methods:             # Default: common HTTP methods
      - GET
      - POST
      - PUT
      - PATCH
      - DELETE
      - HEAD
      - OPTIONS
    path_overrides:              # Per-path limit overrides
      - path: /api/upload
        max_body_size: 104857600 # 100MB for upload endpoints

  # ── Detection Engine ────────────────────────────────────────────────────
  detection:
    enabled: true                # Default: true
    threshold:
      block: 50                  # Default: 50 (block when score >= 50)
      log: 25                    # Default: 25 (log when score >= 25)
    detectors:
      sqli:
        enabled: true            # Default: true
        multiplier: 1.0          # Score multiplier (0.5 = half, 2.0 = double)
      xss:
        enabled: true
        multiplier: 1.0
      lfi:
        enabled: true
        multiplier: 1.0
      cmdi:
        enabled: true
        multiplier: 1.0
      xxe:
        enabled: true
        multiplier: 1.0
      ssrf:
        enabled: true
        multiplier: 1.0
    exclusions:                  # Skip detectors for specific paths
      - path: /api/webhook
        detectors: [sqli, xss]
        reason: "Webhook receives arbitrary payloads"
      - path: /api/markdown
        detectors: [xss]
        reason: "Markdown editor allows HTML-like input"

  # ── Bot Detection ───────────────────────────────────────────────────────
  bot_detection:
    enabled: true                # Default: true
    mode: monitor                # "monitor" or "enforce"
    tls_fingerprint:
      enabled: true              # Default: true
      known_bots_action: block   # Action for known scanner fingerprints
      unknown_action: log        # Action for unrecognized fingerprints
      mismatch_action: log       # Action for UA/TLS mismatches
    user_agent:
      enabled: true              # Default: true
      block_empty: true          # Block requests with no User-Agent
      block_known_scanners: true # Block known vulnerability scanners
    behavior:
      enabled: true              # Default: true
      window: 5m                 # Observation window
      rps_threshold: 10          # Max requests per second per IP
      error_rate_threshold: 30   # Block if >30% of requests are errors

  # ── Response Protection ─────────────────────────────────────────────────
  response:
    security_headers:
      enabled: true              # Default: true
      hsts:
        enabled: true
        max_age: 31536000        # 1 year
        include_subdomains: true
      x_content_type_options: true
      x_frame_options: SAMEORIGIN
      referrer_policy: strict-origin-when-cross-origin
      permissions_policy: "camera=(), microphone=(), geolocation=()"
    data_masking:
      enabled: true              # Default: true
      mask_credit_cards: true
      mask_ssn: true
      mask_api_keys: true
      strip_stack_traces: true
    error_pages:
      enabled: true
      mode: production           # "production" (minimal info) or "development"

# ─────────────────────────────────────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────────────────────────────────────

dashboard:
  enabled: true                  # Default: true
  listen: ":9443"                # Default: :9443
  api_key: ""                    # Set to require X-API-Key header
  tls: true                     # Default: true

# ─────────────────────────────────────────────────────────────────────────────
# MCP Server (Model Context Protocol)
# ─────────────────────────────────────────────────────────────────────────────

mcp:
  enabled: true                  # Default: true
  transport: stdio               # Default: stdio

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging:
  level: info                    # Options: debug, info, warn, error
  format: json                   # Options: json, text
  output: stdout                 # "stdout", "stderr", or file path
  log_allowed: false             # Log allowed (non-suspicious) requests
  log_blocked: true              # Log blocked requests
  log_body: false                # Include request body in logs

# ─────────────────────────────────────────────────────────────────────────────
# Events
# ─────────────────────────────────────────────────────────────────────────────

events:
  storage: memory                # "memory" or "file"
  max_events: 100000             # Default: 100000
  file_path: /var/log/guardianwaf/events.jsonl  # Used when storage is "file"
```

---

## Environment Variable Overrides

All environment variables use the `GWAF_` prefix. These override values from the YAML file.

| Variable | Config Path | Example |
|---|---|---|
| `GWAF_MODE` | `mode` | `monitor` |
| `GWAF_LISTEN` | `listen` | `:9090` |
| `GWAF_LOGGING_LEVEL` | `logging.level` | `debug` |
| `GWAF_LOGGING_FORMAT` | `logging.format` | `text` |
| `GWAF_LOGGING_OUTPUT` | `logging.output` | `/var/log/guardianwaf.log` |
| `GWAF_WAF_DETECTION_THRESHOLD_BLOCK` | `waf.detection.threshold.block` | `60` |
| `GWAF_WAF_DETECTION_THRESHOLD_LOG` | `waf.detection.threshold.log` | `30` |
| `GWAF_DASHBOARD_ENABLED` | `dashboard.enabled` | `false` |
| `GWAF_DASHBOARD_LISTEN` | `dashboard.listen` | `:8443` |
| `GWAF_DASHBOARD_API_KEY` | `dashboard.api_key` | `my-secret-key` |
| `GWAF_EVENTS_STORAGE` | `events.storage` | `file` |
| `GWAF_EVENTS_FILE_PATH` | `events.file_path` | `/var/log/events.jsonl` |
| `GWAF_EVENTS_MAX_EVENTS` | `events.max_events` | `50000` |
| `GWAF_TLS_ENABLED` | `tls.enabled` | `true` |
| `GWAF_TLS_LISTEN` | `tls.listen` | `:8443` |
| `GWAF_TLS_CERT_FILE` | `tls.cert_file` | `/etc/ssl/cert.pem` |
| `GWAF_TLS_KEY_FILE` | `tls.key_file` | `/etc/ssl/key.pem` |

Example:

```bash
GWAF_MODE=monitor GWAF_LISTEN=:9090 guardianwaf serve
```

---

## CLI Flag Overrides

CLI flags override both the YAML file and environment variables.

### `serve` command

```
guardianwaf serve [options]

  -c, --config      Path to config file (default: guardianwaf.yaml)
  -l, --listen      Override listen address
  -m, --mode        Override WAF mode (enforce/monitor/disabled)
      --dashboard   Override dashboard listen address
      --log-level   Override log level (debug/info/warn/error)
```

### `sidecar` command

```
guardianwaf sidecar [options]

  -c, --config      Path to config file (optional)
  -u, --upstream    Upstream URL (required if no config)
  -l, --listen      Listen address (default: :8088)
  -m, --mode        Override WAF mode
```

### `check` command

```
guardianwaf check [options]

  -c, --config      Path to config file (default: guardianwaf.yaml)
      --url         URL path to test (required)
      --method      HTTP method (default: GET)
  -H                HTTP header (repeatable, format: "Name: Value")
      --body        Request body content
  -v, --verbose     Show detailed detection results
```

### `validate` command

```
guardianwaf validate [options]

  -c, --config      Path to config file (default: guardianwaf.yaml)
```

---

## Hot Reload

GuardianWAF supports hot-reloading configuration changes without restarting.

### Via REST API

```bash
curl -X POST http://localhost:9443/api/v1/config/reload \
  -H "X-API-Key: your-secret-key"
```

Reloadable settings include:
- WAF mode (enforce / monitor / disabled)
- Scoring thresholds (block, log)
- Maximum body size

Layer-level changes (adding/removing detectors, IP ACL entries, rate limit rules) are applied through the respective REST API endpoints without requiring a full reload.

---

## Default Values

When no config file is provided, GuardianWAF uses production-safe defaults:

| Setting | Default |
|---|---|
| Mode | `enforce` |
| Listen | `:8088` |
| Block threshold | `50` |
| Log threshold | `25` |
| All 6 detectors | Enabled, multiplier `1.0` |
| Rate limit | 1000 req/min per IP, burst 50 |
| Max URL length | 8192 bytes |
| Max header size | 8192 bytes |
| Max body size | 10 MB |
| Bot detection | Enabled (monitor mode) |
| Security headers | Enabled (HSTS, X-Frame-Options, etc.) |
| Data masking | Enabled (credit cards, SSN, API keys) |
| Dashboard | Enabled on `:9443` |
| MCP | Enabled (stdio) |
| Logging | JSON to stdout, info level |
| Events | In-memory, 100,000 max |
