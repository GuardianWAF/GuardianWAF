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

<!-- guardianwaf-config:validate -->
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

# Direct peer CIDRs/IPs whose proxy headers are trusted.
# Leave empty when GuardianWAF is directly internet-facing. Configure only the
# actual load balancer, ingress, or reverse proxy addresses that connect to
# GuardianWAF; never trust broad client networks.
trusted_proxies: []              # Example: ["10.0.0.10", "192.0.2.0/24"]

# Private/reserved upstreams are blocked by default. Prefer a narrow allowlist
# for service-network backends; use allow_private_upstreams only when the whole
# deployment intentionally trusts all configured private upstream targets.
allowed_upstream_cidrs: []        # Example: ["10.0.0.0/16", "127.0.0.1"]
allow_private_upstreams: false    # Default: false

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

  # ── GeoIP Enrichment ───────────────────────────────────────────────────
  geoip:
    enabled: false               # Default: false
    db_path: ""                  # CSV database path
    auto_download: false         # Download DB when missing
    download_url: ""             # Optional custom GeoIP download URL (must be https://)
    require_ready: false         # If true, /readyz fails until GeoIP is loaded
    allow_insecure_url: false    # Permit a cleartext http:// download_url (see below)

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
  api_key: ""                    # Empty generates a strong random key at startup
  admin_key: ""                  # Required for tenant-admin endpoints; empty disables them
  tls: false                     # Dashboard TLS is not terminated in-process; use ingress/reverse proxy TLS

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
  log_body: false                # Security risk: request bodies may contain credentials/PII; keep false unless explicitly debugging in a controlled environment

# ─────────────────────────────────────────────────────────────────────────────
# Events
# ─────────────────────────────────────────────────────────────────────────────

events:
  storage: memory                # "memory" or "file"
  max_events: 100000             # Default: 100000
  file_path: /var/log/guardianwaf/events.jsonl  # Persistent JSONL when storage is "file"

`memory` keeps only an in-process ring buffer. `file` keeps the same queryable ring buffer, replays the JSONL file on startup, and appends new events to `file_path`; startup fails if the configured file cannot be opened.

# ─────────────────────────────────────────────────────────────────────────────
# Alerting (Webhooks & Email)
# ─────────────────────────────────────────────────────────────────────────────

alerting:
  enabled: false                 # Default: false

  # Webhook targets (Slack, Discord, PagerDuty, generic)
  webhooks:
    - name: "security-slack"     # Human-readable name
      url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
      type: "slack"              # Options: slack, discord, pagerduty, generic
      events: ["block", "challenge"]  # Which events to alert on: block, challenge, log, all
      min_score: 50              # Minimum score to trigger alert
      cooldown: 5m               # Cooldown between alerts from same IP
      headers: {}                # Additional headers for generic webhooks

    - name: "security-discord"
      url: "https://discord.com/api/webhooks/YOUR/WEBHOOK"
      type: "discord"
      events: ["block"]
      min_score: 50
      cooldown: 5m

    - name: "pagerduty"
      url: "https://events.pagerduty.com/v2/enqueue"
      type: "pagerduty"
      events: ["block", "challenge"]
      min_score: 50
      cooldown: 1m
      headers:
        Authorization: "Token token=YOUR_ROUTING_KEY"

  # Email alerts via SMTP
  emails:
    - name: "security-team"
      smtp_host: "smtp.gmail.com"
      smtp_port: 587             # Default: 587
      username: "your-email@gmail.com"
      password: "your-app-password"
      from: "alerts@yourdomain.com"
      to: ["security@yourdomain.com", "admin@yourdomain.com"]
      use_tls: true              # Enable TLS encryption
      events: ["block"]          # Events to send email for
      min_score: 75              # Higher threshold for emails
      cooldown: 15m              # Longer cooldown for emails
      subject: "[GuardianWAF] Security Alert - {{Action}} from {{ClientIP}}"
      template: |                # Optional custom email template
        Event ID: {{EventID}}
        Action: {{Action}}
        Client IP: {{ClientIP}}
        Score: {{Score}}
        Path: {{Method}} {{Path}}
```

---

## Cleartext Fetch URLs

Two settings pull data from a remote source that then steers WAF decisions:

| Setting | What it fetches | What tampering changes |
|---|---|---|
| `waf.threat_intel.feeds[].url` | IP/domain reputation entries | Which clients get blocked — an attacker on the path can both clear their own address and blocklist legitimate traffic |
| `waf.geoip.download_url` | The GeoIP database | Which country a client resolves to, and therefore how geo rules apply |

Both are validated at startup and **must use `https://`**. Configuring an
`http://` URL fails config validation with a message naming the field, so the
process refuses to start rather than silently fetching security-relevant data
over a channel anyone on the path can rewrite.

If you genuinely need cleartext — a mirror on a trusted, isolated network, for
example — opt in explicitly:

<!-- guardianwaf-config:validate -->
```yaml
waf:
  geoip:
    download_url: "http://mirror.internal/dbip-lite.csv"
    allow_insecure_url: true          # acknowledges the tamper risk

  threat_intel:
    feeds:
      - type: url
        url: "http://mirror.internal/bad-ips.txt"
        format: jsonl
        allow_insecure_url: true      # per-feed, not global
```

`allow_insecure_url` is scoped per feed, so one internal mirror does not weaken
the rest. Values written as `${PLACEHOLDER}` are resolved after validation and
are therefore not checked at startup — the scheme of whatever they expand to is
your responsibility.

---

## Built-in Tracing

The optional tracing runtime creates one root span per sampled request and a
child span for each active WAF layer. Tracers are engine-local, survive config
reload through atomic reconfiguration, and close with their owning engine.

```yaml
tracing:
  enabled: true
  service_name: guardianwaf
  sampling_rate: 0.1
  exporter_type: stdout
```

`sampling_rate` must be a finite value from `0` to `1`. The built-in exporter
types are `noop` and `stdout`; unsupported values fail config validation.
`stdout` emits one JSON line synchronously per completed span and is intended
for controlled diagnostics with sampling. GuardianWAF does not currently ship
an OTLP/Jaeger network exporter or W3C trace-context propagation; do not use
design-era OTLP fields such as `endpoint` or `export_interval` in production
config.

---

## SIEM Export

Forward block and challenge events to an external SIEM (Splunk, QRadar, Sentinel) via CEF over TLS syslog (RFC 5425 port 6514).

<!-- guardianwaf-config:validate -->
```yaml
waf:
  siem:
    enabled: true
    endpoint: "siem.example.com:6514"   # host:port of TLS syslog receiver
    format: cef                          # cef | json
    batch_size: 100                      # flush at N events (default: 100)
    flush_interval: 1s                   # or every duration (default: 1s)
    timeout: 10s                         # connection/write timeout (default: 10s)
    skip_verify: false                   # set true to skip TLS cert verification
```

The exporter subscribes to the event bus asynchronously — it never blocks request processing. Only `block` and `challenge` actions are forwarded; passed traffic is silently dropped. The exporter auto-reconnects with exponential backoff on failure.

---

## WebSocket Inspection

GuardianWAF can inspect WebSocket text frames through the full detection pipeline (SQLi, XSS, CMDi, etc.) and enforce connection-level security controls.

<!-- guardianwaf-config:validate -->
```yaml
waf:
  websocket:
    enabled: true
    scan_payloads: true                  # run detection pipeline on text frames
    max_frame_size: 1048576              # max bytes per frame (default: 1 MB)
    max_concurrent_per_ip: 100           # concurrent WS connections per IP
    block_binary_messages: false         # reject all binary frames
    allowed_origins: []                  # empty = allow all; set to restrict (CSWSH protection)
    idle_timeout: 60s                    # close idle connections
```

When enabled, GuardianWAF hijacks WebSocket upgrade requests, validates the Origin header (CSWSH protection), dials the backend, and copies frames bidirectionally with inspection. Non-upgrade requests pass through unaffected. Binary frames are size-checked only; text frames are scanned through all enabled detectors.

---

## Environment Variable Overrides

All environment variables use the `GWAF_` prefix. These override values from the YAML file.
Boolean, integer, and numeric overrides are validated before any environment
overrides are applied. An invalid typed value fails startup/validation instead
of silently retaining a default.

| Variable | Config Path | Example |
|---|---|---|
| `GWAF_MODE` | `mode` | `monitor` |
| `GWAF_LISTEN` | `listen` | `:9090` |
| `GWAF_TRUSTED_PROXIES` | `trusted_proxies` | `10.0.0.0/8,192.0.2.10` |
| `GWAF_ALLOW_PRIVATE_UPSTREAMS` | `allow_private_upstreams` | `false` |
| `GWAF_ALLOWED_UPSTREAM_CIDRS` | `allowed_upstream_cidrs` | `10.0.1.0/24` |
| `GWAF_LOGGING_LEVEL` | `logging.level` | `debug` |
| `GWAF_LOGGING_FORMAT` | `logging.format` | `text` |
| `GWAF_LOGGING_OUTPUT` | `logging.output` | `/var/log/guardianwaf.log` |
| `GWAF_WAF_DETECTION_THRESHOLD_BLOCK` | `waf.detection.threshold.block` | `60` |
| `GWAF_WAF_DETECTION_THRESHOLD_LOG` | `waf.detection.threshold.log` | `30` |
| `GWAF_DASHBOARD_ENABLED` | `dashboard.enabled` | `false` |
| `GWAF_DASHBOARD_LISTEN` | `dashboard.listen` | `:8443` |
| `GWAF_DASHBOARD_API_KEY` | `dashboard.api_key` | `my-secret-key` |
| `GWAF_DASHBOARD_ADMIN_KEY` | `dashboard.admin_key` | `my-admin-secret-key` |
| `GWAF_MCP_ENABLED` | `mcp.enabled` | `false` |
| `GWAF_MCP_TRANSPORT` | `mcp.transport` | `stdio` |
| `GWAF_DOCKER_ENABLED` | `docker.enabled` | `false` |
| `GWAF_WAF_AI_ANALYSIS_ENABLED` | `waf.ai_analysis.enabled` | `false` |
| `GWAF_EVENTS_STORAGE` | `events.storage` | `file` |
| `GWAF_EVENTS_FILE_PATH` | `events.file_path` | `/var/log/guardianwaf/events.jsonl` |
| `GWAF_EVENTS_MAX_EVENTS` | `events.max_events` | `50000` |
| `GWAF_TLS_ENABLED` | `tls.enabled` | `true` |
| `GWAF_TLS_LISTEN` | `tls.listen` | `:8443` |
| `GWAF_TLS_CERT_FILE` | `tls.cert_file` | `/etc/ssl/cert.pem` |
| `GWAF_TLS_KEY_FILE` | `tls.key_file` | `/etc/ssl/key.pem` |
| `GWAF_ALERTING_ENABLED` | `alerting.enabled` | `true` |
| `GWAF_TRACING_ENABLED` | `tracing.enabled` | `true` |
| `GWAF_TRACING_SERVICE_NAME` | `tracing.service_name` | `guardianwaf` |
| `GWAF_TRACING_SAMPLING_RATE` | `tracing.sampling_rate` | `0.1` |
| `GWAF_TRACING_EXPORTER_TYPE` | `tracing.exporter_type` | `stdout` |
| `GWAF_LOGGING_MAX_SIZE_MB` | `logging.max_size_mb` | `100` |
| `GWAF_LOGGING_MAX_BACKUPS` | `logging.max_backups` | `5` |
| `GWAF_LOGGING_MAX_AGE_DAYS` | `logging.max_age_days` | `30` |
| `GWAF_COMPLIANCE_ENABLED` | `compliance.enabled` | `true` |
| `GWAF_COMPLIANCE_FRAMEWORKS` | `compliance.frameworks` | `pci_dss,gdpr` |
| `GWAF_COMPLIANCE_REPORT_DIR` | `compliance.report_dir` | `/var/lib/guardianwaf/reports` |
| `GWAF_COMPLIANCE_AUDIT_TRAIL_ENABLED` | `compliance.audit_trail.enabled` | `true` |

Example:

```bash
GWAF_MODE=monitor GWAF_LISTEN=:9090 guardianwaf serve
```

---

## Migrating Legacy Config Keys

GuardianWAF does not silently accept legacy or design-era top-level keys. Unknown keys fail validation with their field path, for example `server: unknown top-level key`. Update old examples before using them in production:

| Legacy key | Current key |
|---|---|
| `server.listen` | `listen` |
| `server.mode` | `mode` |
| `proxy.upstreams` | `upstreams` |
| `proxy.routes` | `routes` |
| `security.waf` | `waf` |

Run `guardianwaf validate -c guardianwaf.yaml` after migration. Public GuardianWAF YAML snippets in this repository must be preceded by `<!-- guardianwaf-config:validate -->` so CI parses them against `internal/config.Config`.

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

## SIEM Export

Forward block and challenge events to external Security Information and Event Management (SIEM) systems via CEF (Common Event Format) over TLS syslog (RFC 5425).

<!-- guardianwaf-config:validate -->
```yaml
waf:
  siem:
    enabled: true
    endpoint: "siem.example.com:6514"   # TLS syslog port (RFC 5425)
    format: cef                          # cef | json
    batch_size: 100                      # flush at N events
    flush_interval: 1s                   # or every interval, whichever first
    timeout: 10s                         # connection and write timeout
    skip_verify: false                   # set true only for self-signed certs
```

| Setting | Default | Description |
|---|---|---|
| `enabled` | `false` | Enable SIEM event forwarding |
| `endpoint` | — | `host:port` of the TLS syslog receiver |
| `format` | `cef` | Event format: `cef` or `json` |
| `batch_size` | `100` | Maximum events per batch |
| `flush_interval` | `1s` | Maximum time between flushes |
| `timeout` | `10s` | Connection and write timeout |
| `skip_verify` | `false` | Skip TLS certificate verification |

The exporter subscribes to the event bus asynchronously — it never blocks request processing. Only `block` and `challenge` events are forwarded. Connection failures trigger exponential backoff with auto-reconnect. Stats are available at `GET /api/v1/stats` under the `siem` key.

---

## WebSocket Inspection

Inspect WebSocket text frames through the full detection pipeline and enforce security controls on WebSocket connections.

<!-- guardianwaf-config:validate -->
```yaml
waf:
  websocket:
    enabled: true
    scan_payloads: true                  # run detection on text frames
    max_frame_size: 1048576              # 1 MB per frame (DoS protection)
    max_concurrent_per_ip: 100           # concurrent WS connections per IP
    block_binary_messages: false         # reject all binary frames
    block_empty_messages: false          # reject empty payloads
    allowed_origins: []                  # restrict origins (CSWSH protection)
    idle_timeout: 60s                    # close idle connections
```

| Setting | Default | Description |
|---|---|---|
| `enabled` | `false` | Enable WebSocket inspection |
| `scan_payloads` | `true` | Run detection pipeline on text frames |
| `max_frame_size` | `1048576` | Maximum frame size in bytes |
| `max_concurrent_per_ip` | `100` | Max concurrent WS connections per IP |
| `block_binary_messages` | `false` | Block all binary frames |
| `block_empty_messages` | `false` | Block empty payloads |
| `allowed_origins` | `[]` | Allowed origins for CSWSH protection (empty = all) |
| `idle_timeout` | `60s` | Close idle connections |

When enabled, GuardianWAF hijacks WebSocket upgrade requests, validates the origin, dials the backend, and copies frames bidirectionally with inspection. Text frames are scanned through the same detection pipeline as HTTP requests (SQLi, XSS, CMDi, SSRF, etc.). Binary frames are size-checked only.

---

## Hot Reload

GuardianWAF supports targeted hot-reloading for a small set of request policy and routing changes. Listener, storage, startup-owned background service, and WAF layer-instance changes require a rolling restart. See [Runtime Reload Contract](runtime-reload.md) for the exact supported set.

### Via REST API

```bash
curl -X POST http://localhost:9443/api/v1/config/reload \
  -H "X-API-Key: your-secret-key"
```

Reloadable settings include:
- WAF mode (enforce / monitor / disabled)
- Scoring thresholds (block, log)
- Maximum request body inspection size
- Trusted proxy CIDRs
- Upstreams/routes through the routing API

Layer-level state changes such as IP ACL entries, auto-bans, and custom rules are applied through their respective REST API endpoints without requiring a full process restart. `PUT /api/v1/config` rejects WAF layer topology or layer configuration changes with `409 Conflict`; apply those changes through your deployment system and perform a rolling restart.

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
