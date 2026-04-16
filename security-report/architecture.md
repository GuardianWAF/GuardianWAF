# GuardianWAF Security Architecture Report

## 1. Architecture Overview

### Project Identity
GuardianWAF is a production-grade Web Application Firewall (WAF) written in pure Go (zero external dependencies). It operates as a reverse proxy.

### Core Function
GuardianWAF sits between clients and backend servers. All traffic to protected backends flows through the WAF, which applies security checks at each layer.

### Deployment Modes
1. Standalone reverse proxy (guardianwaf serve)
2. Sidecar proxy (guardianwaf sidecar)
3. Go library middleware (guardianwaf.Middleware)

### Request Flow
HTTP Request -> IP ACL (100) -> Threat Intel (125) -> CORS (150) -> Rate Limit (200) -> ATO (250) -> API Security (275) -> Sanitizer (300) -> Detection (400) -> Bot Detect (500) -> Response (600) -> JS Challenge -> Upstream Load Balancer

## 2. Tech Stack

### Go Version
Go 1.25.0

### Dependencies
Only github.com/quic-go/quic-go v0.59.0 for HTTP/3 (optional build tag). Without http3 tag, zero external dependencies.

### Custom YAML Parser
internal/config/yaml.go - zero-dependency parser. No anchors, aliases, tags, or multi-document.

### Environment Variable Expansion
expandEnvVars supports dollar-curly syntax for env var substitution.

## 3. Key Entry Points

### CLI
cmd/guardianwaf/main.go or main_default.go

Commands: serve, sidecar, check, validate, test-alert, setup, version

### Library Mode
guardianwaf.go, options.go
- guardianwaf.New, NewFromFile, NewWithDefaults
- Engine.Middleware, Check, OnEvent, Stats, Close

### HTTP Handlers
/healthz, /metrics, /_guardian/report, challenge verify, dashboard

## 4. Core Components

### internal/engine/
engine.go, pipeline.go, context.go, finding.go, event.go, layer.go, blockpage.go, response_writer.go, logbuffer.go

### internal/layers/
ipacl(100), threatintel(125), cors(150), ratelimit(200), ato(250), apisecurity(275), sanitizer(300), detection(400), botdetect(500), response(600)

### internal/proxy/
proxy.go, router.go, balancer.go, target.go, health.go, circuit.go

### internal/config/
config.go, defaults.go, yaml.go, serialize.go, validate.go

### internal/dashboard/
dashboard.go, auth.go, middleware.go

### internal/tls/
certstore.go

## 5. Security Boundaries

### HTTP Request Fields
All treated as untrusted: path, query params, headers, body, cookies, TLS info (JA3/JA4)

### Configuration
YAML parser with expandEnvVars. Security fields: trusted_proxies, dashboard.api_key, tls paths, challenge.secret_key, alerting passwords

### Docker Socket
Reads gwaf.* labels when enabled (privileged)

### Dashboard Auth
X-API-Key header only, HMAC-SHA256 IP-bound session cookies (24h sliding, 7d max), per-tenant API keys, 5 concurrent sessions per IP max

## 6. Trust Boundaries

### Client IP Extraction
RemoteAddr fallback, X-Forwarded-For only from trusted_proxies CIDRs (default: empty)

### Configuration Precedence
DefaultConfig -> YAML file -> Environment (GWAF_) -> CLI flags

### Multi-Tenancy
Tenant isolation via /t/{tenant-id}/ or X-Tenant-ID header

## 7. Security Controls

### TLS
SNI cert selection, hot-reload, ACME/Let's Encrypt, HTTP/3 optional

### Auth
HMAC session tokens, constant-time API key comparison, crypto/rand

### Input Validation
MaxURLLength 8192, MaxHeaderSize 8192, MaxHeaderCount 100, MaxBodySize 10MB, MaxCookieSize 4096, BlockNullBytes, NormalizeEncoding, StripHopByHop, AllowedMethods

### Attack Detection
sqli, xss, lfi, cmdi, xxe, ssrf - tokenizer-based. Default thresholds: Block=50, Log=25

### Rate Limiting
Token bucket O(1), 1000 req/min per IP default, auto-ban

### IP ACL
Radix tree O(k), whitelist, blacklist, auto-ban (100K entries max)

### PoW Challenge
SHA-256, 20 leading zero bits default, HMAC-signed cookie (1h)

### Response Protection
HSTS, X-Content-Type-Options, X-Frame-Options, data masking (cards, SSN, API keys), stack trace stripping

### Alerting
Webhook/email with TLS, per-event filtering, score thresholds, cooldowns

## Summary

| Category | Status |
|----------|--------|
| Transport security | TLS + ACME, HTTP/3 optional |
| Authentication | HMAC session tokens, API keys, per-tenant scoping |
| Input validation | Size limits, null byte stripping, encoding normalization |
| Attack detection | 6 tokenizer-based detectors, configurable thresholds |
| Bot mitigation | TLS fingerprinting, UA analysis, PoW challenge |
| Rate limiting | Token bucket, per-IP/path, auto-ban |
| IP ACL | Radix tree, auto-ban |
| Dependencies | Zero external (HTTP/3 optional) |
