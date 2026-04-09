# GuardianWAF Architecture Map

## Overview

GuardianWAF is a zero-dependency Web Application Firewall written in Go 1.25+.
Module: `github.com/guardianwaf/guardianwaf`

## Two HTTP Surfaces

| Surface | Port | Purpose | Auth |
|---------|------|---------|------|
| Proxy server | `:8088` / `:8443` (TLS) | Inbound traffic → WAF pipeline → upstream | N/A (WAF itself protects) |
| Dashboard API | `:9443` | Admin REST API + React SPA | API key (`X-API-Key`) or session cookie |
| MCP Server | stdio / SSE | JSON-RPC 2.0 tool interface | Shared secret |

## WAF Pipeline (Layer Order)

```
IPACL(100) → ThreatIntel(125) → CORS(150) → Rules(150) → RateLimit(200) →
ATO(250) → APISecurity(275) → APIValidation(280) → Sanitizer(300) →
CRS(350) → Detection(400) → VirtualPatch(450) → DLP(475) →
BotDetect(500) → ClientSide(590) → Response(600)
```

Short-circuits on `ActionBlock`. Scores accumulate via `ScoreAccumulator`.

## Trust Boundaries

- **Dashboard auth:** `internal/dashboard/auth.go` — session cookie (HMAC-SHA256) + API key via `X-API-Key` header
- **Tenant isolation:** `internal/tenant/` — per-tenant WAF config, rate limits, rules, events
- **Rate limiting:** `internal/layers/ratelimit/` — token bucket per IP or IP+path
- **IP ACL:** `internal/layers/ipacl/` — radix tree CIDR matching with auto-ban
- **Challenge:** `internal/layers/challenge/` — SHA-256 proof-of-work via JS

## External Integrations

| Integration | File | Protocol |
|-------------|------|----------|
| ACME/Let's Encrypt | `internal/acme/` | HTTPS (RFC 8555) |
| AI providers | `internal/ai/` | HTTPS (OpenAI-compatible API) |
| models.dev catalog | `internal/ai/provider.go` | HTTPS |
| Docker daemon | `internal/docker/` | Unix socket / named pipe / CLI |
| GeoIP | `internal/geoip/` | CSV file |
| Threat intel feeds | `internal/layers/threatintel/feed.go` | HTTPS |
| Webhooks | `internal/alerting/webhook.go` | HTTPS (Slack, Discord, PagerDuty) |
| Email alerts | `internal/alerting/email.go` | SMTP |
| Cluster sync | `internal/clustersync/` | HTTPS on port 9444 |
| MCP SSE | `internal/mcp/sse.go` | HTTP/SSE |

## Configuration Loading

```
defaults → YAML file → env vars (GWAF_ prefix) → CLI flags
```

Custom zero-dependency YAML parser (no `yaml` struct tags — uses Node tree walking).

## Key Files

| Concern | File |
|---------|------|
| Pipeline execution | `internal/engine/engine.go`, `pipeline.go` |
| Request context | `internal/engine/context.go` |
| Dashboard routes | `internal/dashboard/dashboard.go` |
| Dashboard auth | `internal/dashboard/auth.go` |
| Dashboard middleware | `internal/dashboard/middleware.go` |
| Proxy routing | `internal/proxy/router.go` |
| Proxy targets | `internal/proxy/target.go` |
| TLS cert store | `internal/tls/certstore.go` |
| JWT validation | `internal/layers/apisecurity/jwt.go` |
| Detection engines | `internal/layers/detection/{sqli,xss,lfi,cmdi,xxe,ssrf}/` |
| CORS | `internal/layers/cors/cors.go` |
| WebSocket | `internal/layers/websocket/websocket.go` |
| Rate limiting | `internal/layers/ratelimit/ratelimit.go` |
| Cluster sync | `internal/clustersync/manager.go`, `handlers.go` |
| Tenant management | `internal/tenant/manager.go`, `handlers.go`, `middleware.go` |
| AI analysis | `internal/ai/analyzer.go`, `client.go`, `provider.go` |
| MCP tools | `internal/mcp/tools.go`, `handlers.go` |
| Public API | `guardianwaf.go`, `options.go` |
