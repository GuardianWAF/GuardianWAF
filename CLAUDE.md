# GuardianWAF — Claude Code Instructions

## Project Overview
GuardianWAF is a zero-dependency Web Application Firewall written in Go.
Module: `github.com/guardianwaf/guardianwaf`

## Key Constraints
- **ZERO external Go dependencies** — only Go stdlib. No exceptions.
- Frontend (React dashboard) uses npm packages — that's OK, they embed into the Go binary.
- Use `any` instead of `interface{}`
- Use built-in `min`/`max` functions (Go 1.21+)
- Use `range N` for simple loops (Go 1.22+)
- Use `slices.Contains` where applicable

## Build & Test
```bash
make build          # Build binary (includes React dashboard)
make test           # Run all tests with -race
make lint           # Run golangci-lint
make bench          # Run benchmarks
make cover          # Generate coverage report
make docker-test    # Full Docker Compose integration test
make smoke          # Build + run smoke tests
go test ./...       # Quick test all packages
go vet ./...        # Vet all packages

# Dashboard frontend
cd internal/dashboard/ui && npm install && npm run build
cp -r internal/dashboard/ui/dist/* internal/dashboard/dist/
```

## Architecture
13-layer pipeline executed in order:
1. IP ACL (100) — radix tree CIDR matching
2. Threat Intel (125) — IP/domain reputation feeds with LRU cache
3. CORS (150) — origin validation, preflight caching
4. Custom Rules (150) — geo-aware rule engine
5. Rate Limit (200) — token bucket per IP/path, auto-ban
6. ATO Protection (250) — brute force, credential stuffing, password spray, impossible travel
7. API Security (275) — JWT validation (RS256/ES256/HS256), API key auth
8. Sanitizer (300) — normalize + validate requests
9. Detection (400) — 6 detectors: sqli, xss, lfi, cmdi, xxe, ssrf
10. Bot Detection (500) — JA3/JA4 TLS fingerprinting, UA, behavioral analysis
11. Response (600) — security headers, data masking
12. JS Challenge — SHA-256 proof-of-work for suspicious requests (score 40-79)
13. AI Analysis — background batch threat analysis via LLM (configurable provider)

## Package Layout
- `cmd/guardianwaf/` — CLI (serve, sidecar, check, validate)
- `internal/engine/` — Core engine, pipeline, scoring, context, access logging, panic recovery
- `internal/config/` — Custom YAML parser, config structs, validation, YAML serializer
- `internal/layers/` — All WAF layers (ipacl, threatintel, cors, ratelimit, ato, apisecurity, sanitizer, detection/*, botdetect, challenge, response, rules)
- `internal/proxy/` — Reverse proxy, load balancer (RR/weighted/least-conn/ip-hash), health check, circuit breaker, host-based router, WebSocket support
- `internal/tls/` — TLS cert store, SNI-based cert selection, hot-reload, HTTP/2 support
- `internal/dashboard/` — Web UI (React+Vite+TailwindCSS), REST API, SSE, config editor, AI page, routing topology graph (React Flow)
- `internal/mcp/` — MCP JSON-RPC server (15 tools)
- `internal/events/` — Event storage (memory ring buffer, JSONL file)
- `internal/ai/` — AI threat analysis (provider catalog from models.dev, OpenAI-compatible client, batch analyzer, cost control, JSON store)
- `internal/docker/` — Docker auto-discovery (Unix socket/CLI, label-based routing, event watcher)
- `internal/geoip/` — GeoIP database with auto-refresh
- `internal/acme/` — ACME/Let's Encrypt auto-certificate (HTTP-01)
- `guardianwaf.go` + `options.go` — Public library API

## Docker Auto-Discovery
- Watches Docker daemon for containers with `gwaf.*` labels
- Auto-creates upstreams, routes, virtual hosts from labels
- Event-driven (container start/stop) + poll fallback
- Zero-downtime atomic proxy rebuild on changes
- Platform-agnostic: Unix socket (Linux), named pipe (Windows), Docker CLI
- Label format: `gwaf.enable`, `gwaf.host`, `gwaf.port`, `gwaf.upstream`, `gwaf.path`, `gwaf.weight`, `gwaf.lb`, `gwaf.health.path`, etc.

## AI Threat Analysis
- Background batch processor (NOT per-request — too slow/expensive)
- Fetches provider/model catalog from models.dev
- OpenAI-compatible API client (works with any provider)
- Configurable cost limits (tokens/hour, tokens/day, requests/hour)
- Auto-block IPs based on AI verdict (confidence >= 70%)
- Dashboard UI for provider config, analysis history, usage stats

## Proxy & Routing
- Multi-upstream with multiple targets per upstream
- 4 load balancing strategies: round_robin, weighted, least_conn, ip_hash
- Active health checks (configurable interval, timeout, path)
- Circuit breaker per target (5 failures → open → 30s → half-open → probe)
- Virtual hosts: domain-based routing via Host header
- Wildcard domain support (*.example.com)
- TLS termination with SNI cert selection, cert hot-reload, HTTP/2
- WebSocket proxy support (Upgrade header forwarding)
- Docker auto-discovery: label-based automatic upstream/route creation

## Observability
- Prometheus `/metrics` endpoint (requests, blocks, latency)
- `/healthz` endpoint (JSON status for K8s probes)
- Structured access logging (JSON or text format)
- Log level filtering (debug/info/warn/error)
- Real-time SSE event streaming to dashboard
- Application log buffer with level filtering

## Scoring System
- Each detector produces scores 0-100
- Scores accumulate per-request
- block_threshold: 50 (default), log_threshold: 25
- Score 40-79 with bot detection → JS challenge
- Per-detector multipliers adjust sensitivity

## Dashboard
- Real-time monitoring UI on `:9443` (React + Vite + Tailwind)
- Pages: Dashboard, Routing (topology graph + config), Rules, WAF Config, AI Analysis, Logs
- Routing topology: interactive React Flow graph with TLS/SSL, ports, health status
- REST API: stats, events, config, IP ACL, rules, routing, AI, Docker discovery
- SSE streaming for live event feed
- Config persistence: changes saved to YAML file on disk

## CLI Commands
```
guardianwaf serve     # Standalone reverse proxy (full features)
guardianwaf sidecar   # Lightweight proxy (no dashboard/MCP)
guardianwaf check     # Dry-run request test
guardianwaf validate  # Config validation
```
