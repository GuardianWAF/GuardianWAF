# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GuardianWAF is a zero-dependency Web Application Firewall written in Go (1.26+; `go.mod` pins 1.26.4).
Module: `github.com/guardianwaf/guardianwaf`

The codebase uses the Go standard library **only** — `go.mod` has zero `require` entries and `go.sum` is empty (verified 2026-06-04, after the dead `internal/http3` package and its sole dependency `quic-go` were removed).

## Key Constraints

- **ZERO external Go dependencies** — only Go stdlib. No exceptions. (`go.mod` has no `require` block; `go.sum` is empty. The former `quic-go`/HTTP-3 dependency was removed on 2026-06-04.)
- Frontend (React dashboard) uses npm packages — that's OK, they embed into the Go binary.
- Use `any` instead of `interface{}`
- Use built-in `min`/`max` functions (Go 1.21+)
- Use `range N` for simple loops (Go 1.22+)
- Use `slices.Contains` where applicable

## Build & Test

```bash
# Build and development
make build          # Build binary (includes React dashboard)
make run            # Build + run serve mode
make ui             # Build React dashboard only
make ui-dev         # Dashboard dev mode (hot reload on :5173, proxies API to :9443)

# Testing
make test           # Run all tests with -race
make vet            # Run go vet
make lint           # Run golangci-lint
make bench          # Run benchmarks
make fuzz           # Run fuzz tests (30s each)
make cover          # Generate coverage report
make smoke          # Build + run smoke tests
make docker-test    # Full Docker Compose integration test

# E2E tests (requires running server — defaults to http://localhost:9443)
make e2e            # Run Playwright tests (Chromium)
make e2e-headed     # Run with browser visible
make e2e-all        # Run all browsers
make e2e-list       # List available E2E tests
# Override defaults: E2E_BASE_URL=http://... E2E_API_KEY=... make e2e

# Running single tests
go test -race -v ./internal/layers/detection/sqli/... -run TestDetector
go test -race -v ./internal/engine/... -run TestPipeline

# Quick validation during development
go test -race -count=1 ./internal/layers/detection/...
go vet ./...

# Code formatting
make fmt            # Format with gofmt -s
make tidy           # Run go mod tidy
```

## Architecture

### Pipeline (core pattern)

All WAF processing flows through a **layer pipeline** (`internal/engine/pipeline.go`). Layers implement the `Layer` interface (`Name() + Process(ctx *RequestContext) LayerResult`) and are sorted by `Order` constant. The pipeline:

1. Iterates layers in order (lowest Order first)
2. Skips `Detector` layers if the path matches an exclusion
3. Layers read `ctx.TenantWAFConfig` directly for per-tenant config overrides (race-free, per-request)
4. Accumulates `Finding` scores via `ScoreAccumulator`
5. **Short-circuits on `ActionBlock`** — immediately returns without running remaining layers
6. `ActionChallenge` only applies if current action is `ActionPass` (block takes priority)

### Request Context

`engine.RequestContext` (`internal/engine/context.go`) carries all per-request state. It's pooled via `sync.Pool` for zero-allocation hot paths:
- Acquired via `AcquireContext()` — parses HTTP request, reads/decompresses body (gzip/deflate), extracts client IP (trusted proxy aware: X-Forwarded-For → X-Real-IP → RemoteAddr; only trusts proxy headers from configured `trusted_proxies` CIDRs)
- Released via `ReleaseContext()` — resets all fields, returns to pool
- Populates JA4 TLS fingerprint fields from custom TLS handler data
- Carries `TenantID` and `TenantWAFConfig` for multi-tenant isolation

### Layer Order Constants

Defined in `internal/engine/layer.go`.

> **⚠️ Accuracy note (verified 2026-06-04):** The serve binary (`cmd/guardianwaf`) wires **16** layers via `layerregistry` — the ones marked ✅ below. The remaining layers in this table are **implemented and unit-tested but NOT compiled into the serve binary**. The `internal/integrations/v040` Integrator that would have wired most of them had zero callers and was **deleted on 2026-06-04** (along with `internal/feature`, `internal/http3`, `internal/analytics` — all dead; see `AUDIT.md` §2). Those ❌ layer packages now have no wiring path at all and are candidates for removal too. The original "29 registered" figure was aspirational/incorrect. Library mode (`guardianwaf.go`) wires only 6 core layers: IP ACL, Rate Limit, Sanitizer, Detection, Bot Detection, Response.

The 16 layers actually wired in serve mode: IP ACL, Threat Intel, CORS, Custom Rules, Rate Limit, ATO Protection, API Security, API Validation, Sanitizer, CRS, Detection, Virtual Patch, DLP, Bot Detection, Client-Side, Response.

**Layer catalogue** — all layers below are wired in serve mode. (The previously-listed
unwired "showcase" layers — SIEM, Cluster, WebSocket, gRPC, Zero Trust, Canary, Cache,
Replay, GraphQL, API Discovery, ML Anomaly, AI Remediation — were **deleted on 2026-06-04**
as dead code with no wiring path; see `AUDIT.md` §2. Their `WAF.*` config structs remain
parsed-but-inert and are rejected as unknown top-level keys.)

| Order | Layer | Description |
|-------|-------|-------------|
| 100 | IP ACL | Radix tree CIDR matching, runtime add/remove, auto-ban |
| 125 | Threat Intel | IP/domain reputation feeds with LRU cache |
| 150 | CORS | Origin validation, preflight caching |
| 150 | Custom Rules | Geo-aware rule engine with dashboard CRUD |
| 200 | Rate Limit | Token bucket per IP/path, auto-ban |
| 250 | ATO Protection | Brute force, credential stuffing, password spray, impossible travel |
| 275 | API Security | JWT validation (RS256/ES256/HS256), API key auth |
| 280 | API Validation | Request/response schema validation (YAML-defined schemas) |
| 300 | Sanitizer | Normalize + validate requests |
| 350 | CRS | OWASP ModSecurity Core Rule Set parser and executor |
| 400 | Detection | 6 detectors: sqli, xss, lfi, cmdi, xxe, ssrf (each in own subdirectory) |
| 430 | JS Challenge | Bot proof-of-work challenge (SHA-256 PoW) — wired via the challenge service |
| 450 | Virtual Patch | Virtual patching layer |
| 475 | DLP | Data Loss Prevention (credit cards, SSNs, API keys, PII) |
| 500 | Bot Detection | JA3/JA4 TLS fingerprinting, UA, behavioral analysis |
| 590 | Client-Side | Client-side protection injection |
| 600 | Response | Security headers, data masking, branded block pages |

(Verified via `go list -deps ./cmd/guardianwaf`.)

### Scoring System

- Each detector produces scores 0-100
- Scores accumulate per-request via `ScoreAccumulator`
- `block_threshold`: 50 (default), `log_threshold`: 25
- Score 40-79 with bot detection → JS challenge
- Per-detector multipliers adjust sensitivity

### Layer vs Library Mode

The `serve` command (`cmd/guardianwaf/main.go` → `cmd/guardianwaf/layers.go`) wires the **16** layers marked ✅ above (via `layerregistry`), plus the JS-challenge service. The remaining (❌) layers exist as packages but are not wired into serve — see `refactor.md` §3.7. The Go library API (`guardianwaf.go`) wires only 6 core layers by default. To add more layers in library mode, access the internal engine and call `AddLayer` directly.

### Multi-Tenancy

`internal/tenant/` provides full tenant isolation:
- Per-tenant WAF config overrides via `RequestContext.TenantWAFConfig` (read directly by each layer, race-free)
- Tenant middleware sets `TenantContext` in request context
- Separate rate tracking, rules, alerts, and billing per tenant
- Domain-based tenant resolution via virtual hosts

### Configuration Layering

Priority: `defaults` → `YAML file` → `environment variables (GWAF_ prefix)` → `CLI flags`

Config path resolution (`config.ResolveConfigPath`): explicit path → `GWAF_CONFIG_PATH` env → `GWAF_ENV` env (`guardianwaf.staging.yaml`) → `guardianwaf.yaml`

Key config files:
- `internal/config/config.go` — All config structs (mirrors YAML schema)
- Custom YAML parser (not using yaml struct tags for loading — uses Node tree)
- Per-domain WAF overrides via `VirtualHostConfig.WAF *WAFConfig`

### Distributed Tracing

`internal/tracing/` — Zero-dependency OpenTelemetry-compatible tracing:
- Per-request root span + per-layer child spans with WAF action/score attributes
- Configurable sampling rate and exporters (stdout, noop, pluggable via `Exporter` interface)
- Enabled via `tracing.enabled: true` in config or `GWAF_TRACING_ENABLED=true`
- `ctx.TraceSpan` on `RequestContext` carries the span through the pipeline

### Observability

- Prometheus `/metrics` endpoint (requests, blocks, latency, GeoIP status)
- `/healthz` endpoint (JSON status for K8s probes, includes GeoIP readiness)
- Built-in distributed tracing (see above)
- Structured access logging (JSON or text format) with `RotatingFileWriter` for file output
- Log rotation: configurable size/age/backup limits (`logging.max_size_mb`, `logging.max_backups`, `logging.max_age_days`)
- Real-time SSE event streaming to dashboard
- Core Web Vitals monitoring via `POST /api/v1/cwv` beacon endpoint
- Application log buffer with level filtering
- `X-Correlation-ID` header propagated through proxy and across cluster nodes

### State Persistence

- IP auto-bans persisted to JSON via `ipacl.AutoBanConfig.PersistPath` (configurable interval, graceful shutdown flush)
- Events persisted via `events.PersistentMemoryStore` (wraps MemoryStore with JSONL replay on startup)
- Event ring buffer also available as JSONL file via `events.storage: file`

### Public API (Library Mode)

`guardianwaf.go` + `options.go` — Functional options API:
- `New(Config, ...Option)` — programmatic creation
- `NewFromFile(path, ...Option)` — from YAML
- `Middleware(http.Handler)` — HTTP middleware wrapper
- `Check(*http.Request)` — dry-run scoring
- `OnEvent(func(Event))` — event callback
- `Stats()` / `Close()` — lifecycle

## Package Layout

- `cmd/guardianwaf/` — CLI (serve, sidecar, check, validate)
- `internal/engine/` — Core engine, pipeline, scoring, context, access logging, panic recovery
- `internal/config/` — Custom YAML parser, config structs, validation, YAML serializer
- `internal/layers/` — All WAF layers (see Layer Order table above)
- `internal/proxy/` — Reverse proxy, load balancer (RR/weighted/least-conn/ip-hash), health check, circuit breaker, host-based router, WebSocket support
- `internal/tls/` — TLS cert store, SNI-based cert selection, hot-reload, HTTP/2 support
- `internal/dashboard/` — Web UI (React+Vite+TailwindCSS), REST API, SSE, config editor, AI page, routing topology graph (React Flow)
- `internal/mcp/` — MCP JSON-RPC server (44 tools: get_stats, get_events, add_blacklist, etc.)
- `internal/events/` — Event storage (memory ring buffer, JSONL file, event bus)
- `internal/ai/` — AI threat analysis (models.dev catalog, OpenAI client, batch analyzer)
- `internal/docker/` — Docker auto-discovery (Unix socket/CLI, label-based routing, event watcher)
- `internal/geoip/` — GeoIP database with auto-refresh
- `internal/acme/` — ACME/Let's Encrypt auto-certificate (HTTP-01)
- `internal/tenant/` — Multi-tenant management (isolation, billing, rate limits, per-tenant rules)
- `internal/alerting/` — Webhook and email alerting (Slack, Discord, PagerDuty, SMTP)
- `internal/compliance/` — Compliance reporting (PCI DSS, GDPR, SOC 2, ISO 27001 control registry, evaluator, reports, audit chain)
- `internal/tracing/` — Zero-dependency distributed tracing (OpenTelemetry-compatible API, sampling, exporters)
- `tests/reliability/` — Flaky test detection (JSONL-based pass/fail tracking across CI runs)
- `guardianwaf.go` + `options.go` — Public library API

## Architecture Decision Records

`docs/adr/` contains 43 ADRs — every significant design decision has a corresponding ADR. See `docs/adr/` for the full list. Key themes: zero-dependencies, pipeline architecture, multi-tenancy, ML/AI detection, gRPC, DLP, SIEM, Zero Trust, caching, virtual patching, HA/Raft, compliance, all individual WAF layers.

## Docker Auto-Discovery

- Watches Docker daemon for containers with `gwaf.*` labels
- Auto-creates upstreams, routes, virtual hosts from labels
- Event-driven (container start/stop) + poll fallback
- Zero-downtime atomic proxy rebuild on changes
- Platform-agnostic: Unix socket (Linux), named pipe (Windows), Docker CLI
- Label format: `gwaf.enable`, `gwaf.host`, `gwaf.port`, `gwaf.upstream`, `gwaf.path`, `gwaf.weight`, `gwaf.lb`, `gwaf.health.path`

## AI Threat Analysis

- Background batch processor (NOT per-request — too slow/expensive)
- Fetches provider/model catalog from models.dev
- OpenAI-compatible API client (works with any provider)
- Configurable cost limits (tokens/hour, tokens/day, requests/hour)
- Auto-block IPs based on AI verdict (confidence >= 70%)
- Dashboard UI for provider config, analysis history, usage stats

## Dashboard Development

```bash
# Hot reload dev server (React + Vite)
cd internal/dashboard/ui && npm run dev
# Vite dev server runs on :5173, proxies API requests to :9443

# Build for production (run from repo root)
make ui
# Outputs to internal/dashboard/dist/ which is embedded in Go binary
```

## CLI Commands

```
guardianwaf serve     # Standalone reverse proxy (full features, includes dashboard on :9443)
guardianwaf sidecar   # Lightweight proxy (no dashboard/MCP)
guardianwaf check     # Dry-run request test (send request and see scoring)
guardianwaf validate  # Config file validation
```

## Proxy & Routing Architecture

- Multi-upstream with multiple targets per upstream
- 4 load balancing strategies: round_robin, weighted, least_conn, ip_hash
- Active health checks (configurable interval, timeout, path)
- Circuit breaker per target (5 failures → open → 30s → half-open → probe)
- Virtual hosts: domain-based routing via Host header
- Wildcard domain support (*.example.com)
- TLS termination with SNI cert selection, cert hot-reload, HTTP/2
- WebSocket proxy support (Upgrade header forwarding)

<!-- rtk-instructions v2 -->
# RTK (Rust Token Killer)

**Always prefix commands with `rtk`** — see global `~/.claude/CLAUDE.md` for the full reference.
<!-- /rtk-instructions -->