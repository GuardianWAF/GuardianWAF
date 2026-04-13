# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GuardianWAF is a zero-dependency Web Application Firewall written in Go (1.25+).
Module: `github.com/guardianwaf/guardianwaf`

The only Go dependency is `quic-go` (for optional HTTP/3 support, build with `-tags http3`).

## Key Constraints

- **ZERO external Go dependencies** — only Go stdlib (plus quic-go for HTTP/3). No exceptions.
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
- Acquired via `AcquireContext()` — parses HTTP request, reads/decompresses body (gzip/deflate), extracts client IP (X-Forwarded-For → X-Real-IP → RemoteAddr)
- Released via `ReleaseContext()` — resets all fields, returns to pool
- Populates JA4 TLS fingerprint fields from custom TLS handler data
- Carries `TenantID` and `TenantWAFConfig` for multi-tenant isolation

### Layer Order Constants

Defined in `internal/engine/layer.go`:

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
| 450 | Virtual Patch | Virtual patching layer |
| 475 | DLP | Data Loss Prevention (credit cards, SSNs, API keys, PII) |
| 500 | Bot Detection | JA3/JA4 TLS fingerprinting, UA, behavioral analysis |
| 590 | Client-Side | Client-side protection injection |
| 600 | Response | Security headers, data masking, branded block pages |
| — | JS Challenge | SHA-256 proof-of-work for suspicious requests (score 40-79) |
| — | AI Analysis | Background batch threat analysis via LLM (configurable provider) |
| — | gRPC Proxy | gRPC protocol handling |
| — | WebSocket | Transparent WebSocket upgrade forwarding |
| — | Cache | In-memory response caching layer |
| — | Canary | Canary/deployment testing layer |
| — | Replay | Request recording and replay for testing |
| — | SIEM | Security event export to external SIEM systems |

### Scoring System

- Each detector produces scores 0-100
- Scores accumulate per-request via `ScoreAccumulator`
- `block_threshold`: 50 (default), `log_threshold`: 25
- Score 40-79 with bot detection → JS challenge
- Per-detector multipliers adjust sensitivity

### Multi-Tenancy

`internal/tenant/` provides full tenant isolation:
- Per-tenant WAF config overrides via `RequestContext.TenantWAFConfig` (read directly by each layer, race-free)
- Tenant middleware sets `TenantContext` in request context
- Separate rate tracking, rules, alerts, and billing per tenant
- Domain-based tenant resolution via virtual hosts

### Configuration Layering

Priority: `defaults` → `YAML file` → `environment variables (GWAF_ prefix)` → `CLI flags`

Key config files:
- `internal/config/config.go` — All config structs (mirrors YAML schema)
- Custom YAML parser (not using yaml struct tags for loading — uses Node tree)
- Per-domain WAF overrides via `VirtualHostConfig.WAF *WAFConfig`

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
- `internal/http3/` — HTTP/3/QUIC support (build with `-tags http3`, stub otherwise)
- `internal/dashboard/` — Web UI (React+Vite+TailwindCSS), REST API, SSE, config editor, AI page, routing topology graph (React Flow)
- `internal/mcp/` — MCP JSON-RPC server (15 tools: get_stats, get_events, add_blacklist, etc.)
- `internal/events/` — Event storage (memory ring buffer, JSONL file, event bus)
- `internal/ai/` — AI threat analysis (provider catalog from models.dev, OpenAI-compatible client, batch analyzer, cost control, JSON store)
- `internal/docker/` — Docker auto-discovery (Unix socket/CLI, label-based routing, event watcher)
- `internal/geoip/` — GeoIP database with auto-refresh
- `internal/acme/` — ACME/Let's Encrypt auto-certificate (HTTP-01)
- `internal/tenant/` — Multi-tenant management (isolation, billing, rate limits, per-tenant rules)
- `internal/analytics/` — Analytics engine and API handlers
- `internal/cluster/` — Cluster mode support
- `internal/clustersync/` — Cross-node state synchronization
- `guardianwaf.go` + `options.go` — Public library API

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

## Observability

- Prometheus `/metrics` endpoint (requests, blocks, latency)
- `/healthz` endpoint (JSON status for K8s probes)
- Structured access logging (JSON or text format)
- Log level filtering (debug/info/warn/error)
- Real-time SSE event streaming to dashboard
- Application log buffer with level filtering

<!-- rtk-instructions v2 -->
# RTK (Rust Token Killer) - Token-Optimized Commands

## Golden Rule

**Always prefix commands with `rtk`**. If RTK has a dedicated filter, it uses it. If not, it passes through unchanged. This means RTK is always safe to use.

**Important**: Even in command chains with `&&`, use `rtk`:
```bash
# ❌ Wrong
git add . && git commit -m "msg" && git push

# ✅ Correct
rtk git add . && rtk git commit -m "msg" && rtk git push
```

## RTK Commands by Workflow

### Build & Compile (80-90% savings)
```bash
rtk cargo build         # Cargo build output
rtk cargo check         # Cargo check output
rtk cargo clippy        # Clippy warnings grouped by file (80%)
rtk tsc                 # TypeScript errors grouped by file/code (83%)
rtk lint                # ESLint/Biome violations grouped (84%)
rtk prettier --check    # Files needing format only (70%)
rtk next build          # Next.js build with route metrics (87%)
```

### Test (90-99% savings)
```bash
rtk cargo test          # Cargo test failures only (90%)
rtk vitest run          # Vitest failures only (99.5%)
rtk playwright test     # Playwright failures only (94%)
rtk test <cmd>          # Generic test wrapper - failures only
```

### Git (59-80% savings)
```bash
rtk git status          # Compact status
rtk git log             # Compact log (works with all git flags)
rtk git diff            # Compact diff (80%)
rtk git show            # Compact show (80%)
rtk git add             # Ultra-compact confirmations (59%)
rtk git commit          # Ultra-compact confirmations (59%)
rtk git push            # Ultra-compact confirmations
rtk git pull            # Ultra-compact confirmations
rtk git branch          # Compact branch list
rtk git fetch           # Compact fetch
rtk git stash           # Compact stash
rtk git worktree        # Compact worktree
```

Note: Git passthrough works for ALL subcommands, even those not explicitly listed.

### GitHub (26-87% savings)
```bash
rtk gh pr view <num>    # Compact PR view (87%)
rtk gh pr checks        # Compact PR checks (79%)
rtk gh run list         # Compact workflow runs (82%)
rtk gh issue list       # Compact issue list (80%)
rtk gh api              # Compact API responses (26%)
```

### JavaScript/TypeScript Tooling (70-90% savings)
```bash
rtk pnpm list           # Compact dependency tree (70%)
rtk pnpm outdated       # Compact outdated packages (80%)
rtk pnpm install        # Compact install output (90%)
rtk npm run <script>    # Compact npm script output
rtk npx <cmd>           # Compact npx command output
rtk prisma              # Prisma without ASCII art (88%)
```

### Files & Search (60-75% savings)
```bash
rtk ls <path>           # Tree format, compact (65%)
rtk read <file>         # Code reading with filtering (60%)
rtk grep <pattern>      # Search grouped by file (75%)
rtk find <pattern>      # Find grouped by directory (70%)
```

### Analysis & Debug (70-90% savings)
```bash
rtk err <cmd>           # Filter errors only from any command
rtk log <file>          # Deduplicated logs with counts
rtk json <file>         # JSON structure without values
rtk deps                # Dependency overview
rtk env                 # Environment variables compact
rtk summary <cmd>       # Smart summary of command output
rtk diff                # Ultra-compact diffs
```

### Infrastructure (85% savings)
```bash
rtk docker ps           # Compact container list
rtk docker images       # Compact image list
rtk docker logs <c>     # Deduplicated logs
rtk kubectl get         # Compact resource list
rtk kubectl logs        # Deduplicated pod logs
```

### Network (65-70% savings)
```bash
rtk curl <url>          # Compact HTTP responses (70%)
rtk wget <url>          # Compact download output (65%)
```

### Meta Commands
```bash
rtk gain                # View token savings statistics
rtk gain --history      # View command history with savings
rtk discover            # Analyze Claude Code sessions for missed RTK usage
rtk proxy <cmd>         # Run command without filtering (for debugging)
rtk init                # Add RTK instructions to CLAUDE.md
rtk init --global       # Add RTK to ~/.claude/CLAUDE.md
```

## Token Savings Overview

| Category | Commands | Typical Savings |
|----------|----------|-----------------|
| Tests | vitest, playwright, cargo test | 90-99% |
| Build | next, tsc, lint, prettier | 70-87% |
| Git | status, log, diff, add, commit | 59-80% |
| GitHub | gh pr, gh run, gh issue | 26-87% |
| Package Managers | pnpm, npm, npx | 70-90% |
| Files | ls, read, grep, find | 60-75% |
| Infrastructure | docker, kubectl | 85% |
| Network | curl, wget | 65-70% |

Overall average: **60-90% token reduction** on common development operations.
<!-- /rtk-instructions -->