# GuardianWAF — Claude Code Instructions

## Project Overview
GuardianWAF is a zero-dependency Web Application Firewall written in Go.
Module: `github.com/guardianwaf/guardianwaf`

## Key Constraints
- **ZERO external dependencies** — only Go stdlib. No exceptions.
- Use `any` instead of `interface{}`
- Use built-in `min`/`max` functions (Go 1.21+)
- Use `range N` for simple loops (Go 1.22+)
- Use `slices.Contains` where applicable

## Build & Test
```bash
make build          # Build binary
make test           # Run all tests with -race
make lint           # Run golangci-lint
make bench          # Run benchmarks
make cover          # Generate coverage report
go test ./...       # Quick test all packages
go vet ./...        # Vet all packages
```

## Architecture
7-layer pipeline executed in order:
1. IP ACL (100) — radix tree CIDR matching
2. Rate Limit (200) — token bucket per IP/path
3. Sanitizer (300) — normalize + validate requests
4. Detection (400) — 6 detectors: sqli, xss, lfi, cmdi, xxe, ssrf
5. Bot Detection (500) — JA3/JA4 TLS fingerprinting, UA, behavioral analysis
6. JS Challenge — SHA-256 proof-of-work for suspicious requests (score 40-79)
7. Response (600) — security headers, data masking

## Package Layout
- `cmd/guardianwaf/` — CLI (serve, sidecar, check, validate)
- `internal/engine/` — Core engine, pipeline, scoring, context
- `internal/config/` — Custom YAML parser, config structs, validation
- `internal/layers/` — All WAF layers (ipacl, ratelimit, sanitizer, detection/*, botdetect, challenge, response)
- `internal/proxy/` — Reverse proxy, load balancer (RR/weighted/least-conn/ip-hash), health check, circuit breaker, host-based router
- `internal/tls/` — TLS cert store, SNI-based cert selection, hot-reload
- `internal/dashboard/` — Web UI, REST API, SSE, config editor
- `internal/mcp/` — MCP JSON-RPC server (15 tools)
- `internal/events/` — Event storage (memory ring buffer, JSONL file)
- `guardianwaf.go` + `options.go` — Public library API

## Proxy & Routing
- Multi-upstream with multiple targets per upstream
- 4 load balancing strategies: round_robin, weighted, least_conn, ip_hash
- Active health checks (configurable interval, timeout, path)
- Circuit breaker per target (5 failures → open → 30s → half-open → probe)
- Virtual hosts: domain-based routing via Host header
- Wildcard domain support (*.example.com)
- TLS termination with SNI cert selection and cert hot-reload

## Scoring System
- Each detector produces scores 0-100
- Scores accumulate per-request
- block_threshold: 50 (default), log_threshold: 25
- Score 40-79 with bot detection → JS challenge
- Per-detector multipliers adjust sensitivity

## Dashboard
- Real-time monitoring UI on `:9443`
- Config editor at `/config` (toggles, inputs, IP ACL management)
- REST API: stats, events, config, IP ACL
- SSE streaming for live event feed
- Event detail panel with findings breakdown

## CLI Commands
```
guardianwaf serve     # Standalone reverse proxy (full features)
guardianwaf sidecar   # Lightweight proxy (no dashboard/MCP)
guardianwaf check     # Dry-run request test
guardianwaf validate  # Config validation
```
