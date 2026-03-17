# GuardianWAF

> Zero-dependency WAF. One binary. Total protection.

[![Go Version](https://img.shields.io/github/go-mod/go-version/ersinkoc/guardianwaf?style=flat-square)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/ersinkoc/guardianwaf?style=flat-square)](https://goreportcard.com/report/github.com/ersinkoc/guardianwaf)
[![Test Coverage](https://img.shields.io/codecov/c/github/ersinkoc/guardianwaf?style=flat-square)](https://codecov.io/gh/ersinkoc/guardianwaf)
[![Release](https://img.shields.io/github/v/release/ersinkoc/guardianwaf?style=flat-square)](https://github.com/ersinkoc/guardianwaf/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/ersinkoc/guardianwaf?style=flat-square)](https://hub.docker.com/r/ersinkoc/guardianwaf)
[![GitHub Stars](https://img.shields.io/github/stars/ersinkoc/guardianwaf?style=flat-square)](https://github.com/ersinkoc/guardianwaf/stargazers)
[![Build Status](https://img.shields.io/github/actions/workflow/status/ersinkoc/guardianwaf/ci.yml?branch=main&style=flat-square)](https://github.com/ersinkoc/guardianwaf/actions)
[![Go Reference](https://pkg.go.dev/badge/github.com/ersinkoc/guardianwaf.svg)](https://pkg.go.dev/github.com/ersinkoc/guardianwaf)
[![Security Headers](https://img.shields.io/security-headers?url=https%3A%2F%2Fguardianwaf.dev&style=flat-square)](https://securityheaders.com/?q=guardianwaf.dev)

GuardianWAF is a production-grade Web Application Firewall written in pure Go with zero external dependencies. It ships as a single binary supporting three deployment modes: standalone reverse proxy, embeddable library, and sidecar proxy. Its tokenizer-based scoring engine provides accurate threat detection with minimal false positives.

---

## Features

**Detection & Protection**
- Six attack detectors: SQL injection, XSS, path traversal, command injection, XXE, SSRF
- Tokenizer-based detection engine with configurable scoring thresholds
- Rate limiting with token bucket algorithm, per-IP and per-path scoping, and auto-ban
- IP whitelist/blacklist with radix tree for O(k) CIDR lookups
- Bot detection via JA3/JA4 TLS fingerprinting, User-Agent analysis, and behavioral tracking
- Response protection: security headers (HSTS, X-Frame-Options, CSP), credit card/SSN/API key masking, stack trace stripping

**Deployment**
- Three deployment modes: standalone reverse proxy, Go library middleware, sidecar proxy
- Single static binary with zero external dependencies -- no CGO, no shared libraries
- Docker image based on Alpine (< 20 MB)
- Built-in ACME client for automatic TLS certificate provisioning
- Load balancing (round-robin, weighted, least-conn, IP hash) with health checks
- Graceful shutdown with connection draining

**Operations**
- Built-in web dashboard with real-time monitoring and rule management
- REST API for programmatic control (whitelist, blacklist, rate limits, exclusions, config)
- Structured JSON logging with configurable levels
- Hot-reload of configuration without restart
- Health check endpoints for Kubernetes liveness probes
- In-memory or file-based event storage (up to 100K events)

**Developer Experience**
- MCP server for AI agent integration (Claude Code, etc.) with 15 structured tools
- Functional options API for library mode
- Event callbacks for custom alerting
- `check` command for dry-run request testing
- `validate` command for config file verification
- < 1ms p99 latency overhead target

---

## Quick Start

### Standalone Reverse Proxy

```bash
# Install
go install github.com/ersinkoc/guardianwaf/cmd/guardianwaf@latest

# Create minimal config
cat > guardianwaf.yaml <<EOF
mode: enforce
listen: ":8080"
upstreams:
  - name: app
    targets:
      - url: "http://localhost:3000"
routes:
  - path: /
    upstream: app
dashboard:
  enabled: true
  listen: ":9443"
  api_key: "change-me"
EOF

# Run
guardianwaf serve
```

### Go Library (Middleware)

```bash
go get github.com/ersinkoc/guardianwaf
```

```go
waf, err := guardianwaf.New(guardianwaf.Config{
    Mode:      guardianwaf.ModeEnforce,
    Threshold: guardianwaf.ThresholdConfig{Block: 50, Log: 25},
})
if err != nil {
    log.Fatal(err)
}
defer waf.Close()

http.ListenAndServe(":8080", waf.Middleware(myHandler))
```

### Sidecar (Docker / Kubernetes)

```bash
docker run -d -p 8080:8080 \
  ersinkoc/guardianwaf:latest \
  sidecar --upstream http://app:3000
```

---

## Why GuardianWAF?

GuardianWAF was built to eliminate the trade-offs other WAF solutions force: complex rule sets, dependency trees, vendor lock-in, or requiring a host process. One binary, zero dependencies, transparent scoring.

*Comparison as of March 2026. Check each project for current status.*

| Feature | GuardianWAF | SafeLine | Coraza | ModSecurity | NAXSI |
|---|---|---|---|---|---|
| **Language** | Go | Go + Lua | Go | C | C |
| **External deps** | Zero | Multiple | Multiple | Multiple | NGINX module |
| **Deployment modes** | 3 (proxy, lib, sidecar) | Reverse proxy | Library / proxy | Module (NGINX/Apache) | NGINX module |
| **Detection method** | Tokenizer + scoring | Semantic analysis | CRS regex rules | CRS regex rules | Scoring + allowlists |
| **Web dashboard** | Built-in | Built-in | No (third-party) | No (third-party) | No |
| **Single binary** | Yes | No | No | No | No |
| **MCP / AI integration** | Built-in MCP server | No | No | No | No |
| **Configuration** | YAML + env vars | Web UI | SecRule directives | SecRule directives | NGINX directives |
| **False positive mgmt** | Score tuning per-route | Auto learning | Rule exclusions | Rule exclusions | Allowlists |
| **Performance overhead** | < 1ms p99 | Low | Low | Moderate | Low |
| **Memory usage** | Minimal | Moderate | Low-moderate | Moderate-high | Low |
| **Learning curve** | Low | Low-moderate | Moderate | High | Moderate |
| **License** | MIT | Apache 2.0 | Apache 2.0 | Apache 2.0 | GPL v3 |

---

## Architecture

```
                          GuardianWAF Pipeline
                          ====================

  HTTP Request
       |
       v
  +-----------+    +------------+    +------------+    +------------+
  |  IP ACL   |--->| Rate Limit |--->| Sanitizer  |--->| Detection  |--+
  |   (100)   |    |   (200)    |    |   (300)    |    |   (400)    |  |
  +-----------+    +------------+    +------------+    +------------+  |
                                                                       |
       +---------------------------------------------------------------+
       |
       v
  +------------+    +------------+         +----------------+
  | Bot Detect |--->|  Response  |-------->|   Upstream     |
  |   (500)    |    |   (600)    |         |   Backend      |
  +------------+    +------------+         +----------------+
                         |
                         +-- Security headers
                         +-- Data masking
                         +-- Error pages
```

Each layer runs in order and can pass, log, or block the request. The detection layer runs 6 independent detectors (SQLi, XSS, LFI, CMDi, XXE, SSRF) and produces a cumulative threat score. The score is compared against configurable thresholds to determine the final action.

---

## Detection Engine

GuardianWAF uses a tokenizer-based scoring system instead of binary allow/block rules. HTTP requests are lexically decomposed into typed tokens, scored against attack patterns, and evaluated with configurable thresholds.

**Example: How scoring produces graduated responses**

```
Input: "O'Brien"
  -> Single apostrophe              score: 10
  -> Total: 10                      -> ALLOW (below log threshold)

Input: "' OR 'a'='a"
  -> Apostrophe + OR keyword        score: 30
  -> Tautology pattern              score: +55
  -> Total: 85                      -> BLOCK (above block threshold)

Input: "'; DROP TABLE users --"
  -> Stacked query + DROP keyword   score: 95
  -> Comment evasion                score: +35
  -> Isolated keyword               score: +10
  -> Total: 140                     -> BLOCK (critical attack)
```

This graduated response eliminates most false positives while catching real attacks. Every blocked request includes the full score breakdown for transparent, data-driven tuning.

See [Detection Engine docs](docs/detection-engine.md) for the full pattern scoring table.

---

## Installation

### go install

```bash
go install github.com/ersinkoc/guardianwaf/cmd/guardianwaf@latest
```

### Binary Download

```bash
# Linux (amd64)
curl -Lo guardianwaf https://github.com/ersinkoc/guardianwaf/releases/latest/download/guardianwaf-linux-amd64
chmod +x guardianwaf
sudo mv guardianwaf /usr/local/bin/

# macOS (arm64)
curl -Lo guardianwaf https://github.com/ersinkoc/guardianwaf/releases/latest/download/guardianwaf-darwin-arm64
chmod +x guardianwaf
sudo mv guardianwaf /usr/local/bin/
```

### Docker

```bash
docker pull ersinkoc/guardianwaf:latest
```

### Build from Source

```bash
git clone https://github.com/ersinkoc/guardianwaf.git
cd guardianwaf
make build
# Binary: ./guardianwaf
```

---

## Configuration

Minimal `guardianwaf.yaml` to protect a backend:

```yaml
mode: enforce
listen: ":8080"

upstreams:
  - name: backend
    targets:
      - url: "http://localhost:3000"

routes:
  - path: /
    upstream: backend

waf:
  detection:
    threshold:
      block: 50
      log: 25

dashboard:
  enabled: true
  listen: ":9443"
  api_key: "your-secret-key"
```

Configuration layering: `defaults` -> `YAML file` -> `environment variables (GWAF_ prefix)` -> `CLI flags`.

See [Configuration Reference](docs/configuration.md) for the complete YAML schema.

---

## Dashboard

GuardianWAF includes a built-in web dashboard accessible on the configured listen address (default `:9443`).

**Capabilities:**
- Real-time traffic monitoring (requests/sec, blocks/sec, latency percentiles)
- Security event viewer with filtering by action, IP, path, score, and time range
- Rule management for whitelist, blacklist, rate limits, and detection exclusions
- Configuration viewer with hot-reload support
- Health and version status

**REST API:** The dashboard exposes a full [REST API](docs/api-reference.md) for programmatic management, protected by API key authentication.

Access at `https://localhost:9443` (enabled by default in standalone mode).

---

## Library Usage

### Minimal

```go
waf, err := guardianwaf.New(guardianwaf.Config{
    Mode:      guardianwaf.ModeEnforce,
    Threshold: guardianwaf.ThresholdConfig{Block: 50, Log: 25},
})
if err != nil {
    log.Fatal(err)
}
defer waf.Close()

http.ListenAndServe(":8080", waf.Middleware(myHandler))
```

### Advanced (Functional Options)

```go
waf, err := guardianwaf.New(guardianwaf.Config{},
    guardianwaf.WithMode(guardianwaf.ModeEnforce),
    guardianwaf.WithThreshold(60, 30),
    guardianwaf.WithDetector("sqli", true, 1.5),   // 50% more sensitive
    guardianwaf.WithDetector("xss", true, 0.5),     // 50% less sensitive
    guardianwaf.WithIPWhitelist("10.0.0.0/8"),
    guardianwaf.WithIPBlacklist("203.0.113.0/24"),
    guardianwaf.WithBotDetection(true),
    guardianwaf.WithSecurityHeaders(true),
    guardianwaf.WithDataMasking(true),
    guardianwaf.WithMaxEvents(50000),
)
if err != nil {
    log.Fatal(err)
}
defer waf.Close()

// Event callback for custom alerting
waf.OnEvent(func(event guardianwaf.Event) {
    if event.Action.String() == "block" {
        fmt.Printf("[BLOCKED] %s %s from %s (score: %d)\n",
            event.Method, event.Path, event.ClientIP, event.Score)
    }
})

// Manual request check (without middleware)
result := waf.Check(req)
fmt.Printf("Score: %d, Blocked: %v, Findings: %d\n",
    result.TotalScore, result.Blocked, len(result.Findings))
```

---

## MCP Integration

GuardianWAF includes a built-in [Model Context Protocol](https://modelcontextprotocol.io) server that enables AI agents to monitor, query, and manage the WAF through structured tool calls.

**15 MCP tools:**

| Category | Tools |
|---|---|
| Monitoring | `get_stats`, `get_events`, `get_top_ips`, `get_detectors` |
| Configuration | `get_config`, `set_mode` |
| IP Management | `add_whitelist`, `remove_whitelist`, `add_blacklist`, `remove_blacklist` |
| Rate Limiting | `add_ratelimit`, `remove_ratelimit` |
| Detection Tuning | `add_exclusion`, `remove_exclusion` |
| Testing | `test_request` |

**Claude Code integration:**

```json
{
  "mcpServers": {
    "guardianwaf": {
      "command": "guardianwaf",
      "args": ["serve", "-c", "guardianwaf.yaml"]
    }
  }
}
```

Then ask: *"Show me the latest blocked requests and blacklist the top attacking IP."*

See [MCP Integration docs](docs/mcp-integration.md) for the complete tool reference with parameters and examples.

---

## Performance

GuardianWAF targets sub-millisecond p99 latency overhead per request.

| Metric | Value |
|---|---|
| IP ACL lookup | < 100ns |
| Rate limit check | < 500ns |
| SQLi detection | < 200us p95 |
| All detectors combined | < 500us p95 |
| **Total pipeline (clean request)** | **< 1ms p99** |
| **Total pipeline (attack)** | **< 2ms p99** |
| Memory baseline (standalone) | < 30 MB |
| Memory baseline (library) | < 5 MB |
| Binary size (stripped) | ~15 MB |
| Docker image size | < 20 MB |
| Startup time | < 100ms |

Design choices for performance:
- Zero-allocation hot paths with `sync.Pool` for request contexts
- Atomic counters for statistics (no mutex contention)
- Radix tree for IP lookups (O(k) where k = address bits)
- Token bucket rate limiter (O(1) per check)
- State-machine tokenizer (no regex on the hot path)

---

## Documentation

| Document | Description |
|---|---|
| [Getting Started](docs/getting-started.md) | Installation and first deployment |
| [Configuration Reference](docs/configuration.md) | Full YAML schema with every field |
| [Detection Engine](docs/detection-engine.md) | Scoring system, detectors, pattern tables |
| [Deployment Modes](docs/deployment-modes.md) | Standalone, library, sidecar comparison |
| [API Reference](docs/api-reference.md) | REST API endpoints with request/response examples |
| [MCP Integration](docs/mcp-integration.md) | AI agent tools and Claude Code setup |
| [Tuning Guide](docs/tuning-guide.md) | False positive reduction and threshold tuning |

Full documentation site: [guardianwaf.dev/docs](https://guardianwaf.dev/docs)

---

## Project Structure

```
guardianwaf/
├── cmd/guardianwaf/       # CLI entry point (serve, sidecar, check, validate)
├── internal/
│   ├── engine/            # Core WAF engine, pipeline, scoring
│   ├── config/            # YAML parser, config structs, env loading, validation
│   ├── layers/
│   │   ├── ipacl/         # IP whitelist/blacklist (radix tree)
│   │   ├── ratelimit/     # Token bucket rate limiter
│   │   ├── sanitizer/     # Request normalization and validation
│   │   ├── detection/     # Attack detectors (sqli/xss/lfi/cmdi/xxe/ssrf)
│   │   ├── botdetect/     # Bot detection (JA3, UA, behavior)
│   │   └── response/      # Response protection (headers, masking, error pages)
│   ├── proxy/             # Reverse proxy, load balancer, circuit breaker, websocket
│   ├── tls/               # TLS manager, ACME client, SNI routing
│   ├── dashboard/         # Web UI, REST API, SSE real-time updates
│   ├── mcp/               # MCP JSON-RPC server and tool definitions
│   ├── events/            # Event storage (memory ring buffer, JSONL file)
│   └── analytics/         # Rolling counters, TopK, time series
├── guardianwaf.go         # Public API for library mode
├── options.go             # Functional options (WithMode, WithThreshold, etc.)
├── examples/              # Library and backend examples
├── docs/                  # Documentation
├── Dockerfile             # Multi-stage Alpine build
├── docker-compose.yml     # Standalone + backend example
└── Makefile               # build, test, lint, bench, fuzz, cover
```

---

## Contributing

Contributions are welcome. GuardianWAF values quality over velocity -- clean code, thorough tests, and zero external dependencies.

1. Fork the repository.
2. Create a feature branch.
3. Run `make test` and `make vet` to verify all tests pass.
4. New features should include tests.
5. No external dependencies -- everything is implemented from scratch.
6. Submit a pull request with a clear description of changes.

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

---

## License

[MIT](LICENSE) -- the core WAF is fully open source. Enterprise features (cluster mode, commercial support) will be available under a separate commercial license in the future.

---

## Author

**Ersin Koc** / [x.com/ersinkoc](https://x.com/ersinkoc)

- GitHub: [@ersinkoc](https://github.com/ersinkoc)
- Website: [guardianwaf.com](https://guardianwaf.com)
