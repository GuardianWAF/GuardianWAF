# GuardianWAF

> Zero-dependency WAF. One binary. Total protection.

<p align="center">
  <img src="guardian_waf_.jpeg" alt="GuardianWAF" width="100%">
</p>

[![Go Version](https://img.shields.io/github/go-mod/go-version/guardianwaf/guardianwaf?style=flat-square)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/guardianwaf/guardianwaf?style=flat-square)](https://goreportcard.com/report/github.com/guardianwaf/guardianwaf)
[![Test Coverage](https://img.shields.io/badge/coverage-91%25-brightgreen?style=flat-square)](/docs/)
[![Release](https://img.shields.io/github/v/release/guardianwaf/guardianwaf?style=flat-square)](https://github.com/guardianwaf/guardianwaf/releases)
[![GHCR](https://img.shields.io/badge/ghcr.io-guardianwaf%2Fguardianwaf-blue?style=flat-square)](https://github.com/guardianwaf/guardianwaf/pkgs/container/guardianwaf)
[![GitHub Stars](https://img.shields.io/github/stars/guardianwaf/guardianwaf?style=flat-square)](https://github.com/guardianwaf/guardianwaf/stargazers)
[![Build Status](https://img.shields.io/github/actions/workflow/status/guardianwaf/guardianwaf/ci.yml?branch=main&style=flat-square)](https://github.com/guardianwaf/guardianwaf/actions)
[![Go Reference](https://pkg.go.dev/badge/github.com/guardianwaf/guardianwaf.svg)](https://pkg.go.dev/github.com/guardianwaf/guardianwaf)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square)](/)

GuardianWAF is a production-grade Web Application Firewall written in pure Go with zero external dependencies. It protects any HTTP backend — Node.js, Python, Java, PHP, Ruby, .NET, or any other language — as a standalone reverse proxy, sidecar, or embeddable Go library. Docker auto-discovery, AI-powered threat analysis, and real-time dashboard included. Single binary, zero config required.

---

## Features

**Detection & Protection**
- Six attack detectors: SQL injection, XSS, path traversal, command injection, XXE, SSRF
- Tokenizer-based detection engine with configurable scoring thresholds
- JS Challenge (SHA-256 proof-of-work) for suspicious requests -- stops bots, passes real browsers
- Rate limiting with token bucket algorithm, per-IP and per-path scoping, and auto-ban
- IP whitelist/blacklist with radix tree for O(k) CIDR lookups (runtime add/remove via dashboard)
- Bot detection via JA3/JA4 TLS fingerprinting, User-Agent analysis, and behavioral tracking
- Response protection: security headers (HSTS, X-Frame-Options, CSP), credit card/SSN/API key masking, stack trace stripping
- Branded HTML block page with request ID and threat score
- **Threat Intelligence**: IP and domain reputation checking with JSONL/CSV/JSON feeds, LRU cache, CIDR matching
- **CORS Security**: Origin validation with wildcard patterns, preflight handling, strict mode blocking
- **API Security**: JWT validation (RS256/ES256/HS256/etc), JWKS support, API key authentication with path authorization
- **Account Takeover Protection**: Brute force detection, credential stuffing detection, password spray detection, impossible travel detection

**Reverse Proxy & Routing**
- Multi-domain routing via virtual hosts (Host header + SNI)
- Wildcard domain support (`*.example.com`)
- Load balancing: round-robin, weighted, least-connections, IP hash
- Active health checks with configurable interval, timeout, and path
- Circuit breaker per target (closed -> open -> half-open -> probe)
- TLS termination with SNI-based certificate selection
- Certificate hot-reload (automatic file change detection)
- ACME / Let's Encrypt client for automatic certificate provisioning
- HTTP to HTTPS redirect (automatic when TLS enabled)
- Path-based routing with optional prefix stripping

**Docker Auto-Discovery**
- Automatic backend discovery from Docker container labels (`gwaf.*`)
- Zero-config service mesh: label your containers, GuardianWAF does the rest
- Event-driven: instant detection of container start/stop/scale
- Upstream pooling: multiple containers with same label = load-balanced pool
- Supports all LB strategies, health checks, weights via labels
- Platform-agnostic: Linux (Unix socket), Windows (named pipe), remote (Docker CLI)
- See [Docker Discovery Guide](docs/docker-discovery.md) for full label reference

**AI-Powered Threat Analysis**
- Background batch AI analysis of suspicious events using LLMs
- 400+ AI providers synced from [models.dev](https://models.dev) (OpenAI, Groq, DeepSeek, Anthropic, etc.)
- Dashboard UI for provider/model selection, API key management, analysis history
- Auto-block malicious IPs based on AI verdict (configurable confidence threshold)
- Hard cost limits: tokens/hour, tokens/day, requests/hour to prevent runaway API costs
- See [AI Analysis Guide](docs/ai-analysis.md) for setup and configuration

**Alerting & Notifications**
- Real-time webhook alerts for Slack, Discord, PagerDuty, and generic HTTP endpoints
- SMTP email alerts with TLS encryption support
- Per-target event filtering (block, challenge, log, or all events)
- Minimum score thresholds and cooldown periods per IP
- Custom email templates with variable substitution
- Dashboard integration with alerting statistics

**Deployment**
- Three deployment modes: standalone reverse proxy, Go library middleware, sidecar proxy
- Single static binary with zero external Go dependencies -- no CGO, no shared libraries
- Docker image based on Alpine (< 20 MB)
- Graceful shutdown with connection draining and event flushing

**Dashboard & Operations**
- Built-in web dashboard with real-time monitoring via SSE (React + Vite + Tailwind)
- **Routing Topology Graph**: interactive React Flow visualization with TLS/SSL, ports, health status
- **Backends View**: discovered Docker containers + static upstreams in a single table
- **AI Analysis Page**: provider catalog, model selection, analysis history, cost tracking
- Configuration editor with live toggles for all WAF settings
- Upstream/domain/route management -- add backends, domains, and routing from the UI
- IP ACL management -- add/remove whitelist and blacklist entries in real-time
- Upstream health panel -- live backend status, circuit breaker state, active connections
- Event detail view -- click any event to see full findings, matched patterns, scores
- REST API for programmatic control (stats, events, config, routing, IP ACL, AI, Docker)
- Prometheus-compatible `/metrics` endpoint for Grafana/monitoring integration
- Structured access logging (JSON or text) with configurable levels
- Hot-reload of configuration with persistence to disk
- `/healthz` endpoint for Kubernetes liveness/readiness probes
- In-memory or file-based event storage (up to 100K events)

**Developer Experience**
- MCP server with 21 tools over stdio + SSE transports (Claude Code, Claude Desktop, VS Code)
- Functional options API for library mode
- Event callbacks for custom alerting
- `check` command for dry-run request testing
- `validate` command for config file verification
- HTTP/2 support with ALPN negotiation
- WebSocket proxy support (transparent Upgrade forwarding)
- < 1ms p99 latency overhead target

---

## Quick Start

### Standalone Reverse Proxy

```bash
# Install
go install github.com/guardianwaf/guardianwaf/cmd/guardianwaf@latest

# Create minimal config
cat > guardianwaf.yaml <<EOF
mode: enforce
listen: ":8088"
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

### Multi-Domain with TLS

```yaml
listen: ":8088"

tls:
  enabled: true
  listen: ":8443"
  http_redirect: true
  cert_file: "/etc/certs/default.pem"
  key_file: "/etc/certs/default-key.pem"

upstreams:
  - name: api
    load_balancer: weighted
    targets:
      - url: "http://api1:3000"
        weight: 3
      - url: "http://api2:3000"
        weight: 1
    health_check:
      enabled: true
      interval: 10s
      path: /healthz

  - name: web
    targets:
      - url: "http://web:8000"

virtual_hosts:
  - domains: ["api.example.com"]
    tls:
      cert_file: "/etc/certs/api.pem"
      key_file: "/etc/certs/api-key.pem"
    routes:
      - path: /
        upstream: api

  - domains: ["www.example.com", "example.com"]
    routes:
      - path: /
        upstream: web

routes:
  - path: /
    upstream: web
```

### Go Library (Middleware)

```bash
go get github.com/guardianwaf/guardianwaf
```

```go
waf, err := guardianwaf.New(guardianwaf.Config{
    Mode:      guardianwaf.ModeEnforce,
    Threshold: guardianwaf.ThresholdConfig{Block: 50, Log: 25},
    Challenge: guardianwaf.ChallengeConfig{Enabled: true, Difficulty: 20},
})
if err != nil {
    log.Fatal(err)
}
defer waf.Close()

http.ListenAndServe(":8088", waf.Middleware(myHandler))
```

### Sidecar (Docker / Kubernetes)

```bash
docker run -d -p 8088:8088 \
  ghcr.io/guardianwaf/guardianwaf:latest \
  sidecar --upstream http://app:3000
```

### Docker Compose with Auto-Discovery

No upstream config needed -- just add `gwaf.*` labels to your containers:

```yaml
services:
  guardianwaf:
    image: ghcr.io/guardianwaf/guardianwaf:latest
    ports:
      - "80:8088"
      - "9443:9443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./guardianwaf.yaml:/etc/guardianwaf/guardianwaf.yaml:ro
    command: ["serve", "-c", "/etc/guardianwaf/guardianwaf.yaml"]

  # Auto-discovered backend (weight: 3)
  api:
    image: myapp:latest
    labels:
      gwaf.enable: "true"
      gwaf.host: "api.example.com"
      gwaf.upstream: "api-pool"
      gwaf.port: "3000"
      gwaf.weight: "3"
      gwaf.health.path: "/healthz"

  # Same upstream pool (weight: 1) = load balanced
  api-2:
    image: myapp:latest
    labels:
      gwaf.enable: "true"
      gwaf.host: "api.example.com"
      gwaf.upstream: "api-pool"
      gwaf.port: "3000"
      gwaf.weight: "1"
      gwaf.health.path: "/healthz"

  # Different service on different domain
  web:
    image: nginx:alpine
    labels:
      gwaf.enable: "true"
      gwaf.host: "www.example.com"
```

Scale instantly: `docker compose up -d --scale api=5` -- GuardianWAF detects all 5 instances automatically.

---

## Production Deployment

### Kubernetes

GuardianWAF includes production-ready Kubernetes manifests:

```bash
# Apply all manifests
kubectl apply -f contrib/k8s/

# Verify deployment
kubectl get pods -l app=guardianwaf
kubectl logs -l app=guardianwaf
```

**Features:**
- 2 replicas with pod anti-affinity
- Security contexts (non-root, read-only filesystem)
- Resource limits (64Mi-256Mi memory, 100m-500m CPU)
- Health checks (`/healthz` endpoint)
- ConfigMap for WAF configuration
- Secret support for TLS certificates
- Horizontal Pod Autoscaler ready

See [contrib/k8s/README.md](contrib/k8s/README.md) for detailed configuration.

### Monitoring (Grafana)

Import the production dashboard:

```bash
# Via Grafana UI
# Dashboards -> Import -> Upload dashboard.json
```

**Dashboard includes:**
- Request rate, block rate, P99 latency
- Detection performance per detector
- Rate limiting and IP blacklist metrics
- Cluster health and upstream status
- Geographic distribution map
- AI analysis queue and cost tracking

See [contrib/grafana/README.md](contrib/grafana/README.md) for metrics reference.

### Docker Build

```bash
# Build image
docker build -t guardianwaf:latest .

# Run container
docker run -d \
  -p 8088:8088 \
  -p 9443:9443 \
  -v $(pwd)/guardianwaf.yaml:/etc/guardianwaf/guardianwaf.yaml:ro \
  guardianwaf:latest
```

---

## Deployment Topologies

```
A) Standalone (replaces nginx):
   Internet --> GuardianWAF(:443 + :80) --> backend-api:3000
                                        --> backend-web:8000

B) Behind CDN:
   Cloudflare --> GuardianWAF(:8088) --> backends
   (TLS handled by Cloudflare)

C) Kubernetes Sidecar:
   Ingress --> GuardianWAF(:8088) --> app(:3000)

D) Embedded Library:
   Go app --> waf.Middleware(handler)
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
| **JS Challenge / PoW** | Built-in | No | No | No | No |
| **Multi-domain routing** | Built-in (virtual hosts) | No | No | No | No |
| **TLS + ACME** | Built-in | External | External | External | External |
| **Load balancing** | 4 strategies + health check | No | No | No | No |
| **Circuit breaker** | Built-in | No | No | No | No |
| **Web dashboard** | Built-in (config + monitoring) | Built-in | No (third-party) | No (third-party) | No |
| **Single binary** | Yes | No | No | No | No |
| **Docker auto-discovery** | Label-based (`gwaf.*`) | No | No | No | No |
| **AI threat analysis** | Built-in (400+ providers) | No | No | No | No |
| **MCP / AI integration** | Built-in MCP server | No | No | No | No |
| **Prometheus metrics** | Built-in `/metrics` | No | No | No | No |
| **Threat Intelligence** | IP/domain reputation feeds | No | No | Partial (external) | No |
| **CORS Security** | Built-in layer | No | No | No | No |
| **ATO Protection** | Brute force + credential stuffing | No | No | No | No |
| **API Security** | JWT validation + API keys | No | No | No | No |
| **Configuration** | YAML + env + dashboard UI | Web UI | SecRule directives | SecRule directives | NGINX directives |
| **False positive mgmt** | Score tuning per-route | Auto learning | Rule exclusions | Rule exclusions | Allowlists |
| **Performance overhead** | < 1ms p99 | Low | Low | Moderate | Low |
| **License** | MIT | Apache 2.0 | Apache 2.0 | Apache 2.0 | GPL v3 |

---

## Architecture

```
                          GuardianWAF Pipeline
                          ====================

  HTTP Request
       |
       v
  +-----------+   +-------------+   +-----------+   +------------+   +-----------+
  |  IP ACL   |-->| Threat Intel|-->|   CORS    |-->| Rate Limit |-->|    ATO    |
  |   (100)   |   |    (125)    |   |   (150)   |   |    (200)   |   |   (250)   |
  +-----------+   +-------------+   +-----------+   +------------+   +-----------+
                                                                            |
       +--------------------------------------------------------------------+
       |
       v
  +-------------+   +------------+   +------------+   +------------+   +-----------+
  | API Security|-->| Sanitizer  |-->| Detection  |-->| Bot Detect |-->|  Response |
  |    (275)    |   |    (300)   |   |    (400)   |   |    (500)   |   |   (600)   |
  +-------------+   +------------+   +------------+   +------------+   +-----------+
                                                                              |
       +----------------------------------------------------------------------+
       |
       v
  +-----------+    +----------------+
  |    JS     |--->|   Upstream     |
  | Challenge |    | Load Balancer  |
  +-----------+    +----------------+
  (score 40-79)    |  |  |  |  |
                   v  v  v  v  v
                  Backend Targets
                  (health checked,
                   circuit breaker)
```

Each layer runs in order and can pass, log, challenge, or block the request. The detection layer runs 6 independent detectors (SQLi, XSS, LFI, CMDi, XXE, SSRF) and produces a cumulative threat score. Bot detection scores between 40-79 trigger a JavaScript proof-of-work challenge instead of blocking outright.

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

Input: Suspicious bot (UA: curl, high RPS)
  -> Bot score: 55                  -> JS CHALLENGE (proof-of-work page)
  -> Browser solves SHA-256 puzzle  -> Sets cookie, request passes
  -> Bot can't solve               -> Stays blocked
```

This graduated response eliminates most false positives while catching real attacks. Every blocked request includes the full score breakdown for transparent, data-driven tuning.

See [Detection Engine docs](docs/detection-engine.md) for the full pattern scoring table.

---

## Installation

### go install

```bash
go install github.com/guardianwaf/guardianwaf/cmd/guardianwaf@latest
```

### Binary Download

```bash
# Linux (amd64)
curl -Lo guardianwaf https://github.com/guardianwaf/guardianwaf/releases/latest/download/guardianwaf-linux-amd64
chmod +x guardianwaf
sudo mv guardianwaf /usr/local/bin/

# macOS (arm64)
curl -Lo guardianwaf https://github.com/guardianwaf/guardianwaf/releases/latest/download/guardianwaf-darwin-arm64
chmod +x guardianwaf
sudo mv guardianwaf /usr/local/bin/
```

### Docker (GHCR)

```bash
docker pull ghcr.io/guardianwaf/guardianwaf:latest
```

### Build from Source

```bash
git clone https://github.com/guardianwaf/guardianwaf.git
cd guardianwaf
make build
# Binary: ./guardianwaf
```

---

## Configuration

Minimal `guardianwaf.yaml` to protect a backend:

```yaml
mode: enforce
listen: ":8088"

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
  challenge:
    enabled: true
    difficulty: 20

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

**Monitoring (`/`)**
- Real-time traffic monitoring (requests/sec, blocks/sec, challenges, latency)
- Security event feed with filtering by action, IP, path, score
- Click any event to see full details: findings, matched patterns, threat scores
- Attack type breakdown and top source IPs charts
- Upstream health: backend status, circuit breaker state, active connections

**Configuration (`/config`)**
- Upstream management: add/remove backends, set load balancing strategy and weights
- Virtual host management: add/remove domains, configure per-domain routing
- Route management: path-to-upstream mapping with prefix stripping
- WAF settings: toggle detectors, adjust thresholds and multipliers
- JS Challenge: enable/disable, set difficulty
- Bot detection: mode, scanner blocking, behavioral thresholds
- IP ACL: add/remove whitelist and blacklist entries in real-time
- Rate limiting, sanitizer, response protection toggles

**Routing (`/routing`)**
- **Topology Graph** -- interactive React Flow visualization of the full request path: Clients -> WAF -> VHosts -> Routes -> Upstreams -> Targets, with TLS/SSL indicators, ports, health status, circuit breaker state
- **Backends** -- Docker-discovered services table + static upstreams, with container name, image, target URL, upstream pool, weight, health check path
- **Configure** -- form-based upstream/route/vhost management with save & rebuild

**AI Analysis (`/ai`)**
- Provider catalog (400+ from models.dev) with search and model details
- Model selection with context window, cost, reasoning/tool_call capabilities
- API key management with connection testing
- Manual "Analyze Now" trigger with instant verdict display
- Analysis history with expandable results, threats, verdicts, costs
- Usage stats: tokens/hour, requests/hour, total cost, AI blocks

**REST API:** The dashboard exposes a full [REST API](docs/api-reference.md) for programmatic management, protected by API key authentication.

| Endpoint | Description |
|---|---|
| `GET /api/v1/stats` | Runtime statistics |
| `GET /api/v1/events` | Paginated events with filters |
| `GET /api/v1/upstreams` | Backend health status |
| `GET/PUT /api/v1/config` | WAF configuration |
| `GET/PUT /api/v1/routing` | Upstreams, virtual hosts, routes |
| `GET/POST/DELETE /api/v1/ipacl` | IP whitelist/blacklist |
| `GET/POST/DELETE /api/v1/rules` | Custom WAF rules |
| `GET /api/v1/docker/services` | Docker-discovered backends |
| `GET/PUT /api/v1/ai/config` | AI provider configuration |
| `GET /api/v1/ai/providers` | Models.dev provider catalog |
| `POST /api/v1/ai/analyze` | Trigger AI analysis |
| `GET /api/v1/ai/history` | AI analysis history |
| `GET /api/v1/ai/stats` | AI usage & cost stats |
| `GET /metrics` | Prometheus metrics |
| `GET /healthz` | Health check (K8s probes) |
| `GET /api/v1/sse` | Server-Sent Events stream |

Access at `http://localhost:9443` (enabled by default in standalone mode).

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

http.ListenAndServe(":8088", waf.Middleware(myHandler))
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

GuardianWAF includes a built-in [Model Context Protocol](https://modelcontextprotocol.io) server that enables AI agents to monitor, query, and manage the WAF through structured tool calls. Two transports: **stdio** (local CLI) and **SSE** (remote HTTP with API key auth).

**15 MCP tools:**

| Category | Tools |
|---|---|
| Monitoring | `get_stats`, `get_events`, `get_top_ips`, `get_detectors` |
| Configuration | `get_config`, `set_mode` |
| IP Management | `add_whitelist`, `remove_whitelist`, `add_blacklist`, `remove_blacklist` |
| Rate Limiting | `add_ratelimit`, `remove_ratelimit` |
| Detection Tuning | `add_exclusion`, `remove_exclusion` |
| Testing | `test_request` |

**Claude Code (stdio):**

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

**Claude Desktop / VS Code (SSE — remote):**

```json
{
  "mcpServers": {
    "guardianwaf": {
      "url": "http://your-waf-host:9443/mcp/sse",
      "headers": { "X-API-Key": "your-api-key" }
    }
  }
}
```

Then ask: *"Show me the latest blocked requests and blacklist the top attacking IP."*

See [MCP Integration docs](docs/mcp-integration.md) for the complete tool reference, SSE protocol details, and curl examples.

---

## Performance

GuardianWAF targets sub-millisecond p99 latency overhead per request.

| Metric | Value |
|---|---|
| IP ACL lookup | < 100ns |
| Rate limit check | < 500ns |
| SQLi detection | < 200us p95 |
| All detectors combined | < 500us p95 |
| PoW verification (server-side) | ~60ns |
| Token generation (HMAC) | ~600ns |
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
- Circuit breaker with atomic state transitions (lock-free)

---

## Documentation

| Document | Description |
|---|---|
| [Getting Started](docs/getting-started.md) | Installation and first deployment |
| [Configuration Reference](docs/configuration.md) | Full YAML schema with every field |
| [Production Deployment](docs/production-deployment.md) | Production hardening, security, monitoring |
| [Architecture](docs/ARCHITECTURE.md) | System diagrams and component overview |
| [Security Best Practices](docs/security-best-practices.md) | Security hardening and hardening guide |
| [API Examples](docs/api-examples.md) | REST API examples in Go, Python, Node.js |
| [Troubleshooting FAQ](docs/troubleshooting-faq.md) | Common issues and solutions |
| [Detection Engine](docs/detection-engine.md) | Scoring system, detectors, pattern tables |
| [Deployment Modes](docs/deployment-modes.md) | Standalone, library, sidecar comparison |
| [Docker Auto-Discovery](docs/docker-discovery.md) | Label-based container discovery and routing |
| [AI Threat Analysis](docs/ai-analysis.md) | AI-powered threat analysis setup and configuration |
| [API Reference](docs/api-reference.md) | REST API endpoints with request/response examples |
| [MCP Integration](docs/mcp-integration.md) | AI agent tools and Claude Code setup |
| [Tuning Guide](docs/tuning-guide.md) | False positive reduction and threshold tuning |

Full documentation site: [guardianwaf.com/docs](https://guardianwaf.com/docs)

---

## Project Structure

```
guardianwaf/
├── cmd/guardianwaf/       # CLI entry point (serve, sidecar, check, validate)
├── internal/
│   ├── engine/            # Core WAF engine, pipeline, scoring, access logging, panic recovery
│   ├── config/            # YAML parser + serializer, config structs, env loading, validation
│   ├── layers/
│   │   ├── ipacl/         # IP whitelist/blacklist (radix tree, runtime add/remove, auto-ban)
│   │   ├── threatintel/   # Threat intelligence feeds (IP/domain reputation, LRU cache)
│   │   ├── cors/          # CORS validation (origin allowlist, preflight handling)
│   │   ├── ratelimit/     # Token bucket rate limiter (dynamic rule add/remove)
│   │   ├── ato/           # Account takeover protection (brute force, credential stuffing)
│   │   ├── apisecurity/   # API authentication (JWT validation, API keys)
│   │   ├── sanitizer/     # Request normalization and validation
│   │   ├── detection/     # Attack detectors (sqli/xss/lfi/cmdi/xxe/ssrf) with dynamic exclusions
│   │   ├── botdetect/     # Bot detection (JA3/JA4, UA, behavior)
│   │   ├── challenge/     # JS proof-of-work challenge (SHA-256 PoW)
│   │   ├── response/      # Response protection (headers, masking, error pages)
│   │   └── rules/         # Custom rule engine (geo-aware, dashboard CRUD)
│   ├── proxy/             # Reverse proxy, load balancer, circuit breaker, router, WebSocket
│   ├── tls/               # TLS cert store, SNI selection, hot-reload, HTTP/2
│   ├── acme/              # ACME client (RFC 8555), HTTP-01 challenge, cert cache
│   ├── dashboard/         # React UI, REST API, SSE, routing graph, AI page, Docker services
│   ├── ai/                # AI threat analysis (models.dev catalog, OpenAI client, batch analyzer)
│   ├── docker/            # Docker auto-discovery (socket client, label parser, event watcher)
│   ├── mcp/               # MCP JSON-RPC server and 15 tool definitions
│   ├── geoip/             # GeoIP database with auto-download and runtime refresh
│   └── events/            # Event storage (memory ring buffer, JSONL file, event bus)
├── guardianwaf.go         # Public API for library mode
├── options.go             # Functional options (WithMode, WithThreshold, etc.)
├── examples/              # Library and backend examples
├── docs/                  # Documentation (docker-discovery, ai-analysis, etc.)
├── testdata/              # Test configs and attack payloads
├── scripts/               # Attack simulation, smoke tests, real E2E tests
├── Dockerfile             # Multi-stage Alpine build
├── docker-compose.yml     # Standalone + auto-discovery example with gwaf.* labels
└── Makefile               # build, test, lint, bench, fuzz, cover, docker-test
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
