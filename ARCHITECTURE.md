# GuardianWAF Architecture

GuardianWAF is a zero-runtime-dependency Web Application Firewall written in Go. It can run as a standalone reverse proxy, as a sidecar proxy, or as an embeddable HTTP middleware. This document describes the architecture implemented in this repository: how the binary starts, how traffic flows through the engine, how optional subsystems connect to the core, and where state is stored.

## Goals and constraints

GuardianWAF is designed around these constraints:

- **Single deployable binary** for the WAF runtime.
- **Go standard library only** at runtime; `go.mod` intentionally has no external module dependencies.
- **Fail-closed startup for explicit durable state**: if file-backed event storage is configured and cannot be opened, startup fails instead of silently falling back to memory.
- **Composable inspection pipeline**: request security features are implemented as ordered engine layers.
- **Operational surfaces are optional**: dashboard, MCP, AI analysis, Docker discovery, ACME, alerting, and tracing plug into the core runtime without being required for request processing.
- **Defensive reverse proxying**: upstream targets are validated, private/reserved backends are blocked by default unless explicitly allowed, and health checking/circuit behavior is isolated in the proxy package.

## Repository map

| Path | Responsibility |
| --- | --- |
| `cmd/guardianwaf/` | CLI entry point, subcommands, runtime assembly, server lifecycle, dashboard/MCP/AI/Docker/alerting wiring. |
| `internal/config/` | Configuration model, defaults, custom YAML parsing, environment/CLI overrides, validation. |
| `internal/engine/` | Core WAF engine, request context, event model, ordered pipeline, logging, thresholds, stats. |
| `internal/layers/` | Security inspection and response layers: IP ACL, threat intel, CORS, rules, rate limit, ATO, API security, API validation, sanitizer, CRS, detection, virtual patching, DLP, bot detection, client-side protection, response handling. |
| `internal/proxy/` | Reverse proxy routing, virtual hosts, load balancing, health checks, circuit state, target validation. |
| `internal/events/` | Event store interface, in-memory ring buffer, persistent JSONL-backed memory store, event bus. |
| `internal/dashboard/` | Embedded dashboard assets and REST/SSE API for stats, events, config, rules, routing, analytics, AI, tenants, and operational endpoints. |
| `internal/mcp/` | JSON-RPC 2.0 Model Context Protocol server for tool-style WAF operations over stdio. |
| `internal/ai/` | Batch analysis of WAF events and optional auto-ban integration. |
| `internal/alerting/` | Webhook and email alert delivery. |
| `internal/docker/` | Docker container auto-discovery using Docker CLI or daemon event streams. |
| `internal/acme/` | ACME/HTTP-01 certificate provisioning using the standard library. |
| `internal/tls/` | Certificate store, SNI selection, OCSP helpers, certificate hot reload support. |
| `internal/tracing/` | Lightweight span/tracer/exporter API with OpenTelemetry-style vocabulary and no external SDK dependency. |
| `internal/tenant/` | Multi-tenant store, quota and billing structures, API-key support. |
| `internal/compliance/` | Compliance reporting helpers. |
| `docs/` | Operator guides, ADRs, API/config references, deployment notes, and detailed feature documentation. |
| `contrib/` | Kubernetes, Grafana, and deployment support assets. |
| `tests/` | End-to-end and integration-oriented test assets. |

## Runtime modes

The same binary supports several operating modes through `cmd/guardianwaf`:

| Mode / command | Purpose |
| --- | --- |
| `guardianwaf serve` | Primary reverse-proxy WAF mode. Builds the engine, registers runtime layers, starts HTTP/HTTPS listeners, optional dashboard, optional MCP server, optional Docker discovery, optional alerting, and optional background analysis. |
| `guardianwaf sidecar` | Sidecar-oriented runtime for protecting a local service. It reuses the same engine/proxy/layer primitives as `serve`. |
| Embeddable middleware | Library users can construct a GuardianWAF instance and wrap an existing `http.Handler`. The same engine and layer concepts apply. |
| Validation/check commands | Configuration and environment checks without starting the full proxy runtime. |
| Health/version/help commands | Operational and diagnostic CLI surfaces. |

The main build has two entry files selected by build tags:

- `cmd/guardianwaf/main_default.go` for the normal build.
- `cmd/guardianwaf/main.go` for builds with the `http3` tag.

## High-level component diagram

```text
Client / Bot / Scanner
        |
        v
HTTP or HTTPS listener
        |
        v
GuardianWAF runtime handler
        |
        +--> engine.Engine
        |        |
        |        v
        |   engine.Pipeline
        |        |
        |        v
        |   ordered internal/layers/* checks
        |        |
        |        +--> findings, scores, action, metadata
        |
        +--> events.EventStore / events.EventBus
        |
        +--> proxy.Router / proxy.Balancer / proxy.Target
                 |
                 v
              Upstream application
```

Optional side surfaces subscribe to or query the same runtime state:

```text
                  +-------------------+
                  | Dashboard REST/SSE|
                  +-------------------+
                           ^
                           |
+---------+       +-------------------+       +----------------+
| Alerting| <---- | EventBus/EventStore| ----> | AI analyzer    |
+---------+       +-------------------+       +----------------+
                           ^
                           |
                  +-------------------+
                  | engine.Engine     |
                  +-------------------+
                           ^
                           |
                  +-------------------+
                  | MCP JSON-RPC      |
                  +-------------------+
```

## Startup sequence

A typical `serve` startup performs these phases:

1. **Load configuration** from defaults, YAML, environment variables, and CLI flags.
2. **Validate configuration**, including listen addresses, upstreams, private upstream policy, TLS settings, dashboard/MCP settings, tenant settings, and state paths.
3. **Create the event store** using `cmd/guardianwaf/event_store.go`:
   - `memory`: fixed-size in-memory ring buffer.
   - `file`: JSONL-backed persistent memory store; parent directories are created with restrictive permissions and open errors abort startup.
4. **Create the event bus** for runtime consumers.
5. **Create `engine.Engine`** with config, event store, event bus, thresholds, logs, and stats.
6. **Register WAF layers** via `cmd/guardianwaf/layers.go` and supporting runtime builders.
7. **Build the reverse proxy** with upstream targets, load balancers, virtual hosts, routes, and health checkers.
8. **Wire optional subsystems** such as dashboard, MCP, AI analyzer, Docker discovery, ACME/TLS, alerting, tracing, cleanup jobs, and probes.
9. **Start HTTP servers** with bounded read, header, write, and idle timeouts.
10. **Handle shutdown** by stopping background resources, health checkers, event consumers, and stores.

## Configuration architecture

`internal/config.Config` is the central runtime model. It includes top-level runtime settings plus nested structures for WAF behavior, TLS, upstreams, routes, virtual hosts, dashboard, MCP, Docker discovery, alerting, logging, events, tenants, tracing, and feature flags.

Configuration layering is:

```text
DefaultConfig()
    -> YAML file
    -> environment variables
    -> CLI flags
```

Important configuration characteristics:

- `mode` controls enforcement behavior: enforce, monitor, or disabled.
- `waf.detection.threshold.block` and `waf.detection.threshold.log` control scoring outcomes.
- `trusted_proxies` determines which direct peers may supply proxy headers such as `X-Forwarded-For`.
- `allow_private_upstreams` and `allowed_upstream_cidrs` protect against accidental SSRF-style routing to private/reserved networks.
- `events.storage` selects in-memory or file-backed event persistence.
- `features` allows feature-gated runtime behavior without changing the core engine API.

The repository has extensive config validation tests because the configuration model is also an operator-facing API.

## Core engine

`internal/engine` owns the request-processing model.

Key types:

| Type | Role |
| --- | --- |
| `Engine` | Runtime owner for pipeline, config-derived thresholds, event store, event bus, stats, logs, challenge integration, and lifecycle cleanup. |
| `Pipeline` | Executes ordered layers and stops early on block actions. |
| `Layer` | Interface implemented by WAF inspection/response components. |
| `RequestContext` | Per-request state: request data, normalized values, client identity, TLS/tenant metadata, findings, scores, actions, timings, and layer metadata. |
| `OrderedLayer` | A layer plus an integer order constant. |
| `Event` | Security event emitted after inspection for storage, dashboard, alerting, AI, and integrations. |

The engine is intentionally independent from the CLI. The CLI assembles concrete runtime resources; the engine only depends on its configuration, event interfaces, and layers.

## Request processing flow

For proxied traffic, the request path is:

1. The HTTP server receives a request and applies server-level timeouts.
2. The runtime handler creates or enriches the request context.
3. `engine.Engine` builds an `engine.RequestContext` from the HTTP request, client IP, trusted proxy policy, tenant/virtual-host information, TLS metadata, and configured thresholds.
4. `engine.Pipeline.Execute` runs ordered layers.
5. Each layer may:
   - add findings,
   - add score,
   - set metadata,
   - mutate sanitized request values,
   - return pass/log/block action,
   - short-circuit the pipeline by blocking.
6. The engine records statistics and emits a security event.
7. If the final action blocks, GuardianWAF returns a block/challenge/response-layer result.
8. If the final action allows the request, `internal/proxy` selects an upstream target and forwards the request.
9. Response-related layers and logging complete the lifecycle.

Simplified flow:

```text
HTTP request
  -> request context
  -> IP / reputation / origin / custom policy checks
  -> rate and account-takeover controls
  -> API authentication/schema checks
  -> normalization and sanitization
  -> CRS and tokenizer-based detection
  -> virtual patching and DLP
  -> bot/client-side/response layers
  -> event + stats
  -> block or reverse proxy
```

## Pipeline order

Layer order constants live in `internal/engine/layer.go`. Some constants are reserved for planned or feature-gated capabilities, while the CLI only registers layers that have runtime implementations and are enabled/configured.

Implemented runtime layer families include:

| Order | Layer family | Package | Purpose |
| --- | --- | --- | --- |
| 100 | IP ACL | `internal/layers/ipacl` | Allow/deny CIDRs and auto-ban integration. |
| 125 | Threat intelligence | `internal/layers/threatintel` | Reputation-based checks and feed-driven decisions. |
| 150 | CORS | `internal/layers/cors` | Origin and CORS policy enforcement. |
| 150 | Custom rules | `internal/layers/rules` | Operator-defined match rules. |
| 200 | Rate limit | `internal/layers/ratelimit` | Token-bucket style request limiting. |
| 250 | ATO protection | `internal/layers/ato` | Brute force and credential-stuffing detection. |
| 275 | API security | `internal/layers/apisecurity` | API key and JWT-related checks. |
| 280 | API validation | `internal/layers/apivalidation` | Path and schema validation. |
| 300 | Sanitizer | `internal/layers/sanitizer` | Normalization before detection. |
| 350 | CRS | `internal/layers/crs` | OWASP CRS-inspired rules. |
| 400 | Detection | `internal/layers/detection` | Tokenizer-based attack detectors. |
| 450 | Virtual patch | `internal/layers/virtualpatch` | CVE/NVD-driven virtual patches. |
| 475 | DLP | `internal/layers/dlp` | Sensitive data leakage detection. |
| 500 | Bot detection | `internal/layers/botdetect` | Bot, fingerprint, and behavior checks. |
| 590 | Client-side protection | `internal/layers/clientside` | Client-side telemetry/report handling. |
| 600 | Response | `internal/layers/response` | Response hardening and final response policy. |

Detector subpackages under `internal/layers/detection/` include SQL injection, XSS, LFI, command injection, NoSQL injection, SSRF, SSTI, XXE, and related tokenizer/scoring utilities.

## Detection and scoring

GuardianWAF does not rely only on raw regex matching. The detection layer tokenizes and normalizes request components, runs enabled detector families, and accumulates findings with scores. The engine compares the cumulative score against configured thresholds:

| Score range | Default behavior |
| --- | --- |
| below log threshold | Pass and record normal stats. |
| at or above log threshold | Allow in normal flow but emit suspicious event. |
| at or above block threshold | Block in enforce mode; log in monitor mode. |

Default thresholds are defined by configuration defaults and can be overridden through YAML, environment variables, or CLI flags.

## Reverse proxy architecture

`internal/proxy` isolates upstream routing and forwarding from WAF inspection.

Main components:

| Component | Responsibility |
| --- | --- |
| `Target` | Validated upstream endpoint with weight and reachability state. |
| `TargetPolicy` | Private/reserved network policy for upstream targets. |
| `Balancer` | Target selection using configured strategies such as round-robin, weighted, IP-hash, or least-connections style behavior. |
| `Router` | Host/path matching, virtual host routing, route ordering, prefix handling, and retry behavior. |
| `HealthChecker` | Periodic target health checks. |
| Circuit state | Avoids repeatedly sending traffic to unhealthy backends. |

`cmd/guardianwaf/proxy_runtime.go` converts `config.UpstreamConfig`, routes, and virtual hosts into balancers and routers. Invalid upstreams are skipped with warnings; empty upstream groups do not become usable routes.

## Event and state model

Security events are the central integration point between request processing and operations.

`internal/events.EventStore` defines:

- `Store`
- `Query`
- `Get`
- `Recent`
- `Count`
- `Close`

Supported stores:

| Store | Behavior |
| --- | --- |
| Memory store | Fixed-size in-memory ring buffer. Fast and ephemeral. |
| Persistent memory store | Appends events to JSONL and replays recent events into memory on startup. Queryability is still bounded by `max_events`. |

The event bus fans out events to runtime consumers such as dashboard streaming, alerting, and AI analysis. Event storage and event streaming are separate so consumers do not need to be in the request hot path.

Default stateful paths are documented in `docs/state-persistence.md`. Operators should put persistent paths on explicit volumes and rotate/archive JSONL event files outside the process.

## Dashboard architecture

`internal/dashboard` provides the web UI and operational API. Static assets are embedded into the binary after the UI build, while legacy static files remain embedded for compatibility.

Dashboard responsibilities include:

- live stats and event views,
- event queries and SSE streaming,
- configuration and routing endpoints,
- dynamic rules and virtual patch views,
- tenant/admin compatibility handlers,
- AI analysis endpoints,
- compliance and analytics endpoints,
- optional profiling/debug endpoints when configured.

The dashboard is not required for request processing. It reads from the engine, event store, event bus, and runtime adapters provided by `cmd/guardianwaf`.

## MCP architecture

`internal/mcp` implements a JSON-RPC 2.0 Model Context Protocol server over stdio. It exposes tool-style operations against GuardianWAF runtime capabilities. Authentication-sensitive comparisons use constant-time checks where applicable. MCP is an optional operational interface and does not sit in the request hot path.

## AI analysis architecture

`internal/ai` performs batch analysis of suspicious WAF events. It is designed as an event consumer rather than an inline request dependency.

Key properties:

- bounded batch sizes,
- interval-based processing,
- token/request accounting fields in configuration,
- JSON-only analyzer response contract,
- optional integration with an `IPBlocker` interface for auto-banning.

If AI analysis is disabled or unavailable, core request inspection continues using deterministic layers.

## Docker discovery

`internal/docker` discovers containers and converts metadata into runtime routing inputs. The implementation primarily uses Docker CLI invocation for portability across local sockets, remote Docker contexts, Windows named pipes, and TLS-enabled Docker daemons. Direct socket/event handling exists where supported.

Production deployment should prefer TLS-based Docker access rather than mounting the Docker socket into the WAF container, because socket mounts are equivalent to high host privilege.

## TLS and ACME

TLS responsibilities are split across:

- `internal/tls`: certificate store, SNI lookup, OCSP helpers, hot reload support.
- `internal/acme`: ACME RFC 8555 client and HTTP-01 challenge support.
- `cmd/guardianwaf/*tls*` and `*acme*` runtime files: configuration-driven wiring into HTTP servers.

The normal runtime can use static certificates or ACME-provisioned certificates depending on configuration.

HTTP/3 is a config/build-tag compatibility surface only: no HTTP/3 runtime package/server is present in the current production binary, no runtime package backs HTTP/3 today, and HTTP/3/QUIC is not a production listener. The historical `internal/http3` experiment was removed, so references to HTTP/3 describe planned compatibility behavior rather than an active runtime package.

## Tracing and logging

GuardianWAF uses structured logging and a lightweight tracing package implemented with the standard library.

`internal/tracing` models:

- tracers,
- spans,
- span status,
- attributes,
- events,
- exporters.

The API uses OpenTelemetry terminology so a future external SDK integration can be added behind build tags without changing call sites. Existing span output uses JSON encoding for safe structured output.

## Multi-tenancy

Tenant support is represented in configuration, request context, dashboard handlers, and `internal/tenant`. The engine can attach tenant context to requests, including tenant identity, plan/quota metadata, and virtual-host information. Tenant-aware runtime behavior is then available to layers and operational surfaces.

## Deployment architecture

The project supports source builds, container builds, compose-based local environments, and Kubernetes/contrib assets.

Important deployment files:

| File/path | Purpose |
| --- | --- |
| `Dockerfile` | Multi-stage build: dashboard UI build, Go binary build, minimal runtime image. |
| `docker-compose.yml` | Development-oriented compose stack with local dashboard binding and test backend examples. |
| `docker-compose.prod.yml` | Production-oriented compose setup with safer Docker integration. |
| `contrib/k8s/` | Kubernetes manifests and deployment guidance. |
| `contrib/grafana/` | Dashboard/observability support assets. |
| `.github/workflows/` | CI and release automation. |
| `scripts/` | Build, prereq, smoke, release, and helper scripts. |

The runtime container runs the compiled Go binary and uses mounted volumes for durable data/log paths. The React dashboard build is a build-time asset pipeline, not a runtime Node.js dependency.

## Build and test architecture

The project is Go-first:

- `go.mod` declares the module and toolchain.
- `Makefile` provides common build, test, lint, coverage, fuzz, smoke, Docker, UI, and end-to-end targets.
- Tests are colocated across `cmd/`, `internal/`, and `tests/`.
- The dashboard UI has its own npm metadata under `internal/dashboard/ui/` and is built into embedded assets.
- CI validates formatting, tests, security posture, build reproducibility, and release artifacts.

## Security boundaries

GuardianWAF relies on several explicit security boundaries:

1. **Configuration validation before serving**: invalid or dangerous config fails early where possible.
2. **Trusted proxy allowlist**: proxy headers are only trusted from configured direct peers.
3. **Private upstream protections**: private, loopback, and reserved backends require explicit allow policy.
4. **Layer isolation**: each WAF feature is an ordered layer with a narrow request-context contract.
5. **Optional subsystem isolation**: dashboard, MCP, Docker discovery, AI, and alerting are not required for the request hot path.
6. **Durable-state honesty**: configured file-backed event storage must open successfully or the runtime fails startup.
7. **Standard-library runtime**: reduced supply-chain attack surface for the WAF binary.
8. **Container hardening**: compose/Docker assets use non-root runtime patterns, read-only filesystem options, and explicit volumes where applicable.

## Planned and reserved architecture points

Some constants, ADRs, and diagrams mention capabilities that are planned, reserved, build-tagged, or partially implemented. Examples include distributed cluster behavior, WebSocket frame inspection, gRPC message inspection, canary routing, replay capture, cache layers, anomaly/remediation layers, zero-trust identity checks, and distributed event storage.

When evaluating the current runtime, prefer the concrete code paths in:

- `cmd/guardianwaf/layers.go` for registered layers,
- `internal/layers/` for implemented layer packages,
- `cmd/guardianwaf/*_runtime.go` for optional subsystem wiring,
- `internal/engine/layer.go` for reserved order values.

## Extension guidelines

When adding a new feature:

1. Add configuration fields in `internal/config` with safe defaults and validation.
2. Implement request-time behavior as an `engine.Layer` if it affects inspection, scoring, blocking, or response policy.
3. Register the layer in `cmd/guardianwaf/layers.go` only when configuration enables it and runtime resources are available.
4. Keep long-running or network-dependent work outside the request hot path; use background consumers or caches.
5. Emit findings and events through the existing engine/event-store model.
6. Add dashboard/MCP/API surfaces as adapters over the core model, not as owners of core state.
7. Preserve the zero-runtime-dependency constraint unless the project intentionally changes that architecture decision.

## References

More detailed operator and design documentation lives in:

- `README.md`
- `docs/configuration.md`
- `docs/detection-engine.md`
- `docs/state-persistence.md`
- `docs/production-deployment.md`
- `docs/security-best-practices.md`
- `docs/api-reference.md`
- `docs/adr/`
