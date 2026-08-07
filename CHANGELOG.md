## [Unreleased]

### Breaking Changes

- Threat intel feed URLs and the GeoIP `download_url` must now use `https://`.
  Cleartext previously logged a warning and continued; it is now rejected at
  config validation, so a config with an `http://` URL fails to start. Set
  `waf.geoip.allow_insecure_url: true` or the per-feed
  `waf.threat_intel.feeds[].allow_insecure_url: true` to keep the old behaviour.
- Tenant-scoped API keys can no longer read `/api/v1/ssl`, `/api/v1/upstreams`,
  `/api/v1/docker/services`, or `/api/v1/alerting/status`. None of the four are
  tenant-partitioned, so every tenant could enumerate other tenants' certificate
  domains, the backend topology, discovered container services, and the
  operator's alert destinations. `/api/v1/stats` and `/api/v1/ai/stats` remain
  available — they return global counters only, with no per-tenant payload.

### Security

- SQLi: the comment-terminator auth bypass family (`admin'--`, `admin'#`,
  `admin')--`, `admin")--`, `admin'/*`) is now blocked. It was detected but
  scored 35, below the default block threshold of 50, so it passed in enforce
  mode. The rule now separates the tight shape (quote abutting the comment) at
  60 from the loose shape reachable through ordinary apostrophes, which stays
  log-only at 35.
- LFI: multiply URL-encoded traversal (`%252e%252e%252f`, and deeper) is now
  detected. The raw value holds only literal `%25` runs and the
  sanitizer-normalized value has already had `../` resolved away by
  `CanonicalizePath`, so neither existing scan view could see it; a third
  recursively-decoded, non-canonicalized view was added.
- SSTI: template-context object access (`{{config.items()}}`, `{{self.__init__}}`,
  `{{request.application}}`) is now detected. It sat between the arithmetic probe
  and the full gadget chain and matched neither. `{{config.items()}}` alone dumps
  a Flask config including `SECRET_KEY`.
- Cleartext `http://` threat-intel and GeoIP fetch URLs are rejected instead of
  warned about — see Breaking Changes.
- Dashboard dependency advisories cleared: `react-router` upgraded to 8.3.0 for
  the RSC CSRF bypass (fixed only in `>=8.3.0`), plus `undici`, `postcss`,
  `js-yaml`, and `brace-expansion`. `npm audit` now reports 0 vulnerabilities.
- CSP default now includes `frame-ancestors` directive to prevent clickjacking
- `Vary: Origin` header only set when CORS headers are actually present
- AI client blocks private/localhost endpoints by default (SSRF hardening)
- JWT algorithm warning message corrected to match actual defaults (RS256, ES256)
- Plaintext credential download removed from tenant creation wizard
- Regenerated API keys no longer shown in toast notifications

### Bug Fixes

- cmdi: a bare `>` in a comparison (`?filter=price>100`) scored 45, within one
  weak signal of the block threshold, which blocked legitimate filter-API
  traffic from non-browser clients. Redirection now requires a target that
  reads as a file path or fd duplication; comparisons score 10.
- Helm: with `replicaCount: 2` and no configured key, each pod generated its own
  dashboard API key, and the session signing secret derives from it — so API
  keys and session cookies issued by one pod were rejected by the others. The
  chart now generates a single Secret for the release, preserved across
  `helm upgrade`.
- Helm: `prometheus.serviceMonitor.*` values were documented but no template
  existed, so the settings did nothing. Added `templates/servicemonitor.yaml`.
- Helm: `Chart.yaml` described a "29-layer" pipeline; serve mode wires 16.
- `docker-compose.prod.yml` did not disable the `backend`/`backend2` example
  services, so the documented production command started two Go toolchain
  containers.
- Dashboard UI: `SortTh` in the rules page was defined inside the render body,
  creating a new component type on every render and remounting the whole table
  header. Moved to module scope.
- Dashboard UI: the alerting page's mount effect called `fetchStatus` before its
  declaration and declared no dependency on it.
- Dashboard UI: nine pages wrote state synchronously inside their mount effect
  and could write after unmount. Consolidated into `useMountLoad` /
  `usePollingLoad`, which add cancellation.
- Repository: `.temp_files/*` was committed as gitlinks with no `.gitmodules`,
  leaving unresolvable submodule references in a fresh clone. Untracked and
  ignored.
- Access log `TenantID` now captured before context pool release (was empty in logs)
- Tenant directory loading from `tenants.d/` now implemented (was stub)

### Performance

- File rotation I/O moved outside main mutex to reduce contention

### Dependencies

- Frontend toolchain taken to latest: Vite 6 → 8 (production build 3.3s → 0.3s,
  bundle 291 KB → 242 KB), ESLint 9 → 10, react-router 7 → 8, lucide-react
  0.500 → 1.29, jsdom 29 → 30, `@testing-library/jest-dom` 6 → 7,
  `@vitejs/plugin-react` 4 → 6.
- TypeScript held at 6.0.3 rather than 7.0.2: `typescript-eslint` does not
  support TS 7 (`peerDependencies.typescript: ">=4.8.4 <6.1.0"`) and hard-fails
  the lint gate. Revisit once upstream ships TS ≥7.1 support.
- Dockerfile UI stage moved to `node:24.15.0-alpine`; the previous
  `node:22.14.0` pin no longer satisfies the lockfile (`jsdom` requires
  `^22.22.2 || ^24.15.0`, `react-router` requires `>=22.22.0`). Runtime base
  moved to `alpine:3.24.1`, CI `node-version` to 24.
- GitHub Actions pins refreshed across all workflows (checkout v4 → v7,
  setup-go v5 → v7, setup-node v4 → v7, upload-artifact v4 → v7,
  download-artifact v4 → v8, cosign v3 → v4, goreleaser v6 → v7, and others).
- pre-commit: `golangci-lint` repository URL corrected (the configured
  `golangci-lint/golangci-lint` does not exist) and the pin moved from v1.64.8
  to v2.12.2, which is required to parse the `version: "2"` `.golangci.yml`.

### Frontend

- Removed duplicate stats polling in dashboard
- Replaced 5 `any` types in admin API with proper TypeScript interfaces
- Removed dead `use-stats` hook

### Testing

- Added 8 tests for tenant directory loading
- Added 6 tests for access log TenantID propagation

### Configuration

- Shutdown timeout increased to 30 seconds with overall deadline enforcement

---

## [1.0.0] - 2026-04-05

### Production Release

#### Critical Fixes
- **Cluster Package Mutex Fix**
  - Fixed sync.RWMutex copying undefined behavior
  - Resolved deadlock in handleJoin and startLeaderElection
  - Added StateSyncData struct with Clone() method for safe copying

- **GraphQL Parser Fix**
  - Fixed alias parsing with parentheses (e.g., `__type(name: "User")`)
  - Fixed depth calculation to start from 1 instead of 0

- **WebSocket Pattern Matching**
  - Fixed flaky test with ordered slice pattern matching
  - Ensured deterministic pattern detection order

#### Infrastructure
- **Kubernetes Support**
  - Added production-ready Kubernetes manifests
  - Deployment with 2 replicas, security contexts, health probes
  - ConfigMap for WAF configuration
  - Service and Ingress with dashboard auth
  - Comprehensive deployment documentation

- **Monitoring**
  - Added Grafana production dashboard (25+ panels)
  - Request rate, block rate, P99 latency metrics
  - Detection performance per detector
  - Geographic distribution map
  - AI analysis queue and cost tracking

#### Documentation
- Updated README with production deployment section
- Added PRODUCTION_READINESS_SUMMARY.md

---

## [0.4.0] - 2026-04-04

### Added

#### Phase 1: ML Anomaly, API Discovery, GraphQL Security, Enhanced Bot Management

- **ML Anomaly Detection Layer**
  - Unsupervised ML-based anomaly detection
  - Real-time behavioral analysis
  - Configurable thresholds and auto-blocking
  - Feature extraction from requests

- **API Discovery Engine**
  - Automatic API endpoint discovery
  - Passive traffic analysis
  - OpenAPI spec generation and export
  - Real-time endpoint statistics
  - JSON and OpenAPI export formats

- **GraphQL Security Layer**
  - Query depth limiting (configurable max depth)
  - Complexity analysis and scoring
  - Introspection blocking
  - Endpoint allowlisting

- **Enhanced Bot Detection**
  - hCaptcha/Turnstile integration
  - Biometric behavioral analysis
  - Browser fingerprinting (Canvas, WebGL, Fonts)
  - Headless browser detection
  - JavaScript challenge collector

#### Phase 2: gRPC Support, Multi-tenancy, Advanced DLP

- **gRPC/gRPC-Web Proxy**
  - HTTP/2 transport support
  - gRPC-Web bridging for browsers
  - Protocol Buffer validation
  - Method-level access control (ACL)
  - Message size limits

- **Multi-tenancy with Namespace Isolation**
  - Tenant CRUD operations
  - Domain-based and API key resolution
  - Resource quotas per tenant:
    - Max requests per minute/hour
    - Bandwidth limits
    - Max rules, rate limits, IP ACLs
  - Usage tracking (requests, bytes, blocked)
  - Wildcard domain support (*.example.com)
  - Context-based tenant propagation
  - REST API: `/api/v1/tenants/*`

- **Advanced DLP (Data Loss Prevention)**
  - Pattern detection for:
    - Credit Cards (Visa, MasterCard, Amex, Discover, JCB, Diners)
    - US Social Security Numbers (SSN)
    - IBAN (International Bank Account Numbers)
    - Email addresses
    - Phone numbers
    - API Keys and tokens
    - Private Keys (RSA, EC, DSA)
    - Passport numbers
    - Tax IDs (EIN)
  - Request/response body scanning
  - Automatic PII masking
  - Risk scoring per pattern
  - Custom pattern support

#### Integration

- **v0.4.0 Feature Integrator** (`internal/integrations/v040`)
  - Unified initialization for all v0.4.0 features
  - Layer registration with proper ordering:
    - 450: GraphQL Security
    - 475: ML Anomaly Detection
    - 500: Enhanced Bot Detection
    - 550: Advanced DLP
  - HTTP handler registration
  - Statistics aggregation

### Changed

- Layer order system updated for new Phase 1 & 2 layers
- Dashboard API extended with tenant management endpoints
- Configuration schema extended:
  - `WAF.MLAnomaly`
  - `WAF.APIDiscovery`
  - `WAF.GraphQL`
  - `WAF.GRPC`
  - `WAF.Tenant`
  - `WAF.DLP`
  - `WAF.ZeroTrust`
  - `WAF.SIEM`
  - `WAF.Cache`
  - `WAF.Replay`
  - `WAF.Canary`

#### Phase 3: Zero Trust, SIEM, Advanced Caching, Request Replay, Canary Releases

- **Zero Trust Network Access (ZTNA)**
  - mTLS client certificate verification
  - Device attestation with 5 trust levels
  - Session-based authentication with TTL
  - Certificate revocation checking
  - Zero Trust middleware

- **SIEM Integration**
  - 6 export formats: CEF, LEEF, JSON, Syslog, Splunk, Elasticsearch
  - Batch export with configurable size and flush interval
  - HTTP/TLS transport support

- **Advanced Caching Layer**
  - Memory (LRU) and Redis backends
  - Configurable TTL and size limits
  - Cache key generation
  - Stale-while-revalidate support

- **Request Replay**
  - HTTP request/response recording
  - JSON and binary format support
  - Replay engine with rate limiting
  - Dry-run mode

- **Canary Releases**
  - 5 routing strategies: percentage, header, cookie, geographic, random
  - Dynamic percentage adjustment
  - Automatic rollback on error/latency thresholds

### Security

- DLP pattern detection prevents data exfiltration
- Multi-tenant isolation prevents cross-tenant data access
- gRPC method ACLs for fine-grained access control
- Enhanced bot detection with biometric analysis

### Testing

- **Phase 1 Tests**: 50+ new test cases
- **Phase 2 Tests**: 47+ new test cases
  - Multi-tenancy: 25 tests
  - gRPC proxy: 12 tests
  - DLP patterns: 22 tests
- Overall test coverage maintained >95%

### Phase 3 Tests

- **Zero Trust**: 15 test cases (mTLS, attestation, sessions)
- **SIEM**: 12 test cases (formatters, exporters)
- **Advanced Caching**: 25 test cases (memory, Redis, layer)
- **Request Replay**: 18 test cases (recorder, replayer, filters)
- **Canary Releases**: 19 test cases (strategies, routing, rollback)

## [0.3.0] - 2026-04-04

### Added

#### Core Infrastructure

- **Multi-Domain Reverse Proxy**
  - Host-based routing via virtual hosts
  - WebSocket proxy support with Upgrade header forwarding
  - Request body decompression (gzip/deflate)
  - Atomic proxy rebuild on configuration changes

- **TLS Termination & ACME**
  - SNI-based certificate selection
  - ACME/Let's Encrypt auto-certificate provisioning (HTTP-01)
  - TLS/SSL configuration in dashboard UI

- **Load Balancing**
  - Round-robin, weighted, least-connections, and IP-hash strategies
  - Circuit breaker per target (5 failures → open → half-open → probe)
  - Active health checks with configurable interval and timeout

- **Load Balancing Dashboard**
  - Configuration editor for upstream targets and health checks
  - Real-time status display

#### Security Layers

- **CORS Layer** (Order 150)
  - Origin validation with configurable allowlists
  - Preflight request caching
  - Configurable methods, headers, and max-age

- **Threat Intelligence** (Order 125)
  - IP/domain reputation feeds with LRU cache
  - Configurable feed sources and TTL

- **ATO (Account Takeover) Protection** (Order 250)
  - Brute force detection with configurable thresholds
  - Credential stuffing pattern recognition
  - Password spray attack detection

- **API Security** (Order 275)
  - JWT validation (RS256, ES256, HS256)
  - API key authentication
  - Per-path security policy configuration

- **JA4 TLS Fingerprinting**
  - JA4 fingerprint extraction from TLS handshake data
  - Bot detection via TLS fingerprint matching
  - Event data enrichment with JA4 fingerprints
  - Dashboard display of JA4 data

- **JavaScript Proof-of-Work Challenge** (Order 430)
  - SHA-256 proof-of-work challenge for bot mitigation
  - Configurable difficulty levels
  - Challenge token validation and expiry

- **Custom Rules Engine** (Order 150)
  - GeoIP-aware rule matching
  - Dashboard CRUD for rule management
  - Rule templates library with 20 pre-built rules
  - Sortable columns in rules table

- **Temporary IP Bans**
  - Duration-based bans with automatic expiry
  - Dashboard management interface
  - Auto-ban integration from rate limit layer

#### Observability

- **Metrics Endpoint**
  - Prometheus `/metrics` endpoint (requests, blocks, latency histograms)
  - Configurable metric collection

- **Log Level Control**
  - Dynamic log level filtering (debug/info/warn/error)
  - Application log buffer with level filtering
  - Application logs viewer in dashboard

- **GeoIP**
  - Auto-download from DB-IP Lite
  - Country-based traffic analytics
  - GeoIP cleanup and refresh

- **Traffic Chart**
  - Real-time traffic visualization (last 30 minutes)
  - Dashboard integration

#### AI Threat Analysis

- **AI-Powered Threat Analysis**
  - Background batch processor (not per-request)
  - OpenAI-compatible API client
  - Configurable cost limits (tokens/hour, tokens/day, requests/hour)
  - Auto-block IPs based on AI verdict (confidence >= 70%)
  - AI analysis history and usage statistics in dashboard

#### Docker Auto-Discovery

- Watches Docker daemon for containers with `gwaf.*` labels
- Auto-creates upstreams, routes, and virtual hosts from labels
- Event-driven (container start/stop) with poll fallback
- Dashboard integration

#### Alerting

- **Webhook Alerting**
  - Slack webhook integration
  - Discord webhook integration
  - Custom webhook support with configurable payloads
  - Event-driven alert triggers

#### MCP (Model Context Protocol)

- MCP JSON-RPC server with 44 tools
- MCP SSE transport with API key authentication
- Persistence for MCP state

### Frontend

- **Modern React Dashboard**
  - Rebuilt with React + Vite + Tailwind 4 + shadcn/ui
  - Real-time monitoring with User-Agent parsing and SSE
  - Interactive routing topology graph with @xyflow/react
  - Live configuration editor (GET/PUT API endpoints)
  - IP ACL management UI
  - AI analysis page with provider configuration
  - Docker/AI/Alerting config sections
  - Dashboard authentication with API key
  - SPA routing for /config and /routing paths

### Infrastructure

- **Docker**
  - Multi-stage Docker build with React dashboard
  - GHCR (GitHub Container Registry) support
  - AI store directory permissions fix for containers

- **CLI**
  - `guardianwaf serve` — full standalone proxy with dashboard
  - `guardianwaf check` — dry-run request scoring
  - `guardianwaf validate` — config file validation
  - Unit tests for CLI commands

- **CI/CD**
  - GitHub Actions CI/CD pipeline
  - Lint job with golangci-lint
  - Enhanced Makefile with test/bench/fuzz/cover targets

### Documentation

- Security layers documentation and comparison table
- JA4 TLS fingerprinting documentation
- MCP SSE transport documentation
- Website landing page updates with new features
- Comprehensive production deployment guide
- Architecture diagrams
- Security, API, and troubleshooting guides

### Testing

- Test coverage improved across all packages
- Detection layer coverage at 100%
- AI package coverage improved to 98.9%
- ATO package coverage improved to 87.5%
- Docker package coverage improved to 75.1%
- E2E test script and configuration
- Smoke test harness and Docker integration test suite
- Race condition fixes in MCP SSE handler tests

### Changed

- Default listen port changed from 8080 to 8088
- Dashboard assets served without separate auth requirement
- Alerting system completed with Slack/Discord payload support
- JWT ASN.1 parser for certificate handling

---

## [0.2.0] - 2026-04-03

_Initial public release with core WAF engine, 6 detection layers (SQLi, XSS, LFI, CMDi, XXE, SSRF), scoring pipeline, basic dashboard, and proxy support._

---

## [0.1.0] - 2026-04-02

_Project initialization, core architecture, and CI/CD pipeline setup._
