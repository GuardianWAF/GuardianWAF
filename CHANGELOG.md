## [v0.6.0] - 2026-09-12


### Features

- **f50ff44** **challenge**: challenge issuance and replay coverage
- **05704bd** **crs**: SETVAR increment, C3 regression; layer/parser/rule updates
- **2c9977f** **dlp**: body replay scanning
- **5f1a71d** **detection**: harden cmdi/lfi/nosqli/sqli/ssrf/xss patterns; openredirect and smuggling coverage
- **ccfe536** **engine**: pipeline action escalation; response writer and redaction coverage
- **5ad9206** authenticate gossip and raft peer traffic with HMAC-SHA256
- **bb8aa6b** **cluster**: add WAL compaction/snapshotting for bounded log growth
- **e77c470** **raft**: add WAL persistence for cluster restart survival
- **5da5a8c** **cli**: add 'guardianwaf cluster health' command for scripting
- **4eaa48c** **cli**: add 'guardianwaf cluster nodes' command
- **74337b1** **cli**: add `guardianwaf cluster bans` command to list cluster-wide bans
- **938d5b6** **cluster**: add `cluster ban` and `cluster unban` CLI commands
- **839497f** **cluster**: add 'cluster status' CLI command for human-readable cluster summary
- **a181ba0** **cluster**: cluster-aware readiness probe via gossip isolation detection
- **0b1bf3d** **k8s**: add cluster StatefulSet, headless Service, and PDB manifests for Kubernetes deployment
- **007d520** **grafana**: add cluster monitoring dashboard with Raft and store metrics
- **6b53571** **cluster**: propagate DashboardAddr via gossip wire format for leader redirects
- **bc68c94** **cluster**: leader-redirect for ban/unban requests on followers
- **2df0d93** **config**: add cluster config validation tests
- **c8513b7** **metrics**: add cluster Prometheus metrics and test
- **3b94fdb** **cluster**: wire ProposeBan/ProposeUnban into dashboard ban/unban handlers
- **cc5001c** integrate gossip membership with Raft for dynamic peer discovery
- **3900eb0** cluster health dashboard endpoints + status provider wiring
- **01d12dc** **cluster**: wire clustersync store into WAF request pipeline
- **0e88f7e** **cluster**: Wire clustersync store into WAF request pipeline
- **4bf1878** **clustersync**: replicated state store for ban lists, rules, and counters
- **24e27c4** **cluster**: implement Raft consensus layer with leader election and log replication
- **bd02f36** **cluster**: SWIM gossip membership protocol

### Bug Fixes

- **e5ab53b** **bug-hunt**: land earlier-series cleanup restart, cluster dashboard advertise-addr, dashboard rules add and CRS toggle MCP fixes
- **34671ee** **acme**: preserve problem documents, fail fast on challenge rejection, guard nil-client obtain
- **e99cbce** **docker**: make discovery network fallback deterministic
- **64c6dfd** **proxy**: retry multi-target failover among untried targets
- **bb6bf3d** land 25-round audit series — 13 proven defects across 12 packages
- **4c6c0f4** **bug-hunt**: land earlier-series detection fail-open, header matching, API-key, cookie, CORS and SIEM lifecycle fixes
- **816b7db** **dashboard**: cap rotate-key request body size
- **97ddc23** **siem**: escape '=' in CEF extension values to stop log forging
- **b5edcc2** **virtualpatch**: match every transmitted header value, not just the first
- **255e51d** **apivalidation**: preserve list-item keys in the YAML schema parser
- **eebe705** **wizard**: correct CORS/ATO YAML indentation in generated config
- **90d6165** **apivalidation**: deep-equality enum matching for object and array enums
- **0a6d877** **dashboard**: reject malformed ban durations instead of silently defaulting to 1h
- **dde4874** **dashboard**: return 404 for unknown patch IDs in virtual patch updates
- **4fc2087** **dashboard**: stop fabricating compliance uptime and log-completeness metrics
- **27f5b81** **ai**: back off analyzer loop restarts after panic
- **7ece9df** **mcp**: convey inline schema content and strict mode in upload_api_schema
- **2f2769d** **docker**: return error when the events stream dies instead of hanging forever
- **50f86dd** **dashboard**: return 503 instead of panicking on disabled billing in tenant billing-detail
- **eb0c091** **acme**: restart renewal loop with backoff after panic
- **72bc29b** **compliance**: make GDPR Art.32 DLP control falsifiable
- **f2e26e4** **docker**: deterministic port selection for unlabeled multi-port containers
- **a1c7162** **gossip**: harden protocol frame handling and relay path
- **af8c127** **peersync**: repair peer bridge reconnect loop
- **123f790** **cluster**: bound Raft startup election timeout
- **11ce920** **cluster**: close WAL write-path size accounting gap
- **977669d** **tls**: harden certificate store lifecycle handling
- **d730578** fix(tls): OCSP response parsing (certStatus/validity window), basic-type enforcement, RFC 6960 request format, and staple policy hardening
- **b9c6b2d** **bug-hunt**: land twelve-round proof-driven series — detection, parsing, transform, wire-format and lifecycle fixes
- **84662f8** **config**: reject routes referencing unknown upstreams with zero upstreams
- **f406c5c** **engine**: prune oldest log generations in numeric order
- **04fd2ee** **events**: reopen persistence after failed compaction
- **2ff7ee1** **mcp**: lock apiKey snapshots in stdio handlers (data race)
- **bb944f8** **cmd**: exit 1 on challenge-init and TLS-listener failures
- **7e8585c** **acme**: force-renew inside the 30d window; atomic cert/key install; reject non-P-256 keys
- **064dd04** **gossip**: join/leave callbacks fire on transitions; wire PurgeDead into probeCycle
- **5df04a3** **raft**: reject stale-term RequestVotes (§5.2); bound WAL snapshot entryCount
- **bb1232c** **dashboard**: replace stub handler responses with real behavior; persist config mutations with rollback
- **3ee6aec** **dashboard**: make virtualpatch DELETE disable honestly instead of faking deletion
- **66f06cd** **websocket**: always run origin gate — empty AllowedOrigins denies browsers (CSWSH)
- **0a191e8** **config**: reject v4-mapped IPv6 trusted-proxy CIDRs that degenerate to trust-everything
- **669fa36** **botdetect**: wire error recording through post-process hook
- **e7e1fb8** **clientside**: match exclusions on path boundary; keep protected paths wide
- **431a9b1** **ato**: build /24 prefix keys in dotted decimal so subnet entries resolve
- **8fee0a7** **ato**: record travel state on successful logins
- **56a45d3** **cors**: reject all-origins wildcard combined with AllowCredentials
- **a9efecc** **ratelimit**: match and key on normalized path to stop encoding bypass
- **659f752** **virtualpatch**: flag uncompilable regex patterns at ingestion
- **3eae4df** **response**: mask adjacent cards inside long digit runs
- **24a4052** **apivalidation**: enforce additionalProperties and strict mode without properties
- **ac9f567** **crs**: make from-file operators read their argument files
- **0b3a3e0** **lfi**: normalize sensitive-path trie entries to lowercase
- **d31581d** **websocket**: forward takeover leftovers to client; scan assembled continuation messages
- **fe777fe** **websocket**: never dial client-supplied Host for upgrades
- **8401f33** **challenge**: reject out-of-range PoW difficulty at construction
- **0310df8** **docker**: label prefix handling; coverage
- **fc3bfaf** **regexsafe**: fail-closed regex evaluation with per-regex deadlines
- **592db7f** **raft**: WAL updates
- **3f17be0** **dashboard**: auth/session updates
- **a443591** **proxy**: circuit half-open probe; extra coverage
- **ffc4567** **ratelimit**: path boundary; coverage
- **7deb68a** **virtualpatch**: CVE handling; byproduct dedup; C4 regression
- **9ba38d3** **ato**: form extraction; tracker hardening
- **12deead** **cors**: origin normalization
- **0fb5e07** **botdetect**: user-agent scanning; scanner knob coverage
- **2e530ed** **apisecurity**: api-key hashing and JWT kid claims validation
- **cd0d8e2** **sanitizer**: encoding-bypass and hop-hop coverage; response masking unicode
- **f3e9fd5** **proxy**: don't replay consumed bodies on failover of chunked uploads
- **b81385d** **crs**: strict %-escape validation; count &ARGS values; Go TIME* layouts
- **f283c75** **dashboard**: clamp audit entries so the persistent log always replays
- **d23ec35** **mcp**: don't answer JSON-RPC notifications over SSE/JSON transport
- **7e5d0d7** **raft**: persist candidate self-votes; unstick single-node commits
- **cfe6245** **ipacl**: validate auto-ban IP inputs
- **be9e54f** **tenant**: multi-tenant accounting, quota, and lifecycle fixes
- **1229eec** **gossip**: guard UpdateMember against use-after-shutdown
- **2fe8ad3** **siem**: honor https scheme prefix on exporter endpoints
- **8de4b37** **engine**: resume log rotation after a failed rotation cycle
- **e289fcf** **rules**: canonicalize rule-authored header names for lookups
- **f33cb04** **threatintel**: enforce DomainRep.BlockMalicious for flagged domains
- **423cc41** **threatintel**: accumulate CIDR feeds into a union before tree publish
- **019bf13** resolve proven defects across crs, compliance, geoip, engine, and tenant
- **54915e0** **crs**: populate ARGS and recognize quoted/negated operators
- **b4dd220** **crs**: recognize quoted operators - file-loaded rules were inert
- **92ce3f3** **clustersync**: counter/ban lifecycle and ban duration validation
- **5e5052d** **mcp**: invalidate authenticated sessions on API-key rotation
- **198f07f** **tenant**: domain resolution, index consistency, store bootstrap
- **23c9cc3** cancel gossip suspect timers on Stop so onLeave cannot fire post-shutdown
- **e94622c** resolve round-3 scan findings (tenant rate window, netutil bare IPv6)
- **d907f76** resolve round-2 scan findings (ai logger race, email nil panic, SIEM JSON injection, event bus close race, GeoLite2 parsing)
- **dafbb06** resolve round-1 scan findings (acme race, SMTP MIME, watcher restart)
- **a51eab8** **config**: enforce strict waf.* key rejection at populate time
- **b0b1d93** **security**: thread per-request regexsafe deadline through CRS and VirtualPatch
- **893eb9f** **security**: harden detection engine, auth, rate limiting, and input parsing
- **af9e2ef** fix WAL filename mismatch and lint warnings
- **bbfa780** correct WAL filename mismatch (raft.wal not raft-wal.log)
- **15e28ab** add #nosec G115 annotations for WAL integer conversions
- **9a3c950** correct #nosec G115 annotation format for gosec
- **54058a7** **security**: add #nosec G115 annotations for int->uint64 conversions in cluster_status.go
- **738b674** use errors.Is for errorlint in e2e redirect test
- **8f47e87** use errors.Is for wrapped error comparison in replication test
- **b356901** resolve lint shadow warning in cluster_runtime.go
- **661821a** **virtualpatch**: replace atomic.Value with mutex-protected lastError
- **9d3d186** check clusterRT.Stop() return value for errcheck lint
- **ac1f8b8** gofmt + deadcode coverage for cluster integration
- **4891c59** **clustersync**: remove internal/clustersync from plannedOnlyDirs guard
- **bdecc1f** **cluster/raft**: fix deadcode findings, stabilize leader election
- **fb5cba9** **raft**: gosec G115 + lint fixes (conversion helpers, shadow, dead imports)
- **a79827a** **gossip**: write address bytes in EncodeMembers — addr was length-only
- **ae83c8b** **gossip**: use correct gosec #nosec G115 directive format
- **f596093** **cluster/gossip**: fix encoding G115 lint, add public API methods, resolve deadcode

### Documentation

- **065e315** **prod-readiness**: mark B2/B3 transitively closed and verify GH Actions pins
- **286ea1e** **cmdi**: document M1 checkEncodedNewline FP risk with regression test
- **46ac14e** **clustering**: comprehensive cluster CLI reference for all 6 subcommands
- **5670e25** add production readiness checklist to clustering guide
- **8cbce60** add CLI reference and partition resilience to clustering guide
- **13582ba** add documentation index page with complete doc links
- **f6ee73f** add clustering guide and cluster metrics documentation
- **f0766a7** update ADR index and v0.6.0 roadmap for gossip implementation
- **e7d715d** v0.6.0 roadmap — cluster sync, canary routing, response cache

### Refactoring

- **f9a0330** **config**: remove inert WAF.MLAnomaly/WAF.APIDiscovery config structs (keep WAF.GraphQL — live)
- **043742c** **cluster**: use peersync.Bridge, add tests, remove dead bridges

### Tests

- **653b8b2** **dashboard**: drop unused round77 mocks that broke the lint and deadcode gates
- **f15b9e6** **sqli**: pin documented comment-after-string semantics
- **2421a9f** **geoip**: extended coverage; remove stale fixture
- **2befa5a** **websocket**: continuation inspection coverage
- **7d1e35c** **clientside**: agent dedup and inject index coverage
- **0a66755** **apivalidation**: content-type bypass, form source, implicit type, JSON detection, ref bypass, schema runes
- **121fe7e** **config**: ingress exposure, outbound network policy, supply-chain coverage
- **72d89fe** **gossip**: partition-level failure detection + readiness isolation
- **0a76cb5** **cluster**: add network partition / split-brain tests
- **2120bf7** add chaos tests for leader failover during active ban operations
- **ecf45a3** add 3-node end-to-end cluster flow test (gossip → leader election → ban via follower → 307 redirect → replication)
- **ee4630e** add cluster ban propagation tests for dashboard handlers
- **18d87ce** add 3-node cluster integration tests for ban/rule/counter replication

### Chores

- **771ea84** **ci**: suppress AVD-KSV-0109 template false positive and gate the config scan on .trivyignore
- **2e0e5bc** **ci**: add justified, self-expiring .trivyignore for CVE-2026-14456
- **4ac3808** **project**: docs reorg, dependabot, release tooling, k8s manifests
- **a345492** **repo**: clean up repo root and tighten .gitignore

### Other Changes

- **24d9766** upgrade Go toolchain 1.26.5 -> 1.26.6 across all build paths
- **8ac3434** **dashboard**: bump nanoid to 3.3.18 (GHSA-2v37-7h3g-55p8)
- **e3da456** **website**: bump browserslist to 4.28.9 (GHSA-c83g-rgw3-j3cx, GHSA-73wf-gq98-2v4g)
- **a4ea8c9** **website**: bump @humanfs/node to 0.16.8 in lockfile
- **8b53a15** **pre-commit**: block banned repo-root paths from being tracked
- **8fb1ca4** fix gofmt in cluster_status.go
## [v0.5.0] - 2026-08-08

### Added — v0.5.0 Detection Expansion

- **HTTP Request Smuggling detector** — inspects CL/TE framing headers for
  desync attacks (CL.TE, CL.CL, TE.TE obfuscation, duplicate TE, HTTP/1.0 + TE,
  CR/LF injection). 15 unit cases + fuzz target.
- **Open Redirect detector** — 18 redirect parameter names + 6 redirect headers,
  detects external URLs, protocol-relative, scheme injection, data exfil,
  backslash confusion, CRLF injection. Same-origin bypass. 27/28 corpus (96.4%).
- **GraphQL depth/complexity detector** — max depth, max complexity, introspection
  blocking, aliasing abuse (>10 same-field), fragment cycles, batch-query bombs,
  parenthesis nesting. Raw/JSON/query-param transport support. 20/20 corpus (100%).
- **SIEM export (CEF over TLS syslog)** — async batch sender via EventBus. CEF
  and JSON formats. Auto-reconnect with exponential backoff. Block/challenge event
  filtering. Tenant-isolated. Config: `waf.siem.*`.
- **WebSocket inspection layer** — frame-level injection detection on text frames
  (full 11-detector pipeline), origin validation (CSWSH), frame size limiting,
  connection limiting per IP, binary frame blocking. Config: `waf.websocket.*`.
- **Dashboard SSE live feed** — real-time event push via Server-Sent Events with
  pause/resume (500-event buffer), connection status indicator, filter chips, search.
- **Fuzz targets** for all three new detectors (smuggling, openredirect, graphql).
  45M combined executions, 0 crashes.

### Changed

- Detection pipeline expanded from 8 to 11 detectors. All benchmarks updated to
  run the full 11-detector pipeline.
- `waf.graphql`, `waf.siem`, `waf.websocket` removed from the "removed layers"
  guard — they are now fully implemented.
- Dashboard config page detector list updated from 6 to 11 detectors.
- ADR status updated: GraphQL, WebSocket, SIEM marked "Implemented".

### Performance

- All new layers within budget: benign request 22.8 µs (budget: <1 ms), attack
  request 22.9 µs (budget: <2 ms). Proxy p99 overhead: 1.0 ms standalone, 1.0 ms
  sidecar (budgets: <5 ms / <3 ms). Zero measurable overhead from new detectors.

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
