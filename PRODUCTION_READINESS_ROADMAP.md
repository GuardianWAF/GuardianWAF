# GuardianWAF Production Readiness Roadmap

This roadmap defines what is required for GuardianWAF to be genuinely production ready: repeatable builds, reliable runtime behavior, security hardening, operational visibility, deployment safety, and clear release gates.

It is based on the current repository state and on a local baseline run performed during this readiness pass.

## 1. Current Baseline

### 1.1 Verified In This Pass

The following checks now pass locally after the fixes in this pass:

| Check | Result |
|---|---|
| Dashboard UI production build | Pass |
| Website production build | Pass |
| Go package discovery | Pass |
| Default CLI build | Pass |
| `go test ./...` | Pass |
| `go vet ./...` | Pass |
| Dashboard UI unit tests | Pass, 13 files / 96 tests |
| Dashboard npm audit | Pass, 0 vulnerabilities at `--audit-level=moderate` |
| Zero Trust package tests | Pass |
| Targeted race tests | Pass for `internal/engine`, `internal/proxy`, `internal/layers/zerotrust`, `internal/config`, `internal/dashboard`, and `cmd/guardianwaf` |
| Full repository race tests | Pass locally via `go test -race ./...`; nightly/manual CI gate added |
| Script-based dashboard build | Pass via `./scripts/build-dashboard.sh` |
| Script-based multi-arch release build | Pass via `./scripts/build.sh dev` |
| CLI smoke test | Pass, 19/19 checks including `/livez`, `/readyz`, and `/healthz` |
| GitHub Actions workflow lint | Pass via `actionlint` |
| Docker Compose syntax | Pass for base, production override, test, and sidecar compose files |
| Docker Compose integration | Pass via `docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test-runner`, 19/19 checks |
| Fuzz smoke suite | Pass via `FUZZTIME=2s ./scripts/fuzz-smoke.sh`; CI runs the same suite with `FUZZTIME=5s` |
| Docker image build | Pass for linux/amd64 runtime image |
| Docker image healthcheck | Pass via `docker run --rm guardianwaf:runtime-check healthcheck` |
| Kubernetes embedded config fixtures | Pass for static ConfigMap-embedded GuardianWAF configs |
| Kubernetes manifest schema validation | Pass locally via `scripts/validate-k8s.sh`; CI job added for checked-in static manifests |
| Helm chart render/schema validation | Pass locally via `scripts/validate-helm.sh`; CI job validates default and production-like renders |
| KinD deployment smoke | Pass locally via `scripts/kind-smoke.sh`; CI job deploys local image into KinD and verifies proxy/dashboard health |
| Explicit private-upstream policy | Pass for config parsing and proxy wiring |
| Dashboard explicit secret validation | Pass for weak configured `api_key`/`admin_key` rejection, strong startup generation for empty `api_key`, and disabled tenant-admin APIs when `admin_key` is empty |
| Go vulnerability scan | Pass via `govulncheck ./...` after moving build/toolchain references to Go 1.26.3 |
| Runtime image SBOM and vulnerability scan | Pass via `scripts/supply-chain-smoke.sh`; CI job builds the runtime image, generates SPDX SBOM, and fails on HIGH/CRITICAL Trivy findings |
| HTTP/3 tagged command build | Pass via `go test -tags http3 ./cmd/guardianwaf` |
| Event secret redaction | Pass for engine event creation and dashboard list/detail API responses |
| CI workflow alignment | Local static review complete; remote GitHub Actions run still required |

### 1.2 Fixes Completed In This Pass

| Area | Change | Production impact |
|---|---|---|
| Dashboard embed buildability | Built dashboard assets into `internal/dashboard/dist` for local verification. | Restores Go package compilation when embed assets are present. |
| Go package discovery hygiene | Added nested module boundaries for `internal/dashboard/ui` and `website`. | Prevents `npm install` from causing `go list ./...` to traverse frontend `node_modules` Go files. |
| Zero Trust sessions | Filled missing `SessionTTL`, `AttestationTTL`, and bypass-path defaults when partial Zero Trust config is supplied. | Prevents valid sessions from expiring immediately when callers provide partial config. |
| Build scripts | Added `scripts/build-dashboard.sh` and made `scripts/build.sh` build embedded dashboard assets before Go binaries. | Provides a make-free build path for clean environments and CI. |
| Makefile delegation | Updated `make ui` to call `scripts/build-dashboard.sh`. | Reduces duplicated dashboard build logic. |
| Config fixtures | Added tests that load and validate shipped GuardianWAF YAML fixtures, and assert the intentionally invalid fixture fails. | Prevents schema drift in public/example configs. |
| Root config | Replaced legacy-shaped root `guardianwaf.yaml` with a schema-valid default config. | Makes the default config executable by `guardianwaf validate` and usable as a starting point. |
| Config schema guard | Added reflection-backed unknown key rejection for top-level, nested struct, and sequence item config keys while preserving dynamic maps. | Prevents stale public examples and mistyped production YAML from being accepted while silently ignoring unsupported sections. |
| Setup wizard output | Updated generated setup config to use the current schema and fixed a test-stubbed alert command nil path. | Keeps first-run generated configs compatible with `guardianwaf validate` and avoids hidden CLI panic paths. |
| CI/release build flow | Updated CI and release workflows to use `scripts/build-dashboard.sh`, removed incompatible Go 1.24 CI matrix entry, and added config/smoke checks to the PR test gate. | Makes automation match the local production build contract and prevents invalid examples from shipping silently. |
| Kubernetes examples | Added validation coverage for static ConfigMap-embedded GuardianWAF configs and aligned Helm-generated config keys with the current schema. | Reduces the chance that Kubernetes examples deploy stale or ignored config. |
| Helm deployment wiring | Made the Helm deployment start with the mounted config file and corrected supported `GWAF_*` environment variable names. | Prevents chart installs from silently running defaults instead of the rendered config. |
| Docker packaging | Fixed OCI label metadata, made runtime image version labeling effective, removed invalid Compose override keys, and verified Docker image build/healthcheck. | Improves image metadata correctness and avoids production Compose parse failures. |
| Go toolchain security | Moved `go.mod`, Docker builders, CI, Compose examples, and Trivy base-image scan target to Go 1.26.3 after `govulncheck` found reachable standard-library vulnerabilities in Go 1.26.0. | Removes known reachable stdlib CVEs from the local production build path and aligns CI/container builds with the patched toolchain. |
| Docker integration smoke | Expanded Compose smoke coverage to assert `/livez` and `/readyz`, and switched the Compose healthcheck to `/livez`. | Verifies the runtime image, backend connectivity, WAF blocking, security headers, request IDs, and operational probes in one local deployment path. |
| Probe documentation | Added `docs/health-probes.md` and updated production/runbook examples to distinguish `/livez`, `/readyz`, and legacy `/healthz`. | Prevents operators from using readiness failures as restart signals and aligns deployment docs with the runtime probe contract. |
| Kubernetes manifest validation | Added `scripts/validate-k8s.sh`, fixed invalid example `securityContext` placement, corrected example service/ingress port wiring, and added a CI job for kubeconform schema validation. | Prevents checked-in static Kubernetes resources from drifting into schema-invalid or non-routable examples. |
| Helm chart validation | Added `scripts/validate-helm.sh`, fixed the Istio service port reference, added HPA/PDB templates for existing values, and wired chart lint/render/schema/config validation into CI. | Prevents the chart from shipping unrenderable templates or rendered GuardianWAF config that fails application validation. |
| KinD deployment smoke | Added `scripts/kind-smoke.sh` and CI coverage that builds the runtime image, loads it into KinD, deploys backend + GuardianWAF, then verifies liveness, readiness, proxy pass-through, attack blocking, and dashboard auth. | Proves the container can run inside a real Kubernetes API/serverlet path rather than only passing static schema validation. |
| Fuzz smoke gate | Added `scripts/fuzz-smoke.sh` and a CI job covering config parsing, sanitizer normalization, SQLi/XSS detectors, IP ACL, rate limiting, bot fingerprinting, and JWT validation. | Adds bounded panic/regression discovery for parser and security-sensitive request processing code. |
| Private upstreams | Added explicit `allow_private_upstreams` config/env support and enabled it only in deployment examples that intentionally target service-network or loopback backends. | Keeps SSRF protection default-deny while making Docker/Kubernetes/internal-backend deployments functional by explicit policy. |
| Dashboard secret hardening | Added config validation that rejects explicitly configured short/common dashboard API/admin keys; empty dashboard API keys still trigger strong random startup generation. Empty `dashboard.admin_key` now disables tenant-admin APIs instead of generating and printing an ephemeral system admin key. | Reduces accidental deployment with hard-coded weak dashboard credentials while keeping first-run local ergonomics for ordinary dashboard access and making cross-tenant admin access explicit. |
| Dashboard admin-key deployment contract | Added `GWAF_DASHBOARD_ADMIN_KEY` config override support, tests for tenant-admin disabled/enabled startup behavior, and production/example docs for the separate admin key. | Gives operators a clear path to enable tenant-admin operations through managed secrets while keeping the admin API closed by default. |
| Supply-chain image gate | Added `scripts/supply-chain-smoke.sh`, pinned Syft/Trivy scanner images in automation, enabled release image SBOM/provenance, and moved runtime/sidecar images to `alpine:3.23.4` after Trivy found HIGH/CRITICAL CVEs in the old Alpine runtime. | Gives CI and release flows a concrete SBOM/vulnerability gate and removes known high-severity OS package findings from the final runtime image. |
| Full-repository race gate | Fixed a real data race in the virtual patch database hit counters and added a scheduled/manual CI job that runs `go test -race ./...`. | Makes concurrency regressions visible outside the PR fast path and removes a runtime race in virtual patch request processing. |
| Health checker lifecycle | Serve, sidecar, dashboard rebuild, and Docker discovery rebuild paths now retain and stop proxy health checkers instead of leaking background probe goroutines; `HealthChecker.Stop` now cancels in-flight probes. | Reduces shutdown/reload resource leaks, prevents stale backend health loops after route replacement, and avoids shutdown waiting for long probe timeouts. |
| Alerting shutdown drain | Alerting manager now tracks asynchronous webhook/email sends, refuses new dispatches after close, waits for in-flight sends with context-bound shutdown, and closes idle HTTP connections. `cmd serve` drains alerting before closing the engine/event bus. | Reduces alert loss during SIGINT/SIGTERM and makes outbound notification shutdown deterministic under test. |
| Event consumer shutdown wait | `cmd serve` now tracks alerting and dashboard SSE event-bus consumer goroutines and waits for them after closing the engine/event bus. | Prevents event forwarding goroutines from outliving shutdown and makes process teardown more deterministic. |
| Cleanup loop shutdown wait | `cmd serve` now tracks the periodic cleanup goroutine with a `WaitGroup`, waits for it before engine close, and releases serve/sidecar signal notification channels on return. | Prevents maintenance work from racing engine teardown and removes lingering signal registrations in embedded/test executions. |
| NVD outbound SSRF guard | Virtual patch NVD client now validates redirect targets and uses an SSRF-safe dialer that rejects private, loopback, link-local, unspecified, and multicast IPs at connection time. | Closes the DNS rebinding/redirect gap for automatic CVE feed updates. |
| Event secret redaction | Event creation now redacts sensitive query parameters, referer URLs, User-Agent token patterns, bearer/JWT tokens, cookies, API keys, CSRF/XSRF tokens, session IDs, passwords, and client secrets from finding evidence before events reach stores, dashboard APIs, SSE, alerts, AI, or MCP consumers. Engine `Check` and middleware no longer overwrite sanitized events with raw pipeline findings. | Reduces credential leakage risk in event retention, UI/API responses, access logs, traces, and downstream integrations while keeping non-sensitive matched evidence visible for investigation. |
| Tenant admin response sanitization | Dashboard tenant admin list/create/get/update responses now strip tenant `api_key_hash` fields and redact nested dashboard `api_key`/`admin_key` config values while preserving explicit one-time tenant key create/regenerate responses. | Prevents stored tenant credential material from leaking through tenant object serialization in admin APIs. |
| Engine-local trusted proxy model | `Engine.Check`, middleware, and wired JavaScript challenge verification now derive client IP from the engine's own parsed `trusted_proxies` list instead of relying on mutable package-global proxy state. | Prevents one Engine instance from changing another Engine instance's `X-Forwarded-For` trust behavior in library or multi-runtime deployments. |
| Event store close safety | FileStore now serializes async channel sends against close, and PersistentMemoryStore serializes file appends against file close, with normal and race regression coverage. | Removes shutdown-time event persistence panic/data-race risk under concurrent request teardown. |
| Runtime event persistence wiring | `cmd serve` and `cmd sidecar` now honor `events.storage: file` by opening a persistent JSONL-backed queryable event store, creating the parent directory, replaying prior events, and failing startup if the configured store cannot be opened. | Makes the documented file event storage mode real in runtime instead of silently running memory-only. |
| HTTP/3 build tag | Re-synchronized the HTTP/3-tagged command entrypoint so it parses, formats, tests, and is covered by CI. | Prevents optional build tags from silently rotting outside the default build. |
| HTTP/3 entrypoint drift guard | Added a command-package regression test that asserts `cmd/guardianwaf/main.go` and `main_default.go` remain identical except for their build tag line until the runtime assembly is split behind smaller adapters. | Prevents one build-tag variant from silently missing production fixes applied to the other variant. |
| Shared event-store assembly | Moved event store construction into shared untagged `cmd/guardianwaf/event_store.go`. | Keeps memory/file event persistence startup behavior identical across default and HTTP3 build paths. |
| Shared engine runtime bootstrap | Moved event bus, engine creation, layer wiring, log-level application, structured access logging, and engine-ready logging into shared untagged `cmd/guardianwaf/engine_runtime.go`. | Keeps serve/sidecar bootstrap behavior aligned and further shrinks tagged CLI entrypoints. |
| Shared event consumers | Moved alerting and dashboard SSE event-consumer goroutine setup into shared untagged `cmd/guardianwaf/event_consumers.go`, with direct shutdown regression coverage. | Keeps event-bus consumer shutdown behavior consistent and removes duplicated recover/wait-group wiring. |
| Shared dashboard startup | Moved dashboard HTTP server startup, compliance dashboard wiring, and dashboard admin-key behavior into shared untagged `cmd/guardianwaf/dashboard_runtime.go`. | Keeps dashboard startup behavior identical across default and HTTP3 build paths and removes more duplicated runtime assembly. |
| Shared dashboard proxy controls | Moved dashboard proxy rebuild, upstream/certificate status providers, dashboard save callback wiring, and custom-rule config sync into shared untagged `cmd/guardianwaf/dashboard_proxy_runtime.go`, with direct config-sync regression coverage. | Keeps dashboard live-reload and persistence behavior isolated from serve startup flow. |
| Shared dashboard rules wiring | Moved dashboard custom-rule CRUD and dashboard GeoIP lookup wiring into shared untagged `cmd/guardianwaf/dashboard_rules_runtime.go`, with direct rules-layer regression coverage. | Keeps dashboard rule management behavior isolated from serve startup flow and shrinks tagged CLI entrypoints. |
| Shared dashboard adapters | Moved tenant, billing, and tenant-alert dashboard adapter implementations into shared untagged `cmd/guardianwaf/dashboard_adapters.go`. | Keeps dashboard multi-tenant adapter behavior identical across default/HTTP3 build paths and removes interface glue from the tagged entrypoints. |
| Shared tenant runtime wiring | Moved tenant persistence initialization, configured tenant seeding, dashboard tenant registration, and tenant middleware wrapping into shared untagged `cmd/guardianwaf/tenant_runtime.go`, with direct regression coverage for defaults, quota mapping, disabled mode, and handler wrapping. | Keeps multi-tenant runtime setup identical across default/HTTP3 build paths and removes another production subsystem from the tagged entrypoints. |
| Shared Docker runtime wiring | Moved Docker watcher startup and discovered-service proxy rebuild handling into shared untagged `cmd/guardianwaf/docker_runtime.go`, with direct regression coverage for disabled mode and daemon-free discovered-service rebuilds. | Keeps Docker auto-discovery behavior identical across default/HTTP3 build paths and isolates route rebuild lifecycle logic from serve startup flow. |
| Shared AI runtime wiring | Moved AI analyzer config mapping, encrypted store setup, event-bus subscription, dashboard AI registration, and optional auto-ban wiring into shared untagged `cmd/guardianwaf/ai_runtime.go`, with direct regression coverage for config mapping and enabled/disabled startup behavior. | Keeps AI analysis startup identical across default/HTTP3 build paths and makes event subscription behavior independently testable. |
| Shared alerting runtime wiring | Moved webhook/email target conversion, alert manager startup, event-bus consumer registration, dashboard alert stats, and MCP stdio alert-manager wiring into shared untagged `cmd/guardianwaf/alerting_runtime.go`, with direct regression coverage for conversion and enabled/disabled startup behavior. | Keeps alerting startup identical across default/HTTP3 build paths and isolates alert event-consumer lifecycle from serve startup flow. |
| Shared cleanup runtime wiring | Moved periodic cleanup goroutine startup and cleanup execution for rate limiting, IP ACL, ATO, and tenant rate limiter state into shared untagged `cmd/guardianwaf/cleanup_runtime.go`, with direct regression coverage for cleanup dispatch and shutdown. | Keeps maintenance cleanup behavior identical across default/HTTP3 build paths and makes background cleanup lifecycle independently testable. |
| Shared serve lifecycle wiring | Moved serve HTTP/TLS listener startup, serve runtime status logging, threat-intel stop, proxy health-checker stop, cleanup stop, and ordered serve-mode shutdown into shared untagged `cmd/guardianwaf/serve_lifecycle.go`, with direct regression coverage for idempotent stop-channel handling, threat-intel stop dispatch, and runtime status logging. | Keeps serve shutdown behavior identical across default/HTTP3 build paths and reduces the signal/shutdown block inside tagged entrypoints. |
| Shared MCP startup | Moved MCP stdio server startup into shared untagged `cmd/guardianwaf/mcp_runtime.go`. | Keeps MCP transport startup behavior identical across default and HTTP3 build paths while leaving the larger adapter surface intact. |
| Shared MCP core adapter | Moved core MCP engine adapter methods for stats/config/mode, IP ACL, rate limiting, exclusions, event queries, top IPs, request testing, and alert targets into shared untagged `cmd/guardianwaf/mcp_adapter_core.go`. | Shrinks the tagged entrypoints further and leaves feature-specific MCP adapters as the next decomposition target. |
| Shared MCP feature adapters | Moved CRS, virtual patch, API validation, client-side, DLP, and HTTP/3 status-stub MCP adapter methods into shared untagged `cmd/guardianwaf/mcp_adapter_features.go`. | Removes the remaining large MCP adapter method block from both tagged entrypoints. |
| Shared small runtime helpers | Moved ACME domain collection, GeoIP database loading, dashboard rule-map conversion, and IP/CIDR validation into shared untagged helper files. | Removes the last standalone helper block from both tagged entrypoints and keeps the CLI files focused on command flow. |
| Shared layer assembly | Moved CLI WAF layer assembly into shared untagged `cmd/guardianwaf/layers.go`. | Reduces duplicated default/HTTP3 entrypoint wiring and makes future runtime decomposition smaller and safer. |
| Shared proxy assembly | Moved reverse-proxy router construction, runtime fallback handlers, health checker shutdown, and context-bound wait helper code into shared untagged `cmd/guardianwaf/proxy_runtime.go`, with direct fallback/router regression coverage. | Reduces duplicated default/HTTP3 runtime wiring and keeps proxy lifecycle behavior identical across build tags. |
| Shared probe assembly | Moved liveness, readiness, and legacy health probe handler registration into shared untagged `cmd/guardianwaf/probes.go`. | Keeps operational probe behavior identical across serve/sidecar and default/HTTP3 build paths. |
| Shared observability assembly | Moved structured access-log setup, Prometheus-compatible metrics handler registration, and log-field sanitization into shared untagged `cmd/guardianwaf/observability_runtime.go`. | Keeps logging and metrics behavior identical across default/HTTP3 build paths and removes more duplicated serve wiring. |
| Shared client-side report assembly | Moved client-side report and CSP-report endpoint registration into shared untagged `cmd/guardianwaf/clientside_runtime.go`. | Keeps serve/sidecar report endpoint mounting consistent and removes another duplicated runtime fragment. |
| Shared challenge assembly | Moved JavaScript challenge service setup and verification endpoint registration into shared untagged `cmd/guardianwaf/challenge_runtime.go`; sidecar metrics now use the same shared Prometheus handler as serve. | Keeps challenge cookie binding and metrics export behavior consistent across serve/sidecar and default/HTTP3 build paths. |
| Shared HTTP handler assembly | Moved HTTP handler selection, ACME redirect bypass, and HTTPS redirect hardening into shared untagged `cmd/guardianwaf/http_runtime.go`, with direct regression tests. | Makes redirect security behavior independently testable and keeps it identical across default/HTTP3 builds. |
| Shared server timeout profile | Moved HTTP server construction into shared untagged `cmd/guardianwaf/server_runtime.go`, with direct timeout regression coverage. | Keeps serve, sidecar, and TLS listener timeout behavior aligned. |
| Shared TLS assembly | Moved TLS server construction, manual certificate loading, ACME account/certificate setup, renewal startup, and certificate hot reload into shared untagged `cmd/guardianwaf/tls_runtime.go`. | Keeps certificate lifecycle behavior identical across default/HTTP3 builds and shrinks the main serve command body. |
| Shared CLI helper assembly | Moved generated dashboard password helpers and upstream summary formatting into shared untagged `cmd/guardianwaf/passwords.go` and `cmd/guardianwaf/upstreams.go`. | Removes more duplicated default/HTTP3 helper code and keeps setup, dashboard startup, and sidecar startup behavior identical across build tags. |
| Layer registry baseline | Added `internal/runtime/layerregistry` with descriptors for active WAF layer names, runtime layer names, orders, enablement checks, construction hooks for IP ACL, threat intelligence, CORS, custom rules, rate limiting, ATO protection, API security, API validation, sanitizer, CRS, detection, virtual patching, DLP, bot detection, client-side protection, and response, plus startup effective-pipeline and active-pipeline logging. | Starts moving layer ownership out of CLI wiring, makes the active pipeline debuggable at startup, and gives tests a bridge between registry metadata and actual engine layers. |
| Architecture docs | Added root `ARCHITECTURE.md`. | Gives maintainers a detailed source-of-truth for runtime shape and extension points. |

### 1.3 Known Baseline Caveats

- `make` is not installed in the current local environment. Script equivalents now exist for the dashboard/release build path, but contributor docs should still clarify tool prerequisites.
- `internal/dashboard/dist` is ignored and generated. A clean checkout cannot compile `internal/dashboard` until `./scripts/build-dashboard.sh` or `./scripts/build.sh` runs.
- The root `guardianwaf.yaml`, setup-generated config, static Kubernetes ConfigMaps, default Helm-rendered config, README, and primary operator docs now align with the current dashboard auth/config contract. ADR/design-era documents may still contain historical schema examples and should be treated as references, not deployment guides.
- The `http3` build tag now compiles, but actual HTTP/3 runtime behavior still needs end-to-end verification with QUIC clients before it should be promoted as production ready.
- CI workflow YAML was updated locally, but a remote GitHub Actions run is still required to validate action versions, artifact behavior, external scanners, and hosted-runner assumptions.
- Docker image build, Compose syntax, Docker Compose integration smoke, Kubernetes static manifest schema validation, Helm render validation, KinD/Kubernetes cluster smoke, Playwright browser smoke, bounded fuzz smoke, full-repository race testing, and runtime image SBOM/vulnerability scanning were verified locally.

## 2. Production Ready Definition

GuardianWAF should only be considered production ready when all of the following are true:

1. A clean checkout can build reproducibly using documented commands.
2. The default binary starts with a documented minimal config and proxies real traffic.
3. All shipped example configs validate and boot.
4. `go test ./...`, `go test -race ./...`, dashboard tests, E2E tests, Docker tests, and smoke tests pass in CI.
5. The container image runs as non-root, has a working healthcheck, and can be deployed with minimal production config.
6. TLS, dashboard auth, API auth, trusted proxy behavior, event redaction, backend SSRF guard, Docker discovery, and alert outbound SSRF protections have tests and documented deployment guidance.
7. Runtime observability is sufficient for operators: health, metrics, logs, events, tracing, dashboard, and failure modes are documented.
8. Runtime state survives expected restarts where configured: event storage, AI config, tenant state, ACME certs, replay data, remediation rules.
9. Release artifacts are versioned, signed or checksummed, and built from CI.
10. A rollback and incident-response path exists.

## 3. Roadmap Priority Model

Priorities:

- **P0**: must be fixed before claiming production readiness.
- **P1**: should be fixed before a stable public production release.
- **P2**: important for enterprise/hardening but can follow a controlled beta.
- **P3**: polish, scale, and long-term maintainability.

Statuses:

- **Done**: completed in this pass or already present and verified.
- **Open**: required work remains.
- **Partial**: present but needs verification, hardening, or docs.

## 4. P0: Build, Test, and Runtime Correctness

### 4.1 Clean Checkout Build Contract

Status: Partial

Problem:

- `internal/dashboard/dashboard.go` embeds `dist`, but `dist` is generated and ignored.
- `go test ./...` on a clean checkout fails until the dashboard UI is built.
- A make-free build path is now available and the CI/release workflows call it.

Required work:

- Keep `Makefile`, CI, and release workflows delegated to the same build scripts.
- Confirm the updated CI workflow on GitHub-hosted runners:
  - clean checkout without `internal/dashboard/dist`,
  - dashboard build,
  - Go build,
  - Go test,
  - config fixture validation,
  - CLI smoke test.
- Decide whether to keep generated dashboard assets ignored or commit release-ready fallback assets.
- Document exact local prerequisites: Go version, Node version, npm version, make or script fallback.

Acceptance criteria:

- `scripts/build.sh` succeeds on a clean checkout.
- `go test ./...` succeeds after the documented build step.
- CI starts from a clean checkout and never relies on locally generated assets.

### 4.2 Configuration Schema Alignment

Status: Partial

Problem:

- The root `guardianwaf.yaml`, setup-generated config shape, static Kubernetes ConfigMaps, and current test fixtures are now schema-valid and covered by tests.
- Unknown top-level keys, nested struct keys, and sequence item keys now fail validation instead of being silently ignored.
- Dynamic maps such as detector names, feature flags, and webhook headers remain intentionally open.
- Remaining public docs, README/ADR snippets, and non-default Helm values still need a full schema alignment audit.

Required work:

- Audit every config file under:
  - root,
  - `examples/`,
  - `testdata/configs/`,
  - Docker Compose mounts,
  - Kubernetes/Helm values,
  - docs snippets.
- Ensure every public config example matches `internal/config.Config`.
- Expand the config fixture test as additional GuardianWAF config examples are identified.
- Extend fixture coverage as additional GuardianWAF config examples are identified.
- Add migration guidance for legacy keys if backwards compatibility is desired.

Acceptance criteria:

- Every shipped config fixture validates.
- The root `guardianwaf.yaml` can start the binary.
- Unknown production config keys fail validation with actionable field paths.

### 4.3 CLI Runtime Smoke Tests

Status: Partial

Progress:

- Existing `scripts/smoke-test.sh` passed against the generated Linux binary with 19/19 checks, including liveness/readiness/legacy health probes.
- CI now builds a binary and runs `scripts/smoke-test.sh` as part of the PR test job.
- `docker-compose.test.yml` passed locally with 19/19 checks against a built runtime image, live backend, and test-runner container.

Required work:

- Add hosted CI execution for the Docker Compose integration smoke path.
- Extend automated smoke tests to verify dashboard health.
- Run the same for `sidecar`.
- Include a minimal config that does not require Docker, ACME, external AI providers, or privileged ports.

Acceptance criteria:

- Smoke tests pass in CI on Linux.
- Smoke tests produce useful logs on failure.

### 4.4 Full Test Matrix

Status: Pass for current P0 scope

Progress:

- `go test -race ./...` now passes locally after fixing a virtual patch data race.
- A scheduled/manual CI job now runs the full repository race suite without slowing every PR.

Required release gates:

- `go test ./...`
- `go test -race ./...`
- dashboard `npm test`
- dashboard `npm run build`
- website `npm run build`
- Playwright E2E tests
- Docker Compose integration tests
- fuzz smoke suite with bounded runtime
- `go vet ./...`
- linter once configured in CI

Acceptance criteria:

- All gates run in CI.
- Required gates are blocking.
- Slow/nightly gates are separated from PR gates but visible.

## 5. P0: Security and Safety Hardening

### 5.1 Dashboard Authentication Defaults

Status: Pass for current P0 scope

Risks:

- Dashboard is enabled by default in `DefaultConfig`.
- Dashboard API/session/admin/tenant auth behavior is extensive and must be easy to configure safely.
- Empty dashboard API keys still generate a random startup secret for local ergonomics; production deployments should configure `dashboard.api_key` or `GWAF_DASHBOARD_API_KEY` through managed secrets.

Remaining work:

- Continue evaluating whether a future production profile should reject empty `dashboard.api_key` instead of generating one.
- Add tests for:
  - additional browser session expiry/rotation paths,
  - reverse-proxy cookie security expectations.

Completed:

- Explicitly configured weak dashboard API/admin keys fail validation.
- Empty `dashboard.admin_key` leaves tenant-admin APIs disabled and emits a startup warning instead of printing an ephemeral admin key.
- `GWAF_DASHBOARD_ADMIN_KEY` can populate `dashboard.admin_key` from environment-managed secrets.
- README, configuration, API, MCP, Kubernetes, Helm, security, and production deployment docs now show header-only API auth and the separate admin-key contract.
- Tests cover tenant-admin rejection when no startup admin key is configured and successful tenant-admin authorization when a configured admin key is present.

Acceptance criteria:

- No default production deployment exposes an unauthenticated dashboard.
- Docs show a secure dashboard config first.

### 5.2 Trusted Proxy and Client IP Model

Status: Pass for current P0 scope

Progress:

- Client IP extraction already ignores `X-Forwarded-For` and `X-Real-IP` unless the direct peer is trusted.
- `X-Forwarded-For` is parsed from right to left so the selected address is the rightmost non-trusted hop, not the attacker-controlled leftmost value.
- Engine runtime paths now use instance-local parsed trusted proxy CIDRs, with regression tests proving two engines in the same process cannot overwrite each other's trust settings.
- JavaScript challenge verification is wired to `Engine.ExtractClientIP`, so challenge cookies are bound to the same client IP model as WAF event/decision processing.
- Reload updates the engine-local trusted proxy list.
- Config validation now rejects invalid trusted proxy entries, `0.0.0.0/0`, `::/0`, and overly broad proxy CIDRs before startup.
- Operator docs now show direct-exposure, Nginx/ingress, and managed-edge guidance for selecting trusted proxy CIDRs.

Remaining work:

- Add broader integration tests that exercise trusted proxy behavior through the full standalone proxy/server path, not only engine-level request processing.

Acceptance criteria:

- Operators can configure real client IP extraction without opening spoofing risks.

### 5.3 Backend SSRF Guard Deployment Decision

Status: Implemented baseline, needs finer-grained policy design

Risk:

- The proxy blocks private/reserved backend targets by default. This is strong SSRF defense but conflicts with common production deployments where upstreams are private services.

Implemented baseline:

- Added top-level `allow_private_upstreams`, plus `GWAF_ALLOW_PRIVATE_UPSTREAMS`, to make private-service deployments possible only through explicit opt-in.
- Deployment examples that target loopback or service-network backends opt in intentionally.
- Keep secure-by-default behavior for externally supplied URLs.

Remaining architectural decision:

- Decide whether production needs finer-grained controls such as `allowed_upstream_cidrs` or per-upstream `allow_private`.
- Document the trust model in operator-facing docs.

Acceptance criteria:

- Private-service production deployments are possible only through explicit config.
- SSRF protections remain default-on for dynamic/user-controlled targets.

### 5.4 Secret Handling and Redaction

Status: Pass for current P0 scope

Progress:

- Engine event creation now centrally redacts sensitive query parameter values, referer URL query values, and secret-like finding evidence.
- Redaction covers common authorization/cookie/API key/token/session/password/client-secret/JWT forms before events are stored or published.
- `Engine.Check` and middleware event persistence preserve redacted findings instead of reassigning raw pipeline results.
- Access-log User-Agent values and trace URL/User-Agent attributes are redacted before emission.
- AI provider config reads expose only `api_key_set`/masked status, and AI provider keys are encrypted at rest when saved.
- Tenant admin API responses strip `api_key_hash` from tenant objects and redact nested dashboard API/admin keys; one-time tenant API keys are still returned only from create/regenerate-key endpoints.
- Regression tests cover `engine.NewEvent`, `Engine.Check`, middleware persistence/access-log behavior, and dashboard event list/detail API rendering.

Required work:

- Continue auditing non-event/non-trace log paths for:
  - additional third-party integration keys,
  - legacy config examples that still show weak placeholder secrets.
- Ensure access logs never include full request bodies unless explicitly enabled with a warning.

Acceptance criteria:

- Secret redaction has regression tests for event creation and dashboard API rendering.
- Dangerous logging options require explicit opt-in and docs warnings.

### 5.5 Outbound Network SSRF

Status: Partial

Outbound integrations include:

- AI model catalog fetch,
- AI provider calls,
- webhook delivery,
- ACME,
- NVD/virtual patch feeds,
- threat intelligence feeds,
- Docker remote clients,
- GeoIP auto-download.
- cluster sync peer replication.
- OCSP responders from certificate AIA data.
- hCaptcha and Cloudflare Turnstile verification endpoints.
- replay targets and canary health-check endpoints.
- SIEM exporter endpoints, proxy upstream health checks, and Docker Unix-socket polling.
- API security JWKS endpoints and legacy cluster coordination endpoints.

Required work:

- Standardize outbound URL validation and dialers.
- Define which integrations may contact private networks and how that is configured.
- Add timeouts, response-size limits, and redirect policies for every outbound HTTP client.

Progress:

- AI provider endpoints, AI catalog fetches, webhooks, GeoIP downloads, threat-intel feeds, dashboard-managed webhook URLs, dashboard-managed AI URLs, and API security JWKS fetches already have SSRF validation coverage.
- Webhook delivery now validates redirect targets, keeps connection-time SSRF protection, and uses explicit dial/TLS/response-header/expect-continue timeouts.
- Virtual patch NVD client now has both preflight URL validation and connection-time SSRF protection, plus redirect target validation.
- AI catalog fetches now have preflight URL validation, redirect target validation, connection-time SSRF protection, and explicit dial/TLS/response-header timeouts.
- GeoIP downloads now have preflight URL validation, redirect target validation, connection-time SSRF protection, explicit dial/TLS/response-header timeouts, and bounded response bodies.
- AI provider calls now validate redirect targets, keep connection-time SSRF protection, enforce TLS 1.2+, and use explicit TLS/response-header/expect-continue timeouts.
- API security JWKS fetches now use redirect target validation, connection-time SSRF protection, explicit dial/TLS/response-header timeouts, and bounded response reads.
- Threat-intel URL feeds now have redirect target validation, connection-time SSRF protection, explicit dial/TLS/response-header timeouts, and bounded response parsing.
- Cluster sync peer URLs intentionally allow private networks, but the client now has explicit dial/TLS/response-header timeouts and does not follow redirects away from the configured peer endpoint.
- Legacy cluster coordination calls now have explicit dial/TLS/response-header timeouts and do not follow redirects away from the configured peer endpoint.
- OCSP responder lookups now use an explicit transport with dial/TLS/response-header timeouts and do not follow redirects from certificate-provided responder URLs.
- hCaptcha and Turnstile verification clients now use explicit dial/TLS/response-header timeouts and do not follow redirects away from the fixed public verification endpoints.
- ACME directory, nonce, order, authorization, challenge, finalize, and certificate-fetch calls now use an explicit transport with dial/TLS/response-header timeouts and do not follow redirects away from the configured CA endpoints.
- Replay target calls now use an explicit transport with dial/TLS/response-header timeouts while preserving the existing `follow_redirects` policy, which defaults to no redirect following.
- Canary health checks now use an explicit transport with dial/TLS/response-header timeouts and do not follow redirects away from the configured upstream health endpoint.
- SIEM exports now validate redirect targets, keep connection-time SSRF protection, enforce TLS verification, and use explicit dial/TLS/response-header/expect-continue timeouts.
- Proxy upstream health checks now use explicit dial/TLS/response-header timeouts and do not follow redirects away from the configured health endpoint.
- Docker Unix-socket HTTP polling now uses explicit response-header, expect-continue, idle, and whole-request timeouts.
- `go test ./internal/layers/virtualpatch` and `go test -race ./internal/layers/virtualpatch` pass with new NVD SSRF regression coverage.
- `go test ./internal/clustersync` and `go test -race ./internal/clustersync` pass with redirect and timeout regression coverage.
- `go test ./internal/tls` and `go test -race ./internal/tls` pass with OCSP redirect and timeout regression coverage.
- `go test ./internal/layers/botdetect/challenge` and `go test -race ./internal/layers/botdetect/challenge` pass with CAPTCHA verification redirect and timeout regression coverage.
- `go test ./internal/acme` and `go test -race ./internal/acme` pass with ACME redirect and timeout regression coverage.
- `go test ./internal/layers/replay ./internal/layers/canary` and `go test -race ./internal/layers/replay ./internal/layers/canary` pass with replay/canary transport regression coverage.
- `go test ./internal/ai ./internal/geoip` and `go test -race ./internal/ai ./internal/geoip` pass with catalog/GeoIP redirect, dial-time SSRF, and timeout regression coverage.
- `go test ./internal/layers/siem ./internal/proxy ./internal/docker` and `go test -race ./internal/layers/siem ./internal/proxy ./internal/docker` pass with SIEM/proxy/Docker transport regression coverage.
- `go test ./internal/cluster ./internal/ai ./internal/layers/apisecurity ./internal/layers/threatintel` and `go test -race ./internal/cluster ./internal/ai ./internal/layers/apisecurity ./internal/layers/threatintel` pass with cluster/provider/JWKS/threat-intel transport regression coverage.
- `go test ./internal/alerting ./internal/layers/cache` and `go test -race ./internal/alerting ./internal/layers/cache` pass with webhook redirect/transport regression coverage and cache dead-client cleanup.

Acceptance criteria:

- Each outbound integration has an explicit SSRF policy.
- Tests cover private/loopback rejection where required.

## 6. P0: Runtime Reliability

### 6.1 Graceful Shutdown

Status: Partial, improved

Required work:

- Ensure shutdown drains:
  - HTTP server,
  - TLS server,
  - HTTP/3 server,
  - Docker watcher,
  - AI analyzer,
  - alert manager background sends,
  - file event store,
  - SIEM exporter,
  - cluster sync,
  - ACME renewal.
- Add integration tests for shutdown under active traffic.

Progress:

- Main serve and sidecar shutdown now stop proxy health checkers.
- Dashboard-triggered proxy rebuilds and Docker discovery rebuilds now stop the replaced health checkers after atomically swapping the active handler.
- `HealthChecker.Stop` now cancels in-flight HTTP probes before waiting for the worker goroutine.
- Alerting manager now drains asynchronous webhook/email sends with a context-bound close, rejects new dispatches after close, closes idle HTTP connections, and has regression coverage for wait, timeout, and post-close dispatch behavior.
- Serve-mode event-bus consumers for alerting and dashboard SSE are tracked with a `WaitGroup`; shutdown closes the engine/event bus and waits for those forwarding goroutines with the shared shutdown context.
- Serve-mode periodic cleanup is tracked with a `WaitGroup`, drained before engine close, and signal notifications are stopped when serve/sidecar commands return.
- `go test ./internal/proxy ./cmd/guardianwaf`, `go test -race ./internal/proxy ./cmd/guardianwaf`, `go test -tags http3 ./cmd/guardianwaf`, and `go test ./cmd/guardianwaf` pass with the lifecycle changes.

Acceptance criteria:

- No goroutine/resource leaks in shutdown tests.
- Event stores flush before process exit.

### 6.2 Runtime Reload Safety

Status: Partial

Required work:

- Define exactly what is hot-reloadable.
- Rebuild pipeline atomically when layer-affecting config changes.
- Rebuild proxy router safely when upstream/route config changes.
- Stop old health checkers and close old transports when replacing routes.
- Add tests for config reload during concurrent traffic.

Progress:

- Dashboard and Docker discovery rebuild paths now stop old health checkers when the proxy handler/router is replaced.
- `internal/engine` now has a reload-during-concurrent-traffic regression test that exercises repeated `Reload()` calls while requests are in flight.
- `Engine.Config()` now returns defensive snapshots, preventing dashboard or runtime callers from mutating the live engine config without going through `Reload()`.

Acceptance criteria:

- Reload cannot leave duplicate background loops, stale targets, or partially applied config.

### 6.3 State Persistence

Status: Partial, improved

Required work:

- Document persistence paths for:
  - events,
  - AI config/history,
  - tenants,
  - ACME certs,
  - replay data,
  - remediation rules,
  - analytics,
  - compliance audit chain.
- Verify permissions in container and Kubernetes examples.
- Add backup/restore guidance.

Progress:

- FileStore close now cannot close the async writer channel between a closed-state check and a send, preventing shutdown-time `send on closed channel` panics.
- PersistentMemoryStore now serializes JSONL appends against close, preventing file handle races during concurrent request teardown.
- Serve and sidecar runtime assembly now use the persistent JSONL-backed event store when `events.storage: file` is configured, create the parent directory, replay prior events, and fail startup if the file cannot be opened.
- Added `docs/state-persistence.md` with default stateful paths, volume permission guidance, and backup/restore order.
- Docker image, Compose, static Kubernetes manifests, and Helm chart now provide writable `/var/lib/guardianwaf` and `/var/log/guardianwaf` paths for read-only-root deployments; Helm includes optional PVC-backed persistence and validates a production-like file-event-storage render.
- `go test ./cmd/guardianwaf ./internal/events`, `go test -race ./cmd/guardianwaf ./internal/events`, `scripts/validate-k8s.sh`, `scripts/validate-helm.sh`, and Docker Compose config validation pass with the event-store persistence and deployment-path changes.

Acceptance criteria:

- Restart behavior is predictable and documented for each stateful subsystem.

## 7. P1: Architecture Simplification and Maintainability

### 7.1 Split CLI Wiring Into Packages

Status: Partial

Problem:

- `cmd/guardianwaf/main.go` and `main_default.go` are very large and duplicate significant wiring.
- Event store assembly has been moved into shared untagged `cmd/guardianwaf/event_store.go`, engine runtime bootstrap has been moved into shared untagged `cmd/guardianwaf/engine_runtime.go`, event-consumer goroutine setup has been moved into shared untagged `cmd/guardianwaf/event_consumers.go`, dashboard startup has been moved into shared untagged `cmd/guardianwaf/dashboard_runtime.go`, dashboard proxy controls have been moved into shared untagged `cmd/guardianwaf/dashboard_proxy_runtime.go`, dashboard custom-rule/GeoIP wiring has been moved into shared untagged `cmd/guardianwaf/dashboard_rules_runtime.go`, dashboard tenant/billing/alert adapters have been moved into shared untagged `cmd/guardianwaf/dashboard_adapters.go`, tenant runtime setup has been moved into shared untagged `cmd/guardianwaf/tenant_runtime.go`, Docker runtime setup has been moved into shared untagged `cmd/guardianwaf/docker_runtime.go`, AI runtime setup has been moved into shared untagged `cmd/guardianwaf/ai_runtime.go`, alerting runtime setup has been moved into shared untagged `cmd/guardianwaf/alerting_runtime.go`, cleanup runtime setup has been moved into shared untagged `cmd/guardianwaf/cleanup_runtime.go`, serve lifecycle startup/shutdown has been moved into shared untagged `cmd/guardianwaf/serve_lifecycle.go`, MCP stdio startup has been moved into shared untagged `cmd/guardianwaf/mcp_runtime.go`, core MCP engine adapter methods have been moved into shared untagged `cmd/guardianwaf/mcp_adapter_core.go`, feature-specific MCP engine adapter methods have been moved into shared untagged `cmd/guardianwaf/mcp_adapter_features.go`, ACME/GeoIP/rule/network helpers have been moved into shared untagged helper files, WAF layer assembly has been moved into shared untagged `cmd/guardianwaf/layers.go`, proxy router/fallback/health-checker helper assembly has been moved into shared untagged `cmd/guardianwaf/proxy_runtime.go`, probe registration has been moved into shared untagged `cmd/guardianwaf/probes.go`, observability setup has been moved into shared untagged `cmd/guardianwaf/observability_runtime.go`, client-side report endpoint registration has been moved into shared untagged `cmd/guardianwaf/clientside_runtime.go`, challenge service setup has been moved into shared untagged `cmd/guardianwaf/challenge_runtime.go`, HTTP handler/redirect selection has been moved into shared untagged `cmd/guardianwaf/http_runtime.go`, shared HTTP server timeout construction has been moved into `cmd/guardianwaf/server_runtime.go`, TLS server/certificate lifecycle setup has been moved into shared untagged `cmd/guardianwaf/tls_runtime.go`, and small shared helpers now live in `cmd/guardianwaf/passwords.go` and `cmd/guardianwaf/upstreams.go`. Broader command parsing and sidecar-specific lifecycle assembly still live in both tagged entrypoint files.
- Build-tag variants increase maintenance risk.

Recommended architecture:

- Move runtime assembly into `internal/app` or `internal/runtime`.
- Keep CLI parsing in `cmd/guardianwaf`.
- Split responsibilities:
  - `runtime.EngineFactory`,
  - `runtime.LayerRegistry`,
  - `runtime.ProxyFactory`,
  - `runtime.DashboardFactory`,
  - `runtime.BackgroundServices`,
  - `runtime.ShutdownGroup`.
- Make HTTP/3 an optional component behind a small interface rather than duplicating whole CLI files.

Progress:

- Added `TestMainEntrypointsStayInSyncAcrossBuildTags` so the duplicated default and HTTP/3 command entrypoints cannot drift while the larger runtime decomposition is still pending.
- Moved `newEventStore` into shared `cmd/guardianwaf/event_store.go`.
- Moved `setupRuntimeEngine` and `logRuntimeEngineReady` into shared `cmd/guardianwaf/engine_runtime.go`.
- Moved event-bus consumer goroutine setup into shared `cmd/guardianwaf/event_consumers.go`.
- Moved `startDashboard` into shared `cmd/guardianwaf/dashboard_runtime.go`.
- Moved dashboard proxy rebuild, upstream/certificate status providers, dashboard save callback wiring, and custom-rule config sync into shared `cmd/guardianwaf/dashboard_proxy_runtime.go`.
- Moved dashboard custom-rule CRUD and dashboard GeoIP lookup wiring into shared `cmd/guardianwaf/dashboard_rules_runtime.go`.
- Moved tenant, billing, and tenant-alert dashboard adapters into shared `cmd/guardianwaf/dashboard_adapters.go`.
- Moved tenant persistence initialization, configured tenant seeding, dashboard tenant registration, and tenant middleware wrapping into shared `cmd/guardianwaf/tenant_runtime.go`.
- Moved Docker watcher startup and discovered-service proxy rebuild handling into shared `cmd/guardianwaf/docker_runtime.go`.
- Moved AI analyzer config mapping, encrypted store setup, event-bus subscription, dashboard AI registration, and optional auto-ban wiring into shared `cmd/guardianwaf/ai_runtime.go`.
- Moved webhook/email target conversion, alert manager startup, event-bus consumer registration, dashboard alert stats, and MCP stdio alert-manager wiring into shared `cmd/guardianwaf/alerting_runtime.go`.
- Moved periodic cleanup goroutine startup and cleanup execution for rate limiting, IP ACL, ATO, and tenant rate limiter state into shared `cmd/guardianwaf/cleanup_runtime.go`.
- Moved serve HTTP/TLS listener startup, serve runtime status logging, and ordered serve-mode shutdown into shared `cmd/guardianwaf/serve_lifecycle.go`.
- Moved `startMCPServer` into shared `cmd/guardianwaf/mcp_runtime.go`.
- Moved core MCP engine adapter methods into shared `cmd/guardianwaf/mcp_adapter_core.go`.
- Moved feature-specific MCP engine adapter methods into shared `cmd/guardianwaf/mcp_adapter_features.go`.
- Moved ACME, GeoIP, rule conversion, and IP/CIDR helper functions into shared helper files.
- Moved `addLayers` into shared `cmd/guardianwaf/layers.go` so both default and HTTP/3 builds now use one physical layer assembly implementation.
- Moved `buildReverseProxy`, `buildProxyRuntime`, runtime fallback handlers, `stopHealthCheckers`, and `waitForWaitGroup` into shared `cmd/guardianwaf/proxy_runtime.go`.
- Moved `registerProbeHandlers` into shared `cmd/guardianwaf/probes.go`.
- Moved `setupAccessLogging`, `registerMetricsHandler`, and `sanitizeLogField` into shared `cmd/guardianwaf/observability_runtime.go`.
- Moved client-side report and CSP-report endpoint registration into shared `cmd/guardianwaf/clientside_runtime.go`.
- Moved `setupChallengeService` and `registerChallengeHandler` into shared `cmd/guardianwaf/challenge_runtime.go`, and aligned sidecar `/metrics` output with the shared serve metrics contract.
- Moved HTTP handler selection and HTTPS redirect hardening into shared `cmd/guardianwaf/http_runtime.go`, with tests for disabled redirect fallback, normal redirects, ACME bypass, unsafe Host rejection, and protocol-relative URI normalization.
- Moved shared HTTP server timeout construction into `cmd/guardianwaf/server_runtime.go`, with direct regression coverage for the production timeout profile.
- Moved TLS server construction, manual certificate loading, ACME certificate setup, renewal startup, and certificate hot reload into shared `cmd/guardianwaf/tls_runtime.go`.
- Moved generated dashboard password helpers and upstream summary formatting into shared `cmd/guardianwaf/passwords.go` and `cmd/guardianwaf/upstreams.go`.

Acceptance criteria:

- One shared runtime assembly path for default and HTTP/3 builds.
- Build tags only swap small adapter files.
- Layer registration has tests.

### 7.2 Layer Registry

Status: Partial

Problem:

- Layer order constants exist centrally, but layer creation logic is spread through CLI wiring and library wiring.

Recommended architecture:

- Introduce a layer registry:
  - `Name`,
  - `Order`,
  - `Enabled(cfg)`,
  - `Build(deps, cfg)`,
  - `Start/Stop` optional hooks.
- Use the registry for CLI builds.
- Keep library mode as a consciously smaller registry profile.

Progress:

- Added `internal/runtime/layerregistry` with descriptors for layer name, runtime `Layer.Name()`, order, and active/config-driven enablement. The always-present response layer is represented explicitly.
- Added registry builders for IP ACL, threat intelligence, CORS, custom rules, rate limiting, ATO protection, API security, API validation, sanitizer, CRS, detection, virtual patching, DLP, bot detection, client-side protection, and response layers, and changed CLI `addLayers` to use those builders for the completed migration slices.
- Added `BuildContext` so registry-built layers can share build-time dependencies; rate limiting now wires auto-ban to the registry-built IP ACL layer through context instead of CLI-local variables, and custom rules receive the optional GeoIP database through the same path.
- Added registry lifecycle start hooks; threat intelligence now registers its feed refresh startup hook from the descriptor-backed builder.
- Shared `cmd/guardianwaf/layers.go` layer wiring now logs the effective WAF pipeline before constructing layers, making startup pipeline state visible to operators.
- `Engine.PipelineLayers()` now exposes a defensive active-pipeline snapshot for diagnostics and tests, and `addLayers` logs the active pipeline after construction.
- Registry tests assert deterministic ordering, unique names, nil-config behavior, and config-driven enablement.
- Command-package tests assert that registry runtime layer names and orders exactly match the engine after `addLayers` runs, catching missing, extra, and order-drift cases between the registry and the existing CLI construction path.

Acceptance criteria:

- Adding a layer requires one registration and tests.
- The effective pipeline can be printed/debugged at startup.

### 7.3 Config Parser Coverage

Status: Open

Problem:

- The config model has many fields. Parser population must stay aligned with the struct.

Required work:

- Add tests that compare parsed YAML to expected config structs for every major subsection.
- Add unknown-key detection.
- Add generated or table-driven parser coverage for large nested sections.

Acceptance criteria:

- New config fields cannot silently be ignored by YAML loading.

### 7.4 Frontend/Backend API Contract

Status: Partial

Required work:

- Generate or maintain OpenAPI for dashboard APIs.
- Type dashboard client models from the API contract where possible.
- Add contract tests for all dashboard endpoints used by the UI.

Acceptance criteria:

- UI changes cannot silently drift from backend endpoint shape.

## 8. P1: Deployment Readiness

### 8.1 Container Image Hardening

Status: Partial, improved

Progress:

- Runtime and sidecar images now use `alpine:3.23.4`.
- `scripts/supply-chain-smoke.sh` builds the runtime image, generates an SPDX SBOM with Syft, and scans OS packages plus the Go binary with Trivy.
- CI includes a supply-chain smoke job that fails on HIGH/CRITICAL image vulnerabilities.
- Release workflow enables Docker build provenance/SBOM attestations and uploads a Syft-generated image SBOM.

Required work:

- Verify read-only root filesystem compatibility.
- Verify writable volumes for `/var/lib/guardianwaf` and config paths.
- Add image signature verification policy or keyless signing documentation.
- Confirm release SBOM/provenance behavior on GitHub-hosted runners.

Acceptance criteria:

- Published image has SBOM, provenance, vulnerability scan result, and non-root runtime.

### 8.2 Kubernetes and Helm

Status: Partial

Progress:

- Static Kubernetes ConfigMap-embedded GuardianWAF configs are now parsed and validated by `internal/config` tests.
- Static Kubernetes manifests are validated by `scripts/validate-k8s.sh` and a CI job using kubeconform.
- Helm chart renders are validated by `scripts/validate-helm.sh`, including default values and a production-like values file that enables ingress, autoscaling, PDB, and Istio resources.
- Helm template config keys were aligned with the current schema.
- Helm deployment now passes `serve -c /etc/guardianwaf/<config.fileName>` so the mounted config is actually used.
- Helm now includes templates for the existing autoscaling and PodDisruptionBudget values.
- Kubernetes and Helm probes now use `/livez` for liveness and `/readyz` for readiness.
- `scripts/kind-smoke.sh` deploys the runtime image into KinD and verifies the main proxy and dashboard auth path.

Required work:

- Add secret management examples.
- Add persistent volume examples.
- Add ingress examples for dashboard and proxy.

Acceptance criteria:

- Static manifest, Helm render schema validation, and KinD proxy/dashboard smoke pass in CI; Istio CRDs are allowed to skip schema validation unless their schemas are installed.

### 8.3 Production Config Profiles

Status: Open

Required profiles:

- local development,
- standalone production,
- sidecar production,
- Kubernetes production,
- Docker discovery production,
- dashboard-disabled edge proxy,
- dashboard-enabled admin-only deployment.

Acceptance criteria:

- Each profile validates and has a matching runbook.

## 9. P1: Observability and Operations

### 9.1 Health Semantics

Status: Implemented baseline, documented, needs deeper dependency coverage

Implemented baseline:

- Added `/livez` for process liveness.
- Added `/readyz`, which returns `503` when any configured upstream group has zero healthy targets.
- Kept `/healthz` as a backward-compatible liveness-style endpoint.
- Added production probe documentation in `docs/health-probes.md` and updated production/runbook examples to use `/livez` and `/readyz`.

Remaining work:

- Expand readiness to reflect:
  - config loaded,
  - router built,
  - event store ready,
  - GeoIP state if required,
  - dashboard state if dashboard is enabled.

Acceptance criteria:

- Kubernetes probes can distinguish dead process from temporarily unavailable upstreams.

### 9.2 Metrics Contract

Status: Partial

Required work:

- Define stable metric names and labels.
- Include:
  - requests by action,
  - latency histograms,
  - layer timing,
  - upstream health,
  - circuit breaker state,
  - event store drops,
  - alert failures,
  - AI token/cost usage,
  - Docker discovery status.

Acceptance criteria:

- Grafana dashboard and Prometheus docs match exported metrics.

### 9.3 Runbooks

Status: Partial

Required runbooks:

- high block spike,
- false positive rollback,
- dashboard lockout,
- upstream outage,
- event store full/drops,
- AI provider cost cap hit,
- ACME renewal failure,
- Docker discovery failure,
- suspected WAF bypass,
- incident export for compliance.

Acceptance criteria:

- Operators have step-by-step actions and verification commands.

## 10. P2: Security Validation and Assurance

### 10.1 Threat Model

Status: Open

Required work:

- Write a formal threat model for:
  - edge proxy path,
  - dashboard/admin API,
  - MCP interface,
  - Docker socket/remote Docker,
  - AI provider integrations,
  - tenant isolation,
  - event/log storage,
  - plugin-like generated rules/remediation.

Acceptance criteria:

- Every trust boundary and high-risk data flow is documented.
- Mitigations map to tests or open issues.

### 10.2 Detection Quality Program

Status: Partial

Required work:

- Build an attack corpus from `testdata/attacks`.
- Build a benign corpus from realistic traffic samples.
- Track false positive and false negative rates.
- Add regression tests for known bypasses.
- Add fuzzing for parser/detector boundaries.

Acceptance criteria:

- Detection changes report measurable impact.

### 10.3 External Security Review

Status: Open

Required work:

- Commission or perform security review focused on:
  - proxy SSRF,
  - auth/session/CSRF,
  - tenant isolation,
  - outbound integrations,
  - YAML parser,
  - response masking,
  - WebSocket/gRPC/HTTP3 paths.

Acceptance criteria:

- Findings are tracked and remediated before stable production release.

## 11. P2: Performance and Scale

### 11.1 Performance Budget

Status: Open

Required work:

- Define latency and throughput budgets by deployment mode.
- Benchmark with:
  - clean traffic,
  - attack-heavy traffic,
  - large headers,
  - large bodies,
  - gzip/deflate bodies,
  - many routes,
  - many tenants,
  - high event rate.

Acceptance criteria:

- Release notes include measured performance and environment.

### 11.2 Backpressure and Limits

Status: Partial

Required work:

- Confirm bounded memory for:
  - request body inspection,
  - decompression,
  - event bus subscribers,
  - alert queues,
  - AI pending batches,
  - file event store channel,
  - per-IP trackers,
  - tenant maps.
- Add metrics for drops and backpressure.

Acceptance criteria:

- Overload behavior is predictable and observable.

## 12. P3: Developer Experience

### 12.1 Single Developer Command

Status: Open

Required work:

- Provide `scripts/dev.sh` or equivalent that:
  - verifies tools,
  - installs dashboard dependencies,
  - builds dashboard assets,
  - runs Go tests,
  - builds the binary,
  - optionally starts a demo backend and GuardianWAF.

Acceptance criteria:

- A new contributor can get to a working local instance with one documented command.

### 12.2 Documentation Consistency

Status: Partial

Required work:

- Align README, docs, config examples, Helm examples, Docker examples, and generated API docs.
- Clearly label experimental features.
- Distinguish default build vs `http3` build.

Acceptance criteria:

- Docs are executable and match current code paths.

## 13. Suggested Release Gates

### PR Gate

- Dashboard build.
- Dashboard tests.
- `go test ./...`.
- `go vet ./...`.
- Config fixture validation.
- Default CLI build.
- Minimal smoke test.

### Nightly Gate

- `go test -race ./...`.
- Bounded fuzz smoke suite.
- Playwright E2E.
- Docker Compose test.
- Kubernetes/Helm template validation.
- Container vulnerability scan.
  - Current implementation: `scripts/supply-chain-smoke.sh`.

### Release Gate

- All PR and nightly gates.
- Multi-arch Docker build.
- SBOM and provenance.
  - Current implementation: Docker build provenance/SBOM attestations plus uploaded Syft SPDX image SBOM.
- Release artifact checksums.
- Upgrade test from previous version.
- Rollback test.
- Production config examples validated.
- Security checklist signed off.

## 14. Immediate Next Actions

Recommended order:

1. Run the updated CI workflow on GitHub and fix any hosted-runner-only failures.
2. Expand fixture coverage across any remaining GuardianWAF-specific YAML examples.
3. Continue splitting CLI runtime assembly out of the very large `main*.go` files; event-store, engine bootstrap, event consumers, dashboard startup, dashboard proxy controls, dashboard rules wiring, dashboard adapters, tenant runtime setup, Docker runtime setup, AI runtime setup, alerting runtime setup, cleanup runtime setup, serve lifecycle startup/shutdown, MCP startup, MCP adapter methods, layer, proxy helper, probe assembly, observability setup, client-side report endpoints, challenge setup, HTTP handler selection, server timeout construction, TLS assembly, ACME/GeoIP/rule/network helpers, generated dashboard password helpers, and upstream summary helpers are already shared in small untagged files under `cmd/guardianwaf/`.
4. Expand readiness checks to cover non-upstream dependencies.
5. Confirm full-repository race/nightly CI behavior on GitHub-hosted runners.
6. Confirm release SBOM/provenance and image scan behavior on GitHub-hosted runners.
7. Add QUIC client E2E coverage before documenting HTTP/3 as production supported.

## 15. Production Readiness Verdict

Current state after this pass:

- The project can build and pass the main local Go/UI test baseline once dashboard assets are generated by `./scripts/build-dashboard.sh` or `./scripts/build.sh`.
- There were real correctness and build hygiene issues, and the immediate safe ones were fixed.
- The project should not yet be marketed as fully production ready until P0 items are complete, especially hosted CI proof, reload/shutdown reliability, remaining outbound-integration SSRF hardening, hosted-runner confirmation for release supply-chain attestations, and QUIC/HTTP/3 E2E coverage.
