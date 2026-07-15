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
| Dashboard UI unit tests | Pass, 14 files / 100 tests |
| Full production-binary browser/API E2E | Pass, 531/531 tests: 177 each on Chromium, Firefox, and WebKit via `make e2e-full-all` |
| Dashboard npm audit | Pass, 0 vulnerabilities at `--audit-level=moderate` |
| Zero Trust config/default tests | Pass |
| Targeted race tests | Pass for `internal/engine`, `internal/proxy`, `internal/config`, `internal/dashboard`, and `cmd/guardianwaf` |
| Full repository race tests | Pass locally via `go test -race ./...`; nightly/manual CI gate added |
| Script-based dashboard build | Pass via `./scripts/build-dashboard.sh` |
| Script-based multi-arch release build | Pass via `./scripts/build.sh dev` |
| CLI smoke test | Pass, 32/32 checks when self-building and 31/31 checks with a prebuilt binary, including `/livez`, `/readyz`, `/healthz`, dashboard health/auth, sidecar proxying, sidecar probes, and sidecar SQLi blocking |
| GitHub Actions workflow lint | Pass via `actionlint` |
| Docker Compose syntax | Pass for base, production override, test, and sidecar compose files |
| Docker Compose integration | Pass via `docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test-runner`, 19/19 checks |
| Fuzz smoke suite | Pass via `FUZZTIME=2s ./scripts/fuzz-smoke.sh`; CI runs the same suite with `FUZZTIME=5s` |
| Docker image build | Pass for linux/amd64 runtime image |
| Docker image healthcheck | Pass via `docker run --rm guardianwaf:runtime-check healthcheck` |
| Kubernetes embedded config fixtures | Pass for static ConfigMap-embedded GuardianWAF configs |
| Installer-generated config fixtures | Pass for Bash and PowerShell installer-generated GuardianWAF configs |
| Kubernetes manifest schema validation | Pass locally via `scripts/validate-k8s.sh`; CI job added for checked-in static manifests |
| Helm chart render/schema validation | Pass locally via `scripts/validate-helm.sh`; CI job validates default and production-like renders |
| KinD deployment smoke | Pass locally via `scripts/kind-smoke.sh`; CI job deploys local image into KinD and verifies proxy/dashboard health |
| Explicit private-upstream policy | Pass for config parsing and proxy wiring |
| Dashboard explicit secret validation | Pass for weak configured `api_key`/`admin_key` rejection, strong startup generation for empty `api_key`, and disabled tenant-admin APIs when `admin_key` is empty |
| Go vulnerability scan | Pass after moving build/toolchain references to Go 1.26.5; Go 1.26.4 was rejected after `govulncheck` found reachable GO-2026-5856 in `crypto/tls` |
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
| Compose config fixtures | Added regression coverage that parses Docker Compose mounts for `/etc/guardianwaf/guardianwaf.yaml` and validates the referenced host-side GuardianWAF configs. | Prevents Compose examples from silently mounting stale, missing, or schema-invalid runtime configs. |
| Installer config fixtures | Updated Bash and PowerShell installers to generate current-schema configs and added regression coverage that extracts and validates those embedded snippets. | Prevents first-install generated configs from drifting back to legacy keys. |
| Root config | Replaced legacy-shaped root `guardianwaf.yaml` with a schema-valid default config. | Makes the default config executable by `guardianwaf validate` and usable as a starting point. |
| Config schema guard | Added reflection-backed unknown key rejection for top-level, nested struct, and sequence item config keys while preserving dynamic maps. | Prevents stale public examples and mistyped production YAML from being accepted while silently ignoring unsupported sections. |
| Config parser coverage | Added a tag-driven populate fallback that preserves existing manual defaults while loading yaml-tagged schema fields not covered by older hand-written parser branches, with regression coverage for top-level and nested WAF sections. | Prevents newly added config fields from being accepted by validation but silently ignored during loading. |
| Markdown config snippet validation | Added marker-based regression coverage for public GuardianWAF YAML snippets in README and primary operator docs, including security best-practice snippets, and corrected stale examples to the current schema. | Prevents user-facing docs from drifting back to unsupported config keys or invalid route/upstream shapes. |
| Public config marker contract | Added a regression test that rejects unmarked GuardianWAF YAML blocks in README and primary operator docs, marked the remaining deployable snippets, corrected the production TLS snippet to the current schema, and documented legacy key migration. | Prevents public deployment docs from adding unvalidated config examples or reintroducing legacy `server`/`proxy`/`security` keys. |
| Single developer command | Added `scripts/dev.sh` for prerequisite checks, dashboard asset build, Go tests, local binary build, optional smoke testing, and optional demo backend + GuardianWAF runtime. | Gives new contributors one documented command to reach a tested local binary or running demo. |
| Production config profiles | Added validated config profiles for local development, standalone production, sidecar production, Kubernetes production, Docker discovery production, dashboard-disabled edge, and dashboard-enabled admin-only deployments, plus a profile runbook. | Gives operators concrete starting configs for each supported deployment shape and keeps them under fixture validation. |
| Metrics contract baseline | Centralized the Prometheus `/metrics` exporter contract, added GeoIP readiness/range gauges, documented stable metric names/types/queries, and added handler regression coverage. | Gives operators a stable baseline metrics surface and prevents docs/exporter drift for current metrics. |
| Event store write-error observability | Added engine-level event store write-error counting, exported `guardianwaf_event_store_errors_total`, and exposed `event_store_errors` through dashboard and MCP stats with OpenAPI/UI contract coverage. | Makes persistence write failures visible even when a custom event store does not implement drop reporting. |
| Alert delivery metrics | Added alert manager sent/failed counters, SMTP email sent/failed counters, configured alert target gauges, Grafana panels, and recommended alert rules. | Lets operators detect broken webhook/email alert delivery paths before notification failures hide production incidents. |
| Docker discovery metrics | Added Docker discovery enabled/running gauges, discovered service count, last-sync/event-stream gauges, sync failure counter, Grafana panels, and recommended alert rules. | Lets operators detect broken Docker auto-discovery before dynamic routing silently stops reflecting container changes. |
| Remote Docker TLS gate | Added Docker discovery config fields for TLS-verified remote Docker endpoints, made `tcp://` Docker daemon configs fail validation unless TLS verification and CA/client certificate paths are configured, passed those TLS flags to the Docker CLI runtime, and replaced unauthenticated TCP Docker guidance with a TLS-only profile. | Prevents Docker discovery from being pointed at unauthenticated remote Docker daemons and closes the documented remote Docker TLS assurance gap. |
| AI usage metrics | Added AI enabled, token, request, estimated cost, and verdict counters/gauges to `/metrics`, plus Grafana panels and recommended budget alerts. | Gives operators direct visibility into AI provider spend and usage limits from Prometheus without relying only on dashboard APIs. |
| AI provider SSRF hardening | Added `NewClientValidated` for operator-supplied AI provider endpoints, rejecting non-HTTP(S), hostless, credential-bearing, private, loopback, link-local, localhost, `.internal`, and `.local` URLs before provider configs are saved or activated. Stored private endpoints no longer become active clients on analyzer startup. | Prevents AI provider configuration from silently becoming an outbound SSRF path while preserving explicit private-endpoint opt-in for controlled tests. |
| Alert webhook URL preflight hardening | Dashboard-managed, runtime, and redirect webhook URLs now reject hostless URLs, URL userinfo/credentials, and multicast IPs during preflight in addition to existing HTTPS, localhost, private, loopback, and link-local checks. | Blocks malformed or credential-bearing webhook targets before the outbound HTTP client reaches dial-time SSRF defenses. |
| Webhook private-target test bypass hygiene | Made the alerting private-webhook bypass package-local test plumbing instead of an exported production symbol, with a static regression test preventing it from being re-exported. | Reduces the chance that runtime code accidentally disables webhook SSRF protections outside tests. |
| Proxy private-target bypass hygiene | Removed the legacy exported `proxy.AllowPrivateTargets` helper and added a static guard that production code cannot call the global proxy private-target setter; runtime paths must use instance-scoped `TargetPolicy` instead. | Keeps backend SSRF policy scoped to each router/config instead of relying on mutable package-global state. |
| Layer timing metrics | Aggregated per-layer pipeline timings into the Prometheus histogram `guardianwaf_layer_duration_seconds`, with docs, regression coverage, and Grafana visibility. | Lets operators identify which WAF layer is responsible for latency before tuning or disabling protections. |
| Operator runbooks | Expanded `docs/runbook.md` with step-by-step actions for block spikes, false positive rollback, dashboard lockout, upstream outage, event store pressure, AI cost caps, ACME renewal, Docker discovery, suspected bypass, and compliance export. | Gives operators concrete diagnosis, mitigation, and verification commands for common production incidents. |
| Setup wizard output | Updated generated setup config to use the current schema and fixed a test-stubbed alert command nil path. | Keeps first-run generated configs compatible with `guardianwaf validate` and avoids hidden CLI panic paths. |
| CI/release build flow | Updated CI and release workflows to use `scripts/build-dashboard.sh`, removed incompatible Go 1.24 CI matrix entry, and added config/smoke checks to the PR test gate. | Makes automation match the local production build contract and prevents invalid examples from shipping silently. |
| Release checklist alignment | Updated release verification commands to use the script-based source build, direct Go test/vet/race commands, direct Docker Compose smoke command, and the current direct-dashboard HTTP/TLS proxy contract. | Keeps release operators on the same verified build and validation path as local and CI readiness checks. |
| Kubernetes examples | Added validation coverage for static ConfigMap-embedded GuardianWAF configs and aligned Helm-generated config keys with the current schema. | Reduces the chance that Kubernetes examples deploy stale or ignored config. |
| Helm deployment wiring | Made the Helm deployment start with the mounted config file and corrected supported `GWAF_*` environment variable names. | Prevents chart installs from silently running defaults instead of the rendered config. |
| Docker packaging | Fixed OCI label metadata, made runtime image version labeling effective, removed invalid Compose override keys, and verified Docker image build/healthcheck. | Improves image metadata correctness and avoids production Compose parse failures. |
| Go toolchain security | Moved `go.mod`, Docker builders, CI, Compose examples, and Trivy base-image scan target to Go 1.26.5 after `govulncheck` found reachable GO-2026-5856 in Go 1.26.4 `crypto/tls`. | Removes the known reachable stdlib CVE from production build paths and aligns CI/container builds with the patched toolchain. |
| CLI healthcheck SSRF hardening | Restricted healthcheck overrides to local `/livez` endpoints, added preflight and dial-time local-address validation with direct validated-IP dialing, and fail-gated G704 for `cmd/guardianwaf`. | Prevents the container healthcheck command from becoming a general outbound fetcher or DNS-rebinding path while preserving local liveness probes. |
| Docker integration smoke | Expanded Compose smoke coverage to assert `/livez` and `/readyz`, and switched the Compose healthcheck to `/livez`. | Verifies the runtime image, backend connectivity, WAF blocking, security headers, request IDs, and operational probes in one local deployment path. |
| CLI dashboard smoke | Extended `scripts/smoke-test.sh` to start the dashboard on an unprivileged local port, verify `/api/v1/health`, verify `/api/v1/stats` rejects missing API keys, and verify the configured API key succeeds. | Covers the dashboard startup/auth/health path in the minimal binary smoke test without Docker, ACME, external providers, or privileged ports. |
| CLI sidecar smoke | Extended `scripts/smoke-test.sh` to start a temporary local backend, run `guardianwaf sidecar` against it with explicit private-upstream opt-in, verify sidecar probes, verify clean request proxying, verify SQLi blocking, and shut both processes down. | Covers the sidecar runtime path in the minimal binary smoke test without Docker, ACME, external providers, or privileged ports. |
| Release upgrade/rollback smoke gate | Added `scripts/release-rollback-smoke.sh` and wired it into CI after the binary smoke test; it starts the previous/rollback binary to create file-backed event state, starts the candidate against that same config/state to prove upgrade boot, then starts the rollback binary again to verify rollback readiness plus proxying. | Gives release operators and CI a repeatable upgrade/rollback proof without Docker, Kubernetes, ACME, or external providers. |
| Tenant/admin OpenAPI response-shape contract | Expanded dashboard OpenAPI contract coverage for tenant/admin tenant and usage response shapes, added `Tenant`, `AdminTenant`, `AdminTenantDetail`, `TenantUsage`, and `ResourceQuota` schemas, and fail-gated `api_key_hash` from documented tenant response schemas. | Prevents dashboard tenant UI and admin API docs from drifting into undocumented or credential-leaking response shapes. |
| AI/Docker/Compliance OpenAPI response-shape contract | Added dashboard contract guards and OpenAPI schemas for AI provider/config/history/stats responses, Docker discovery service/container/event responses, and compliance controls/report/audit-chain responses, including a negative guard that AI config responses must not document raw `api_key`. | Reduces frontend/backend drift across high-variance dashboard integrations while keeping secret-bearing AI configuration responses documented as masked/status-only. |
| Security operations OpenAPI response-shape contract | Added dashboard contract guards and OpenAPI response schemas for IP ACL, temporary bans, GeoIP lookup, and alerting status/webhook/email/test responses, including a negative guard that email target responses must not document SMTP `password`. | Keeps security-operations UI responses documented and prevents alert email credential fields from becoming part of the public response contract. |
| Config/routing/SSL OpenAPI response-shape contract | Added dashboard contract guards and OpenAPI response schemas for config summaries, routing upstream/virtual-host/route responses, SSL certificate status, and generic mutation results, including a negative guard that config responses must not document raw `api_key`, `admin_key`, or `password` fields. | Keeps operator-facing configuration screens aligned with documented response shapes while preventing sensitive config fields from becoming part of the public dashboard response contract. |
| Legacy cluster/sync OpenAPI response-shape contract | Added dashboard contract guards and OpenAPI schemas for the currently implemented legacy cluster list, node list, sync stats, and sync status compatibility responses. | Keeps the visible cluster UI compatibility surface documented without claiming unimplemented cluster mutation/detail success responses. |
| Custom rules mutation OpenAPI response-shape contract | Added dashboard contract guards and OpenAPI `ApiResult` response schemas for custom rule create/update/delete operations while keeping the existing `CustomRule` list schema covered. | Prevents rule-management UI mutations from drifting into undocumented success/error response shapes. |
| Dashboard mutation result OpenAPI contract | Added dashboard contract guards and OpenAPI `ApiResult` response schemas for IP ACL add/remove, temporary ban add/remove, AI config update, and alerting webhook/email add/delete operations. | Keeps common dashboard write actions aligned on a documented success/error response envelope instead of silently drifting per handler. |
| UI `ApiResult` OpenAPI drift gate | Added a dashboard contract test that scans UI `request<ApiResult>` calls and fails unless the matching OpenAPI operation documents an `ApiResult` response schema; aligned alerting test responses to the shared schema. | Turns the common dashboard mutation response envelope into an automated contract instead of relying on hand-maintained path assertions. |
| UI typed response OpenAPI drift gate | Added a dashboard contract test that scans non-void UI `request<T>` calls and fails unless the matching OpenAPI operation documents a 2xx response schema; aligned legacy cluster client methods with their no-success-payload backend behavior. | Prevents dashboard typed response expectations from silently drifting ahead of the documented backend response contract. |
| External security review scope | Added `docs/security-review-scope.md` and linked it from README, covering required focus areas, attacker models, review inputs, finding format, and release exit criteria. | Turns the remaining external review requirement into a concrete work package without claiming the review has been performed. |
| External review evidence templates | Added `docs/templates/security-review-report.md` and `docs/templates/security-risk-acceptance.md`, linked them from the review scope and release checklist, and made the evidence verifier reject placeholder text in copied review evidence. | Gives reviewers and release owners a concrete report/risk-acceptance format while preventing unfilled templates from satisfying the release gate. |
| Profile readiness policy | Added profile-by-profile `/readyz` dependency policy to `docs/health-probes.md` and regression coverage requiring every shipped production profile to appear in that policy. | Prevents new deployment profiles from shipping without an explicit traffic-admission contract. |
| Docker Compose smoke CI gate | Added and regression-guarded the `docker-compose-integration` GitHub Actions job, including Docker Compose up with `--exit-code-from test-runner` and cleanup with `docker compose down --remove-orphans`. | Keeps the containerized WAF/backend/test-runner smoke path in hosted CI instead of relying only on local compose evidence. |
| CLI smoke minimal-config guard | Added regression coverage that extracts the inline `scripts/smoke-test.sh` config, validates it, and proves it does not require Docker, ACME/TLS certificates, external AI providers, outbound alerting, MCP, or privileged ports. | Keeps the fast binary smoke gate self-contained and suitable for CI hosts without external services or elevated bind privileges. |
| Config parser struct coverage | Added struct-level parser regression coverage for major nested WAF sections including Zero Trust, cache, replay, canary, analytics, cluster sync, remediation, WebSocket, SIEM, and virtual patching. | Catches parser drift at whole-section shape level instead of relying only on individual field spot checks. |
| Dashboard routing reload | Dashboard-triggered routing rebuilds now rebuild the proxy from the engine's reloaded config snapshot instead of the original startup config pointer, with a regression test proving old in-flight requests drain while new requests use the updated route. | Prevents successful dashboard routing updates from leaving the live proxy on stale upstreams/routes. |
| Detection quality docs guard | Added a regression test requiring README to link `docs/detection-quality.md`, requiring the detection-quality guide to document the corpus gate and current baseline, and requiring the application-log benign corpus to remain wired into the gate. | Keeps the measured detection-quality program discoverable and prevents corpus documentation from drifting away from the executable gate. |
| Release security/detection checklist guard | Expanded the release checklist with detection-quality corpus gate evidence, threat-model review, external security review scope sign-off, HIGH/CRITICAL finding remediation, detector-delta release notes, and evidence-bundle requirements; added regression coverage for those gates. | Turns the final security checklist from a vague sign-off into concrete release evidence that must stay documented. |
| Release evidence bundle | Added `scripts/release-evidence.sh` to collect release docs, git state, local Go/vet/HTTP3/detection/Kubernetes/Helm validation logs, optional heavy race/build/smoke/rollback/benchmark/load/supply-chain evidence, and explicit pending files for hosted CI, external security review, target-environment load, release artifact checksums, and tag-time image signature/provenance evidence. CI now publishes the fast bundle as `release-evidence-ci`; the release workflow publishes `release-binary-checksums` with GoReleaser's `checksums.txt` and `release-supply-chain-evidence` with image digest, imagetools output, cosign signature verification, provenance attestation verification, SBOM attestation verification, SPDX SBOM, and Trivy output; supply-chain smoke can persist `sbom.spdx.json`, `image-inspect.json`, and `trivy.txt` into local bundles; and `scripts/verify-release-evidence.sh` fail-gates dirty worktree or `git diff --check` evidence, a final manifest not generated with `RELEASE_EVIDENCE_HEAVY=1`, missing baseline logs, missing heavy race/build/smoke/rollback/load/benchmark evidence, rollback smoke logs that do not prove previous persistent writes plus candidate/rollback readiness and proxying, unresolved pending evidence, missing release checksums, checksum evidence without a real GuardianWAF SHA-256 artifact line matching the bundle version, release checksum names that include mixed GuardianWAF artifact versions, malformed or mismatched image digest/imagetools evidence, missing or empty SPDX package inventory, supply-chain verification files missing the same image ref, release workflow certificate identity, or GitHub Actions OIDC issuer, mixed-tag or mixed-commit manifest/CI/supply-chain evidence, external review files that do not match the bundle version and hosted CI commit, external review reports with open HIGH/CRITICAL findings or missing valid review dates/sign-off, risk acceptances without valid non-expired expiration/owner/follow-up tracking, missing GitHub Actions run URLs, missing target-load runtime context, environment-specific label, backend baseline, or minimum sample size, non-zero Trivy HIGH/CRITICAL findings, missing external artifacts, and placeholder-like CI/load/supply-chain/review evidence; `--allow-pending` now only tolerates intermediate bundles while pending files remain, and an empty `pending/` directory still triggers the full strict gate. | Gives release operators one auditable evidence directory while keeping unverifiable external gates visible instead of silently treating local checks as full production proof. |
| Release evidence assembly | Added `scripts/assemble-release-evidence.sh` to copy hosted CI, target-load, release supply-chain, and external-review evidence into the final bundle while clearing the matching pending blockers; hosted CI evidence, target-load evidence, release checksums, release supply-chain evidence, and external security review/risk-acceptance evidence are preflight-validated with the verifier before their pending files are cleared. Hosted CI evidence now rejects duplicate `url`, `commit`, or `result` fields, requires an exact passing result value, and requires a canonical run URL from `github.com/guardianwaf/guardianwaf` with no query string or extra path; release checksum evidence must include a real GuardianWAF version-matching SHA-256 line, not just a filename mention; manifest, hosted CI, and supply-chain image digest evidence must now carry the same full 40-character commit SHA. External review validation also revalidates hosted CI evidence before clearing the external-review pending blocker. | Reduces manual release evidence assembly errors before running the strict verifier. |
| Target load evidence | Added `scripts/target-load-evidence.sh` for backend-vs-deployed-proxy p95/p99 and overhead measurements in the target deployment environment. | Turns the remaining target-environment performance gate into a repeatable command that can produce `target_load_results.txt` for the release evidence bundle. |
| Source build prerequisite guard | Added regression coverage that keeps `scripts/check-prereqs.sh` minimum Go/Node/npm versions aligned with README, getting-started, production-deployment, and release-checklist build instructions. | Prevents clean-checkout build prerequisites from drifting between the enforcing script and operator docs. |
| MCP tool authorization and audit classes | Documented read-only vs mutating classes for all 44 MCP tools, added a regression test requiring every tool definition to remain classified in `docs/mcp-integration.md`, and added structured audit logs for mutating tool success/error outcomes plus available SSE transport identity fields without logging arguments or credentials. | Reduces remote-MCP review ambiguity, prevents new tools from shipping without an operator-impact classification, and gives operators a correlated audit signal for high-impact MCP changes without leaking secrets. |
| Probe documentation | Added `docs/health-probes.md` and updated production/runbook examples to distinguish `/livez`, `/readyz`, and legacy `/healthz`. | Prevents operators from using readiness failures as restart signals and aligns deployment docs with the runtime probe contract. |
| Mandatory GeoIP readiness policy | Added `waf.geoip.require_ready`, validation that it can only be enabled with GeoIP, `/readyz` `geoip_not_ready` behavior, and docs/OpenAPI coverage for mandatory GeoIP deployments. | Lets profiles that depend on GeoIP keep traffic out until location data is loaded instead of only surfacing advisory GeoIP gauges. |
| Kubernetes manifest validation | Added `scripts/validate-k8s.sh`, fixed invalid example `securityContext` placement, corrected example service/ingress port wiring, and added a CI job for kubeconform schema validation. | Prevents checked-in static Kubernetes resources from drifting into schema-invalid or non-routable examples. |
| Helm chart validation | Added `scripts/validate-helm.sh`, fixed the Istio service port reference, added HPA/PDB templates for existing values, and wired chart lint/render/schema/config validation into CI. | Prevents the chart from shipping unrenderable templates or rendered GuardianWAF config that fails application validation. |
| KinD deployment smoke | Added `scripts/kind-smoke.sh` and CI coverage that builds the runtime image, loads it into KinD, deploys backend + GuardianWAF, then verifies liveness, readiness, proxy pass-through, attack blocking, and dashboard auth. | Proves the container can run inside a real Kubernetes API/serverlet path rather than only passing static schema validation. |
| Fuzz smoke gate | Added `scripts/fuzz-smoke.sh` and a CI job covering config parsing, sanitizer normalization, SQLi/XSS detectors, IP ACL, rate limiting, bot fingerprinting, and JWT validation. | Adds bounded panic/regression discovery for parser and security-sensitive request processing code. |
| Private upstreams | Added explicit `allowed_upstream_cidrs` and `allow_private_upstreams` config/env support, with target-scoped proxy preflight and dial-time enforcement. | Keeps SSRF protection default-deny while making Docker/Kubernetes/internal-backend deployments functional by explicit and preferably narrow policy without cross-router policy leakage. |
| Dashboard secret hardening | Added config validation that rejects explicitly configured short/common dashboard API/admin keys; empty dashboard API keys still trigger strong random startup generation. Empty `dashboard.admin_key` now disables tenant-admin APIs instead of generating and printing an ephemeral system admin key. | Reduces accidental deployment with hard-coded weak dashboard credentials while keeping first-run local ergonomics for ordinary dashboard access and making cross-tenant admin access explicit. |
| Dashboard admin-key deployment contract | Added `GWAF_DASHBOARD_ADMIN_KEY` config override support, tests for tenant-admin disabled/enabled startup behavior, and production/example docs for the separate admin key. | Gives operators a clear path to enable tenant-admin operations through managed secrets while keeping the admin API closed by default. |
| Standalone trusted-proxy integration coverage | Added a command-package integration regression that builds the standalone runtime proxy path and proves untrusted peers cannot spoof `X-Forwarded-For` while trusted proxy chains select the rightmost non-trusted hop recorded in stored events. | Extends the trusted client-IP model from engine-only tests to the real standalone proxy/middleware assembly path operators deploy. |
| Public API secret examples | Updated REST and MCP API examples to source dashboard keys from `GWAF_DASHBOARD_API_KEY` or a secret manager placeholder instead of copy-pasteable weak literals, with a regression test banning `secret123`-style dashboard API key examples. | Reduces the chance that public API examples become weak credentials in deployed scripts, snippets, or runbooks. |
| CAPTCHA outbound SSRF hardening | hCaptcha and Turnstile verification clients now reject private, loopback, link-local, multicast, and unspecified dial targets even though their request URLs are fixed public provider endpoints. | Prevents DNS poisoning or resolver mistakes from turning CAPTCHA verification into an outbound private-network connection path. |
| Body logging guardrail | `logging.log_body=true` now emits an explicit startup warning that request body logging can expose credentials/PII, the structured access-log tests assert request bodies are not emitted, and configuration docs warn to keep it disabled except controlled debugging. | Makes dangerous body logging opt-in visible to operators and prevents access-log schema changes from silently leaking request payloads. |
| Dashboard cookie gosec gate | Added explicit dashboard session/logout cookie assertions, documented the dynamic Secure-cookie behavior for direct TLS and trusted TLS-terminating proxies, and made CI fail on medium-confidence `gosec` G124 regressions in `internal/dashboard`. | Turns a previously advisory static-analysis finding into a release gate for browser session cookies while broader `gosec` findings remain tracked separately. |
| Integer conversion gosec gate | Added explicit bounds for engine detection thresholds, guarded proxy circuit-breaker threshold narrowing, avoided unsafe weighted/IP-hash balancer conversions, and made CI fail on medium-confidence `gosec` G115 regressions in `internal/engine` and `internal/proxy`. | Prevents overflow-prone runtime threshold and routing conversions from silently entering request-processing paths. |
| SSRF IP parser integer conversion gate | Added overflow rejection for flexible decimal/octal/hex abbreviated-IP parsing, centralized bounded IPv4 byte narrowing, and made CI fail on medium-confidence `gosec` G115 regressions in `internal/layers/detection/ssrf`. | Prevents malformed numeric host encodings from wrapping during SSRF normalization and keeps IP parser narrowing auditable. |
| Repository-wide integer conversion gate | Cleared the remaining medium-confidence `gosec` G115 findings in sanitizer/XSS decoders, JA4 formatting, GeoIP CIDR range calculation, and event JSON float formatting, then added a full-repository G115 CI gate. | Prevents new unchecked integer narrowing from entering parser, fingerprinting, GeoIP, event serialization, or future packages. |
| Config path/file inclusion gosec gate | Added filename-fragment validation for `GWAF_ENV`, cleaned operator-selected config paths, constrained `rules.d`, `domains.d`, and `tenants.d` child file loads to their parent directories, and made CI fail on medium-confidence `gosec` G304/G703 regressions in `internal/config`. | Prevents config loading from accumulating path traversal or file inclusion regressions while keeping explicit operator-selected config files supported. |
| Example server timeout gosec gate | Updated the backend and library examples to use explicit `http.Server` instances with read-header, read, write, and idle timeouts, and made CI fail on medium-confidence `gosec` G114 regressions in those examples. | Keeps public copy-paste examples from teaching timeout-free HTTP serving patterns. |
| Attack simulation gosec gate | Replaced weak random selection/session IDs in `scripts/attack-simulation` with crypto-backed helpers, documented the outbound local-HTTP simulation cookie exception, and made CI fail on medium-confidence `gosec` G404/G124 regressions in that tool. | Keeps operator test tooling from accumulating avoidable static-analysis exceptions while preserving local attack-simulation behavior. |
| Runtime file permission gosec gate | Tightened setup-generated config directories to `0750`, rotating log directories to `0750`, and active rotated log files to `0600`, with CI fail-gating medium-confidence `gosec` G301/G302 regressions in command and engine runtime paths. | Reduces accidental disclosure of generated secrets, request logs, and rotated access/security evidence on shared hosts. |
| Protocol hash gosec gate | Documented the standards-required MD5 use for JA3 fingerprint compatibility and SHA-1 issuer hashes for OCSP CertID generation, with CI fail-gating medium-confidence `gosec` G401/G501/G505 regressions in bot fingerprinting and TLS OCSP code. | Keeps weak-primitive exceptions narrow, auditable, and limited to protocol interoperability rather than security decisions. |
| Tenant one-time API key gosec gate | Documented and fail-gated the intentional one-time tenant API key returned by create/regenerate responses, while tests assert tenant response objects do not expose stored `api_key_hash`, plaintext nested `api_key`, or nested `admin_key` fields. | Keeps tenant credential exposure limited to explicit one-time issuance paths and prevents stored credential material from leaking in tenant objects. |
| Tenant persistence path/file inclusion gate | Tenant store paths now reject NUL bytes, tenant filenames are derived only from validated tenant IDs, tampered index entries cannot redirect load/delete operations, unsafe tenant data filenames are skipped during rebuild, billing store paths are cleaned before load/save, and CI fail-gates medium-confidence `gosec` G304/G703 regressions in `internal/tenant`. | Prevents tenant metadata, hashed keys, quota, and billing persistence from regressing into traversal-prone filesystem access. |
| Event persistence path/file inclusion gate | File-backed event stores now reject NUL paths, clean operator-selected JSONL paths before open/replay/rewrite/rotation, use `filepath` joins for rotated cleanup, and CI fail-gates medium-confidence `gosec` G304/G703 regressions in `internal/events`. | Keeps durable security-event history and async event rotation from regressing into traversal-prone filesystem access. |
| GeoIP cache path/file inclusion gate | GeoIP CSV load, reload, auto-refresh, and download cache writes now reject NUL paths, clean operator-selected DB/cache paths before file access, and CI fail-gates medium-confidence `gosec` G304/G703 regressions in `internal/geoip`. | Keeps location-enrichment state from regressing into traversal-prone filesystem access while preserving explicit operator-managed GeoIP database paths. |
| Runtime log path/file inclusion gate | Rotating runtime log writers now reject empty/NUL paths, clean configured log file sinks before directory creation/open/rotation, and CI fail-gates medium-confidence `gosec` G304/G703 regressions in `internal/engine`. | Keeps access/security log persistence from regressing into unsafe filesystem access while preserving explicit operator-selected log destinations. |
| AI store path/file inclusion gate | AI config and encryption-key persistence now reject NUL store paths, normalize store directories before config/key file access, preserve temp fallback for invalid or unwritable directories, and CI fail-gates medium-confidence `gosec` G304/G703 regressions in `internal/ai`. | Keeps AI provider credentials, usage history, and encrypted-at-rest key material from regressing into unsafe filesystem access. |
| Generated virtual patch review gate | Auto-generated virtual patches now start disabled with `review_status=pending_review` and provenance metadata, explicit apply/disable transitions record actor/timestamps, and the virtual patch layer emits structured audit logs for create/apply/disable transitions. | Prevents CVE-derived generated regex rules from blocking production traffic before human review while preserving an audit trail for generated-rule lifecycle changes. |
| Compliance audit path/file inclusion gate | Compliance audit replay and JSONL persistence now reject NUL paths, clean configured audit trail paths before open/append, preserve memory-only fallback for non-strict engines, and CI fail-gates medium-confidence `gosec` G304/G703 regressions in `internal/compliance`. | Keeps hash-chained audit evidence from regressing into unsafe filesystem access while preserving strict startup failure for explicitly durable deployments. |
| Compliance audit anchoring | Dashboard audit-chain responses now expose the current hash-chain `head_hash`, OpenAPI documents it, the UI displays it, and the incident export runbook requires anchoring that hash in approved write-once evidence storage. | Makes audit-chain tamper evidence operationally usable outside the local JSONL file and closes the remaining write-once evidence guidance gap. |
| ACME account key path/file inclusion gate | TLS ACME startup now rejects empty/NUL cache directories, builds `account.key` with `filepath.Join`, reads and writes account keys only under the cleaned cache path, and CI fail-gates medium-confidence `gosec` G304/G703 regressions in `cmd/guardianwaf`. | Keeps certificate automation key material from regressing into unsafe filesystem access while preserving operator-selected ACME cache locations. |
| IP ACL auto-ban path/file inclusion gate | Auto-ban persistence paths now reject NUL input, are cleaned at layer construction and before load/save, nested persistence directories are created with private permissions, and CI fail-gates medium-confidence `gosec` G304/G703 regressions in `internal/layers/ipacl`. | Keeps temporary IP ban state from regressing into unsafe filesystem access while preserving configured persistence across restarts. |
| CRS rule path/file inclusion gate | CRS rule paths now reject NUL input, are cleaned before stat/walk/read, directory traversal checks use `filepath.Rel` instead of string-prefix matching, and CI fail-gates medium-confidence `gosec` G304/G703 regressions in `internal/layers/crs`. | Keeps operator-managed CRS rule loading fail-closed and prevents rule file access from regressing into unsafe filesystem handling. |
| Repository-wide path/file inclusion gate | Attack simulation payload files and reliability JSONL result paths now reject empty/NUL input, clean caller-selected paths before read/write, the full repository now has zero medium-confidence `gosec` G304/G703 findings, and CI fail-gates those rules with a repo-wide `./...` scan. | Keeps runtime, release, and reliability tooling from accumulating unsafe filesystem patterns while preserving explicit operator and test-owned local file inputs. |
| Outbound integration SSRF static gate | Webhook, GeoIP, JWKS, threat-intel feed, and NVD URL preflight DNS checks now carry explicit `gosec` G704 rationale tied to their SSRF-safe `DialContext` and redirect validation, and CI fail-gates medium-confidence G704 regressions across those outbound integrations. | Keeps DNS preflight checks, connection-time IP enforcement, and redirect validation aligned for production outbound HTTP clients. |
| Redirect sink static gate | Challenge verification redirects now pass through a same-origin path helper, HTTP-to-HTTPS redirects sanitize Host-derived authority before constructing a fixed-scheme target, and CI fail-gates medium-confidence `gosec` G710 regressions in `cmd/guardianwaf` and `internal/layers/challenge`. | Prevents redirect sinks from regressing into attacker-controlled off-site redirects while preserving ACME passthrough and normal HTTPS upgrade behavior. |
| Response sink static gate | MCP SSE endpoint events now reject Host values with control characters or authority delimiters, embedded dashboard asset writes carry explicit static-asset provenance, the example backend escapes reflected paths, and CI fail-gates medium-confidence `gosec` G705 regressions. | Keeps HTML/SSE/text response sinks from drifting toward request-controlled script or event injection. |
| Docker CLI execution static gate | Docker auto-discovery now rejects NUL/control characters in socket-derived host flags, event label filters, and CLI arguments before invoking the Docker binary without a shell, and CI fail-gates medium-confidence `gosec` G204 regressions in `internal/docker`. | Keeps Docker integration command execution explicit and argument-safe while preserving CLI-based daemon compatibility. |
| Production build prerequisite gate | `scripts/build.sh`, CI dashboard builds, and release dashboard builds now run `scripts/check-prereqs.sh` before building, with regression coverage that requires the prereq gate to run before dashboard asset generation. | Keeps clean-checkout production builds fail-fast on unsupported Go, Node.js, npm, or missing git instead of failing later with opaque build errors. |
| Supply-chain image gate | Added `scripts/supply-chain-smoke.sh`, pinned Syft/Trivy scanner images in automation, enabled release image SBOM/provenance, verified release provenance/SBOM attestations with cosign into release evidence, and moved runtime/sidecar images to `alpine:3.23.4` after Trivy found HIGH/CRITICAL CVEs in the old Alpine runtime. | Gives CI and release flows a concrete SBOM/vulnerability gate and removes known high-severity OS package findings from the final runtime image. |
| CI tool pinning | Pinned TruffleHog to a commit SHA, pinned GoReleaser to `v2.16.0`, and pinned CI-installed Go tools (`deadcode`, `benchstat`, `govulncheck`, `gosec`) to concrete versions, with regression coverage that rejects `@main`, `@master`, `@latest`, and `version: latest` in workflows. | Reduces hosted-runner drift and closes an avoidable CI supply-chain/reproducibility gap before remote workflow validation. |
| Full-repository race gate | Fixed a real data race in the virtual patch database hit counters and added a scheduled/manual CI job that runs `go test -race ./...`. | Makes concurrency regressions visible outside the PR fast path and removes a runtime race in virtual patch request processing. |
| Health checker lifecycle | Serve, sidecar, dashboard rebuild, and Docker discovery rebuild paths now retain and stop proxy health checkers instead of leaking background probe goroutines; `HealthChecker.Stop` cancels in-flight probes and serve/sidecar shutdown now drain health checkers with the shared shutdown context. | Reduces shutdown/reload resource leaks, prevents stale backend health loops after route replacement, and avoids shutdown waiting for long probe timeouts. |
| Docker watcher shutdown bound | Docker discovery watcher shutdown now has `StopWithContext`, and `cmd serve` uses the shared shutdown context when stopping Docker auto-discovery. | Prevents Docker event-stream or poll fallback teardown from blocking SIGINT/SIGTERM shutdown beyond the graceful-drain budget. |
| ACME renewal shutdown bound | ACME certificate renewal now exposes `StopRenewalWithContext`, uses idempotent close-once shutdown signaling, and `cmd serve` prefers the shared shutdown context when stopping ACME renewal. | Prevents certificate renewal work from extending SIGINT/SIGTERM shutdown past the graceful-drain budget and removes concurrent stop-close panic risk. |
| TLS certificate reload shutdown bound | TLS certificate hot-reload now exposes `StopReloadWithContext`, and `cmd serve` uses the shared shutdown context when stopping the certificate reload watcher. | Prevents certificate file reload work from extending SIGINT/SIGTERM shutdown past the graceful-drain budget. |
| GeoIP auto-refresh shutdown handle | GeoIP auto-refresh now exposes `StartAutoRefreshWithContext` with an idempotent `StopWithContext` handle while preserving the legacy stop function API, and serve/sidecar/check runtime wiring tracks GeoIP refresh handles from custom-rule and dashboard GeoIP loading. | Stops GeoIP refresh goroutines with the shared graceful-shutdown context instead of leaking auto-refresh loops or only signaling them to stop. |
| Alerting shutdown drain | Alerting manager now tracks asynchronous webhook/email sends, refuses new dispatches after close, waits for in-flight sends with context-bound shutdown, and closes idle HTTP connections. `cmd serve` drains alerting before closing the engine/event bus. | Reduces alert loss during SIGINT/SIGTERM and makes outbound notification shutdown deterministic under test. |
| Dashboard cleanup shutdown drain | Dashboard login/API/session cleanup loops are now tracked with a `WaitGroup`, expose `CloseWithContext`, and `cmd serve` uses the shared shutdown context when closing the dashboard. | Prevents dashboard maintenance goroutines from outliving shutdown or extending SIGINT/SIGTERM beyond the graceful-drain budget. |
| Tenant runtime shutdown drain | Tenant alert dispatch and cluster broadcast goroutines are now tracked, tenant manager shutdown drains queued tenant alerts and cluster broadcasts with `CloseWithContext`, rejects new tenant alerts and cluster broadcasts after close, and `cmd serve` uses the shared shutdown context when closing tenant runtime. | Prevents tenant alert handlers or cluster broadcast calls from outliving shutdown, and prevents tenant runtime from accepting new asynchronous work after graceful shutdown starts. |
| Engine shutdown idempotency | Engine shutdown now uses a close-once guard, returns the first event-store close error to all callers, closes the event bus only once under concurrent or repeated `Close` calls, and rejects new event persistence/publish work after close. | Prevents repeated teardown from double-closing event subscribers while preserving durable event-store shutdown errors and avoiding post-close writes to closed stores. |
| Compliance audit durability errors | Compliance audit persistence now returns durable append failures from `AppendChainWithError`/`GenerateReportWithError`, avoids advancing the in-memory chain when the file append fails, returns `Sync`/`Close` failures from `Close`, and dashboard report/shutdown paths surface those errors. | Keeps configured compliance audit-chain durability failures visible instead of silently reporting a persisted report or clean close. |
| AI analyzer shutdown bound | AI analyzer shutdown now has `StopWithContext`, and `cmd serve` uses the shared shutdown context when draining AI analysis. | Prevents slow provider calls from extending SIGINT/SIGTERM shutdown past the configured graceful-drain budget. |
| Threat-intel shutdown bound | Threat-intel feed refresh loops now cancel in-flight URL loads and expose `StopWithContext`; `cmd serve` uses the shared shutdown context when stopping the threat-intel layer. | Prevents slow feed refreshes from blocking SIGINT/SIGTERM shutdown beyond the configured graceful-drain budget. |
| Virtual patch shutdown bound | Virtual patch auto-update now cancels in-flight NVD searches and exposes `StopWithContext`; `cmd serve` uses the shared shutdown context when stopping the virtual patch layer. | Prevents slow CVE feed updates from blocking SIGINT/SIGTERM shutdown beyond the configured graceful-drain budget. |
| IP ACL persistence shutdown bound | IP ACL auto-ban persistence now tracks its save goroutine with a `WaitGroup`, exposes `StopWithContext`, avoids starting persistence until constructor validation succeeds, and serve/sidecar shutdown use the shared shutdown context when stopping the layer. | Prevents persisted temporary-ban state from leaking a background save loop or extending SIGINT/SIGTERM shutdown beyond the graceful-drain budget. |
| Event consumer shutdown wait | `cmd serve` now tracks alerting and dashboard SSE event-bus consumer goroutines and waits for them after closing the engine/event bus. | Prevents event forwarding goroutines from outliving shutdown and makes process teardown more deterministic. |
| Cleanup loop shutdown wait | `cmd serve` and `cmd sidecar` now track the periodic cleanup goroutine with a `WaitGroup`, wait for it before engine close, and release serve/sidecar signal notification channels on return. | Prevents maintenance work from racing engine teardown and removes lingering signal registrations in embedded/test executions. |
| NVD outbound SSRF guard | Virtual patch NVD client now rejects non-HTTP(S), hostless, credential-bearing, private, loopback, link-local, unspecified, multicast, localhost, `.internal`, and `.local` operator URLs, validates redirect targets, and uses an SSRF-safe dialer that rejects private, loopback, link-local, unspecified, and multicast IPs at connection time. | Closes the DNS rebinding/redirect gap for automatic CVE feed updates. |
| Event secret redaction | Event creation now redacts sensitive query parameters, referer URLs, User-Agent token patterns, bearer/JWT tokens, cookies, API keys, CSRF/XSRF tokens, session IDs, passwords, and client secrets from finding evidence before events reach stores, dashboard APIs, SSE, alerts, AI, or MCP consumers. Engine `Check` and middleware no longer overwrite sanitized events with raw pipeline findings. | Reduces credential leakage risk in event retention, UI/API responses, access logs, traces, and downstream integrations while keeping non-sensitive matched evidence visible for investigation. |
| Tenant admin response sanitization | Dashboard tenant admin list/create/get/update responses now strip tenant `api_key_hash` fields and redact nested dashboard `api_key`/`admin_key` config values while preserving explicit one-time tenant key create/regenerate responses. | Prevents stored tenant credential material from leaking through tenant object serialization in admin APIs. |
| Engine-local trusted proxy model | `Engine.Check`, middleware, and wired JavaScript challenge verification now derive client IP from the engine's own parsed `trusted_proxies` list instead of relying on mutable package-global proxy state. | Prevents one Engine instance from changing another Engine instance's `X-Forwarded-For` trust behavior in library or multi-runtime deployments. |
| Event store close safety | FileStore now serializes async channel sends against close, and PersistentMemoryStore serializes file appends against file close, with normal and race regression coverage. | Removes shutdown-time event persistence panic/data-race risk under concurrent request teardown. |
| Runtime event persistence wiring | `cmd serve` and `cmd sidecar` now honor `events.storage: file` by opening a persistent JSONL-backed queryable event store, creating the parent directory, replaying prior events, and failing startup if the configured store cannot be opened. | Makes the documented file event storage mode real in runtime instead of silently running memory-only. |
| HTTP/3 build tag | Re-synchronized the HTTP/3-tagged command entrypoint so it parses, formats, tests, and is covered by CI. | Prevents optional build tags from silently rotting outside the default build. |
| HTTP/3 entrypoint drift guard | Added a command-package regression test that asserts `cmd/guardianwaf/main.go` and `main_default.go` remain identical except for their build tag line until the runtime assembly is split behind smaller adapters. | Prevents one build-tag variant from silently missing production fixes applied to the other variant. |
| HTTP/3 documentation consistency | Threat model, gRPC ADR, and MCP integration docs now consistently describe HTTP/3 as build-tag/config compatibility only, with no production QUIC listener in the current tree. | Prevents operator-facing docs from implying unsupported HTTP/3 ingress before a concrete QUIC runtime and E2E coverage exist. |
| Planned layer ADR consistency | gRPC, cache, WebSocket, canary, and replay ADRs now describe their missing layer packages as planned runtime work instead of claiming package directories already exist. | Keeps design-era ADRs useful without overstating the current production runtime surface. |
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
| Shared serve lifecycle wiring | Moved serve HTTP/TLS listener startup, serve runtime status logging, threat-intel stop, proxy health-checker stop, cleanup stop, and ordered serve/sidecar shutdown helpers into shared untagged `cmd/guardianwaf/serve_lifecycle.go`, with direct regression coverage for idempotent stop-channel handling, threat-intel stop dispatch, proxy target close, sidecar cleanup stop, and runtime status logging. | Keeps serve and sidecar shutdown behavior identical across default/HTTP3 build paths and reduces the signal/shutdown block inside tagged entrypoints. |
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
| Layer registry descriptor guard | Added registry inventory and pipeline-summary shape regression tests. | Forces any new runtime layer descriptor to update the intentional registry inventory and keeps startup/debug pipeline output stable. |
| Dashboard OpenAPI contract gate | Expanded the dashboard UI/OpenAPI regression tests from path presence to UI-used HTTP methods, mutating JSON request bodies, typed JSON 2xx response schemas, `ApiResult` response schemas, and core response-shape tokens, with minimum extraction thresholds so parser drift cannot silently empty coverage. | Reduces operator-facing API/UI contract drift risk and turns the former path-only assurance into an executable contract gate. |
| Full cross-browser/API E2E gate | Added a self-contained production-binary runner for 177 tests on each of Chromium, Firefox, and WebKit (531 total), including backend startup, isolated mutable config, MCP coverage, digest-pinned official browser runtime, 320/375/768 px navigation and overflow checks, and CI wiring. | Expands the browser gate from a six-test Chromium shell smoke to cross-engine authentication, mutations, routing, rules, AI, tenants, analytics, SSE, MCP, security validation, responsive layout, and console-error coverage. |
| Atomic dashboard mutation persistence | Routing updates now prepare a complete candidate proxy, reload and atomically persist config before swapping handlers, and preserve the old engine/proxy on failure; general config and alert-target mutations roll back runtime snapshots on persistence failure. | Prevents 200 responses for non-durable changes and eliminates mixed old-proxy/new-config runtime states. |
| ACME response-origin confinement | ACME directory and server-provided nonce/order/authz/challenge/finalize/certificate URLs must be valid HTTP(S), credential/fragment-free, and same-origin with the configured directory. | Prevents a CA response from turning the ACME client into a cross-origin or internal-network request primitive. |
| Shutdown error propagation | Serve and sidecar aggregate HTTP/TLS/background-component and event-store close errors and exit unsuccessfully when graceful shutdown cannot complete durably. | Makes event-store sync/close failures and bounded-drain timeouts visible to supervisors instead of reporting a clean stop. |
| Atomic fail-loud environment and entrypoint validation | Typed `GWAF_*` boolean/integer/number overrides are validated before any overlay is applied; serve, sidecar, check, validate, test-alert, healthcheck, and public `New`/`NewFromFile` callers propagate parse and semantic validation errors. The documented override table is regression-checked against the runtime map, and trusted-proxy/alerting overrides now match operator docs. | Prevents misspelled TLS, dashboard, Docker, alerting, tracing, threshold, retention, or compliance values from silently retaining defaults, stops invalid library/CLI configs before engine construction, and keeps environment documentation aligned with executable behavior. |
| Engine-local tracing runtime | Wired parsed tracing config into every engine, replaced process-global runtime use with isolated per-engine tracers, added reload/shutdown lifecycle handling, 128-bit trace IDs and 64-bit span IDs, service tagging, root/layer span regression coverage, finite sampling/exporter validation, and Prometheus tracing counters. | Turns a previously parsed-but-inert operator feature into executable behavior without cross-engine configuration races, while documenting that built-in noop/stdout exporters are not an OTLP network integration. |
| Architecture docs | Added root `ARCHITECTURE.md`. | Gives maintainers a detailed source-of-truth for runtime shape and extension points. |

### 1.3 Known Baseline Caveats

- `make` is not installed in the current local environment. Script equivalents now exist for the dashboard/release build path, but contributor docs should still clarify tool prerequisites.
- `internal/dashboard/dist/placeholder.txt` is kept for clean-checkout Go compilation, while generated React assets remain ignored. Production binaries still require `./scripts/build-dashboard.sh` or `./scripts/build.sh` so the embedded dashboard serves the real UI instead of only the placeholder.
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

Status: Partial, improved

Problem:

- `internal/dashboard/dashboard.go` embeds `dist`; generated dashboard assets remain ignored, but a tracked placeholder keeps the embed directory present in clean checkouts.
- `go test ./...` on a clean checkout no longer fails solely because the dashboard UI has not been built; production binaries still need the dashboard build step for the React UI assets.
- A make-free build path is now available and the CI/release workflows call it.
- `scripts/check-prereqs.sh` now validates the local production-build toolchain before dashboard/release builds.
- `scripts/build.sh` now runs the prereq gate before dashboard generation, avoids duplicate prereq checks when delegating to `scripts/build-dashboard.sh`, and passed locally for `dev-readiness`, producing Linux, macOS, Windows, amd64/arm64 binaries plus checksums.
- Regression coverage now keeps the prereq script's Go 1.26.5, Node.js 20.19.0, and npm 10.x minimums aligned with README, getting-started, production-deployment, and release-checklist build instructions.

Required work:

- Keep `Makefile`, CI, and release workflows delegated to the same build scripts.
- Confirm the updated CI workflow on GitHub-hosted runners:
  - clean checkout with only `internal/dashboard/dist/placeholder.txt`,
  - dashboard build,
  - Go build,
  - Go test,
  - config fixture validation,
  - CLI smoke test.
- Keep exact local prerequisites documented: Go 1.26.5+, Node.js 20.19.0+, npm 10.x+, `git`, and script fallback when `make` is unavailable.

Acceptance criteria:

- `scripts/build.sh` succeeds on a clean checkout.
- `go test ./...` succeeds on a clean checkout and after the documented dashboard build step.
- `scripts/check-prereqs.sh` fails fast with actionable messages when required build tools are missing or too old.
- CI starts from a clean checkout and never relies on locally generated assets.

### 4.2 Configuration Schema Alignment

Status: Partial

Problem:

- The root `guardianwaf.yaml`, setup-generated config shape, Bash/PowerShell installer-generated configs, static Kubernetes ConfigMaps, Docker Compose-mounted runtime configs, and current test fixtures are now schema-valid and covered by tests.
- README and primary operator-doc GuardianWAF YAML snippets are now marker-validated by `internal/config` tests, including security best-practice snippets for trusted proxies, dashboard keys, TLS/ACME, alerting, logging, ATO, detector tuning, and detection exclusions.
- Public deployment docs now reject unmarked GuardianWAF YAML blocks in CI, so newly added deployable snippets must be explicitly marked and parsed against `internal/config.Config`.
- `docs/configuration.md` now documents migration from legacy `server.*`, `proxy.*`, and `security.waf` keys to the current top-level schema and calls out fail-loud unknown-key validation.
- Design-era full configuration references in `docs/design/SPECIFICATION.md` and `docs/design/GuardianWAF-Claude-Code-Prompt.md` are now marker-validated by the same config snippet test.
- Unknown top-level keys, nested struct keys, and sequence item keys now fail validation instead of being silently ignored.
- Dynamic maps such as detector names, feature flags, and webhook headers remain intentionally open.
- Default and production-like Helm-rendered GuardianWAF configs validate through `scripts/validate-helm.sh`.
- Remaining ADR snippets are treated as proposal/subsection examples unless explicitly marked as deployable GuardianWAF configs.

Required work:

- Audit any newly identified ADR/design-era snippet before presenting it as a deployable GuardianWAF config.
- Ensure every newly added public deployable config example matches `internal/config.Config` and is preceded by `<!-- guardianwaf-config:validate -->`.
- Expand the config fixture test as additional GuardianWAF config examples are identified.

Acceptance criteria:

- Every shipped config fixture validates.
- The root `guardianwaf.yaml` can start the binary.
- Unknown production config keys fail validation with actionable field paths.

### 4.3 CLI Runtime Smoke Tests

Status: Partial

Progress:

- Existing `scripts/smoke-test.sh` passed with 32/32 checks when it self-builds the binary and 31/31 checks when pointed at a prebuilt binary, including liveness/readiness/legacy health probes, dashboard health/auth, sidecar proxying, sidecar probes, and sidecar SQLi blocking.
- CI now builds a binary and runs `scripts/smoke-test.sh` as part of the PR test job.
- CI now runs `scripts/release-rollback-smoke.sh ./guardianwaf ./guardianwaf` after the binary smoke test to prove previous-version state creation, candidate upgrade startup, persistent event-state reuse, rollback startup, readiness, and proxying through the same production-like config. Release operators can pass the previous release binary as the second argument for cross-version upgrade and rollback evidence.
- CI includes a `docker-compose-integration` job that runs `docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test-runner` and always cleans up with `docker compose down --remove-orphans`; `internal/config` regression coverage keeps that job and cleanup command present.
- `internal/config` regression coverage extracts the inline `scripts/smoke-test.sh` config, validates it, and asserts the smoke gate does not require Docker, ACME/TLS certificates, external AI providers, outbound alerting, MCP, or privileged ports.
- `docker-compose.test.yml` passed locally with 19/19 checks against a built runtime image, live backend, and test-runner container.

Required work:

- Confirm the updated smoke workflow on GitHub-hosted runners.

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
- full production-binary Playwright/API E2E suite (`./scripts/full-e2e.sh`)
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
  - additional reverse-proxy cookie security expectations beyond the current TLS-forwarded Secure-cookie regression coverage.
- Continue triaging the broader medium/high `gosec` advisory backlog; dashboard cookie handling, engine/proxy integer conversions, public example server timeouts, attack-simulation random/cookie handling, runtime file permissions, protocol-required hash use, and tenant one-time API key issuance are now fail-gated, but the full repository scan still runs in report-only mode.

Completed:

- Explicitly configured weak dashboard API/admin keys fail validation.
- Empty `dashboard.admin_key` leaves tenant-admin APIs disabled and emits a startup warning instead of printing an ephemeral admin key.
- `GWAF_DASHBOARD_ADMIN_KEY` can populate `dashboard.admin_key` from environment-managed secrets.
- Session and logout cookies are asserted as `HttpOnly`, `SameSite=Strict`, path-scoped to `/`, and `Secure` when requests arrive over direct TLS or trusted TLS-terminating proxy headers; CI now fail-gates G124 regressions for `internal/dashboard`.
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
- The standalone runtime proxy/middleware assembly now has integration coverage proving an untrusted direct peer cannot spoof `X-Forwarded-For`, while a configured trusted proxy chain records the rightmost non-trusted hop in stored events.
- JavaScript challenge verification is wired to `Engine.ExtractClientIP`, so challenge cookies are bound to the same client IP model as WAF event/decision processing.
- Reload updates the engine-local trusted proxy list.
- Config validation now rejects invalid trusted proxy entries, `0.0.0.0/0`, `::/0`, and overly broad proxy CIDRs before startup.
- Operator docs now show direct-exposure, Nginx/ingress, and managed-edge guidance for selecting trusted proxy CIDRs.

Acceptance criteria:

- Operators can configure real client IP extraction without opening spoofing risks.

### 5.3 Backend SSRF Guard Deployment Decision

Status: Pass for current P0 scope

Risk:

- The proxy blocks private/reserved backend targets by default. This is strong SSRF defense but conflicts with common production deployments where upstreams are private services.

Implemented:

- Added top-level `allowed_upstream_cidrs`, plus `GWAF_ALLOWED_UPSTREAM_CIDRS`, to allow only specified private/reserved upstream ranges through explicit opt-in.
- Added top-level `allow_private_upstreams`, plus `GWAF_ALLOW_PRIVATE_UPSTREAMS`, for deployments that intentionally trust every configured private upstream target.
- Proxy target creation, connection-time dial validation, and health-check transports all enforce the configured allowlist before permitting private/reserved upstream addresses.
- Runtime proxy assembly binds backend SSRF policy to the target/router generation instead of mutating package-global proxy state.
- Production deployment guidance now shows the narrow CIDR allowlist first.
- Keep secure-by-default behavior for externally supplied URLs.

Remaining work:

- Consider whether per-upstream `allow_private` is worth the additional schema complexity for multi-tenant deployments.

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
- Public API examples no longer use `secret123` or hard-coded `X-API-Key: secret` dashboard credentials; `internal/config` tests require `docs/api-examples.md` to demonstrate `GWAF_DASHBOARD_API_KEY`.
- `logging.log_body=true` now produces an explicit warning, configuration docs call out the credentials/PII risk, and access-log regression coverage proves request bodies are not emitted by the current structured log schema.

Required work:

- Continue auditing non-event/non-trace log paths for:
  - additional third-party integration keys,
  - legacy config examples that still show weak placeholder secrets.
- Continue checking future access-log schema changes against the body logging warning and no-body-emission regression tests.

Acceptance criteria:

- Secret redaction has regression tests for event creation and dashboard API rendering.
- Dangerous logging options require explicit opt-in and docs warnings.

### 5.5 Outbound Network SSRF

Status: Pass for the current implemented runtime scope

Outbound integrations include:

- AI model catalog fetch,
- AI provider calls,
- webhook delivery,
- ACME,
- NVD/virtual patch feeds,
- threat intelligence feeds,
- Docker remote clients,
- GeoIP auto-download.
- planned cluster sync peer replication.
- OCSP responders from certificate AIA data.
- hCaptcha and Cloudflare Turnstile verification endpoints.
- planned replay targets and canary health-check endpoints.
- planned SIEM exporter endpoints, proxy upstream health checks, and Docker Unix-socket polling.
- API security JWKS endpoints and planned legacy cluster coordination endpoints.

Future integration requirements:

- Standardize outbound URL validation and dialers.
- Define which integrations may contact private networks and how that is configured.
- Add timeouts, response-size limits, and redirect policies for every outbound HTTP client.

Progress:

- AI provider endpoints, AI catalog fetches, webhooks, GeoIP downloads, threat-intel feeds, dashboard-managed webhook URLs, dashboard-managed AI URLs, and API security JWKS fetches already have SSRF validation coverage.
- Webhook delivery now validates redirect targets, keeps connection-time SSRF protection, and uses explicit dial/TLS/response-header/expect-continue timeouts.
- Virtual patch NVD client now has both preflight URL validation and connection-time SSRF protection, redirect target validation, and oversized response rejection before parsing.
- AI catalog fetches now reject non-HTTP(S), hostless, credential-bearing, private, loopback, link-local, unspecified, multicast, localhost, `.internal`, and `.local` operator URLs before request creation; keep redirect target validation and connection-time SSRF protection; use explicit dial/TLS/response-header timeouts; and reject oversized catalog responses before parsing.
- GeoIP downloads now reject non-HTTP(S), hostless, credential-bearing, private, loopback, link-local, unspecified, multicast, localhost, `.internal`, and `.local` operator URLs before request creation, validate redirect targets, use connection-time SSRF protection, set explicit dial/TLS/response-header timeouts, and reject oversized plain or decompressed downloads before writing the final cache file.
- AI provider calls now reject non-HTTP(S), hostless, credential-bearing, private, loopback, link-local, unspecified, multicast, localhost, `.internal`, and `.local` operator URLs before provider configs are activated; validate redirect targets; keep connection-time SSRF protection; enforce TLS 1.2+; use explicit TLS/response-header/expect-continue timeouts; and reject oversized provider responses before parsing.
- API security JWKS fetches now reject non-HTTP(S), hostless, credential-bearing, private, loopback, link-local, unspecified, multicast, localhost, `.internal`, `.local`, and `.localhost` operator URLs before request creation; keep redirect target validation and connection-time SSRF protection; use explicit dial/TLS/response-header timeouts; and reject oversized responses before caching keys.
- Threat-intel URL feeds now reject non-HTTP(S), hostless, credential-bearing, private, loopback, link-local, unspecified, multicast, localhost, `.internal`, and `.local` operator URLs before request creation; keep redirect target validation and connection-time SSRF protection; use explicit dial/TLS/response-header timeouts; and reject oversized responses before updating entries.
- OCSP responder lookups now use an explicit transport with dial-time private/loopback/link-local address rejection, dial/TLS/response-header timeouts, oversized response rejection before parsing/stapling/caching, and no redirects from certificate-provided responder URLs.
- hCaptcha and Turnstile verification clients now use explicit dial/TLS/response-header timeouts, do not follow redirects away from the fixed public verification endpoints, and reject oversized verification responses before JSON parsing.
- ACME directory, nonce, order, authorization, challenge, finalize, and certificate-fetch calls now use an explicit transport with dial/TLS/response-header timeouts, do not follow redirects away from the configured CA endpoints, and reject oversized responses before parsing or certificate caching.
- ACME server-provided endpoints are confined to the configured directory's exact scheme/host/effective-port origin and reject credentials, fragments, relative URLs, scheme downgrades, and cross-origin pivots before any request is sent.
- Proxy upstream health checks now use explicit dial/TLS/response-header timeouts and do not follow redirects away from the configured health endpoint.
- Docker Unix-socket HTTP polling now uses explicit response-header, expect-continue, idle, and whole-request timeouts.
- `go test ./internal/layers/virtualpatch` and `go test -race ./internal/layers/virtualpatch` pass with new NVD SSRF regression coverage.
- `go test ./internal/tls` and `go test -race ./internal/tls` pass with OCSP redirect and timeout regression coverage.
- `go test ./internal/layers/botdetect/challenge` and `go test -race ./internal/layers/botdetect/challenge` pass with CAPTCHA verification redirect and timeout regression coverage.
- `go test ./internal/acme` and `go test -race ./internal/acme` pass with ACME redirect and timeout regression coverage.
- `go test ./internal/ai ./internal/geoip` and `go test -race ./internal/ai ./internal/geoip` pass with catalog/GeoIP redirect, dial-time SSRF, and timeout regression coverage.
- `go test ./internal/proxy ./internal/docker` and `go test -race ./internal/proxy ./internal/docker` pass with proxy/Docker transport regression coverage.
- `go test ./internal/ai ./internal/layers/apisecurity ./internal/layers/threatintel` and `go test -race ./internal/ai ./internal/layers/apisecurity ./internal/layers/threatintel` pass with provider/JWKS/threat-intel transport regression coverage.
- `go test ./internal/alerting` and `go test -race ./internal/alerting` pass with webhook redirect/transport regression coverage.
- Added `docs/outbound-network-policy.md` with an integration-by-integration private-network, redirect, timeout, and response-size policy matrix, linked it from README, and added a static regression guard that prevents production code from reintroducing `http.Get`, `http.Post`, `http.Head`, or `http.DefaultClient` convenience clients.
- Added an AST-based static regression guard that requires every production `http.Client` literal to declare `Timeout`, `Transport`, and `CheckRedirect`; Docker Unix-socket polling now refuses redirects explicitly with `http.ErrUseLastResponse`.
- Blocking CI G704 scope now covers ACME, AI, alerting, GeoIP, proxy, TLS/OCSP, API security, CAPTCHA verification, threat intelligence, virtual patching, and the CLI; the current 64-file targeted scan reports zero findings.
- Current-tree accuracy note: `internal/cluster`, `internal/clustersync`, `internal/layers/siem`, `internal/layers/replay`, `internal/layers/canary`, `internal/layers/cache`, and `internal/http3` runtime packages are not present. Their outbound policies are future implementation requirements, not completed runtime evidence.

Acceptance criteria:

- Each outbound integration has an explicit SSRF policy.
- Tests cover private/loopback rejection where required.

## 6. P0: Runtime Reliability

### 6.1 Graceful Shutdown

Status: Pass for the current implemented runtime scope

Implemented shutdown contract:

- Ensure shutdown drains:
  - HTTP server,
  - TLS server,
  - HTTP/3 server once a concrete HTTP/3 runtime exists,
  - Docker watcher,
  - AI analyzer,
  - dashboard cleanup loops,
  - tenant alert dispatch and cluster broadcast,
  - alert manager background sends,
  - file event store,
  - IP ACL auto-ban persistence,
  - SIEM exporter once a concrete exporter runtime exists,
  - cluster sync once a concrete sync runtime exists,
  - ACME renewal.
- Add integration tests for shutdown under active traffic.

Progress:

- Main serve and sidecar shutdown now stop proxy health checkers.
- Dashboard-triggered proxy rebuilds and Docker discovery rebuilds now stop the replaced health checkers after atomically swapping the active handler.
- `HealthChecker.Stop` now cancels in-flight HTTP probes before waiting for the worker goroutine, and serve/sidecar shutdown use `StopWithContext` so health checker drain cannot exceed the graceful-shutdown budget.
- Docker watcher shutdown now uses the shared shutdown context instead of waiting unbounded on Docker event-stream or poll fallback teardown.
- ACME certificate renewal shutdown now uses the shared shutdown context instead of waiting unbounded on renewal work.
- TLS certificate hot-reload shutdown now uses the shared shutdown context instead of waiting unbounded on reload work.
- GeoIP auto-refresh loops created for custom-rule GeoIP enrichment or dashboard GeoIP lookup are now tracked by runtime layer resources and stopped with the shared shutdown context in serve, sidecar, and check command paths.
- Alerting manager now drains asynchronous webhook/email sends with a context-bound close, rejects new dispatches after close, closes idle HTTP connections, and has regression coverage for wait, timeout, and post-close dispatch behavior.
- Dashboard login/API/session cleanup loops now drain with the shared shutdown context instead of only receiving stop-channel signals.
- Tenant alert dispatch and cluster broadcast goroutines now drain with the shared shutdown context through tenant manager shutdown, and new cluster broadcasts are rejected after close begins.
- AI analyzer shutdown now uses the shared shutdown context and logs timeout instead of blocking process teardown past the graceful-drain budget.
- Threat-intel feed refresh shutdown now cancels in-flight URL loads and uses the shared shutdown context instead of waiting unbounded on refresh work.
- Virtual patch auto-update shutdown now cancels in-flight NVD searches and uses the shared shutdown context instead of waiting unbounded on CVE feed work.
- IP ACL auto-ban persistence shutdown now closes the persistence loop, waits with the shared shutdown context, flushes active bans, and is called from both serve and sidecar teardown.
- Serve-mode event-bus consumers for alerting and dashboard SSE are tracked with a `WaitGroup`; shutdown closes the engine/event bus and waits for those forwarding goroutines with the shared shutdown context.
- Serve-mode and sidecar-mode periodic cleanup are tracked with a `WaitGroup`, drained before engine close, and signal notifications are stopped when serve/sidecar commands return.
- Sidecar shutdown now uses the shared lifecycle helper to stop health checkers, close proxy target transports, stop periodic cleanup, and close the engine in order, with direct regression coverage.
- Serve-mode shutdown now stops the ACME certificate renewal loop and TLS certificate hot-reload watcher with the shared shutdown context, with default and HTTP/3 build-tag regression coverage.
- Serve and sidecar command-level tests now hold active proxied requests open, send SIGTERM, verify the in-flight requests complete successfully, and verify the commands return.
- Serve and sidecar shutdown now aggregate listener, watcher, analyzer, alerting, dashboard, tenant, GeoIP, cleanup, event-consumer, and engine/event-store errors; durable close failures produce a non-zero process exit and are covered in both default and HTTP/3-tagged builds.
- `go test ./internal/proxy ./cmd/guardianwaf`, `go test -race ./internal/proxy ./cmd/guardianwaf`, `go test -tags http3 ./cmd/guardianwaf`, and `go test ./cmd/guardianwaf` pass with the lifecycle changes.
- Current-tree accuracy note: the `http3` build tag currently proves mirrored CLI build/test compatibility only; no QUIC/HTTP/3 listener package exists to drain. SIEM exporter and cluster sync shutdown remain future requirements because those runtime packages are not present.

Acceptance criteria:

- No goroutine/resource leaks in shutdown tests.
- Event stores flush before process exit.

### 6.2 Runtime Reload Safety

Status: Pass for the current supported hot-reload scope

Implemented reload contract:

- Define exactly what is hot-reloadable.
- Rebuild pipeline atomically when layer-affecting config changes.
- Rebuild proxy router safely when upstream/route config changes.
- Add tests for config reload during concurrent traffic.

Progress:

- Dashboard, Docker discovery, and serve shutdown paths now stop old health checkers and close target transports when the proxy handler/router is replaced or torn down.
- Proxy routers now expose a close path that deduplicates balancers/targets across default routes and virtual hosts, with regression coverage for route reload and shutdown cleanup.
- `docs/runtime-reload.md` now defines the supported hot-reload set, API semantics, restart-required config classes, and the fact that serve/sidecar do not currently install a SIGHUP reload handler.
- Dashboard config updates now reject WAF layer topology or layer-instance configuration changes with `409 Conflict` instead of accepting config that the active pipeline cannot apply without a restart.
- `internal/engine` now has a reload-during-concurrent-traffic regression test that exercises repeated `Reload()` calls while requests are in flight.
- `Engine.Config()` now returns defensive snapshots, preventing dashboard or runtime callers from mutating the live engine config without going through `Reload()`.
- Dashboard routing rebuilds now read `eng.Config()` after `engine.Reload()` and have command-package regression coverage showing old in-flight requests complete while new requests use the rebuilt route.
- Dashboard routing updates now build a strict all-or-nothing candidate router, reload the engine, atomically persist the exact config, and only then swap the handler; prepare/reload/persist failures close candidate resources and leave the old runtime active.
- Legacy routing controllers, general config updates, and webhook/email config mutations roll back the engine snapshot on rebuild or persistence failure and return 5xx instead of claiming a non-durable success.
- The resolved default/explicit config path is passed to dashboard persistence, so starting without `-config` no longer loses the actual default path.

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

- FileStore close now cannot close the async writer channel between a closed-state check and a send, runtime `Flush`/`Sync`, rotation, and rotated-file cleanup failures increment the event-store drop counter, close drains queued events, and final `Flush`/`Sync`/`Close` errors are returned instead of hiding durability failures.
- PersistentMemoryStore now serializes JSONL appends against close, preventing file handle races during concurrent request teardown.
- Serve and sidecar runtime assembly now use the persistent JSONL-backed event store when `events.storage: file` is configured, create the parent directory, replay prior events, and fail startup if the file cannot be opened.
- Added `docs/state-persistence.md` with default stateful paths, volume permission guidance, and backup/restore order.
- State persistence guidance now covers GeoIP cache/download state, IP auto-ban persistence, AI/API discovery/analytics/remediation paths, compliance report/audit/archive outputs, and the difference between strict and best-effort local persistence paths.
- Dashboard compliance audit persistence now fails startup when `compliance.audit_trail.persist_path` is configured but cannot be opened, returns durable append failures during report generation, does not advance the in-memory audit chain after failed file appends, closes the audit file during dashboard shutdown, and surfaces close-time `Sync`/`Close` failures instead of hiding them.
- Persistent event JSONL store startup compaction now returns rewrite `Write`/`Sync`/`Close`/`Rename` errors instead of hiding them, shutdown returns file `Sync`/`Close` errors, post-close stores are rejected, and durable append errors are returned instead of accepting failed writes as memory-only success. Regression coverage proves compaction commit failures surface and remove temp files, close-time persistence failures surface to the caller, repeated `Close` remains idempotent, post-close events do not mutate the in-memory ring, and failed durable appends are not exposed through event queries.
- Engine-level event store write failures are counted in `Stats()`, exported as `guardianwaf_event_store_errors_total`, and included in dashboard/MCP stats. Regression coverage proves request/event-bus flow continues while the write-error counter and log entry are emitted.
- Production backup/runbook examples now use the actual file-backed event default path `/var/log/guardianwaf/events.jsonl` and include key `/var/lib/guardianwaf` state directories.
- Docker image, Compose, static Kubernetes manifests, and Helm chart now provide writable `/var/lib/guardianwaf` and `/var/log/guardianwaf` paths for read-only-root deployments; Helm includes optional PVC-backed persistence and validates a production-like file-event-storage render.
- `go test ./cmd/guardianwaf ./internal/events ./internal/compliance`, `go test -race ./cmd/guardianwaf ./internal/events`, `scripts/validate-k8s.sh`, `scripts/validate-helm.sh`, and Docker Compose config validation pass with the event-store persistence and deployment-path changes.

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
- Registry tests now assert the full descriptor inventory, require each descriptor to have exactly one build path, and lock the startup/debug `PipelineSummary` shape to `name`, `runtime_name`, and `order`.
- Command-package tests assert that registry runtime layer names and orders exactly match the engine after `addLayers` runs, catching missing, extra, and order-drift cases between the registry and the existing CLI construction path.

Acceptance criteria:

- Adding a layer requires one registration and tests.
- The effective pipeline can be printed/debugged at startup.

### 7.3 Config Parser Coverage

Status: Partial, improved

Problem:

- The config model has many fields. Parser population must stay aligned with the struct.

Progress:

- Unknown top-level, nested struct, sequence item, and non-dynamic map keys fail validation.
- `PopulateFromNode` now runs a tag-driven fallback after existing hand-written parsing, preserving special manual defaults while loading yaml-tagged fields that did not previously have explicit populate branches.
- Regression coverage now exercises top-level `tenant`, `trusted_proxies`, `tracing`, `features`, `compliance`, `tls.http3`, logging rotation fields, virtual-host WAF overrides, and WAF subsections including custom rules, gRPC, DLP, Zero Trust, SIEM, cache, replay, canary, analytics, cluster sync, cluster config, remediation, WebSocket, and virtual patching.
- Added struct-level expected-value comparisons for major nested WAF subsections: Zero Trust, cache, replay, canary, analytics, cluster sync, remediation, WebSocket, SIEM, and virtual patching.

Required work:

- Keep adding generated or table-driven parser coverage as new nested config sections are introduced.

Acceptance criteria:

- New config fields cannot silently be ignored by YAML loading.

### 7.4 Frontend/Backend API Contract

Status: Partial

Progress:

- Added a dashboard contract test that scans production UI TypeScript sources for `/api/...` endpoint literals and fails when any UI-used path is missing from `docs/openapi.yaml`.
- Expanded the dashboard contract test to compare UI-used HTTP methods against OpenAPI operations, including dynamic path templates assembled in `api.ts`.
- Added core response-shape contract coverage for UI-critical stats, events, upstream health, and log responses, and corrected `/api/v1/events` plus `/api/v1/logs` OpenAPI response schemas to match backend/UI behavior.
- Added the legacy cluster UI compatibility paths (`/api/clusters`, `/api/clusters/{id}`, `/api/nodes`, `/api/sync/stats`, `/api/sync/status`) to OpenAPI so the current UI/backend compatibility surface is documented.
- Added request-body contract coverage for UI operations that send JSON bodies, and documented the missing tenant compatibility, admin tenant regenerate-key, and legacy cluster create/join request bodies in `docs/openapi.yaml`.
- Expanded response-shape contract coverage to tenant/admin tenant and usage endpoints used by the UI, including schema refs for `Tenant`, `AdminTenant`, `AdminTenantDetail`, `TenantUsage`, `ResourceQuota`, and a negative guard that documented tenant schemas must not expose `api_key_hash`.
- Expanded response-shape contract coverage to AI, Docker discovery, and compliance dashboard endpoints, including schemas for provider/model summaries, masked AI config, AI analysis/stats, Docker services/events, compliance controls/reports, audit-chain status, and a negative guard that AI config responses must not document raw `api_key`.
- Expanded response-shape contract coverage to security-operations dashboard endpoints for IP ACLs, temporary bans, GeoIP lookup, and alerting status/webhook/email/test responses, including a negative guard that documented email target responses must not expose SMTP `password`.
- Expanded response-shape contract coverage to config, routing, and SSL dashboard endpoints, including schemas for sanitized config summaries, routing upstream/virtual-host/route responses, SSL certificate status, generic mutation results, and a negative guard that config responses must not document raw `api_key`, `admin_key`, or `password`.
- Expanded response-shape contract coverage to the currently implemented legacy cluster compatibility responses for cluster lists, node lists, sync counters, and sync status, while keeping unimplemented mutation/detail success responses out of the documented contract.
- Expanded response-shape contract coverage to custom rule create/update/delete operations by documenting the `ApiResult` response shape and guard-checking the existing `CustomRule` list schema.
- Expanded response-shape contract coverage to additional dashboard write operations that return `ApiResult`, including IP ACL add/remove, temporary ban add/remove, AI config update, and alerting webhook/email add/delete operations.
- Added a UI-driven `ApiResult` response contract test so any future dashboard client call typed as `request<ApiResult>` must have a matching OpenAPI operation response schema using `ApiResult`.
- Added a UI-driven typed response contract test so any non-void dashboard client `request<T>` call must have a matching OpenAPI 2xx response schema, and aligned legacy cluster detail/create/join client typings with the backend's current no-success-payload behavior.

Required work:

- Generate or maintain OpenAPI for dashboard APIs.
- Type dashboard client models from the API contract where possible.
- Keep expanding semantic field-level response-shape checks as dashboard endpoints evolve beyond the current typed-response/schema presence gate.

Acceptance criteria:

- UI changes cannot silently drift from backend endpoint shape.

## 8. P1: Deployment Readiness

### 8.1 Container Image Hardening

Status: Partial, improved

Progress:

- Runtime and sidecar images now use `alpine:3.23.4`.
- `scripts/supply-chain-smoke.sh` builds the runtime image, generates an SPDX SBOM with Syft, and scans OS packages plus the Go binary with Trivy.
- CI includes a supply-chain smoke job that fails on HIGH/CRITICAL image vulnerabilities.
- Release workflow enables Docker build provenance/SBOM attestations, signs the pushed image digest with cosign keyless signing, scans the released image, and uploads a Syft-generated image SBOM.
- CI workflow actions and installed tool versions are pinned; `internal/config` regression coverage rejects floating `@main`, `@master`, `@latest`, and `version: latest` workflow references.
- Release checklist now documents digest-based image verification, GitHub Actions OIDC signature verification, and provenance/SBOM attestation checks.
- Compose, static Kubernetes, and Helm deployment fixtures now have regression coverage for read-only root filesystem hardening, no privilege escalation, dropped Linux capabilities, non-root UID/GID, read-only config mounts, and writable `/var/lib/guardianwaf` plus `/var/log/guardianwaf` runtime paths.
- `contrib/k8s/deployment.yaml` now sets `runAsGroup: 1000`, matching the Helm chart and example Kubernetes manifests.
- Static Kubernetes manifests and Helm defaults now disable service account token automounting for GuardianWAF pods, with regression coverage to prevent accidental Kubernetes API credentials from being mounted.
- Static Kubernetes manifests now include an ingress NetworkPolicy example, and Helm has an optional rendered NetworkPolicy path covered by production-like chart validation.

Required work:

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
- Added `docs/kubernetes-helm.md` with Secret-backed dashboard/admin key examples, TLS Secret guidance, PVC-backed state examples for `ReadWriteOnce`, `ReadWriteMany`, and existing claims, proxy/dashboard ingress examples, and rollout validation commands.
- Added `internal/config` regression coverage that keeps the Kubernetes/Helm guide linked from README and preserves secret, persistence, ingress, and validation examples.
- Kubernetes/Helm docs now call out the service account token automount default so operators keep Pod credentials disabled unless a future integration explicitly needs Kubernetes API access.
- Kubernetes/Helm docs now include NetworkPolicy guidance for ingress-controller, same-namespace, monitoring, and admin access selectors.

Required work:

- Keep static manifests, Helm values, and the Kubernetes/Helm guide aligned as deployment templates evolve.

Acceptance criteria:

- Static manifest, Helm render schema validation, and KinD proxy/dashboard smoke pass in CI; Istio CRDs are allowed to skip schema validation unless their schemas are installed.

### 8.3 Production Config Profiles

Status: Done for baseline profiles

Completed profiles:

- local development,
- standalone production,
- sidecar production,
- Kubernetes production,
- Docker discovery production,
- dashboard-disabled edge proxy,
- dashboard-enabled admin-only deployment.

Progress:

- Profiles live under `examples/profiles/`.
- `internal/config` fixture tests automatically discover and validate `examples/profiles/*.yaml`.
- `docs/config-profiles.md` maps each profile to its use case, run command, secret contract, persistence expectations, and rollout checklist.
- README and getting-started docs link to the profile runbook.

Remaining work:

- Keep profiles aligned with Helm, Docker Compose, and future production profiles as deployment templates evolve.

Acceptance criteria:

- Each profile validates and has a matching runbook.

## 9. P1: Observability and Operations

### 9.1 Health Semantics

Status: Done for current profiles

Implemented baseline:

- Added `/livez` for process liveness.
- Added `/readyz`, which returns `503` when config/engine/event-store initialization is incomplete, dashboard listener startup failed while dashboard is enabled, configured proxy routing has no active router or active upstreams, or any configured upstream group has zero healthy targets.
- Kept `/healthz` as a backward-compatible liveness-style endpoint.
- Added production probe documentation in `docs/health-probes.md` and updated production/runbook examples to use `/livez` and `/readyz`.
- `/readyz` response JSON now includes machine-readable `reasons`, `dashboard_ready`, `event_store_ready`, `router_ready`, `geoip_ready`, and `geoip_ranges` fields.
- `waf.geoip.require_ready` can make GeoIP a hard readiness dependency for deployment profiles that require location enrichment before serving traffic; config validation rejects `require_ready` unless GeoIP is enabled, and `/readyz` returns `geoip_not_ready` until the engine reports loaded GeoIP data.
- Vhost-only proxy configurations now build a real router instead of falling back to the no-upstream handler.
- Dashboard startup now opens the listener synchronously, so bind failures fail serve startup instead of being hidden in the background goroutine.
- `docs/health-probes.md` now includes a profile-by-profile readiness policy for every shipped config profile, and `internal/config` regression coverage fails if a profile is added without updating the policy.
- `/readyz` now has direct regression coverage for non-upstream hard dependencies: missing engine, missing event store, dashboard listener readiness, and mandatory GeoIP readiness.

Remaining work:

- Keep the profile readiness policy and `/readyz` implementation aligned whenever a future deployment profile makes an additional dependency mandatory.

Acceptance criteria:

- Kubernetes probes can distinguish dead process from temporarily unavailable upstreams.

### 9.2 Metrics Contract

Status: Done for current stable contract

Progress:

- `/metrics` now uses a centralized Prometheus contract list for metric names, HELP text, TYPE, and values.
- Current stable metrics are documented in `docs/metrics.md` with types, cardinality policy, scrape config, and baseline PromQL.
- Exporter regression coverage asserts every contract metric has HELP, TYPE, and value lines.
- Request actions are exported through documented separate bounded counters: `guardianwaf_requests_blocked_total`, `guardianwaf_requests_challenged_total`, `guardianwaf_requests_logged_total`, and `guardianwaf_requests_passed_total`.
- GeoIP readiness and loaded range gauges are exported as `guardianwaf_geoip_ready` and `guardianwaf_geoip_ranges`.
- Request processing latency is now exported as the Prometheus histogram `guardianwaf_request_duration_seconds` with fixed bounded buckets for P95/P99 alerting.
- Per-layer processing latency is now exported as the Prometheus histogram `guardianwaf_layer_duration_seconds` with fixed buckets and bounded active pipeline layer names.
- Upstream route health is now exported as `guardianwaf_upstream_targets_total`, `guardianwaf_upstream_targets_healthy`, `guardianwaf_upstream_active_connections`, and `guardianwaf_upstream_circuit_state` with bounded `upstream`/`state` label policy.
- Event store drops and persistence failures are now exported as `guardianwaf_event_store_dropped_total`.
- Event bus fan-out pressure is now exported as `guardianwaf_event_bus_subscribers`, `guardianwaf_event_bus_published_total`, and `guardianwaf_event_bus_dropped_total`.
- Alert delivery health is now exported as `guardianwaf_alert_manager_sent_total`, `guardianwaf_alert_manager_failed_total`, `guardianwaf_alert_email_sent_total`, `guardianwaf_alert_email_failed_total`, and `guardianwaf_alert_targets_configured` with fixed `type` values.
- Alert dispatch backpressure is now exported as `guardianwaf_alert_manager_dropped_total`.
- Docker discovery status is now exported as `guardianwaf_docker_discovery_enabled`, `guardianwaf_docker_discovery_running`, `guardianwaf_docker_discovered_services`, `guardianwaf_docker_discovery_last_sync_success`, `guardianwaf_docker_discovery_event_stream_connected`, and `guardianwaf_docker_discovery_sync_failures_total`.
- AI provider usage is now exported as `guardianwaf_ai_enabled`, `guardianwaf_ai_tokens_used_total`, `guardianwaf_ai_tokens_used_current`, `guardianwaf_ai_requests_total`, `guardianwaf_ai_requests_current`, `guardianwaf_ai_cost_usd_total`, and `guardianwaf_ai_verdicts_total` with bounded `window` and `action` labels.
- AI pending batch pressure is now exported as `guardianwaf_ai_pending_events`.
- Runbook references now use the exported `guardianwaf_latency_avg_microseconds` gauge instead of a non-existent request-duration metric.

Acceptance criteria:

- Grafana dashboard and Prometheus docs match exported metrics.

### 9.3 Runbooks

Status: Done for baseline incident coverage

Completed runbooks:

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

Progress:

- `docs/runbook.md` includes symptoms, diagnosis commands, resolution steps, and verification guidance for each baseline incident class.
- Runbook examples now use current config schema for detection thresholds and detector multipliers.
- Compliance export guidance includes metrics, events, config snapshot, runtime logs, version/image digest, and evidence retention notes.

Remaining work:

- Keep runbooks synchronized with future metrics, dashboard API, and deployment template changes.

Acceptance criteria:

- Operators have step-by-step actions and verification commands.

## 10. P2: Security Validation and Assurance

### 10.1 Threat Model

Status: Done for baseline, keep current

Completed:

- Added `docs/threat-model.md` covering the edge proxy path, dashboard/admin API, MCP interface, Docker socket/remote Docker, AI provider integrations, tenant isolation, event/log/audit/compliance storage, generated rules/remediation, and release/deployment supply chain.
- Documented trust boundaries, high-risk data flows, STRIDE categories, current mitigations, test evidence, and open assurance work.
- MCP assurance evidence now includes a regression-guarded read-only/mutating classification for all 44 exposed MCP tools and structured audit logs for mutating tool success/error outcomes.
- Linked the threat model from README documentation index.

Remaining work:

- Keep the threat model updated when new listeners, mutating APIs, outbound integrations, generated-rule flows, storage paths, reload classes, or release controls change.

Acceptance criteria:

- Every trust boundary and high-risk data flow is documented.
- Mitigations map to tests or open assurance work.

### 10.2 Detection Quality Program

Status: Partial

Progress:

- Added a detection-layer corpus gate that reads `testdata/attacks/{cmdi,lfi,nosqli,sqli,ssrf,ssti,xss,xxe}.txt` plus generic, CMDi, LFI, NoSQLi, SSRF, and SSTI benign corpora, logs per-detector attack detection rates, and fail-gates attack coverage below 90% per detector.
- The corpus gate tracks benign block-threshold false positives and fails if the combined benign baseline exceeds 6%. Current local combined baseline is 4/211, 1.9%.
- Closed SSRF corpus misses for single-number octal loopback IPs and dangerous non-HTTP URL schemes (`gopher://`, `dict://`, `ftp://`, `ldap://`) with detector-level regression tests.
- Added NoSQLi and SSTI attack corpus files to the shared corpus gate. Current local baseline is 26/26 NoSQLi and 22/23 SSTI samples detected.
- Added `docs/detection-quality.md` with current corpus rates, the local gate command, known bypass coverage, and remaining quality work.
- Added NoSQLi-specific and SSTI-specific benign corpora, expanded the corpus gate to measure context-specific benign false positives, and added a severity-weighted benign false-positive budget.
- Added CMDi, LFI, and SSRF-specific benign corpora, narrowed CMDi `$()` and encoded-newline detection to command-bearing contexts, stopped treating generic Windows drive-letter paths as high-confidence LFI by themselves, and isolated LFI benign samples to query-value context. Current local benign baseline is 3/181 at or above block threshold, 1.7%, with 0.33 average weighted FP score.
- Reduced benign template-placeholder false positives by narrowing XSS template-marker detection to executable/probing template expressions and CMDi backtick detection to shell execution signals, while keeping XSS/CMDi/SSTI attack corpora above the 90% gate.
- Added an application/audit-log benign corpus, wired it into the context-specific detection gate, and narrowed standalone XSS event-handler detection so normal log keys such as `component=` are not treated as inline handlers while null-byte tag evasion remains covered. Current local benign baseline is 4/211 at or above block threshold, 1.9%, with 0.40 average weighted FP score.

Required work:

- Expand benign traffic with more realistic form, search-box, API query-string, documentation-page, and application-log samples split by request context.
- Keep adding regression tests for newly reported bypasses.
- Keep parser/detector fuzz targets in the bounded fuzz smoke suite.

Acceptance criteria:

- Detection changes report measurable impact.

### 10.3 External Security Review

Status: Open, scoped

Required work:

- Commission or perform security review focused on:
  - proxy SSRF,
  - auth/session/CSRF,
  - tenant isolation,
  - outbound integrations,
  - YAML parser,
  - response masking,
  - WebSocket/gRPC/HTTP3 paths.

Progress:

- Added `docs/security-review-scope.md` with review inputs, focus-area checklists, attacker models, finding format, severity definitions, and release exit criteria.
- Linked the security review scope from the README documentation index.
- Release checklist now requires threat-model review, external security review scope completion or explicit risk acceptance, remediation of all HIGH/CRITICAL external review findings before tagging, and an evidence bundle containing digest, SBOM, provenance, signature verification, vulnerability scan, performance, and detection-quality output.

Acceptance criteria:

- Findings are tracked and remediated before stable production release.

## 11. P2: Performance and Scale

### 11.1 Performance Budget

Status: Partial, improved

Progress:

- Added `docs/performance-budget.md` with release budgets by deployment mode, required benchmark scenarios, operational metrics, and a release notes template.
- Extended `scripts/benchmark.sh` to record timestamp, Go version, `GOOS`, `GOARCH`, CPU count, kernel, benchmark pattern, `benchtime`, count, and package set into `benchmark_results.txt`.
- Added named integration benchmarks for large headers, large bodies, gzip bodies, deflate bodies, many routes, many tenants, and high event rate.
- Linked the performance budget from the README documentation index.
- Captured a local focused release-candidate benchmark run with `count=5` across `./tests/integration` and `./internal/tenant`, and recorded the measured environment plus worst average/op rows in `docs/release-performance-evidence.md`.
- Added `scripts/proxy-load-test.sh` for local standalone and sidecar HTTP p95/p99 load evidence against a measured backend baseline, and recorded a local run in `docs/release-performance-evidence.md`.
- `scripts/target-load-evidence.sh` and the strict release evidence verifier now reject duplicate critical target-load metadata, invalid UTC timestamps, generic `TARGET_LABEL` values, non-numeric sample settings, non-HTTP(S), whitespace-bearing, hostless, credential-bearing, or fragment-bearing target URLs, and too-small release-evidence samples before accepting target load evidence, matching the strict verifier minimums (`requests >= 1000`, `concurrency >= 10`, `warmup >= 50`).

Required work:

- Confirm the focused benchmark suite on GitHub-hosted runners.
- Repeat standalone and sidecar proxy load tests in the target deployment environment before stable release tagging.
- Keep `docs/release-performance-evidence.md` updated for each release candidate.

Acceptance criteria:

- Release notes include measured performance and environment.

### 11.2 Backpressure and Limits

Status: Partial, improved

Progress:

- Request body inspection and gzip/deflate inspection are bounded by the configured sanitizer max body size plus one byte for oversize detection, with regression coverage for raw body restoration, decompressed oversize caps, and gzip ratio-abuse fallback to raw capped bytes.
- DLP request scanning now reads at most the configured body limit plus one byte for oversize detection, skips partial DLP decisions on oversized bodies, and restores the full request stream for upstream proxying.
- Tenant management write APIs now use a shared 1 MiB JSON decoder that returns HTTP 413 for oversized bodies and rejects trailing JSON before mutating tenant state.
- Dashboard mutating JSON APIs now share a 1 MiB decoder that returns HTTP 413 for oversized bodies and rejects trailing JSON instead of accepting the first object and ignoring appended payload.
- Dashboard login form parsing now returns HTTP 413 for oversized bodies before authentication comparison or failed-login accounting.
- JavaScript challenge verification now returns HTTP 413 for oversized form bodies before proof-of-work verification or cookie issuance.
- MCP SSE stream and JSON-RPC message handlers now enforce their expected HTTP methods at the handler boundary, and message bodies remain capped at 1 MiB with HTTP 413 regression coverage for oversized requests.
- Event store drops and persistence failures are observable through `guardianwaf_event_store_dropped_total`.
- File event store writes use a fixed 1024-event async channel; channel-full drops are fail-gated by `TestFileStore_ChannelFullDrop` and visible through `guardianwaf_event_store_dropped_total`.
- Event bus fan-out now tracks subscriber count, published events, and dropped deliveries with `guardianwaf_event_bus_subscribers`, `guardianwaf_event_bus_published_total`, and `guardianwaf_event_bus_dropped_total`.
- Event bus subscribers are now capped at 1024 by default, cap and post-close rejected subscriptions are counted with `guardianwaf_event_bus_rejected_subscriptions_total`, and `guardianwaf_event_bus_max_subscribers` exposes the active cap.
- Alert dispatch now reports semaphore backpressure drops separately through `guardianwaf_alert_manager_dropped_total`; the fixed dispatch concurrency cap is exposed as `guardianwaf_alert_manager_max_dispatch` and covered by manager stats regression tests.
- AI analyzer pending batch depth is observable through `guardianwaf_ai_pending_events`.
- AI analysis `batch_size` is now validated to 1-1000 and the analyzer defensively clamps direct construction to 1000, bounding pending AI batch memory.
- Client-side browser report and CSP report ingestion now rejects request bodies over 1 MiB with HTTP 413 before JSON/raw report storage, with regression coverage for both endpoints.
- Rate-limit stale bucket and rule-removal cleanup now releases bucket capacity, with regression coverage for the hard-cap counter.
- ATO attempt tracking now bounds top-level maps, per-IP email sets, per-email IP sets, password source-IP sets, and block-list record creation under `maxEntries`.
- Tenant manager tenant/domain maps, tenant rate tracker slots, and tenant rate-limiter cleanup now have explicit boundedness regression coverage.
- The operator-facing bounded overload contract is documented in `docs/performance-budget.md` and linked to runbook diagnosis for event store, event bus, alert, and AI pressure signals.
- Local release-candidate benchmark evidence records bounded overload observations and the metrics operators should watch during pressure.

Required work:

- Validate bounded overload observations during external proxy load testing.

Acceptance criteria:

- Overload behavior is predictable and observable.

## 12. P3: Developer Experience

### 12.1 Single Developer Command

Status: Done for baseline source workflow

Completed:

- Added `scripts/dev.sh` with options for `--demo`, `--smoke`, `--skip-dashboard`, and `--skip-tests`.
- The default command:
  - verifies tools,
  - installs dashboard dependencies,
  - builds dashboard assets,
  - runs Go tests,
  - builds the local `dist/guardianwaf-dev` binary.
- `./scripts/dev.sh --demo` starts a temporary local backend and GuardianWAF with a local dashboard.
- README and getting-started docs now show `./scripts/dev.sh` as the source-development path and reserve `./scripts/build.sh` for release-style multi-platform artifacts.

Remaining work:

- Keep `scripts/dev.sh` aligned with the production build contract as release gates evolve.

Acceptance criteria:

- A new contributor can get to a working local instance with one documented command.

### 12.2 Documentation Consistency

Status: Partial

Required work:

- Keep README, docs, config examples, Helm examples, Docker examples, and generated API docs aligned as code paths change.
- Clearly label experimental features.
- Keep distinguishing the default build from the `http3` compatibility build until a concrete QUIC runtime lands.

Progress:

- HTTP/3 docs now consistently label current support as build-tag/config compatibility only. Threat model, gRPC ADR, and MCP docs no longer imply a production QUIC listener.
- Planned-layer ADRs now consistently label missing gRPC, cache, WebSocket, canary, and replay packages as future runtime work.
- Website GuardianWAF YAML examples are now parsed and validated by config fixture tests, and the website snippets were updated from legacy `server`/top-level layer keys to the current `listen`, `upstreams`, `routes`, and `waf.*` schema.
- Website runtime examples now use the current `GWAF_*` environment prefix and valid `serve`/`sidecar` CLI flag split, with regression coverage rejecting stale `GUARDIANWAF_*`, `serve --upstream`, `--block-score`, `--log-score`, and `--dry-run` examples.
- Website Go API examples now match the current public `guardianwaf` package contract (`Engine`, `Middleware`, `Check`, `OnEvent`, `Stats`, and `Close`) with regression coverage rejecting stale `WAF`, `Handler`, `HandlerFunc`, `Analyze`, `BlockScore`, `LogScore`, `DryRun`, and design-era mode/type names.
- Tuning and state-persistence guide YAML examples are now marker-gated and parsed by config fixture tests; an invalid inline-commented whitelist example was corrected to schema-valid YAML.
- Runbook remediation YAML examples are now marker-gated and parsed by config fixture tests; the upstream health-check example now includes a deployable target so validation covers the complete upstream shape.
- `docs/ARCHITECTURE.md`, `docs/detection-engine.md`, and `docs/market-comparison.md` now distinguish the current registered runtime pipeline from planned protocol/layer work. Regression coverage rejects stale claims that planned gRPC inspection, WebSocket frame-security, HTTP/3/QUIC, canary, replay, or old six-detector wording are current production runtime behavior.
- Detection-quality docs are now regression-guarded: README must link `docs/detection-quality.md`, the guide must describe the executable corpus gate and measured baseline, and the application-log benign corpus must remain wired into `TestDetectionLayer_CorpusQualityBaseline`.

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
  - Current implementation: `scripts/release-rollback-smoke.sh <candidate-binary> <previous-release-binary>` first creates state with the previous binary, then boots the candidate against the same config and file-backed event state.
- Rollback test.
  - Current implementation: the same script stops the candidate and verifies the previous rollback binary can boot the unchanged config and file-backed event state again.
- Production config examples validated.
- Security checklist signed off.
  - Current implementation: `docs/release-checklist.md` requires threat-model review, external security review scope sign-off or explicit risk acceptance, HIGH/CRITICAL finding remediation, detection-quality corpus gate evidence, detector-delta release notes, and a release evidence bundle.

## 14. Immediate Next Actions

Recommended order:

1. Run the updated CI workflow on GitHub and fix any hosted-runner-only failures.
2. Expand fixture coverage across any remaining GuardianWAF-specific YAML examples.
3. Continue splitting CLI runtime assembly out of the very large `main*.go` files; event-store, engine bootstrap, event consumers, dashboard startup, dashboard proxy controls, dashboard rules wiring, dashboard adapters, tenant runtime setup, Docker runtime setup, AI runtime setup, alerting runtime setup, cleanup runtime setup, serve lifecycle startup/shutdown, MCP startup, MCP adapter methods, layer, proxy helper, probe assembly, observability setup, client-side report endpoints, challenge setup, HTTP handler selection, server timeout construction, TLS assembly, ACME/GeoIP/rule/network helpers, generated dashboard password helpers, and upstream summary helpers are already shared in small untagged files under `cmd/guardianwaf/`.
4. Keep expanding readiness checks when future profiles make additional non-upstream dependencies mandatory.
5. Confirm full-repository race/nightly CI behavior on GitHub-hosted runners.
6. Confirm release SBOM/provenance and image scan behavior on GitHub-hosted runners.
7. Add QUIC client E2E coverage before documenting HTTP/3 as production supported.

## 15. Production Readiness Verdict

Current state after this pass:

- The project can pass the main local Go test baseline from a checkout that includes `internal/dashboard/dist/placeholder.txt`; production binaries and UI/E2E flows still require dashboard assets generated by `./scripts/build-dashboard.sh` or `./scripts/build.sh`.
- There were real correctness and build hygiene issues, and the immediate safe ones were fixed.
- The project should not yet be marketed as fully production ready until the remaining release evidence is complete, especially hosted CI proof for the exact commit, an independent external review or explicit risk acceptance, hosted-runner confirmation for release supply-chain attestations, target-environment load evidence, and QUIC/HTTP/3 E2E coverage if that feature is claimed as production-supported.
