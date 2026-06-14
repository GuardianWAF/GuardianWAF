# GuardianWAF Threat Model

This document records the production threat model for GuardianWAF. It focuses on deployed runtime behavior, operator-facing interfaces, and remaining assurance work.

## Scope

In scope:

- Edge proxy request and response path.
- Dashboard, admin APIs, sessions, and REST APIs.
- MCP stdio and SSE interfaces.
- Docker socket and remote Docker discovery.
- AI provider integrations and generated analysis.
- Tenant isolation and tenant-scoped runtime state.
- Event, log, audit, compliance, and replay storage.
- Generated rules, virtual patches, and remediation output.
- Container, Kubernetes, Helm, and release supply-chain controls.

Out of scope:

- Vulnerabilities in protected upstream applications, except where GuardianWAF forwards, rewrites, masks, or stores their traffic.
- Third-party infrastructure such as CDNs, cloud load balancers, container runtimes, Kubernetes control planes, SMTP servers, AI providers, and SIEMs beyond the GuardianWAF integration boundary.
- HTTP/3 production assurance until QUIC E2E coverage is complete.

## Assets

Primary assets:

- Protected backend availability and request integrity.
- Dashboard API keys, admin keys, session cookies, TLS keys, ACME account keys, AI provider keys, webhook credentials, SMTP credentials, and Docker credentials.
- Tenant configuration, tenant isolation rules, and tenant-scoped events.
- Security events, replay samples, audit logs, compliance exports, and runtime logs.
- Dynamic routing configuration, Docker-discovered upstreams, generated rules, remediation output, and virtual patches.
- Container image provenance, SBOM, signatures, release artifacts, and deployment manifests.

## Trust Boundaries

| Boundary | Trusted side | Untrusted or less-trusted side | Main risk |
|---|---|---|---|
| Public ingress to proxy | GuardianWAF listener and configured trusted proxies | Internet clients, bots, spoofed headers | Request smuggling, bypass, spoofed client identity, resource exhaustion |
| Proxy to upstream | Configured backend targets | Backend network, DNS, service discovery results | SSRF, lateral movement, confused routing, stale health state |
| Dashboard/API | Authenticated operator session/API key | Browser, network clients, CSRF-capable origins | Unauthorized config changes, credential leakage, privilege escalation |
| Tenant admin APIs | System admin key holder | Tenant-scoped users and compromised API keys | Cross-tenant reads/writes |
| MCP SSE | Authenticated MCP client | Remote AI tools and network clients | Tool abuse, data exfiltration, unauthorized WAF changes |
| MCP stdio | Local process boundary | Local AI agent and shell environment | Local privilege misuse, secret exposure through prompts |
| Docker discovery | Docker daemon/API and labeled containers | Container labels, Docker event stream, remote Docker endpoint | Route injection, socket privilege escalation, stale discovery |
| Outbound integrations | GuardianWAF HTTP clients | AI, webhook, threat intel, SIEM, ACME, GeoIP endpoints | SSRF, credential disclosure, unbounded cost, TLS downgrade |
| Event/log storage | Local filesystem and configured volumes | Request payloads, backend responses, operator downloads | Sensitive data retention, tampering, disk exhaustion |
| Generated rules/remediation | Human-reviewed config path | AI/provider output and learned data | Unsafe rule activation, false positives, policy bypass |
| Release/deployment | CI OIDC identity and pinned workflows | Registry, scanners, base images, runner environment | Unsigned image, vulnerable image, forged provenance |

## High-Risk Data Flows

### Edge Proxy Path

Flow:

1. Client request enters the current HTTP, HTTPS, WebSocket, or gRPC-compatible HTTP/2 paths. HTTP/3/QUIC is not currently a production listener; the `http3` build tag is a compatibility surface until a concrete QUIC runtime and E2E coverage exist.
2. Trusted proxy logic derives client identity.
3. The request is bounded, normalized, inspected, scored, and optionally challenged or blocked.
4. Allowed traffic is routed to a configured upstream target.
5. Response processing can apply headers, masking, and event generation.

Threats:

- Spoofed `X-Forwarded-For` or equivalent headers if trusted proxies are too broad.
- Parser differentials between GuardianWAF, reverse proxies, and upstreams.
- Decompression or request body memory exhaustion.
- SSRF through configured or dynamically discovered upstreams.
- WebSocket and gRPC bypass if protocol paths drift from HTTP coverage; future HTTP/3/QUIC support must receive the same coverage before a production support claim.
- Block/challenge false positives causing availability impact.

Mitigations and evidence:

- Trusted proxy configuration is explicit and covered by config validation and docs.
- Request body inspection is bounded by config limits.
- Sanitizer and detector fuzz smoke coverage runs through `scripts/fuzz-smoke.sh`.
- Backend private/reserved targets are denied by default, with explicit `allowed_upstream_cidrs` and `allow_private_upstreams` opt-in.
- Proxy target creation and dial-time validation enforce upstream CIDR policy.
- Runtime reload rejects WAF layer topology changes that cannot be safely hot-applied.
- Open assurance: add QUIC client E2E before documenting HTTP/3 as production supported.

### Dashboard and Admin API

Flow:

1. Operator authenticates with API key or dashboard session.
2. Dashboard APIs read stats, events, routes, tenants, Docker state, AI state, rules, and config.
3. Hot-safe config updates call runtime reload; unsafe topology changes require restart.
4. Tenant admin APIs require a separate admin key.

Threats:

- Weak or reused API/admin keys.
- Session theft or CSRF from a browser context.
- Unauthorized tenant-admin use.
- Config injection that changes protection semantics without restart.
- API/UI contract drift causing operators to believe a change was applied when it was ignored.

Mitigations and evidence:

- Validation rejects explicitly configured short/common dashboard API and admin keys.
- Empty dashboard API keys generate strong random startup keys; empty admin key disables tenant-admin APIs.
- Query-string MCP/API keys are rejected for MCP SSE.
- Dashboard config handlers reject restart-required WAF layer changes with `409 Conflict`.
- OpenAPI/UI contract tests prevent UI-used endpoints from disappearing from docs and now gate UI-used HTTP methods, JSON request bodies, typed JSON 2xx response schemas, `ApiResult` response schemas, and core response-shape fields.

### MCP Interface

Flow:

1. Local tools connect over stdio, or remote tools connect through dashboard SSE and message endpoints.
2. MCP tool calls query or mutate WAF runtime state through typed handlers.
3. Results can include stats, event summaries, rule data, and configuration-derived data.

Threats:

- Remote MCP client performs high-impact WAF changes with stolen dashboard credentials.
- Sensitive event or config data is exfiltrated into AI prompts or tool transcripts.
- Long-lived SSE connections consume resources.
- Tool schema drift allows unexpected arguments or behavior.

Mitigations and evidence:

- SSE transport is protected by the dashboard API key.
- Query-string API keys are rejected to avoid URL and log leakage.
- Deployment modes can disable dashboard/MCP for reduced attack surface.
- MCP tools use structured handlers instead of arbitrary shell execution.
- MCP integration docs classify every exposed tool as read-only or mutating, and regression coverage requires all 44 tool definitions to remain documented in that authorization table.
- Mutating MCP tool calls emit structured audit logs with tool name, success/error outcome, and available transport identity fields (`transport`, `auth_type`, `principal`, and `remote_addr` for SSE API-key calls) while omitting arguments to avoid leaking URLs, credentials, or custom patterns.

### Docker Discovery

Flow:

1. GuardianWAF connects to Docker socket or remote Docker endpoint.
2. It lists labeled containers and consumes Docker events.
3. Labels are converted into upstreams, routes, pools, weights, and health checks.
4. Runtime proxy routing is rebuilt when discovery state changes.

Threats:

- Mounting Docker socket grants broad host/container control if GuardianWAF is compromised.
- Malicious or compromised containers inject labels that route traffic to attacker-controlled services.
- Remote Docker TLS misconfiguration permits event or route manipulation.
- Discovery failures leave stale routes.

Mitigations and evidence:

- Docker discovery is explicit configuration and documented as a privileged integration.
- Docker discovery metrics expose enabled/running state, discovered service count, event-stream health, last sync, and failures.
- Proxy reload cleanup closes old health checkers and transports.
- Deployment docs recommend limiting Docker socket exposure and using label controls.
- Remote `tcp://` Docker endpoints require `tls_verify: true` plus CA/client certificate paths, and config validation rejects unauthenticated TCP Docker daemons.

### AI Provider Integrations

Flow:

1. Events or batches are selected for AI analysis.
2. The AI client sends bounded data and credentials to a configured provider.
3. Verdicts, summaries, generated rules, or remediation text return to GuardianWAF.
4. Operators may review or apply generated output.

Threats:

- Sensitive payloads, headers, tokens, or tenant data leave the deployment.
- Provider outage or quota exhaustion affects operator workflows.
- Prompt injection in event payloads influences generated rules or remediation.
- Generated rules cause bypasses, false positives, or unsafe config changes.
- Unbounded usage creates unexpected cost.

Mitigations and evidence:

- AI provider usage metrics expose enabled state, request/token counters, and estimated cost.
- Events and compliance paths preserve redacted findings instead of raw pipeline data where configured.
- Generated outputs should be treated as recommendations until human-reviewed and validated.
- Runtime config validation and reload guards prevent unsupported hot changes.
- Auto-generated virtual patches start disabled with `review_status=pending_review` and provenance metadata; explicit enable/apply transitions record reviewer/apply actor metadata and emit structured virtual-patch audit logs.

### Tenant Isolation

Flow:

1. Tenant identity is derived from configured host/path/API-key rules.
2. Tenant WAF config and limits are attached to the per-request context.
3. Events, analytics, dashboard views, and admin APIs read tenant-scoped data.

Threats:

- Tenant misclassification from ambiguous host/path rules.
- Cross-tenant event reads through dashboard/API bugs.
- Shared detector/rate-limit state leaks behavior across tenants.
- Admin key compromise enables tenant-wide changes.

Mitigations and evidence:

- Tenant manager and dashboard tenant handlers have regression coverage.
- Tenant WAF config is per-request state, not a mutable shared config pointer.
- Separate dashboard admin key gates tenant-admin APIs.
- Open assurance: add end-to-end tenant isolation tests for event reads, analytics, routing, and MCP tools.

### Event, Log, Audit, and Compliance Storage

Flow:

1. Pipeline and runtime components emit events and audit records.
2. Data is held in memory, appended to JSONL files, or exported for compliance.
3. Operators query, download, back up, or restore evidence.

Threats:

- Sensitive data retention beyond policy.
- Log injection or malformed JSONL breaks downstream ingestion.
- Disk exhaustion or slow storage causes drops or startup failures.
- Audit trail cannot be trusted if writes silently fail.
- Compliance export leaks secrets or unredacted payloads.

Mitigations and evidence:

- File event store serializes appends against close and replays prior events.
- Strict persistence paths fail startup when configured durable audit storage cannot be opened.
- State persistence and runbook docs identify backup/restore paths and evidence retention notes.
- Metrics and runbooks cover event store pressure and drop investigation.
- Compliance audit records are SHA-256 hash chained, `/api/v1/compliance/audit-chain` verifies chain integrity and exposes the current `head_hash`, and the incident export runbook requires storing that head hash in an approved write-once evidence system for later truncation/tamper checks.

### Generated Rules, Virtual Patches, and Remediation

Flow:

1. Rules can come from static config, dynamic APIs, CVE/virtual patching, learned behavior, or AI remediation output.
2. Config validation parses and rejects unsupported schema.
3. Runtime applies hot-safe changes or requires restart for layer topology changes.

Threats:

- Generated or imported rule blocks benign production traffic.
- Rule ordering or scoring changes create bypasses.
- CVE feed or generated patch source is poisoned.
- A tenant-scoped generated rule affects another tenant.

Mitigations and evidence:

- Config schema validation rejects unknown keys in non-dynamic structures.
- Hot reload boundaries are documented and enforced.
- Detection quality program tracks attack and benign corpora as open assurance work.
- Generated virtual patches are staged as disabled pending-review entries with provenance metadata, and applied/disabled transitions are explicit so operators can roll back by disabling the patch while preserving review/apply metadata.

### Release and Deployment Supply Chain

Flow:

1. CI builds binaries and container images.
2. Runtime image is scanned, signed, and published.
3. SBOM/provenance artifacts are uploaded or attached to OCI images.
4. Operators deploy Docker Compose, Kubernetes manifests, or Helm chart.

Threats:

- Compromised base image or scanner drift.
- Unsigned or mutable-tag image is deployed.
- Generated deployment manifests lose non-root/read-only hardening.
- Release artifacts do not match source.

Mitigations and evidence:

- Runtime image uses pinned Alpine and patched Go toolchain versions.
- Supply-chain smoke builds the image, generates SPDX SBOM, fails on HIGH/CRITICAL Trivy findings, and can persist `sbom.spdx.json`, `image-inspect.json`, and `trivy.txt` into the release evidence bundle.
- Release workflow enables Buildx provenance/SBOM, signs image digest with cosign keyless signing, scans released image, and uploads Syft SPDX SBOM.
- Deployment hardening tests cover Compose, static Kubernetes, and Helm defaults for non-root, read-only root filesystem, dropped capabilities, readonly config mounts, and writable state/log paths.
- Open assurance: confirm release SBOM/provenance/signature behavior on GitHub-hosted runners after the next real tag.

## STRIDE Summary

| Category | Highest-risk examples | Primary controls |
|---|---|---|
| Spoofing | Client IP spoofing, stolen dashboard key, forged Docker event source | Trusted proxy config, dashboard key validation, Docker TLS guidance, separate admin key |
| Tampering | Config/rule changes, event log modification, poisoned generated rules | Config validation, reload guards, audit persistence, human review for generated output |
| Repudiation | Missing audit trail for admin/MCP/generated-rule actions | Dashboard audit persistence, compliance export, MCP mutating-tool audit classes, generated virtual-patch transition logs |
| Information disclosure | Event payloads to AI, API keys in URLs/logs, cross-tenant reads | Redaction, query-key rejection, tenant scoping, persistence guidance |
| Denial of service | Request body/decompression pressure, SSE connections, event-store pressure, upstream health churn | Bounded body config, metrics, backpressure roadmap, health-check cleanup |
| Elevation of privilege | Dashboard admin misuse, Docker socket compromise, unsafe dynamic rules | Admin key gate, deployment hardening, Docker privilege warnings, restart-required config classes |

## Assurance Map

| Control area | Current evidence | Remaining work |
|---|---|---|
| Config schema and public examples | `internal/config` fixture and snippet tests | Keep expanding as new deployable examples are added |
| Backend SSRF policy | CIDR allowlist tests and proxy target enforcement | Consider per-upstream private-target policy |
| Runtime reload boundaries | Engine/dashboard reload tests and `docs/runtime-reload.md` | Extend concurrent reload coverage for more config classes |
| Deployment hardening | `internal/config/deployment_hardening_test.go` | Confirm in a live Kubernetes restricted-policy cluster |
| Release supply chain | `internal/config/release_supply_chain_test.go` | Confirm real hosted-runner release artifacts |
| Dashboard API contract | `internal/dashboard/openapi_contract_test.go` | Add method/body/response-shape contract coverage |
| Event/audit persistence | Event store and compliance tests | Add tamper-evident audit trail guidance |
| Detection quality | Detector tests and bounded fuzz smoke | Build measured benign/attack corpus reporting |
| MCP safety | Authenticated SSE and structured tools | Add per-tool authorization/audit matrix |
| HTTP/3/QUIC | Tagged command compatibility tests and planned-runtime docs | Add a concrete QUIC listener plus QUIC client E2E before production support claim |

## Review Triggers

Update this threat model when any of the following changes:

- A new listener, protocol, or proxy path is added.
- Dashboard, admin, MCP, tenant, or Docker APIs gain mutating capabilities.
- A new outbound integration is added.
- Event, audit, replay, compliance, or AI data retention changes.
- Runtime reload supports a new config class.
- Release signing, SBOM, provenance, or deployment hardening changes.
