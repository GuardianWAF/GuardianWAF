# Security Review Scope

This document defines the minimum external security review scope for a stable GuardianWAF production release. It complements the threat model; it does not replace an independent review or penetration test.

## Review Inputs

Reviewers should receive:

- current source tree and release candidate commit,
- `docs/threat-model.md`,
- `docs/outbound-network-policy.md`,
- `docs/runtime-reload.md`,
- `docs/state-persistence.md`,
- `docs/security-best-practices.md`,
- `docs/openapi.yaml`,
- latest local and CI test evidence,
- container image digest, SBOM, provenance, and vulnerability scan evidence for the release candidate.

## Required Focus Areas

### Proxy SSRF and Routing

Review:

- configured upstream URL validation,
- `allowed_upstream_cidrs` and `allow_private_upstreams` behavior,
- dial-time IP enforcement after DNS resolution,
- redirect policy for proxy health checks and outbound clients,
- Docker label and remote Docker route discovery inputs,
- request host/header handling that can influence upstream selection.

Required attacker models:

- public client attempting loopback, link-local, metadata, RFC1918, IPv6 local, and DNS-rebinding targets,
- compromised container controlling Docker labels,
- operator misconfiguration that accidentally broadens private network access.

### Auth, Sessions, and CSRF

Review:

- dashboard API key and admin key validation,
- session cookie flags, expiry, logout, and trusted-proxy TLS detection,
- CSRF exposure for browser-initiated dashboard writes,
- tenant-admin authorization boundaries,
- MCP SSE authentication and rejection of query-string credentials.

Required attacker models:

- stolen tenant key,
- stolen dashboard key without admin key,
- cross-origin browser request against an authenticated dashboard session,
- untrusted reverse proxy header injection.

### Tenant Isolation

Review:

- tenant lookup and domain routing,
- tenant-scoped event, stats, billing, rate-limit, and quota state,
- tenant admin list/get/create/update/delete responses,
- response sanitization for tenant credential fields.

Required attacker models:

- tenant attempting to read another tenant's events or usage,
- admin API consumer receiving stored credential hashes,
- route/domain collision between tenants.

### Outbound Integrations

Review:

- AI provider calls and model catalog fetches,
- webhooks and email delivery,
- ACME, OCSP, GeoIP, NVD, threat-intel, JWKS, Docker remote, and CAPTCHA clients,
- timeout, redirect, TLS, and response-size limits,
- private-network allow/deny policy per integration.

Required attacker models:

- attacker-controlled URL in config or dashboard input,
- redirect to local/private targets,
- oversized or slow responses,
- TLS downgrade or cleartext credential exposure.

### Parser and Detection Inputs

Review:

- YAML parser unknown-key rejection and error paths,
- request normalization and decompression bounds,
- SQLi, XSS, SSRF, XXE, LFI, CMDi, NoSQLi, and SSTI parser edge cases,
- fuzz smoke coverage and corpus gates,
- differential parsing against common upstream servers.

Required attacker models:

- malformed YAML config from operator workflow,
- encoded payloads intended to bypass normalization,
- compression bombs or large bodies,
- payloads that are benign in app context but high scoring in generic context.

### Response Masking and Sensitive Data

Review:

- event evidence redaction,
- log and trace redaction,
- dashboard/API response schemas and OpenAPI contract tests,
- AI, alerting, MCP, compliance, and SSE data paths,
- download/export paths for logs, reports, and audit evidence.

Required attacker models:

- credential in query string, header, cookie, JSON body, referer, or user agent,
- sensitive backend response stored in events or forwarded to AI/alerts,
- operator exporting evidence for a tenant or incident.

### Protocol Compatibility Paths

Review:

- current HTTP/1.1 and HTTP/2 proxy behavior,
- WebSocket and gRPC-compatible paths that ride existing HTTP handling,
- `http3` build-tag compatibility claims and documentation.

Required attacker models:

- protocol upgrade bypassing inspection or logging,
- gRPC/HTTP2 method/path/header normalization mismatch,
- documentation overstating HTTP/3 production support before a QUIC listener exists.

## Findings Format

Use `docs/templates/security-review-report.md` for the final review report, or `docs/templates/security-risk-acceptance.md` when the release owner explicitly accepts a residual review gap or finding. Copy the completed file into the release evidence bundle as `external-security-review/report.md` or `external-security-review/risk-acceptance.md`.

Track each finding with:

- stable ID,
- title,
- affected component,
- severity,
- exploit preconditions,
- proof of concept or reproduction steps,
- expected vs actual behavior,
- remediation owner,
- remediation pull request or commit,
- regression test added,
- reviewer verification status.

Severity should use:

- Critical: unauthenticated remote code execution, credential disclosure, cross-tenant data compromise, or default remote SSRF to private networks.
- High: authenticated privilege escalation, dashboard/admin bypass, persistent protection bypass, or serious secret leakage.
- Medium: bounded data exposure, misconfiguration footgun with clear mitigation, or non-default bypass.
- Low: hardening gap, confusing docs, missing alerting, or defense-in-depth improvement.

## Release Exit Criteria

Before a stable production tag:

- all Critical and High findings are fixed and independently verified,
- Medium findings are fixed or explicitly accepted with compensating controls,
- every fixed finding has a regression test or documented reason a test is not practical,
- accepted residual risks are recorded in release notes,
- the threat model is updated for any new trust boundary or data flow discovered during review.
