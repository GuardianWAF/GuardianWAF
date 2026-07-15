# GuardianWAF Security Architecture

**Revalidated:** 2026-07-10

## Runtime Shape

- `cmd/guardianwaf`: CLI entrypoints for serve, sidecar, check, validate, setup, and local healthcheck.
- `internal/engine`: request context, ordered WAF pipeline, decisions, event creation, logging, and reload boundaries.
- `internal/layers`: active request protections including IP ACL, threat intelligence, CORS, rules, rate limiting, ATO, API security/validation, sanitizer, CRS/detection, virtual patching, DLP, bot detection, client-side protection, and response hardening.
- `internal/proxy`: reverse proxy, routing, load balancing, health checking, circuit breaking, and upstream SSRF policy.
- `internal/dashboard`: authenticated dashboard APIs, sessions, SSE, persistence integrations, and embedded React SPA.
- `internal/tenant`: tenant resolution, admin lifecycle, quotas, persistence, and tenant-scoped policy.
- `internal/ai`, `internal/alerting`, `internal/acme`, `internal/geoip`, `internal/docker`: optional outbound or environment integrations with explicit lifecycle and network policies.

## Trust Boundaries

1. Untrusted inbound HTTP traffic enters the WAF pipeline before reaching configured upstreams.
2. Dashboard operators cross API-key/session authentication; tenant administration uses a separate admin key.
3. Upstream and integration destinations cross SSRF policy, redirect, timeout, and response-size controls.
4. Persisted events, tenant data, AI configuration, certificates, and audit chains cross local filesystem permission and durability boundaries.
5. Docker discovery crosses a privileged daemon boundary and is production-disabled unless explicitly configured with the documented transport controls.

## Primary Security Controls

- Default-deny private/reserved upstream SSRF filtering with explicit instance-scoped allow policy.
- Trusted-proxy CIDR validation and right-to-left forwarded-address selection.
- Constant-time authentication comparisons, signed sessions, CSRF origin checks, strict cookies, and bounded login/session state.
- Request/body/decompression limits, detector scoring, panic recovery, and security response headers.
- Secret redaction before event, dashboard, access-log, and trace exposure.
- Explicit outbound clients with URL validation, dial-time address enforcement where required, redirect policy, deadlines, and response-size bounds.
- Non-root, read-only-root container and restricted Kubernetes deployment profiles.
- File-backed state paths with restrictive creation modes, shutdown flushing, and documented backup/restore order.

## Assurance Boundaries

The current repository contains no concrete QUIC/HTTP/3 listener implementation, cluster-sync runtime, SIEM exporter, replay target, or canary runtime. Build-tag compatibility or historical design documents must not be treated as evidence that those absent runtimes are production supported.
