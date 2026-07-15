# GuardianWAF Security Audit Report

**Revalidated:** 2026-07-10
**Scope:** Current production Go runtime, dashboard UI, build/deployment manifests, and dependency locks
**Method:** Recon → static hunt → tool verification → remediation → regression verification

## Executive Summary

The current revalidation found three actionable issues. All were remediated in the worktree and protected by regression gates:

| ID | Severity | Finding | Status |
|---|---|---|---|
| SEC-2026-07-01 | High | Go 1.26.4 exposed reachable `crypto/tls` code affected by GO-2026-5856 | Fixed by pinning Go 1.26.5 across local, CI, Docker, Compose, sidecar, and prerequisite contracts |
| SEC-2026-07-02 | High | CLI healthcheck accepted a tainted URL and used a general HTTP dial path (G704) | Fixed with local-interface-only URL validation, dial-time DNS revalidation, direct validated-IP dialing, strict `/livez` path policy, redirect refusal, and bounded timeouts |
| SEC-2026-07-03 | Medium | ACME response-provided operation URLs were not confined to the configured directory origin | Fixed with exact scheme/host/effective-port origin binding plus credential, fragment, relative-URL, and scheme-downgrade rejection before requests |

No open Critical or High finding remains from this automated revalidation. This is not a substitute for the independent external review required by `docs/security-review-scope.md` and the release checklist.

## Verification Evidence

- `govulncheck ./...`: no vulnerabilities found with Go 1.26.5.
- Full `gosec -no-fail ./...`: no unsuppressed findings after remediation.
- Fail-gated `gosec` G704 scan covers the CLI and all implemented outbound HTTP integration packages; the current targeted scan checked 64 files / 17,181 lines with zero findings.
- Dashboard `npm audit --audit-level=moderate`: zero vulnerabilities.
- Website `npm audit --audit-level=moderate`: zero vulnerabilities.
- Healthcheck regression tests cover loopback IPv4/IPv6, localhost, non-HTTP schemes, URL credentials, non-local targets, wrong paths, query strings, and dial-time non-local rejection.
- `go test -race ./...`, `go vet ./...`, 100 dashboard unit tests, 531 production-binary browser/API E2E tests across Chromium, Firefox, and WebKit, and CLI smoke passed in the current revalidation.

## Remediation Details

### SEC-2026-07-01 — Reachable standard-library vulnerability

`govulncheck` against Go 1.26.4 reported GO-2026-5856 through reachable TLS call paths. The repository now requires Go 1.26.5 in `go.mod`, source-build prerequisites, CI setup, Docker builders, Compose helper images, and sidecar examples. CI continues to run `govulncheck` as a blocking job.

### SEC-2026-07-02 — Healthcheck outbound request hardening

The `healthcheck --url` override is intentionally limited to the local GuardianWAF liveness endpoint. It now:

- accepts only `http` and `https`;
- rejects credentials, missing hosts, query strings, fragments, and paths other than `/livez`;
- permits only loopback or addresses assigned to a local network interface;
- resolves and validates all addresses again at dial time;
- dials the validated IP directly to prevent DNS-rebinding TOCTOU;
- refuses redirects and bounds DNS validation, connect, TLS, response-header, and whole-request time.

### SEC-2026-07-03 — ACME response-origin confinement

ACME protocol responses contain absolute URLs for nonce, account, order, authorization, challenge, finalize, and certificate operations. Before any such request, GuardianWAF now requires the endpoint to use HTTP(S), contain no credentials or fragment, and match the configured directory's scheme, hostname, and effective port. Redirects remain disabled and the existing response-size and timeout limits remain enforced.

## Residual Assurance Requirements

- Obtain the independent external security review or an explicit, time-bounded risk acceptance before a production release.
- Require passing hosted CI evidence for the exact release commit.
- Require clean image/SBOM/provenance evidence and target-environment load evidence for the exact release candidate.
- Re-run vulnerability and dependency scans at release time; point-in-time results expire as advisories and registries change.

## Historical Reports

The individual `sc-*.md` files in this directory are point-in-time hunt artifacts from earlier scans. Some mention packages that were subsequently removed. This report and `verified-findings.md` are the current consolidated status; historical artifacts must not be interpreted as current architecture or open findings.
