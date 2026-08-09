# Security Check — Verified Findings

**Project:** GuardianWAF
**Revalidated:** 2026-07-10
**Status:** No open Critical/High finding from the current automated scan

## Current Findings

| ID | Tool evidence | Verification | Resolution |
|---|---|---|---|
| SEC-2026-07-01 | `govulncheck` reported reachable GO-2026-5856 in Go 1.26.4 `crypto/tls` | Call traces reached TLS through proxy, SMTP, GeoIP, and HTTP server paths | Repository and build/deployment toolchains pinned to Go 1.26.5; repeat scan reports no vulnerabilities |
| SEC-2026-07-02 | `gosec` G704 identified tainted input reaching the CLI healthcheck HTTP request | Manual review confirmed the URL override lacked a local-only policy and dial-time address enforcement | Strict local `/livez` validation plus DNS-rebinding-safe dialer; tests and blocking CI G704 scope added |
| SEC-2026-07-03 | Outbound-call inventory found ACME server-provided endpoints were requested without an origin-binding policy | Production starts from a fixed public directory, but nonce/order/authz/challenge/finalize/certificate URLs are response-controlled and could pivot to another origin | Every ACME endpoint is validated as HTTP(S), credential/fragment-free, and same-origin with the configured directory before request creation; regression tests and blocking G704 scope added |

All three findings are closed in the current worktree.

## False-Positive Handling

The healthcheck request retains narrow G704 suppressions only at the request-construction and execution sinks. The suppression is backed by executable controls before and during the connection; it is not used to bypass validation. CI scans the CLI plus ACME, AI, alerting, GeoIP, proxy, TLS/OCSP, JWKS, CAPTCHA, threat-intel, and virtual-patch outbound packages explicitly so moving or weakening guarded flows fails the security job.

## Remaining Assurance Gap

An independent external assessment has not been supplied. That is a release-evidence gap, not proof of a code vulnerability, and remains mandatory under `docs/security-review-scope.md` and `docs/release-checklist.md`.

Point-in-time scanner dumps and superseded finding lists are intentionally
excluded from the repository. Regenerate them for the exact release candidate;
do not treat an older scan as current evidence.
