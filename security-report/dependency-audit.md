# Dependency Security Audit

**Project:** GuardianWAF
**Revalidated:** 2026-07-10

## Current Result

| Ecosystem | Production contract | Audit result |
|---|---|---|
| Go runtime | Standard library only; root `go.mod` has no `require` entries | `govulncheck ./...`: no vulnerabilities with Go 1.26.5 |
| Dashboard UI | npm dependencies locked by `internal/dashboard/ui/package-lock.json` | `npm audit --audit-level=moderate`: zero vulnerabilities |
| Website | npm dependencies locked by `website/package-lock.json` | `npm audit --audit-level=moderate`: zero vulnerabilities |

The separate `tools/deepcopy` module is a development tool boundary and is not linked into GuardianWAF runtime binaries.

## Supply-Chain Controls

- Go runtime builds are pinned to the patched Go 1.26.5 toolchain.
- Docker builder and Compose Go images use `golang:1.26.5-alpine`.
- npm production builds use committed lockfiles and `npm ci`.
- GitHub Actions are pinned to commit SHAs.
- CI blocks on `govulncheck`, selected `gosec` rules, secret scanning, HIGH/CRITICAL Trivy results, dashboard audit, tests, and build gates.
- Release evidence requires checksums, SBOM, image digest, signature/provenance verification, and clean vulnerability output.

## Release Policy

Dependency results are point-in-time evidence. Re-run Go, npm, container, and secret scans for the exact release commit and image; do not reuse this report as evidence for a later release candidate.
