# ADR 0001: Zero External Go Dependencies

**Date:** 2026-04-15
**Status:** Accepted
**Deciders:** GuardianWAF Team

---

## Context

Supply chain attacks on open-source dependencies are a persistent threat to software security. The 2022 Log4Shell vulnerability (CVE-2021-44228) and the 2023 XZ Utils backdoor (CVE-2024-3094) demonstrated that even widely-used, well-maintained dependencies can contain critical vulnerabilities — or worse, be intentionally compromised. For a security product like a WAF, this is unacceptable: the attack surface introduced by dependencies can exceed the attack surface the WAF is meant to protect against.

Beyond security, dependency management creates operational friction: version conflicts when pulling transitive dependencies, breaking changes on upgrade, builds that fail due to a第三方 dependency being unavailable, and the cognitive overhead of auditing code that is not yours.

Go's standard library (`net/http`, `crypto/*`, `text/scanner`, `encoding/*`, etc.) provides the vast majority of what a WAF needs. The remaining functionality (YAML parsing, JWT validation, OWASP CRS rule parsing) was designed to be reimplemented as part of this project.

## Decision

GuardianWAF will use **zero external Go dependencies** in its core codebase. The only exception is `quic-go` for optional HTTP/3 support, enabled via the `-tags http3` build tag.

This means reimplementing from scratch:

1. **YAML configuration parser** — custom Node-tree parser with `${VAR}` substitution and hot-reload support (see ADR 0002)
2. **JWT validation** — RS256, ES256, HS256 signature verification, claim validation (expiry, issuer, audience), key JWKS fetching
3. **OWASP CRS SecLang parser** — native Go parser for ModSecurity's SecLang rule language (see ADR 0032)
4. **HTTP/3 + QUIC** — via `quic-go` (the only permitted external dependency)

No `go.mod` `replace` directives, no vendoring, no `//go:build ignore` blocks pulling in third-party code.

## Consequences

### Positive

- **Near-zero supply chain attack surface** — the only code that runs in GuardianWAF is code written by the team (plus quic-go when HTTP/3 is enabled)
- **Fully auditable** — any engineer can read, review, and understand every line of code; no opaque library behavior
- **Static binary with known contents** — `go build -o guardianwaf` produces a single statically-linked binary with no `.so` files, no dynamic loader resolution, no hidden library dependencies
- **Reproducible builds** — `go build` today produces the same binary as `go build` in two years; no accidental dependency version drift
- **No transitive dependency conflicts** — two dependencies cannot require different versions of the same third-party package
- **Faster builds** — no `go mod download` phase, no checksum validation against the Go module proxy

### Negative

- **More initial development time** — implementing YAML parsing, JWT validation, and CRS parsing from scratch requires significant engineering effort compared to `go get gopkg.in/yaml.v3` or `go get github.com/golang-jwt/jwt/v5`
- **Ongoing maintenance burden** — YAML spec edge cases, new JWT algorithms, updated CRS rule syntax must all be handled by the team rather than relying on community bug fixes
- **No access to ecosystem improvements** — performance optimizations, bug fixes, and new features in third-party libraries require manual reimplementation
- **Code size** — stdlib-based implementations are sometimes more verbose than their dependency-backed equivalents

### Supply Chain Comparison

| Component | External Library (rejected) | GuardianWAF Implementation |
|-----------|---------------------------|---------------------------|
| YAML parsing | `gopkg.in/yaml.v3`, `go.yaml.dev` | `internal/config/yaml.go` (~800 LOC) |
| JWT validation | `golang-jwt/jwt/v5`, `go-jose` | Built into `internal/layers/apisecurity/jwt.go` |
| CRS SecLang | `github.com/frictionlesssecurity/ModSecurity` (C bindings) | `internal/config/config_crs.go` + `internal/layers/crs/parser.go` |
| HTTP/3 | `quic-go/quic-go` | Stub in `internal/http3/` (optional, `-tags http3`) |

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/config/yaml.go` | Custom YAML Node parser, `${VAR}` substitution, Node→struct mapping |
| `internal/layers/apisecurity/jwt.go` | JWT signature verification (RS256/ES256/HS256), JWKS fetching, claim validation |
| `internal/config/config_crs.go` | CRS rule file loading, SecLang rule loading |
| `internal/layers/crs/parser.go` | Native Go SecLang subset parser (actions, variables, operators, phases) |
| `internal/http3/` | HTTP/3/QUIC stub; activates only with `-tags http3` |

## References

- [Go stdlib documentation](https://pkg.go.dev/std)
- [ADR 0002: Custom YAML Parser](./0002-custom-yaml-parser.md)
- [ADR 0032: OWASP CRS Integration](./0032-owasp-crs-integration.md)
- [CVE-2021-44228: Log4Shell](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [CVE-2024-3094: XZ Utils Backdoor](https://nvd.nist.gov/vuln/detail/CVE-2024-3094)
