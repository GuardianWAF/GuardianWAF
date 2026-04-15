# ADR 0031: CORS Validation Layer

**Date:** 2026-04-15
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

Cross-Origin Resource Sharing (CORS) is a browser security mechanism that restricts which origins can make cross-site requests to an API. Misconfigured CORS policies are a common vulnerability:

- `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` is forbidden by browsers but occasionally misconfigured at the application level
- Overly broad origin allowlists (`*.example.com` accepting `evil-example.com`) due to poor regex escaping
- Missing `Vary: Origin` causes CDNs to serve wrong CORS headers to different clients

GuardianWAF sits in front of the backend and can enforce a correct CORS policy centrally, preventing misconfigurations at the application layer from becoming exploitable.

## Decision

Implement a CORS validation layer (`internal/layers/cors/`, Order 150) that:

1. Validates `Origin` headers against a configurable allowlist (exact match + wildcard)
2. Handles preflight (`OPTIONS`) requests with configurable response headers
3. Caches preflight responses to reduce backend load
4. Enforces `strict_mode` which blocks requests with disallowed origins (vs. just stripping headers)

### Origin Matching

Two strategies are used:

**Exact match** — the `Origin` header is looked up in a `map[string]bool`. O(1) per lookup.

**Wildcard match** — patterns like `https://*.example.com` are compiled to `*regexp.Regexp` at startup:

```
Pattern:  https://*.example.com
Regex:    ^https://[^.]+\.example\.com$
```

The regex uses `[^.]+` (not `.*`) for the wildcard to prevent `https://evil.example.com.attacker.com` from matching `https://*.example.com`. This is a deliberate security tightening over naive glob-to-regex conversion.

### Preflight Handling

`OPTIONS` requests with an `Access-Control-Request-Method` header are preflight checks. The layer short-circuits these before they reach the backend, responding with the configured CORS headers:

```
Access-Control-Allow-Origin: <matched-origin>
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Max-Age: 600
Vary: Origin
```

`Vary: Origin` is always added to prevent CDN cache poisoning — a cached CORS response for origin A must not be served to origin B.

Preflight results are cached per origin for `preflight_cache_seconds` duration (default: 600s). Cache hits are served with a header `X-CORS-Cache: hit`.

### Strict Mode

| Mode | Behaviour on disallowed origin |
|------|-------------------------------|
| `strict_mode: false` (default) | Strip CORS response headers; let backend decide |
| `strict_mode: true` | Return HTTP 403 immediately; backend never sees the request |

Strict mode is recommended for APIs that serve sensitive data where cross-origin access must be absolutely prevented.

### Configuration

```yaml
cors:
  enabled: true
  allow_origins:
    - "https://app.example.com"
    - "https://*.example.com"
    - "http://localhost:3000"      # Development only — remove in production
  allow_methods: [GET, POST, PUT, DELETE, PATCH, OPTIONS]
  allow_headers: [Content-Type, Authorization, X-Request-ID]
  expose_headers: [X-Request-ID, X-RateLimit-Remaining]
  allow_credentials: false
  max_age_seconds: 600
  preflight_cache_seconds: 600
  strict_mode: false
```

### Interaction with `allow_credentials`

When `allow_credentials: true`, the layer enforces that the response `Access-Control-Allow-Origin` is never the wildcard `*` (browsers reject this combination). If the operator sets `allow_origins: ["*"]` and `allow_credentials: true` simultaneously, the layer logs a warning at startup and overrides `allow_credentials` to `false`.

## Consequences

### Positive
- Centralised CORS policy prevents backend misconfigurations from being exploitable
- Wildcard regex uses `[^.]+` (not `.*`), closing the common subdomain-confusion bypass
- Preflight caching reduces backend `OPTIONS` request volume significantly on high-traffic APIs
- `strict_mode` provides hard enforcement for sensitive APIs

### Negative
- The CORS layer adds a response-phase header-write on every request — minimal overhead (~1µs) but non-zero
- Preflight cache is in-process only; in a cluster, each node has its own cache (consistent results, just no sharing — acceptable)
- Wildcard patterns are limited to subdomain substitution (`*.example.com`); path-level wildcards (`https://example.com/*`) are not supported and must be expressed as exact matches or custom regex patterns

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/layers/cors/cors.go` | Origin validation, preflight handling, header injection |
| `internal/config/config.go` | `CORSConfig` struct |

## References

- [RFC 6454: The Web Origin Concept](https://datatracker.ietf.org/doc/html/rfc6454)
- [Fetch Standard: CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol)
- [OWASP CORS Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html)
- [PortSwigger: CORS vulnerabilities](https://portswigger.net/web-security/cors)
