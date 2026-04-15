# ADR 0033: Request Sanitizer

**Date:** 2026-04-15
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

Attackers routinely encode payloads to evade signature-based detection:

- `%3Cscript%3E` — URL-encoded `<script>`
- `%252F` — double-encoded `%2F` (path traversal evasion)
- `\u003cscript\u003e` — Unicode-escaped `<script>`
- `&#60;script&#62;` — HTML entity-encoded `<script>`
- `%c0%af` — overlong UTF-8 encoding of `/` (path traversal)
- Mixed-case hex encoding, null byte injection, whitespace normalization

If detection layers receive raw encoded input, a single encoding layer between the payload and the rule pattern evades detection. The sanitizer's job is to produce a **normalized** representation of each request field so that detection layers can apply patterns against a canonical form.

The sanitizer runs at **Order 300**, before CRS (350) and detection (400), and **after** the API security (275) and API validation (280) layers. It writes normalized values to dedicated fields on `RequestContext` rather than mutating the original fields — preserving the raw values for logging and forensics.

## Decision

Implement a request sanitizer (`internal/layers/sanitizer/`) that:

1. **Normalizes** each request field (path, query, body, headers) into a canonical string
2. **Validates** normalized inputs against configurable constraints (max length, allowed chars)
3. Writes results to `ctx.NormalizedPath`, `ctx.NormalizedQuery`, `ctx.NormalizedBody`, `ctx.NormalizedHeaders`
4. Downstream layers read from `Normalized*` fields; raw fields remain unchanged

### Normalization Pipeline

`NormalizeAll(input string) string` applies these transformations in order:

```
1. URL decode         %3C → <
2. Double-decode      %253C → %3C → <
3. HTML entity decode &#60; → <
4. Unicode unescape   \u003c → <
5. Null byte removal  \x00 removal
6. Overlong UTF-8     %c0%af → /  (invalid multi-byte sequences → canonical form)
7. Whitespace collapse  tabs → spaces, strip leading/trailing
8. Case fold          (optional, configurable per field)
9. Path normalize     //foo/../bar → /bar  (for path fields only)
```

Each step produces a string that is fed into the next step. The final output is a single normalized string that collapses multiple encoding layers into the decoded plaintext.

**Performance:** `NormalizeAll` is O(n) in input length. It avoids allocations for inputs with no encoding (fast path: scan for `%`, `&`, `\u`, `\x` — if none found, return input unchanged).

### Validation

After normalization, each field is validated against configurable limits:

| Check | Default | Rationale |
|-------|---------|-----------|
| Max path length | 2048 | Oversized paths are anomalous |
| Max query string length | 4096 | |
| Max body size (already checked) | Per config | Set in `RequestContext.AcquireContext` |
| Max header value length | 8192 | |
| Max header count | 100 | Header flooding |
| Null bytes in path | Block | Always invalid in HTTP paths |
| Non-printable chars in headers | Score | Log anomaly |

Validation failures generate a `Finding` with a configurable score (default: 25) rather than an immediate block, allowing the score to accumulate with findings from other layers before a block decision is made.

### Interaction with Detection Layers

Detection layers (sqli, xss, lfi, etc.) and CRS always read from `ctx.NormalizedPath/Query/Body/Headers`. This guarantees that a SQL injection payload of `%27%20OR%20%271%27%3D%271` is seen by the SQLi detector as `' OR '1'='1` — matching the detection pattern — regardless of how many encoding layers the attacker used.

The raw fields (`ctx.Path`, `ctx.BodyString`) are logged unchanged for forensic purposes, so operators can see the original encoded payload in event records.

### Configuration

```yaml
sanitizer:
  enabled: true
  normalize:
    url_decode: true
    double_decode: true
    html_entity: true
    unicode_unescape: true
    remove_nulls: true
    overlong_utf8: true
    whitespace_collapse: true
    case_fold: false           # Disabled by default (may break case-sensitive apps)
    path_normalize: true

  validate:
    max_path_length: 2048
    max_query_length: 4096
    max_header_value: 8192
    max_header_count: 100
    block_null_bytes: true
    score_non_printable: true
    violation_score: 25        # Score added per validation failure
```

### Per-Tenant Override

Tenants can disable specific normalization steps if their application legitimately requires double-encoded parameters or HTML entities in input (e.g., a CMS that accepts raw HTML). This is done via `TenantWAFConfig.Sanitizer`.

## Consequences

### Positive
- All downstream detection layers automatically benefit from normalization without implementing it themselves
- The fast-path check (scan for encoding markers before allocating) keeps overhead near zero for clean traffic
- Raw fields are preserved — normalization is non-destructive

### Negative
- Aggressive normalization may produce false positives for applications that legitimately use double-encoded URLs (rare but possible with some URL shorteners or legacy systems)
- `case_fold` is disabled by default because case-folding path and query values can break case-sensitive identifiers in some APIs; enabling it for the entire WAF requires coordination with application owners
- Overlong UTF-8 decoding handles the known CVE patterns but does not validate full UTF-8 conformance (the Go `unicode/utf8` package's `Valid()` would be needed for strict mode)

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/layers/sanitizer/normalize.go` | `NormalizeAll` and individual normalization steps |
| `internal/layers/sanitizer/validate.go` | Field validation checks, `Finding` generation |
| `internal/layers/sanitizer/sanitizer.go` | Layer, orchestrates normalize + validate |
| `internal/config/config.go` | `SanitizerConfig` struct |

## References

- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [RFC 3986: URI Encoding](https://datatracker.ietf.org/doc/html/rfc3986)
- [Overlong UTF-8 — CVE-2000-0884](https://nvd.nist.gov/vuln/detail/CVE-2000-0884)
- [ADR 0003: Tokenizer-Based Detection](./0003-tokenizer-based-detection.md)
- [ADR 0032: OWASP CRS Integration](./0032-owasp-crs-integration.md)
