# ADR 0027: Virtual Patching with NVD Integration

**Date:** 2026-04-15
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

When a CVE is disclosed for a web application framework (e.g., a Struts RCE, a WordPress plugin SQLi, a Log4Shell), the window between disclosure and patch deployment is a period of maximum risk. Organizations that cannot immediately update their backend applications are exposed.

**Virtual patching** bridges this gap: the WAF blocks known exploit patterns for a specific CVE at the network layer, without touching the vulnerable application. This is a standard WAF capability offered by Imperva, F5, AWS WAF (managed rule groups), and CloudFlare.

GuardianWAF's existing detection layers (CRS, detection/sqli, etc.) cover generic attack classes but do not track individual CVEs. A dedicated virtual patching layer provides:
- CVE-specific blocking that is more targeted than generic rules (fewer false positives)
- Automatic updates as new CVEs are published to the NVD
- A clear audit trail linking WAF findings to specific CVE identifiers

## Decision

Implement a virtual patching layer (`internal/layers/virtualpatch/`, Order 450) that:

1. Maintains a **patch database** of CVE → detection pattern mappings
2. **Auto-updates** from the NIST National Vulnerability Database (NVD) API v2
3. **Compiles patterns** to `regexp.Regexp` at load time for zero-allocation matching
4. **Generates patches automatically** for CVEs with known exploit patterns
5. Allows **manual patch overrides** via the dashboard

### Patch Database Structure

Each virtual patch maps a CVE ID to one or more detection patterns:

```go
type VirtualPatch struct {
    CVEID       string     // e.g., "CVE-2021-44228"
    CVSSScore   float64    // CVSS v3 base score
    Severity    string     // critical, high, medium, low
    Description string
    Enabled     bool
    Patterns    []Pattern
    CreatedAt   time.Time
    UpdatedAt   time.Time
    Source      string     // "nvd", "manual", "builtin"
}

type Pattern struct {
    Target   string   // "path", "query", "body", "header:<name>", "any"
    Regex    string   // Raw regex (compiled at load time)
    Score    int      // Score added to ScoreAccumulator on match
    Action   string   // "block" | "log" | "score"
}
```

### Built-in Patches

A curated set of high-severity patches ships embedded in the binary (`data/virtualpatch/builtin.yaml`):

| CVE | Description | CVSS |
|-----|-------------|------|
| CVE-2021-44228 | Log4Shell RCE (JNDI injection) | 10.0 |
| CVE-2022-22965 | Spring4Shell RCE | 9.8 |
| CVE-2021-26855 | ProxyLogon (Exchange SSRF) | 9.8 |
| CVE-2019-0232 | Apache CGI RCE | 8.1 |
| CVE-2017-5638 | Apache Struts RCE | 10.0 |
| CVE-2014-6271 | Shellshock | 10.0 |

Built-in patches are versioned with the GuardianWAF binary and updated in each release. The auto-update mechanism can supplement these with newly published CVEs.

### NVD Auto-Update

A background goroutine polls the NVD API v2 on a configurable schedule:

```
GET https://services.nvd.nist.gov/rest/json/cves/2.0
    ?cvssV3Severity=CRITICAL,HIGH
    &pubStartDate=<last_check>
    &resultsPerPage=100
```

For each new CVE:
1. Check if a pattern can be auto-generated (heuristic: CVE description mentions URL-encoded payload, JNDI, path traversal, shell metacharacters)
2. If yes: use the `generator.go` template engine to produce a detection regex
3. If no: create a disabled patch stub with the CVE metadata and severity (operator reviews and enables manually)

**SSRF Protection:** The NVD base URL is validated against a blocklist of private and loopback IP ranges before any HTTP request is made (`validateURLNotPrivate` in `nvd.go`). Configuring a custom `nvd_feed_url` pointing to an internal host is rejected at startup.

### Pattern Generator

The `generator.go` heuristic engine maps CVE keywords to pattern templates:

| CVE Keyword | Generated Pattern Target | Template |
|-------------|--------------------------|---------|
| `JNDI injection` | `any` | `\$\{jndi:(ldap\|rmi\|dns)://` |
| `path traversal` | `path` | `\.\./\.\./` |
| `SQL injection` | `query,body` | `['\"];?\s*(OR\|AND\|UNION)` |
| `shell metachar` | `any` | `[;&\|` + "`" + `]\s*(bash\|sh\|cmd)` |
| `PHP deserialization` | `body` | `O:\d+:"[A-Za-z]` |

Auto-generated patterns are tagged `source: "nvd_auto"` and default to `action: "log"` until an operator promotes them to `action: "block"` via the dashboard. This prevents auto-updates from introducing false-positive blocks.

### Dashboard Integration

- **Patch list page** — CVE ID, severity, status (enabled/disabled/log-only), last updated
- **Enable/disable toggle** — per-patch, per-tenant
- **Manual patch editor** — add custom patterns for CVEs not in NVD or with insufficient auto-generated patterns
- **Update log** — history of NVD-sourced additions and changes

### Configuration

```yaml
virtual_patch:
  enabled: true
  database_path: /var/lib/guardianwaf/patches.json

  auto_update:
    enabled: true
    nvd_api_key: "${NVD_API_KEY}"     # Optional: higher rate limits with key
    nvd_feed_url: ""                  # Default: services.nvd.nist.gov (blank = default)
    interval: 6h
    min_cvss: 7.0                     # Only auto-import CVEs with CVSS >= 7.0
    auto_enable_threshold: 9.0        # Auto-enable (log mode) for CVSS >= 9.0

  default_action: log                 # New patches default to "log" not "block"

  score_on_match:
    critical: 80                      # CVSS 9.0-10.0
    high: 60                          # CVSS 7.0-8.9
    medium: 35                        # CVSS 4.0-6.9

  per_tenant: true                    # Tenants can enable/disable patches independently
```

### Performance

All patterns are compiled to `*regexp.Regexp` when the patch is loaded or updated. Matching runs against `RequestContext` fields that are already parsed strings — no additional parsing overhead. The pattern set is protected by a `sync.RWMutex`; hot-reload swaps the compiled set atomically.

For a database of 500 patches (each with 1–3 patterns), matching a typical request takes approximately 200–500µs. Patches that specify `target: "body"` are skipped for requests with no body.

## Consequences

### Positive
- Provides immediate protection for newly disclosed CVEs before backend patches are applied
- NVD integration keeps the patch database current without manual research
- Auto-generated log-mode patches (CVSS ≥ 9.0) give visibility before operators decide to block
- CVE-specific findings improve audit trail quality — each event links to a published vulnerability identifier

### Negative
- Auto-generated patterns have high false-positive risk for broad CVEs (e.g., a SQLi CVE in a specific ORM affects millions of unrelated SQL patterns)
- NVD API rate limits (50 requests/30s without key, 2000/30s with key) constrain update frequency
- The pattern generator covers only a subset of CVE types; complex memory-corruption CVEs (buffer overflows) cannot be detected at the HTTP layer
- Maintaining per-CVE patterns alongside generic CRS rules creates overlap — a Log4Shell request may trigger both `CVE-2021-44228` and a generic JNDI CRS rule, double-counting score

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/layers/virtualpatch/layer.go` | WAF pipeline layer (Order 450), pattern matching |
| `internal/layers/virtualpatch/cve.go` | Patch database, CVE struct, load/save |
| `internal/layers/virtualpatch/nvd.go` | NVD API v2 client, SSRF-safe URL validation |
| `internal/layers/virtualpatch/generator.go` | Heuristic pattern generator from CVE description |
| `data/virtualpatch/builtin.yaml` | Curated built-in patches (embedded in binary) |
| `internal/config/config.go` | `VirtualPatchConfig` struct |

## References

- [NVD API v2 Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [Log4Shell CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [OWASP Virtual Patching Guide](https://owasp.org/www-community/Virtual_Patching_Best_Practices)
- [ADR 0003: Tokenizer-Based Detection](./0003-tokenizer-based-detection.md)
- [ADR 0014: WASM Sandbox for Rule Evaluation](./0014-wasm-sandbox.md)
