# ADR 0032: OWASP Core Rule Set Integration

**Date:** 2026-04-15
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

The OWASP ModSecurity Core Rule Set (CRS) is the industry-standard WAF rule set, used by ModSecurity, AWS WAF, Cloudflare, and most commercial WAF products. It provides coverage for the OWASP Top 10 with thousands of battle-tested rules maintained by the security community.

GuardianWAF's proprietary detection layers (sqli, xss, lfi, cmdi, xxe, ssrf) provide fast, targeted detection using a tokenizer-based approach (ADR 0003). CRS complements this with broader coverage, including:

- Protocol enforcement (anomalous HTTP methods, malformed headers)
- Request validation (oversized requests, encoding attacks)
- File upload scanning
- Reputation-based rules

The challenge: CRS rules are written in **SecLang** (ModSecurity rule language), which is a custom DSL. GuardianWAF's zero-dependency constraint (ADR 0001) means it cannot use libmodsecurity. A pure-Go SecLang parser is required.

## Decision

Implement a native Go SecLang parser and executor (`internal/layers/crs/`) that runs a subset of the CRS rule language sufficient to load and execute the standard CRS rule files.

### Supported SecLang Subset

The parser handles the subset of SecLang directives used by the CRS:

| Directive | Support | Notes |
|-----------|---------|-------|
| `SecRule` | ✅ Full | Core matching directive |
| `SecAction` | ✅ | Action-only rules |
| `SecRuleRemoveById` | ✅ | Disable specific rules |
| `SecDefaultAction` | ✅ | Default phase actions |
| `SecMarker` | ✅ | Jump targets |
| `SecComponentSignature` | ✅ (ignored) | CRS metadata |
| `SecRequestBodyAccess` | ✅ | Body inspection toggle |
| `SecResponseBodyAccess` | ✅ | Response inspection toggle |
| `ctl:ruleRemoveById` | ✅ | Dynamic rule suppression |
| Lua scripts | ❌ | Not supported — CRS Lua rules are skipped |

**Variables supported:** `ARGS`, `ARGS_NAMES`, `REQUEST_HEADERS`, `REQUEST_URI`, `REQUEST_BODY`, `REQUEST_METHOD`, `REQUEST_FILENAME`, `REQUEST_COOKIES`, `REMOTE_ADDR`, `TX` (transaction variables).

**Operators supported:** `@rx` (regex), `@pm` (phrase match), `@gt`, `@lt`, `@ge`, `@le`, `@eq`, `@streq`, `@contains`, `@beginsWith`, `@endsWith`, `@detectSQLi` (libinjection-compatible), `@detectXSS`.

**Actions supported:** `id`, `phase`, `deny`, `pass`, `block`, `log`, `nolog`, `msg`, `tag`, `severity`, `setvar`, `expirevar`, `chain`, `skip`, `skipAfter`.

### Rule Execution Model

CRS rules execute in phases (1=request headers, 2=request body, 3=response headers, 4=response body). GuardianWAF maps these to pipeline execution:

- Phases 1–2: executed during `Process()` call (Order 350)
- Phases 3–4: executed in the response layer (Order 600) — output is advisory (log only)

Rules are organized by phase in `rulesByPhase map[int][]*Rule`. Within a phase, rules execute in numeric ID order. The `chain` action links multiple rules that must all match to trigger an action.

Transaction variables (`TX.*`) are stored in `RequestContext.Metadata` as a `map[string]string`.

### Loading CRS Rule Files

```go
layer.LoadRules("/etc/guardianwaf/crs/")
```

The loader walks the directory in alphabetical order (matching the CRS intended loading sequence: `REQUEST-901-INITIALIZATION.conf` → `REQUEST-910-IP-REPUTATION.conf` → ... → `RESPONSE-999-EXCLUSION-RULES.conf`). Each `.conf` file is parsed line by line. Comments (`#`) and continuation lines (`\`) are handled. Rules are indexed by ID in `rulesByID`.

### Disabling Rules

Individual rules can be disabled to suppress false positives:

```yaml
crs:
  rule_path: /etc/guardianwaf/crs/
  disabled_rules:
    - "920230"    # Multiple URL encoding
    - "949110"    # Anomaly score threshold — use GuardianWAF's own scoring
  paranoia_level: 1   # 1-4, controls which rules are active (tag-based filter)
```

`paranoia_level` mirrors the CRS concept: rules tagged `paranoia-level/2` through `4` are skipped at lower paranoia levels, reducing false positive rate at the cost of coverage.

### Performance

CRS contains ~1,500 rules at paranoia level 1. Running all rules on every request would be expensive. Optimizations:

1. **Phase filtering**: only phase-1 rules run on GET requests with no body (skipping phase-2)
2. **`@pm` compiled to Aho-Corasick**: phrase-match operators use a prebuilt Aho-Corasick automaton (pure Go, in-process) for O(n) scanning rather than O(n×m)
3. **Early exit**: a rule with `deny` action short-circuits the remaining rules in that phase

Even so, CRS adds ~1–3ms latency for a typical request at paranoia level 1 (benchmarked on representative CRS traffic). This is the accepted cost for broad-coverage rule evaluation.

### Configuration

```yaml
crs:
  enabled: false             # Disabled by default — requires rule files to be present
  rule_path: /etc/guardianwaf/crs/
  paranoia_level: 1          # 1 (lowest FP) to 4 (maximum coverage)
  disabled_rules: []
  request_body_access: true
  response_body_access: false
  anomaly_threshold: 5       # CRS anomaly score threshold for block action
```

## Consequences

### Positive
- Standard CRS rule files can be dropped into the `rule_path` directory without any modification — community CRS updates work out of the box
- Paranoia level knob allows operators to tune coverage vs. false positive rate exactly as they would with ModSecurity
- Rule disabling by ID provides surgical false-positive suppression without forking the rule files

### Negative
- Lua rule support is absent — approximately 5% of CRS rules use Lua for complex logic; these rules are silently skipped (logged at startup)
- The Go SecLang parser covers the CRS subset but is not a complete ModSecurity compatibility layer; non-CRS rule files may use unsupported directives
- `@detectSQLi` / `@detectXSS` reimplements libinjection's heuristics in Go — accuracy is close but not identical; some libinjection edge cases may behave differently
- Phase 3–4 (response) rules are advisory (log only) because response blocking is complex and risks breaking legitimate responses; this differs from full ModSecurity behaviour

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/layers/crs/parser.go` | SecLang tokenizer and directive parser |
| `internal/layers/crs/rule.go` | `Rule` struct, variable expansion, action execution |
| `internal/layers/crs/operators.go` | Operator implementations (`@rx`, `@pm`, `@detectSQLi`, etc.) |
| `internal/layers/crs/variables.go` | Variable resolution from `RequestContext` |
| `internal/layers/crs/layer.go` | WAF pipeline layer, phase execution |
| `internal/config/config.go` | `CRSConfig` struct |

## References

- [OWASP ModSecurity Core Rule Set](https://github.com/coreruleset/coreruleset)
- [ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual)
- [libinjection](https://github.com/client9/libinjection)
- [ADR 0001: Zero External Dependencies](./0001-zero-external-dependencies.md)
- [ADR 0003: Tokenizer-Based Detection](./0003-tokenizer-based-detection.md)
