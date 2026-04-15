# ADR 0020: Advanced Data Loss Prevention (DLP) Pattern Engine

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF's current DLP layer (Order 475) implements basic regex matching for a fixed set of sensitive data types: credit card numbers (Luhn), US SSNs, API keys, and generic PII patterns. It operates only on response bodies and takes a binary block/pass action.

This is insufficient for enterprise compliance requirements:

- **No request-body inspection** — data exfiltration via POST/PUT bodies is undetected
- **No masking** — the only action is block; legitimate responses containing partial card numbers (for display) are also blocked
- **No custom patterns** — operators cannot add organization-specific patterns (e.g., employee IDs, proprietary data formats)
- **No compliance mapping** — no structured way to associate detected patterns with PCI DSS, GDPR, or HIPAA obligations
- **No Turkish/regional identifiers** — Turkish TC Kimlik No, IBAN formats are absent

Imperva and F5 offer mature DLP with masking, custom pattern libraries, and compliance reporting integration.

## Decision

Rewrite the DLP layer as a pattern engine that supports:

1. **Bidirectional inspection** — request and response bodies
2. **Multiple actions per pattern** — block, mask (redaction), log-only, alert
3. **Custom pattern library** — user-defined regex with metadata (compliance tag, sensitivity level)
4. **Luhn and checksum validation** — beyond regex for financial identifiers
5. **Structured data awareness** — JSON/XML field-level matching

### Pattern Library

Patterns are defined in YAML and loaded at startup (hot-reloadable):

```yaml
dlp_patterns:
  - id: cc_visa
    name: Visa Credit Card
    regex: '\b4[0-9]{12}(?:[0-9]{3})?\b'
    validate: luhn                  # secondary validation
    sensitivity: critical
    compliance: [pci_dss]
    directions: [request, response]
    action: mask
    mask_chars: 12                  # Mask first 12, show last 4
    mask_char: "*"

  - id: ssn_us
    name: US Social Security Number
    regex: '\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'
    sensitivity: critical
    compliance: [hipaa, gdpr]
    directions: [response]
    action: block

  - id: tc_kimlik
    name: Turkish National ID (TC Kimlik No)
    regex: '\b[1-9]\d{10}\b'
    validate: tc_checksum           # 10-digit weighted checksum
    sensitivity: critical
    compliance: [kvkk]
    directions: [request, response]
    action: log

  - id: iban_tr
    name: Turkish IBAN
    regex: '\bTR\d{2}[0-9]{22}\b'
    validate: iban_checksum
    sensitivity: high
    compliance: [pci_dss, kvkk]
    directions: [response]
    action: mask

  - id: custom_employee_id
    name: ACME Employee ID
    regex: '\bEMP-[A-Z]{3}-\d{6}\b'
    sensitivity: medium
    compliance: []
    directions: [request, response]
    action: log
```

### Validation Functions

| Validator | Description |
|-----------|-------------|
| `luhn` | Luhn algorithm for credit/debit card numbers |
| `tc_checksum` | Turkish TC Kimlik 11-digit weighted checksum |
| `iban_checksum` | IBAN MOD-97 checksum (ISO 13616) |
| `nhs_checksum` | UK NHS number Modulus 11 |
| `sin_checksum` | Canadian SIN Luhn variant |

Pattern regex first, then validator — a match must satisfy both to trigger an action.

### Actions

| Action | Request | Response | Description |
|--------|---------|----------|-------------|
| `block` | 403 returned | 403 returned | Request/response terminated |
| `mask` | Field replaced | Field replaced | Sensitive value partially redacted in-flight |
| `log` | Finding logged | Finding logged | Traffic allowed, event recorded |
| `alert` | Finding + webhook | Finding + webhook | Log + external notification |

**Masking** rewrites the matching substring in the response body. For JSON fields, it targets the field value specifically:

```json
// Before masking (cc_visa):
{ "card": "4111111111111234" }

// After masking (mask_chars=12):
{ "card": "************1234" }
```

For non-JSON bodies, the regex match is replaced in-place. Masking is applied after all detection layers have run, in the response layer (Order 600), to avoid corrupting downstream scoring.

### Structured Data Inspection

For `Content-Type: application/json` bodies, the DLP engine walks the JSON tree and applies patterns to string leaf values. This prevents false positives from matching numbers in non-sensitive contexts (e.g., a timestamp `1234567890123` matching a loose card regex).

Field paths can be scoped in pattern definitions:

```yaml
  - id: cc_json_payment
    name: Credit Card in Payment Field
    regex: '\b[0-9]{13,19}\b'
    validate: luhn
    json_paths: ["$.payment.card_number", "$.billing.cc"]
    directions: [request]
    action: block
```

### Configuration

```yaml
dlp:
  enabled: true
  pattern_file: /etc/guardianwaf/dlp-patterns.yaml
  builtin_patterns:
    enabled: true
    categories: [financial, pii, credentials]  # or "all"

  inspect:
    request_body: true
    response_body: true
    max_body_bytes: 1048576        # 1MB — skip inspection above this size

  masking:
    enabled: true
    apply_in: response             # Masking applied by response layer

  score_on_detection:
    critical: 60
    high: 35
    medium: 15
    low: 5

  compliance_reporting:
    enabled: true
    report_dir: /var/log/guardianwaf/compliance/
```

### Performance Considerations

All patterns are compiled to `regexp.Regexp` at startup. For response bodies, inspection runs in the response layer after the upstream response is fully buffered. The engine uses `regexp.FindAllIndex` (not `FindAllString`) to avoid allocating match substrings unless masking is required.

For large bodies (>1MB by default), inspection is skipped and a `Finding` of type `dlp_skipped_oversized` is logged with low score. This bound prevents DoS via giant response bodies.

## Consequences

### Positive
- Custom pattern library enables organization-specific compliance use cases without code changes
- Masking allows legitimate business flows (displaying partial card numbers) while protecting full PANs
- Bidirectional inspection catches data exfiltration via request bodies
- Compliance tags enable automated report generation (see ADR 0022)

### Negative
- Response body buffering is required for masking — increases memory consumption per request
- Structured JSON inspection is O(n) in JSON tree depth; deeply nested payloads incur more CPU
- False positives remain possible for high-entropy strings that pass regex but not checksum (pattern authors must use both)
- Masking rewrites content length headers — may break clients that validate `Content-Length` strictly

## Implementation Locations

**Note**: `internal/layers/dlp/` exists with `layer.go`, `engine_layer.go`, `patterns.go`. The files
below describe the planned Advanced DLP implementation.

| File | Purpose |
|------|---------|
| `internal/layers/dlp/engine.go` | Pattern engine, match loop |
| `internal/layers/dlp/validators.go` | Luhn, TC checksum, IBAN, etc. |
| `internal/layers/dlp/mask.go` | In-flight body masking |
| `internal/layers/dlp/json_walker.go` | Structured JSON field inspection |
| `internal/layers/dlp/patterns/builtin.yaml` | Built-in pattern library (embedded) |
| `internal/config/config.go` | `DLPConfig` extension |

## References

- [PCI DSS v4.0](https://www.pcisecuritystandards.org/)
- [KVKK (Turkish Personal Data Protection Law)](https://www.kvkk.gov.tr/)
- [IBAN Validation ISO 13616](https://www.swift.com/standards/data-standards/iban)
- [Luhn Algorithm](https://en.wikipedia.org/wiki/Luhn_algorithm)
- [ADR 0006: Multi-Tenant Isolation](./0006-multi-tenant-isolation.md)
