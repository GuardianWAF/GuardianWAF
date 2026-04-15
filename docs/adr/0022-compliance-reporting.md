# ADR 0022: Compliance & Reporting Framework

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

Enterprise customers operating GuardianWAF in regulated industries require evidence that the WAF is functioning as a control for specific compliance frameworks:

- **PCI DSS v4.0** — Requirement 6.4 (web-facing application protection), 10.2 (audit log), 10.3 (log protection)
- **GDPR / KVKK** — Article 32 (technical measures), data processing records, DPA notification support
- **SOC 2 Type II** — CC6.6 (logical access controls), CC7.2 (security event monitoring)
- **ISO 27001** — A.12.4 (logging), A.14.2 (secure development), A.18.2 (compliance review)

Currently GuardianWAF produces event logs and Prometheus metrics but has no structured compliance reporting. Customers must manually extract, correlate, and format data for audit evidence — a time-consuming and error-prone process.

## Decision

Implement a compliance reporting framework that:

1. **Maps WAF events to compliance controls** — each event type tagged with relevant framework/requirement IDs
2. **Generates scheduled reports** — PDF/JSON/CSV exports on daily/weekly/monthly schedules
3. **Provides an audit trail API** — tamper-evident log export with hash chaining
4. **Tracks data retention** — enforces configurable retention periods per compliance framework
5. **Offers a compliance dashboard page** — real-time control status and coverage heatmap

### Control Mapping

WAF capabilities are mapped to compliance requirements in a YAML registry:

```yaml
# internal/compliance/controls.yaml
controls:
  pci_dss_6_4_1:
    name: "PCI DSS v4.0 Req 6.4.1 — WAF in place"
    frameworks: [pci_dss]
    evidence:
      - type: waf_active
        description: "WAF is operational and processing requests"
      - type: block_events
        description: "Attack attempts blocked in the reporting period"
    passing_criteria:
      - metric: waf_uptime_pct
        operator: ">="
        threshold: 99.9

  pci_dss_10_2_1:
    name: "PCI DSS v4.0 Req 10.2.1 — Audit log of individual access"
    frameworks: [pci_dss]
    evidence:
      - type: access_log_entries
        description: "All requests logged with user, action, timestamp"
    passing_criteria:
      - metric: log_completeness_pct
        operator: ">="
        threshold: 100.0

  gdpr_art32:
    name: "GDPR Art. 32 — Technical security measures"
    frameworks: [gdpr, kvkk]
    evidence:
      - type: block_events
      - type: dlp_events
        description: "Personal data exfiltration attempts blocked"
    passing_criteria:
      - metric: dlp_blocks_in_period
        operator: ">="
        threshold: 0                # At least the capability exists

  soc2_cc7_2:
    name: "SOC 2 CC7.2 — Security event monitoring"
    frameworks: [soc2]
    evidence:
      - type: alert_events
        description: "Security alerts generated and acknowledged"
    passing_criteria:
      - metric: alert_response_time_p95_minutes
        operator: "<="
        threshold: 60
```

### Report Structure

Reports are generated as structured JSON (machine-readable) and optionally rendered to PDF via an embedded HTML template:

```json
{
  "report_id": "rpt_pci_2026Q2_tenant001",
  "generated_at": "2026-04-15T00:00:00Z",
  "period": { "from": "2026-01-01", "to": "2026-03-31" },
  "tenant_id": "tenant001",
  "framework": "pci_dss",
  "summary": {
    "controls_passing": 14,
    "controls_failing": 1,
    "controls_not_applicable": 3,
    "overall_status": "partial"
  },
  "controls": [
    {
      "id": "pci_dss_6_4_1",
      "status": "passing",
      "evidence": {
        "waf_uptime_pct": 99.97,
        "total_requests": 45200000,
        "blocked_requests": 12450
      }
    }
  ],
  "audit_trail_hash": "sha256:abc123...",
  "signature": "..."
}
```

### Audit Trail & Tamper Evidence

The event log chain uses SHA-256 hash linking (similar to blockchain but without consensus):

```
Event N:  { ...data..., prev_hash: hash(Event N-1), hash: sha256(data + prev_hash) }
Event N+1:{ ...data..., prev_hash: hash(Event N),   hash: sha256(data + prev_hash) }
```

An auditor can verify integrity by recomputing the chain. The genesis hash is published to the dashboard and optionally to an external notarization service. This provides tamper evidence without requiring an external database.

### Data Retention Engine

```yaml
retention:
  default_days: 90
  per_framework:
    pci_dss: 365       # PCI DSS requires 12 months
    hipaa: 2190        # HIPAA: 6 years
    gdpr: 90           # GDPR: minimize retention
    kvkk: 365
  auto_delete: true    # Purge events older than max(per_framework) for tenant
  archive_before_delete: true
  archive_path: /var/lib/guardianwaf/archive/
```

A background goroutine runs daily to enforce retention limits, archiving events to JSONL files before deletion from the active store.

### Scheduled Reports

```yaml
compliance:
  reports:
    - id: pci_monthly
      framework: pci_dss
      schedule: "0 6 1 * *"          # 1st of each month at 06:00
      format: [json, pdf]
      recipients:
        - email: security@example.com # Future: email delivery
      output_dir: /var/lib/guardianwaf/reports/

    - id: gdpr_weekly
      framework: gdpr
      tenant_id: tenant001
      schedule: "0 8 * * 1"          # Every Monday at 08:00
      format: [json]
```

### Dashboard Compliance Page

- **Control status table** — pass/fail/N/A for each mapped control, with drill-down to evidence
- **Framework switcher** — view compliance posture per framework (PCI, GDPR, SOC 2, ISO 27001)
- **Trend graph** — blocking rate, uptime, alert response time over time
- **Report download** — one-click PDF/JSON export for any historical period
- **Audit trail verifier** — UI to verify hash chain integrity for a given time range

### Configuration

```yaml
compliance:
  enabled: true
  frameworks: [pci_dss, gdpr, soc2]   # Active frameworks for this installation
  report_dir: /var/lib/guardianwaf/reports/
  audit_trail:
    hash_algorithm: sha256
    chain_enabled: true
  retention:
    default_days: 365
  scheduled_reports:
    - ...
```

## Consequences

### Positive
- Reduces audit preparation from days to minutes
- Control mapping is externalized to YAML — new frameworks can be added without code changes
- Hash-chained audit trail provides forensic integrity guarantees
- Per-tenant reports enable MSSPs to deliver compliance reporting as a service

### Negative
- PDF generation requires an embedded HTML-to-PDF renderer (adds binary size ~5MB) or an external tool (`chromium --print-to-pdf`), which conflicts with the zero-dependency ethos — PDF export will use an external process invocation, not a Go library
- Retention enforcement deletes data permanently — misconfigured retention settings could violate compliance requirements; deletion requires explicit operator confirmation in the dashboard
- Control mapping accuracy depends on accurate event tagging; if an event type is missing a compliance tag, the corresponding control will appear as "no evidence"

## Implementation Locations

**Note**: `internal/compliance/` does not exist yet — all files below are planned.

| File | Purpose |
|------|---------|
| `internal/compliance/registry.go` | Control definition loader (YAML) |
| `internal/compliance/evaluator.go` | Control pass/fail evaluation against event metrics |
| `internal/compliance/reporter.go` | Report generation (JSON + PDF shell-out) |
| `internal/compliance/retention.go` | Data retention enforcement |
| `internal/compliance/audit_chain.go` | Hash-chain audit trail |
| `internal/compliance/controls.yaml` | Built-in control definitions (embedded) |
| `internal/dashboard/compliance.go` | Dashboard REST handlers |
| `internal/config/config.go` | `ComplianceConfig` struct |

## References

- [PCI DSS v4.0 Requirements](https://www.pcisecuritystandards.org/document_library/)
- [GDPR Article 32](https://gdpr-info.eu/art-32-gdpr/)
- [SOC 2 Trust Service Criteria](https://www.aicpa.org/resources/download/2017-trust-services-criteria)
- [ISO/IEC 27001:2022 Annex A](https://www.iso.org/standard/82875.html)
- [KVKK (Turkey)](https://www.kvkk.gov.tr/Icerik/6649/KVKK-English)
- [ADR 0020: Advanced DLP](./0020-advanced-dlp.md)
- [ADR 0015: Distributed Event Store](./0015-distributed-event-store.md)
