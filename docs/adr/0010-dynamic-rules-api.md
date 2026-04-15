# ADR 0010: Dynamic Rule Updates via API

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

Currently, GuardianWAF rules are managed via YAML configuration files. To add/modify rules:
1. Edit the YAML config file
2. Send SIGHUP or call config reload API
3. Rules are reloaded into memory

This approach works for static configurations but is cumbersome for:
- Automated threat response (blocking new attack patterns)
- Rule management via dashboard UI
- Integration with external threat feeds
- Multi-tenant rule management

## Decision

Add REST API endpoints for dynamic rule management without requiring config file changes:

### API Endpoints

```
POST   /api/v1/rules              # Create rule
GET    /api/v1/rules              # List rules
GET    /api/v1/rules/:id          # Get rule
PUT    /api/v1/rules/:id          # Update rule
DELETE /api/v1/rules/:id          # Delete rule
PATCH  /api/v1/rules/:id/enable    # Enable rule
PATCH  /api/v1/rules/:id/disable  # Disable rule
POST   /api/v1/rules/validate      # Validate rule without applying
```

### Rule Storage

Rules are stored in memory with optional persistence:

1. **Memory-only** (default): Rules persist until restart
2. **File persistence**: Rules saved to YAML on change (via `rules_file` config)
3. **External store**: Future Redis/PostgreSQL adapter

### Rule Schema

```json
{
  "id": "SQLI-BLOCK-001",
  "name": "Block SQL injection attempts",
  "type": "sqli",
  "action": "block",
  "enabled": true,
  "priority": 100,
  "conditions": [
    {
      "field": "query",
      "operator": "contains",
      "value": "'"
    },
    {
      "field": "query",
      "operator": "contains",
      "value": "OR"
    }
  ],
  "tags": ["owasp", "sql-injection"],
  "metadata": {
    "created_by": "api",
    "created_at": "2026-04-15T10:30:00Z"
  }
}
```

### Condition Operators

| Operator | Description | Applicable Fields |
|----------|-------------|-------------------|
| `equals` | Exact match | any |
| `contains` | Substring match | any |
| `regex` | Regular expression | any |
| `starts_with` | Prefix match | any |
| `ends_with` | Suffix match | any |
| `in_list` | Value in list | any |
| `ip_in_range` | CIDR match | client_ip |
| `ip_in_blacklist` | Check blacklist | client_ip |
| `ip_in_whitelist` | Check whitelist | client_ip |
| `country_in` | GeoIP country check | country |

### Atomic Updates

All rule changes are atomic:
- Uses read-copy-update pattern
- Active requests use old ruleset
- New requests use updated ruleset
- No downtime during rule updates

### API Authentication

- Requires valid session cookie or API key
- Rate limited: 100 requests/minute per IP
- Audit logged: all changes recorded in event log

## Consequences

### Positive
- Real-time threat response without restart
- Dashboard rule management UI
- Integration with external threat feeds
- Multi-tenant isolated rule sets

### Negative
- In-memory rules lost on restart (unless file persistence enabled)
- Potential for rule conflicts (mitigated by priority system)
- API complexity increase

### Design Notes

- Rules are validated before apply
- Invalid rules rejected with 400 error + details
- Rule IDs must be unique (prefix recommended: SQLI-, XSS-, etc.)
- Built-in rules (from CRS) are read-only via API

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/layers/rules/api.go` | REST API handlers |
| `internal/layers/rules/store.go` | In-memory rule store with atomic updates |
| `internal/layers/rules/validator.go` | Rule validation logic |
| `internal/dashboard/api/routes.go` | Route registration |

## References

- [GuardianWAF Custom Rules Layer](../ARCHITECTURE.md#layer-order)
- [OWASP ModSecurity CRS](https://coreruleset.org/)
- [Rule Engine Pattern](https://martinfowler.com/bliki/RulesEngine.html)
