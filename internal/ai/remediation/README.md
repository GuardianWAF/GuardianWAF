# AI Auto-Remediation

AI Auto-Remediation automatically generates security rules from AI threat analysis findings. When the AI analysis detects attack patterns with high confidence, the system can automatically create and apply blocking rules to protect against similar attacks.

## Features

- **Automatic Rule Generation**: Creates rules from AI analysis results
- **Confidence-Based Filtering**: Only generates rules above configurable confidence threshold
- **Auto-Apply Mode**: Automatically apply rules for critical threats (90%+ confidence)
- **Daily Rate Limiting**: Prevents rule explosion with configurable daily limits
- **Rule TTL**: Automatic expiration of generated rules
- **Excluded Paths**: Configurable path exclusions (e.g., health checks)
- **Manual Review**: Queue rules for manual approval before applying
- **Rule Lifecycle**: Apply, revoke, and delete generated rules

## Configuration

```yaml
waf:
  remediation:
    enabled: true
    auto_apply: false              # Auto-apply rules for critical threats
    confidence_threshold: 85       # Minimum confidence to generate rule (0-100)
    max_rules_per_day: 10          # Maximum rules per day
    rule_ttl: 24h                  # Rule lifetime
    excluded_paths:                # Paths to exclude from remediation
      - "/healthz"
      - "/metrics"
      - "/api/v1/status"
    storage_path: "data/remediation"  # Rule storage directory
```

## Rule Types

The system generates different rule types based on attack classification:

| Attack Type | Rule Type | Action |
|-------------|-----------|--------|
| SQL Injection | `sqli_block` | block |
| XSS | `xss_block` | block |
| LFI/RFI | `lfi_block` / `rfi_block` | block |
| Command Injection | `cmdi_block` | block |
| XXE | `xxe_block` | block |
| SSRF | `ssrf_block` | block |
| NoSQL Injection | `nosql_block` | block |
| LDAP Injection | `ldap_block` | block |
| XPath Injection | `xpath_block` | block |
| Path Traversal | `path_traversal_block` | block |
| Brute Force | `rate_limit` | challenge |
| Bot Attack | `bot_block` | block |
| IP Reputation | `ip_block` | block |

## How It Works

1. **AI Analysis**: AI engine analyzes request and identifies attack
2. **Confidence Check**: Verify confidence >= threshold (default: 85%)
3. **Path Check**: Verify path is not in excluded list
4. **Daily Limit Check**: Verify daily rule limit not exceeded
5. **Rule Generation**: Create rule with pattern matching
6. **Auto-Apply Decision**:
   - If confidence >= 90% and auto_apply enabled: Apply immediately
   - Otherwise: Queue for manual review

## API Endpoints

### GET /api/v1/remediation/rules
List all rules or filter by status.

**Query Parameters:**
- `status`: `all` (default), `active`, `pending`

**Response:**
```json
{
  "rules": [
    {
      "id": "a1b2c3d4e5f6",
      "created_at": "2024-01-15T10:30:00Z",
      "expires_at": "2024-01-16T10:30:00Z",
      "analysis_id": "analysis-123",
      "rule_type": "sqli_block",
      "name": "AI-sqli-192.168.1.100",
      "description": "Auto-generated rule for sqli attack from 192.168.1.100",
      "pattern": "'\\s+OR\\s+'1'='1",
      "action": "block",
      "confidence": 95.5,
      "applied": true,
      "auto_applied": false,
      "hit_count": 42,
      "last_hit": "2024-01-15T14:20:00Z"
    }
  ],
  "count": 1
}
```

### GET /api/v1/remediation/rules/{id}
Get specific rule details.

### DELETE /api/v1/remediation/rules/{id}
Delete a rule.

### GET /api/v1/remediation/stats
Get remediation statistics.

**Response:**
```json
{
  "total_generated": 15,
  "total_applied": 8,
  "total_auto_applied": 3,
  "active_rules": 5,
  "expired_rules": 2,
  "last_rule_time": "2024-01-15T10:30:00Z",
  "rules_today": 2
}
```

### POST /api/v1/remediation/apply
Apply a pending rule.

**Request:**
```json
{
  "rule_id": "a1b2c3d4e5f6"
}
```

**Response:**
```json
{
  "status": "applied",
  "rule_id": "a1b2c3d4e5f6"
}
```

### POST /api/v1/remediation/revoke
Revoke an applied rule.

**Request:**
```json
{
  "rule_id": "a1b2c3d4e5f6"
}
```

## Safety Mechanisms

1. **Confidence Threshold**: Rules only generated for high-confidence detections
2. **Daily Limits**: Prevents excessive rule generation
3. **Excluded Paths**: Critical endpoints never remediated
4. **Rule TTL**: Rules expire automatically
5. **Manual Review**: Non-critical rules require approval
6. **Pattern Sanitization**: Payloads are escaped for safe regex

## Best Practices

### Conservative Mode (Recommended)
```yaml
remediation:
  enabled: true
  auto_apply: false        # Manual review required
  confidence_threshold: 90 # High confidence only
  max_rules_per_day: 5     # Strict limit
  rule_ttl: 12h            # Short TTL
```

### Aggressive Mode (High Security)
```yaml
remediation:
  enabled: true
  auto_apply: true         # Auto-apply critical rules
  confidence_threshold: 85 # Medium confidence
  max_rules_per_day: 20    # Higher limit
  rule_ttl: 48h            # Longer TTL
```

### Monitoring Mode (Learning)
```yaml
remediation:
  enabled: true
  auto_apply: false
  confidence_threshold: 95 # Very high confidence
  max_rules_per_day: 3     # Very strict limit
  rule_ttl: 4h             # Very short TTL
```

## Integration with AI Analysis

```go
// Process AI analysis result
result := &remediation.AnalysisResult{
    ID:         analysis.ID,
    AttackType: analysis.AttackType,
    Confidence: analysis.Confidence,
    SourceIP:   request.ClientIP,
    Path:       request.Path,
    Method:     request.Method,
    Payload:    request.Body,
    Severity:   analysis.Severity,
}

rule, err := engine.ProcessAnalysis(result)
if err != nil {
    log.Printf("Failed to process analysis: %v", err)
}

if rule != nil {
    log.Printf("Generated rule: %s (auto_applied: %v)", 
        rule.ID, rule.AutoApplied)
}
```

## Rule Lifecycle

```
Analysis → Generation → [Auto-Apply | Queue] → Active → Expiry/Revoke
                ↓
           Manual Apply
```

## Statistics

The system tracks:
- Total rules generated
- Total rules applied (manual + auto)
- Auto-applied rule count
- Currently active rules
- Expired rules
- Rules generated today
- Last rule generation time

## Troubleshooting

### Rules not being generated
- Check confidence threshold (current detection confidence may be too low)
- Check daily limit (may have been reached)
- Check excluded paths (request path may be excluded)
- Check if remediation is enabled

### Too many rules generated
- Increase confidence threshold
- Lower daily limit
- Add more excluded paths
- Reduce rule TTL

### Rules not matching attacks
- Check pattern generation (may need refinement)
- Verify rule is applied (not just generated)
- Check rule expiry (may have expired)

## Performance

- Rule matching: O(n) where n = active rules
- Storage: ~1KB per rule on disk
- Memory: ~500 bytes per rule in memory
- Cleanup: Runs hourly, removes expired rules
