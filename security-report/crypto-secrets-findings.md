# GuardianWAF - HUNT Phase: DATA EXPOSURE Security Report
**Scan Date:** 2026-04-16
**Scope:** GuardianWAF codebase
**Phase:** HUNT - Data Exposure

---

## Executive Summary

The scan identified 9 verified findings across 4 categories.

---

## Category 1: Hardcoded Secrets

### Finding HDS-001: Dashboard API Key Printed to stdout on Auto-Generation
**Severity:** HIGH
**File:** cmd/guardianwaf/main.go (lines 2921-2923) and cmd/guardianwaf/main_default.go

**Description:**
When cfg.Dashboard.APIKey is empty, the server auto-generates a random password using crypto/rand and prints it unmasked to stdout:

```go
cfg.Dashboard.APIKey = generateDashboardPassword()
fmt.Printf("Dashboard API key not set - generated: %s
", cfg.Dashboard.APIKey)
```

**Impact:** Any process with access to stdout/stderr can read the credential.

**Recommendation:** Suppress printing; require GWAF_DASHBOARD_API_KEY env var in production.

---

### Finding HDS-002: Default Commented Password Placeholder in Config
**Severity:** LOW
**File:** guardianwaf.yaml (lines 166-169)

guardianwaf.yaml contains commented password placeholder which may be inadvertently used.

---

### Finding HDS-003: Redis Password Stored as Plaintext String
**Severity:** MEDIUM
**File:** internal/config/config.go (line 268)

RedisPass is stored as plain string. No GWAF_CACHE_REDIS_PASSWORD env var override exists.

---

### Finding HDS-004: SIEM API Key Stored as Plaintext String
**Severity:** MEDIUM
**File:** internal/config/config.go (line 1119)

SIEM APIKey is stored as plain string. No GWAF_SIEM_API_KEY env var override exists.

---

## Category 2: Sensitive Data Exposure

### SDE-001: No Credentials Returned in API Responses - NOT A FINDING
### SDE-002: No Intentional Secret Logging - NOT A FINDING (caveat HDS-001)
### SDE-003: Error Messages Generic - NOT A FINDING

---

## Category 3: Crypto Issues

### CRY-001: SHA-1 Used for OCSP Certificate Identification
**Severity:** MEDIUM
**File:** internal/tls/ocsp.go (lines 241-259)

SHA-1 is used for OCSP CertID hash. Low risk for OCSP but outdated crypto hygiene.

---

### CRY-002: TLS 1.3 Minimum Version - POSITIVE FINDING
**File:** internal/tls/certstore.go

TLS 1.3 enforced as minimum. No weak cipher suites.

---

### CRY-003: HTTP/3 0-RTT Configurable
**Severity:** LOW
**File:** internal/config/config.go (line 103)

Enable0RTT allows replay-vulnerable 0-RTT handshakes. Default is false.

---

## Category 4: Secrets in Environment Variables

### ENV-001: YAML Config Supports env var Expansion - POSITIVE
**File:** internal/config/yaml.go

${VAR} and ${VAR:-default} patterns supported with safe variable name validation.

---

### ENV-002: LoadEnv Missing Sensitive Field Overrides
**Severity:** MEDIUM
**File:** internal/config/validate.go (lines 484-534)

No env var overrides for: GWAF_CACHE_REDIS_PASSWORD, GWAF_SIEM_API_KEY, GWAF_CLUSTER_AUTH_SECRET, WAF.Challenge.SecretKey.

---

## Summary

| ID | Severity | Category | File(s) |
| HDS-001 | HIGH | Hardcoded | main.go:2921 |
| HDS-002 | LOW | Hardcoded | guardianwaf.yaml:168 |
| HDS-003 | MEDIUM | Hardcoded | config.go:268 |
| HDS-004 | MEDIUM | Hardcoded | config.go:1119 |
| CRY-001 | MEDIUM | Crypto | ocsp.go:241 |
| CRY-002 | INFO | Crypto | certstore.go:136 |
| CRY-003 | LOW | Crypto | config.go:103 |
| ENV-001 | INFO | Env | yaml.go:1114 |
| ENV-002 | MEDIUM | Env | validate.go:484 |

---

## Positive Security Observations

1. TLS 1.3 enforced - no weak ciphers
2. HMAC session signing with IP binding
3. Constant-time API key comparison
4. crypto/rand for key generation
5. OCSP stapling with 1-hour refresh
6. AI store uses crypto/rand for encryption key (0600 perms)
7. Cluster TLS enforcement - fails fast without TLS
8. DLP detects private_key exfiltration
9. API key query param rejected to prevent log leakage
10. Session cookies: HttpOnly, Secure, SameSite=Strict
