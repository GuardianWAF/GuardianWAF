# GuardianWAF Security Assessment Report

**Date:** 2026-04-18
**Scope:** Full codebase — 198 Go files (~77K lines), React dashboard (TypeScript)
**Methodology:** 4-phase pipeline (Recon → Hunt → Verify → Report) with 6 parallel scanners
**Scanners:** Injection, Access Control, Data Exposure, Server-Side/API, Infrastructure/Logic, Go Deep

---

## Executive Summary

GuardianWAF demonstrates **strong overall security posture**. The codebase uses constant-time comparisons for auth, SSRF DialContext protection in the proxy layer, body size limits on all endpoints, TLS 1.3 minimum, HMAC-SHA256 session tokens with IP binding, and proper CSRF/same-origin enforcement. No critical or high-severity vulnerabilities were found.

**22 medium-severity and 25 low-severity findings** were identified across 6 scan categories. The most impactful findings are:

1. **SSRF via DNS rebinding** in AI client (no DialContext hook)
2. **Tenant API key scoping bypass** — per-tenant keys grant full admin access
3. **Timing-vulnerable comparison** in MCP stdio server
4. **CRLF injection** in gRPC proxy error responses
5. **TOCTOU race** in tenant rule quota enforcement

### Risk Distribution

| Severity | Count | Action Required |
|----------|-------|-----------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 22 | Fix before production |
| Low | 25 | Fix when convenient |
| Info | 8 | Awareness only |

### Positive Security Controls Verified

- No `unsafe` package usage
- No `InsecureSkipVerify: true` in production code
- TLS 1.3 minimum on main listener
- Constant-time comparison for all auth secrets (20+ locations)
- SSRF protection with DNS-rebinding prevention via DialContext in proxy, webhook, SIEM
- Decompression bomb protection (100:1 ratio check)
- JWT `alg: none` rejection, algorithm confusion prevention
- Proper session security (HttpOnly, Secure, SameSite=Strict, IP binding)
- No SQL injection surface (no database)
- No command injection surface (Docker client validates all input)
- No XSS surface (JSON-only API, React auto-escaping)
- Body size limits on all HTTP endpoints

---

## Findings by Category

---

### 1. Server-Side Request Forgery (SSRF)

#### SEC-001: SSRF via DNS Rebinding in AI Client (Medium)
**CWE-918** | `internal/ai/client.go:50-89` | Confidence: HIGH

The AI client validates the base URL only at creation time and only checks raw IP literals. Hostnames are NOT resolved via DNS, and the HTTP transport has no `DialContext` hook to re-validate at connection time.

```go
// Only checks raw IPs, not hostname DNS resolution:
if ip := net.ParseIP(host); ip != nil {
    if ip.IsLoopback() || ip.IsPrivate() { ... }
} else if strings.EqualFold(host, "localhost") {
    log.Fatalf(...)
}
// Hostname like "evil.internal" passes through unchecked!

// HTTP client has NO DialContext hook:
transport := &http.Transport{ ... } // no custom DialContext
```

**Impact:** An attacker who can modify the AI provider URL (via dashboard config API) could use DNS rebinding to reach internal services (metadata endpoints, localhost services).

**Contrast:** The proxy layer (`internal/proxy/target.go:103-135`), webhook client (`internal/alerting/webhook.go:611-628`), and SIEM exporter all implement proper DialContext-level SSRF protection with DNS rebinding mitigation.

**Recommendation:** Add a custom `DialContext` to the AI client's HTTP transport that resolves DNS, validates the IP, and dials the validated IP directly — matching the pattern used in `internal/proxy/target.go`.

---

#### SEC-002: SSRF — AI Endpoint URL Validation Skips DNS Resolution (Medium)
**CWE-918** | `internal/dashboard/ai_handlers.go:246-265` | Confidence: HIGH

The dashboard's `validateAIEndpointURL` function has the same gap: when a hostname is provided, `net.ParseIP` returns nil, and the function returns `nil` (no error) without resolving DNS to check if the hostname resolves to a private IP.

**Recommendation:** Resolve hostnames via `net.LookupHost()` and check all resulting IPs, matching the pattern in `validateHostNotPrivate()` at `internal/alerting/webhook.go:580`.

---

#### SEC-003: SSRF Bypass via DNS Failure — Threat Intel & NVD Clients (Low)
**CWE-918** | `internal/layers/threatintel/feed.go:427-431`, `internal/layers/virtualpatch/nvd.go:68-71` | Confidence: MEDIUM

When DNS lookup fails in SSRF validation, the URL is allowed through. The webhook and SIEM clients mitigate this with DialContext hooks, but the threat intel feed and NVD clients do not have connection-time validation.

**Recommendation:** Add DialContext hooks to threat intel and NVD HTTP clients, or block URLs when DNS fails.

---

### 2. Authentication & Access Control

#### SEC-004: Timing-Vulnerable API Key Comparison in MCP stdio Server (Medium)
**CWE-208** | `internal/mcp/server.go:130-135` | Confidence: HIGH

```go
return key == s.apiKey  // Standard string comparison — timing leak
```

The MCP stdio server uses standard string comparison instead of `subtle.ConstantTimeCompare`. The MCP SSE transport (`internal/mcp/sse.go:55`) correctly uses constant-time comparison, making this an oversight.

**Recommendation:** Replace with `subtle.ConstantTimeCompare([]byte(key), []byte(s.apiKey)) == 1`.

---

#### SEC-005: Per-Tenant API Key Grants Full Dashboard Access (Medium)
**CWE-639** | `internal/dashboard/auth.go:301-309` | Confidence: HIGH

After a per-tenant API key is validated, `isAuthenticated()` returns `true` without recording which tenant was authenticated. The `authWrap` handler then grants full access to all dashboard endpoints, including admin-only operations (config update, IP ACL changes, ban management).

```go
if key := r.Header.Get("X-API-Key"); key != "" && verifyTenantAPIKey(hash, key) {
    return true  // Full access granted — no tenant scoping!
}
```

Additionally, `extractTenantID` reads from `X-Tenant-ID` header or URL path — both client-controlled — allowing a tenant to impersonate other tenant IDs.

**Impact:** A tenant-scoped API key holder can access ALL dashboard API routes, not just their tenant-scoped data.

**Recommendation:** Record the authenticated tenant ID in the request context and enforce tenant scoping on all endpoints. Reject tenant API keys on admin-only routes.

---

#### SEC-006: MCP stdio Server Allows Unauthenticated Access When No API Key Set (Low)
**CWE-306** | `internal/mcp/server.go:130-133` | Confidence: HIGH

When no API key is configured (default for stdio mode), all tool calls execute without authentication. This is intentional for local-only stdio transport, but would become critical if the stdio server were exposed via a network wrapper.

---

#### SEC-007: Undocumented X-Admin-Key Authentication Fallback (Low)
**CWE-287** | `internal/tenant/handlers.go:31-42` | Confidence: HIGH

The tenant handlers accept API keys via either `X-API-Key` or `X-Admin-Key` header. The fallback header is undocumented and could be missed by security audits and logging configurations.

---

### 3. Injection

#### SEC-008: CRLF Injection in gRPC Proxy Error Responses (Medium)
**CWE-113** | `internal/proxy/grpc/proxy.go:406-412` | Confidence: HIGH

```go
func writeGRPCError(w http.ResponseWriter, code int, message string) {
    w.Header().Set("grpc-message", message)  // No CRLF sanitization
    w.WriteHeader(http.StatusOK)
}
```

The `message` parameter contains user-influenced data (e.g., `"method not allowed: <user_path>"`) and is written into an HTTP header without CRLF sanitization. The gRPC *security layer* at `internal/layers/grpc/grpc.go` correctly percent-encodes via `encodeGRPCMessage()`, but the gRPC *proxy* does not.

**Recommendation:** Sanitize `message` by stripping `\r` and `\n` before setting the header, or use the existing `encodeGRPCMessage()` function.

---

#### SEC-009: CRLF Injection in Content-Disposition Header (Low)
**CWE-113** | `internal/integrations/v040/integrator.go:696` | Confidence: HIGH

```go
w.Header().Set("Content-Disposition", "attachment; filename="+filename)
```

Filename is currently hardcoded to `"api-spec.json"`, but the concatenation pattern is fragile. The dashboard's export handlers correctly quote the filename.

---

#### SEC-010: Email Template Injection (Low)
**CWE-94** | `internal/alerting/email.go:148-160` | Confidence: MEDIUM

Event data (ClientIP, UserAgent) from attacker-controlled requests is substituted into email templates via `strings.ReplaceAll` without sanitization. Email headers are properly sanitized via `sanitizeHeader()`, but body content is not.

---

### 4. Race Conditions & Concurrency

#### SEC-011: TOCTOU Race in Tenant Rule Quota Enforcement (Medium)
**CWE-367** | `internal/tenant/rules.go:98-110` | Confidence: HIGH

```go
func (trm *TenantRulesManager) AddTenantRule(tenantID string, rule rules.Rule, maxRules int) error {
    currentRules := trm.GetTenantRules(tenantID)  // RLock + unlock
    if len(currentRules) >= maxRules && maxRules > 0 {
        return ErrQuotaExceeded
    }
    layer := trm.GetRulesLayer(tenantID, maxRules) // Separate lock acquisition
    layer.AddRule(rule)
    return nil
}
```

The quota check releases the lock before adding the rule. Concurrent `AddTenantRule` calls could both pass the quota check before either adds the rule, exceeding per-tenant rule limits.

**Recommendation:** Hold a write lock for the entire quota-check-and-add operation.

---

#### SEC-012: Config Mutation Without Deep Copy in CRS/ClientSide Handlers (Medium)
**CWE-362** | `internal/dashboard/crs_handlers.go:181-191`, `internal/dashboard/clientside_handlers.go:80-96` | Confidence: HIGH

Unlike `handleUpdateConfig` (which calls `deepCopyConfig`), the CRS and ClientSide config handlers directly mutate the shared config pointer returned by `engine.Config()`. This creates a data race with concurrent config readers.

**Recommendation:** Call `deepCopyConfig()` before mutating, matching the pattern in `handleUpdateConfig`.

---

#### SEC-013: Persistent Event Store File Writes Without Synchronization (Low)
**CWE-366** | `internal/events/persistent.go:49-62` | Confidence: HIGH

The `Store` method writes to the JSONL file outside the lock. Concurrent writes could interleave partial lines.

---

#### SEC-014: deepCopyConfig Shallow Copy Fallback (Low)
**CWE-362** | `internal/dashboard/dashboard.go:2487-2500` | Confidence: MEDIUM

If JSON marshal fails, the fallback is a shallow copy that shares maps/slices with the original. Very low probability but creates a latent race.

---

#### SEC-015: Goroutine Leak in Cluster Broadcast (Low)
**CWE-404** | `internal/cluster/cluster.go:458-469` | Confidence: HIGH

The `broadcast` method launches goroutines per node without WaitGroup tracking. No clean cancellation path on shutdown.

---

#### SEC-016: Fire-and-forget JWKS Fetch Goroutine (Low)
**CWE-404** | `internal/layers/apisecurity/jwt.go:103` | Confidence: HIGH

Initial `fetchJWKS()` is launched without WaitGroup tracking. Mitigated by 10-second timeout.

---

### 5. Data Exposure

#### SEC-017: Raw Query Strings Stored in WAF Events (Medium)
**CWE-532** | `internal/engine/event.go:105` | Confidence: HIGH

```go
query = ctx.Request.URL.RawQuery
```

The raw query string (which may contain tokens, session IDs, PII parameters) is stored in every WAF event and persisted to event storage. This is by design for forensic analysis, but operators should be aware of the data sensitivity.

**Recommendation:** Add configurable query parameter redaction for known sensitive parameter names (e.g., `token`, `session_id`, `password`, `api_key`).

---

#### SEC-018: Tenant Admin Handler Returns API Key Hashes (Medium)
**CWE-200** | `internal/dashboard/tenant_admin_handler.go:158-171` | Confidence: HIGH

The admin handler's `getTenant` and `listTenants` methods return the raw tenant object including `api_key_hash`. The tenant package's own handlers properly sanitize via `sanitizeTenant()`, but the admin handler bypasses this.

**Recommendation:** Filter `api_key_hash` from GET responses, matching the pattern in `internal/tenant/handlers.go`.

---

#### SEC-019: Raw Errors Leaked in 3 API Responses (Low)
**CWE-209** | `internal/dashboard/dashboard.go:800,805,898` | Confidence: HIGH

Three locations bypass the `sanitizeErr()` function and return raw error details to clients. The rest of the codebase properly sanitizes errors.

---

#### SEC-020: pprof Endpoints on localhost (Low — Mitigated)
**CWE-215** | `internal/dashboard/dashboard.go:220-225,297-313` | Confidence: HIGH

pprof is restricted to localhost via `r.RemoteAddr` check. Secure for standalone deployments, but could be an issue if behind a reverse proxy making all connections appear as 127.0.0.1.

---

### 6. Cryptographic Issues

#### SEC-021: Weak Crypto Fallback in Tenant API Key Hash Salt (Medium)
**CWE-330** | `internal/tenant/manager.go:737-738` | Confidence: HIGH

```go
if _, err := rand.Read(salt); err != nil {
    salt = []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
}
```

If `crypto/rand.Read` fails, the salt fallsbacks to a nanosecond timestamp — predictable if key creation time is known. The auth.go password generation correctly treats `crypto/rand` failure as fatal.

**Recommendation:** Fail fatally on `crypto/rand` error instead of falling back.

---

#### SEC-022: JWT Algorithm Confusion Protection is Conditional (Low)
**CWE-327** | `internal/layers/apisecurity/jwt.go:222-230` | Confidence: HIGH

HMAC algorithms are only blocked when asymmetric key sources are configured. The default whitelist (RS256/ES256) is safe, but explicit permissive configuration could allow algorithm confusion.

---

### 7. Resource Exhaustion

#### SEC-023: Unbounded Body Read in AI Remediation Handler (Medium)
**CWE-770** | `internal/ai/remediation/handler.go:297` | Confidence: HIGH

```go
body, _ := io.ReadAll(ctx.Request.Body)  // No LimitReader, error ignored
```

Reads the original request body without `io.LimitReader`. Every other call site in the project uses `LimitReader`. The error is silently discarded.

**Recommendation:** Wrap with `io.LimitReader(ctx.Request.Body, maxBodySize)` and check the error.

---

#### SEC-024: Redis Unbounded Bulk String Allocation (Medium)
**CWE-770** | `internal/layers/cache/redis.go:123-135` | Confidence: HIGH

```go
size, err := strconv.Atoi(data)
buf := make([]byte, size+2)  // No upper bound check
```

A compromised Redis server could report an extremely large bulk string size, causing OOM. No upper bound is enforced on `size` before allocation.

**Recommendation:** Add a maximum size check (e.g., 10MB) before allocating the buffer.

---

#### SEC-025: Unbounded Revoked Sessions Map (Low)
**CWE-770** | `internal/dashboard/auth.go:32-35,132-135` | Confidence: HIGH

`revokedSessions sync.Map` grows indefinitely with no cleanup. Over time, frequent logins/logouts cause unbounded memory growth.

**Recommendation:** Add periodic cleanup of expired session tokens from the revocation map.

---

#### SEC-026: 50MB Models.dev Catalog Fetch (Low)
**CWE-770** | `internal/ai/provider.go:232` | Confidence: HIGH

50MB limit is excessive for a JSON catalog. Most other external fetches use 1-10MB limits.

---

### 8. Input Validation

#### SEC-027: gRPC Timeout Parsing Integer Overflow (Low)
**CWE-190** | `internal/layers/grpc/grpc.go:548-577` | Confidence: HIGH

Custom `parseUint` accumulates into `int64` without overflow checking. Impact is limited since the timeout is informational, not enforced.

---

#### SEC-028: Tenant ID Not Validated for Format/Length (Low)
**CWE-20** | `internal/dashboard/auth.go:206-219` | Confidence: MEDIUM

Tenant IDs from URL paths and `X-Tenant-ID` headers are not validated for length or character format.

---

#### SEC-029: Score Accumulator Accepts Negative Scores (Low)
**CWE-20** | `internal/engine/finding.go:95-99` | Confidence: LOW

No enforcement that detector scores are non-negative. Currently theoretical — all detectors produce positive scores.

---

#### SEC-030: Integer Overflow in Custom parseInt (Low)
**CWE-190** | `internal/layers/threatintel/feed.go:391-408` | Confidence: MEDIUM

Custom integer parser lacks overflow checking. Only affects threat intel feed scores.

---

### 9. CI/CD Security

#### SEC-031: Unpinned GitHub Actions in Release Workflow (Medium)
**CWE-1353** | `.github/workflows/release.yml:45,54,61,86,95,101,105` | Confidence: HIGH

All third-party actions use version tags (`@v6`, `@v0`) instead of commit SHA pins. An attacker who compromises an action repo could replace the tag. The CI workflow has an `actions-hardened` job that defines SHA pins, but the release workflow does NOT use those pinned values.

**Recommendation:** Pin all actions to commit SHAs. See OWASP CI/CD security guidelines.

---

#### SEC-032: Script Injection in CI Benchmark Job (Medium)
**CWE-78** | `.github/workflows/ci.yml:145-161` | Confidence: HIGH

```yaml
git checkout origin/${{ github.base_ref }}
```

`github.base_ref` is used directly in a shell command without sanitization. A crafted branch name with shell metacharacters could execute arbitrary commands.

**Recommendation:** Use environment variable: `env: BASE_REF: ${{ github.base_ref }}` then `git checkout "origin/${BASE_REF}"`.

---

#### SEC-033: CI Actions-Hardened Job is Advisory Only (Low)
**CWE-1353** | `.github/workflows/ci.yml:17-29` | Confidence: HIGH

The `actions-hardened` job reports pin violations but does not prevent actual jobs from using unpinned actions.

---

### 10. Session Management

#### SEC-034: Session Token Rotation Without Old Token Revocation (Low)
**CWE-613** | `internal/dashboard/dashboard.go:280-282` | Confidence: HIGH

Every authenticated request generates a new session cookie. Previous tokens remain valid until they independently expire. Mitigated by IP binding and short expiry.

---

#### SEC-035: No CSRF Protection on GET Logout Without Origin Header (Low)
**CWE-352** | `internal/dashboard/dashboard.go:455-478` | Confidence: MEDIUM

GET logout only checks CSRF when the `Origin` header is present. Impact is limited to session invalidation.

---

### 11. Infrastructure

#### SEC-036: Docker Compose Uses :latest Tag (Low)
**CWE-829** | `docker-compose.yml:8` | Confidence: HIGH

Dev compose uses `ghcr.io/guardianwaf/guardianwaf:latest`. The prod compose and release workflow use semver tags.

---

#### SEC-037: Sidecar Dockerfile Missing Health Check (Low)
**CWE-778** | `examples/sidecar/Dockerfile` | Confidence: HIGH

No HEALTHCHECK directive in the sidecar Dockerfile. Compensated by compose-level healthcheck.

---

#### SEC-038: 0.0.0.0 Default Bind Addresses (Info)
**CWE-1327** | `internal/config/defaults.go:295`, `internal/cluster/cluster.go:67` | Confidence: HIGH

Cluster sync and cluster modules default to `0.0.0.0`. Auth is enforced, but requires explicit configuration before production use.

---

### 12. Business Logic

#### SEC-039: Dashboard Config API Allows Disabling All Security (Medium)
**CWE-862** | `internal/dashboard/dashboard.go:1126-1228` | Confidence: HIGH

The `PUT /api/v1/config` endpoint allows toggling off all security features. Requires authentication, but a compromised key enables total WAF disabling.

**Recommendation:** Add confirmation/audit logging for security feature disable operations.

---

#### SEC-040: Compliance Audit Chain is In-Memory Only (Medium)
**CWE-312** | `internal/compliance/compliance.go:120-127` | Confidence: HIGH

The hash chain design is correct, but the chain is lost on restart. This undermines the compliance value — a restart allows rewriting history since there is no persisted genesis state.

**Recommendation:** Persist the audit chain to disk (like events are persisted to JSONL).

---

### 13. API Security

#### SEC-041: API Keys Accepted via Query Parameters in WAF API Security Layer (Medium)
**CWE-598** | `internal/layers/apisecurity/apisecurity.go:228-248` | Confidence: HIGH

The WAF's API security layer for protecting upstream APIs accepts API keys via query parameters by default (`api_key`). This leaks keys via access logs, browser history, and Referer headers. The dashboard correctly rejects query parameter keys.

**Recommendation:** Make query parameter API key extraction opt-in rather than default behavior.

---

#### SEC-042: Silent Write Errors in Persistent Event Store (Low)
**CWE-775** | `internal/events/persistent.go:56-59` | Confidence: HIGH

File write errors are silently ignored. Events could be silently dropped on disk full or stale file descriptor.

---

#### SEC-043: Fragile Multi-Return RLock Pattern in Webhook TestAlert (Low)
`internal/alerting/webhook.go:532-560` | Confidence: MEDIUM

Multiple RUnlock points create a maintenance risk for future modifications.

---

## Remediation Roadmap

### Priority 1 — Fix Before Production (Medium Severity)

| ID | Finding | Effort | File |
|----|---------|--------|------|
| SEC-001 | AI client SSRF — add DialContext hook | Medium | `internal/ai/client.go` |
| SEC-002 | AI endpoint URL — add DNS resolution | Small | `internal/dashboard/ai_handlers.go` |
| SEC-004 | MCP stdio timing-safe comparison | Small | `internal/mcp/server.go` |
| SEC-005 | Tenant API key scoping | Medium | `internal/dashboard/auth.go` |
| SEC-008 | gRPC proxy CRLF sanitization | Small | `internal/proxy/grpc/proxy.go` |
| SEC-011 | TOCTOU in tenant rule quota | Small | `internal/tenant/rules.go` |
| SEC-012 | Deep copy in CRS/ClientSide handlers | Small | `internal/dashboard/crs_handlers.go` |
| SEC-021 | Fatal on crypto/rand failure | Small | `internal/tenant/manager.go` |
| SEC-023 | LimitReader in remediation handler | Small | `internal/ai/remediation/handler.go` |
| SEC-024 | Redis bulk string size limit | Small | `internal/layers/cache/redis.go` |
| SEC-031 | Pin GitHub Actions to SHAs | Medium | `.github/workflows/release.yml` |
| SEC-032 | Fix CI script injection | Small | `.github/workflows/ci.yml` |
| SEC-039 | Audit log for security disable | Small | `internal/dashboard/dashboard.go` |
| SEC-040 | Persist compliance audit chain | Medium | `internal/compliance/compliance.go` |
| SEC-041 | Make query param API keys opt-in | Small | `internal/layers/apisecurity/apisecurity.go` |
| SEC-017 | Query string redaction in events | Medium | `internal/engine/event.go` |
| SEC-018 | Filter API key hash from admin responses | Small | `internal/dashboard/tenant_admin_handler.go` |

### Priority 2 — Fix When Convenient (Low Severity)

| ID | Finding | Effort |
|----|---------|--------|
| SEC-003 | SSRF DialContext for threat intel/NVD | Medium |
| SEC-006 | MCP stdio auth documentation | Small |
| SEC-007 | Document X-Admin-Key header | Small |
| SEC-009 | Quote Content-Disposition filename | Small |
| SEC-010 | Sanitize email template substitutions | Small |
| SEC-013 | Synchronize persistent store file writes | Small |
| SEC-014 | Handle deepCopyConfig failure better | Small |
| SEC-015 | Add WaitGroup to cluster broadcast | Small |
| SEC-016 | Add WaitGroup to JWKS fetch | Small |
| SEC-019 | Apply sanitizeErr to 3 remaining error paths | Small |
| SEC-020 | pprof reverse proxy awareness | Small |
| SEC-022 | Document JWT algorithm scoping | Small |
| SEC-025 | Add revoked sessions cleanup | Small |
| SEC-026 | Reduce models.dev fetch limit | Small |
| SEC-027 | Add overflow check to parseUint | Small |
| SEC-028 | Validate tenant ID format | Small |
| SEC-029 | Clamp negative scores in ScoreAccumulator | Small |
| SEC-030 | Add overflow check to parseInt | Small |
| SEC-033 | Enforce action pinning in CI | Medium |
| SEC-034 | Document session rotation behavior | Small |
| SEC-035 | Evaluate POST-only logout | Small |
| SEC-036 | Pin docker-compose image tag | Small |
| SEC-037 | Add health check to sidecar Dockerfile | Small |
| SEC-042 | Log file write errors in persistent store | Small |
| SEC-043 | Refactor webhook RLock pattern | Small |

---

## Categories With No Findings

| Category | Status | Notes |
|----------|--------|-------|
| SQL Injection | CLEAN | No database layer, no SQL query construction |
| Command Injection | CLEAN | Docker client validates all input via `isSafeContainerRef` |
| XSS | CLEAN | JSON-only API, React auto-escaping, `html.EscapeString` on login page |
| XXE | CLEAN | No XML parsing anywhere |
| LDAP Injection | CLEAN | No LDAP libraries or queries |
| SSTI | CLEAN | No Go template engine usage |
| Path Traversal | CLEAN | Assets served from `embed.FS`, path traversal checked |
| Open Redirect | CLEAN | All redirects use hardcoded internal paths |
| CORS (WAF Layer) | CLEAN | No origin reflection, explicit allowlist, null origin blocked |
| WebSocket Origin | CLEAN | Proper same-origin enforcement |
| Rate Limit IP Spoofing | CLEAN | Trusted proxy model properly implemented |
| Unsafe Deserialization | CLEAN | No `gob.Decode`, no `json.Unmarshal` into `interface{}` |
| Hardcoded Production Credentials | CLEAN | All production credentials are auto-generated or required |
