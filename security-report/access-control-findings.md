# GuardianWAF Access Control Security Report

**Scan Date:** 2026-04-16
**Phase:** HUNT - ACCESS CONTROL
**Scope:** Authentication, Authorization, Session Management, Privilege Escalation, CORS

---

## Executive Summary

The GuardianWAF codebase implements layered access controls across three distinct service surfaces: the React dashboard (web UI + REST API), the MCP JSON-RPC server, and the multi-tenant WAF proxy layer. Most controls are implemented correctly with defense-in-depth. One high-severity gap was found: critical middleware (SecurityHeaders, CORS) is defined but **never applied** to the dashboard HTTP handler.

---

## 1. Authentication

### AUTH-001 | Dashboard Authentication | HIGH (Design)

The dashboard supports three authentication mechanisms (auth.go:249-283):

1. **Global X-API-Key header** - compared with subtle.ConstantTimeCompare
2. **Per-tenant API key** - scoped to /t/{tenant-id}/ path or X-Tenant-ID header
3. **HMAC-signed session cookie** - IP-bound, 24h sliding / 7d absolute expiry

Positives: crypto/rand failure causes fatal exit. Query param API keys rejected. Per-tenant keys scoped to tenant context only.

### AUTH-002 | Session Token Structure | INFORMATIONAL

Session format: timestamp.creation_timestamp.HMAC(timestamp.created:clientIP, secret)

IP binding prevents session cookie theft across different clients.

### AUTH-003 | MCP Server Authentication | MEDIUM

MCP uses stateful auth: client calls initialize with api_key in params, then tools/call checks s.checkAuth(). tools/list is also protected.

### AUTH-004 | Tenant Admin API - No Rate Limiting | HIGH

/api/v1/tenants endpoints require API key (X-API-Key or X-Admin-Key header). Uses subtle.ConstantTimeCompare.

CONCERN: No rate limiting. Brute-forcing the admin key has no per-IP limits.

### AUTH-005 | Tenant API Key Hashing | LOW

API keys stored as salt$hash (salted SHA-256). Legacy unsalted hashes auto-upgraded on first verification.

---

## 2. Authorization

### AUTH-006 | Admin Route Protection | INFORMATIONAL

/api/admin/* routes protected by isAdminAuthenticated(). Admin key set via Dashboard.SetAdminKey(). Separate credentials from user-facing API.

### AUTH-007 | Tenant Isolation | INFORMATIONAL

tenant/middleware.go Handler() resolves tenant on every request, checks active status, enforces quota. Resolution priority: API Key > Domain > Default tenant.

---

## 3. Session Management

### SESSION-001 | Cookie Security | INFORMATIONAL

Cookies: HttpOnly=true, Secure=true, SameSite=StrictMode, Path=/, MaxAge=24h (auth.go:286-299)

### SESSION-002 | Dual Expiry | INFORMATIONAL

24h sliding idle timeout + 7 day absolute maximum lifetime (auth.go:113-127)

### SESSION-003 | Concurrent Session Limit | INFORMATIONAL

MaxConcurrentSessionsPerIP = 5. Oldest sessions evicted when exceeded (auth.go:143-187)

### SESSION-004 | Server-Side Revocation | INFORMATIONAL

RevokeSession() adds to sync.Map; verifySession() checks it first (auth.go:129-141)

### SESSION-005 | Sliding Expiry Refresh | INFORMATIONAL

setSessionCookie() called on each authenticated request (dashboard.go:267-270)

---

## 4. Privilege Escalation

### PRIV-001 | Per-Tenant Key Scoping | INFORMATIONAL

Per-tenant API keys validated only against hash stored for that specific tenant ID. Cross-tenant access requires admin key.

### PRIV-002 | Tenant Resolution Priority | INFORMATIONAL

Priority: X-GuardianWAF-Tenant-Key > Domain match > Default tenant. No parameter confusion possible.

---

## 5. CORS

### CORS-001 | CORS Disabled | INFORMATIONAL

middleware.go CORSMiddleware: No Access-Control-Allow-Origin set. Cross-origin requests blocked by browser. Preflight only returns Allow-Methods/Headers.

### CORS-002 | handleCORS Dead Code | LOW

dashboard.go:1989 defines handleCORS registered on specific OPTIONS routes. Never wired via CORSMiddleware. Dead code.

---

## 6. CSRF Protection

### CSRF-001 | Same-Origin Verification | INFORMATIONAL

State-changing requests require X-API-Key header OR Origin/Referer matching Host. API key auth inherently CSRF-safe (dashboard.go:272-279).

---

## 7. Security Headers

### HEADERS-001 | SecurityHeadersMiddleware Never Applied | HIGH

DEFINED in middleware.go:54-74 but NEVER wired to dashboard handler in startDashboard().

Headers that should be set but are not:
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Content-Security-Policy
- Strict-Transport-Security
- Referrer-Policy
- Permissions-Policy

Impact: Dashboard responses lack all security headers. Must be set by external proxy.

---

## 8. Additional Observations

| # | Category | Finding | Severity |
|---|----------|---------|----------|
| 8.1 | Debug | pprof restricted to localhost (dashboard.go:285-301) | INFO |
| 8.2 | Brute Force | Login rate limiting: 5 attempts/5min, 15min lockout | INFO |
| 8.3 | SSRF | Webhook URL scheme validation (http/https only) | INFO |
| 8.4 | Injection | CSV formula injection prevention (dashboard.go:659-671) | INFO |
| 8.5 | Auth | MCP HTTP transport: processRequest does not enforce initialize auth | LOW |

---

## 9. Summary

| ID | Severity | Finding |
|----|----------|---------|
| HEADERS-001 | HIGH | SecurityHeadersMiddleware never applied to dashboard handler |
| AUTH-004 | HIGH | Tenant admin API lacks rate limiting |
| CORS-002 | LOW | handleCORS dead code |
| 8.5 | LOW | MCP HTTP transport auth gap |

**Good Security:**
- HMAC-signed IP-bound sessions with dual expiry
- HttpOnly/Secure/SameSite=Strict cookies
- Concurrent session limiting (max 5 per IP)
- Per-tenant API key scoping
- Same-origin CSRF verification
- pprof localhost-only restriction
- Login brute-force protection
- Webhook URL SSRF prevention
- CSV formula injection prevention

---

## 10. Recommendations

### Priority 1

1. **Apply SecurityHeadersMiddleware** in startDashboard() - wrap returned handler with SecurityHeadersMiddleware(RecoveryMiddleware(dash.Handler()))

2. **Wire CORSMiddleware globally** or remove handleCORS dead code for consistency

### Priority 2

3. **Add rate limiting** to /api/v1/tenants (tenant admin API) - use per-IP token bucket

4. **Wire RecoveryMiddleware** for panic safety

### Priority 3

5. Add auth check to MCP processRequest if HTTP transport is externally exposed
