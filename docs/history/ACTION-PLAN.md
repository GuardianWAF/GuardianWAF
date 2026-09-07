# GuardianWAF — Action Plan & Implementation Roadmap

**Based on:** COMPREHENSIVE-AUDIT.md findings  
**Date:** 2026-07-15  
**Version:** 0.4.0  
**Priority schema:** P0 (must address before release) → P1 (important) → P2 (enhancement) → P3 (strategic)

---

## Table of Contents

1. [How to use this plan](#1-how-to-use-this-plan)
2. [Work packages overview](#2-work-packages-overview)
3. [WP-01: Split dashboard.go](#3-wp-01-split-dashboardgo)
4. [WP-02: Login rate limiting](#4-wp-02-login-rate-limiting)
5. [WP-03: Test file consolidation](#5-wp-03-test-file-consolidation)
6. [WP-04: API key rotation endpoint](#6-wp-04-api-key-rotation-endpoint)
7. [WP-05: DeepCopy regeneration documentation](#7-wp-05-deepcopy-regeneration-documentation)
8. [WP-06: Legacy static dashboard deprecation](#8-wp-06-legacy-static-dashboard-deprecation)
9. [WP-07: Tenant-level rate limiting](#9-wp-07-tenant-level-rate-limiting)
10. [WP-08: REST API mutation audit logging](#10-wp-08-rest-api-mutation-audit-logging)
11. [WP-09: Docs/design cleanup](#11-wp-09-docsdesign-cleanup)
12. [WP-10: Dashboard dark/light theme toggle](#12-wp-10-dashboard-darklight-theme-toggle)
13. [WP-11: General code quality items](#13-wp-11-general-code-quality-items)
14. [WP-12: Strategic / long-term items](#14-wp-12-strategic--long-term-items)
15. [Dependency graph](#15-dependency-graph)
16. [Effort summary](#16-effort-summary)
17. [Risk register](#17-risk-register)

---

## 1. How to use this plan

Each work package below contains:

- **Goal** — what the completed task achieves
- **Rationale** — why it matters (linked to audit finding references)
- **Preconditions** — what must be done first
- **Implementation steps** — actionable, ordered sub-tasks
- **Files to modify / create**
- **Testing requirements** — how to validate success
- **Risks** — what could go wrong
- **Effort estimate** — in engineering hours

Work packages are ordered by priority (P0 → P3). Within each package, steps are ordered for execution. Some packages can run in parallel; the dependency graph in §15 shows which must be sequential.

---

## 2. Work packages overview

| ID | Title | Priority | Effort | Risk | Dependencies |
|---|---|---|---|---|---|
| WP-01 | Split dashboard.go | **P0** | 12–16h | Medium | None |
| WP-02 | Login rate limiting | **P0** | 3–5h | Low | None |
| WP-03 | Test file consolidation | **P1** | 8–12h | Medium | None |
| WP-04 | API key rotation endpoint | **P1** | 6–8h | Low | WP-01 (recommended) |
| WP-05 | DeepCopy regeneration docs | **P1** | 0.5–1h | None | None |
| WP-06 | Legacy static dashboard deprecation | **P2** | 2–3h | Low | WP-01 (recommended) |
| WP-07 | Tenant-level rate limiting | **P2** | 8–12h | Medium | WP-02 (depends concept) |
| WP-08 | REST API mutation audit logging | **P2** | 6–10h | Low | WP-01 (recommended) |
| WP-09 | Docs/design cleanup | **P2** | 2–3h | None | None |
| WP-10 | Dashboard dark/light theme toggle | **P2** | 4–6h | Low | None |
| WP-11 | General code quality items | **P1-P2** | 4–6h | Low | See per-item |
| WP-12 | Strategic / long-term items | **P3** | 40–80h | Varies | Foundation from WP-01/07 |

**Total estimated effort:** 95–162 hours (2.5–4 weeks for one engineer)

---

## 3. WP-01: Split dashboard.go

**Priority:** P0  
**Audit ref:** C1 (High — dashboard.go is 2,009 lines), C3 (inconsistent handler patterns)  
**Effort:** 12–16 hours  
**Risk:** Medium — refactor of a heavily-used file; regression risk in HTTP handler routing

### 3.1 Goal

Refactor `internal/dashboard/dashboard.go` from a ~2,009-line monolith into a coherent package structure with clear file boundaries and consistent handler patterns.

### 3.2 Rationale

The file mixes server setup, route registration, SSE handling, session management, event streaming, config CRUD, and three dozen API handlers. This hides dependencies, makes code review painful, and increases the risk of merge conflicts. It is the single highest-impact code quality improvement available.

### 3.3 Preconditions

- Full test suite passes before refactoring (`go test -race -count=1 ./...`)
- E2E tests pass (`make e2e-full` or equivalent)
- A `git stash` or branch point is created so we can bisect if something breaks

### 3.4 Implementation steps

**Phase A — Structural analysis (1h)**

1. Read `dashboard.go` end-to-end and catalog every exported symbol, handler function, route registration, and dependency
2. Identify natural groupings: server lifecycle, routing, SSE middleware, session/auth, event endpoints, config endpoints, stats endpoints, tenant endpoints, AI endpoints, SSL endpoints, Docker endpoints, cluster endpoints, compliance endpoints

**Phase B — Extract server lifecycle & config (2h)**

3. Create `internal/dashboard/server.go`
   - Move `Dashboard` struct definition
   - Move `NewDashboard()`, `Start()`, `Shutdown()`, `Close()`
   - Move any helper that deals with server setup (TLS config, address parsing)
4. Create `internal/dashboard/routes.go`
   - Move `registerRoutes()` and any route-helper functions
   - Keep route registration in one file so the URL space is reviewable at a glance

**Phase C — Extract middleware & SSE (2h)**

5. Create `internal/dashboard/middleware.go`
   - Move `isAuthenticated()`, `requestFromTrustedProxy()`, `secureCookieForRequest()`
   - Keep the typed-context auth helpers (`setAuthInfo`, `getAuthType`, `tenantScope`)
6. Create `internal/dashboard/sse.go`
   - Move SSE broker, event broadcasting, client management
   - Keep the SSE endpoint handler that wires into routes

**Phase D — Extract handler groups (5h)**

7. Create `internal/dashboard/handlers/stats_handlers.go`
   - Move `handleStats`, `handleUpstreams`, latency handlers
8. Create `internal/dashboard/handlers/event_handlers.go`
   - Move `handleEvents`, `handleEventDetail`, `handleSSE` (wiring)
9. Create `internal/dashboard/handlers/config_handlers.go`
   - Move `handleConfigGet`, `handleConfigUpdate`, `handleConfigBackup`
   - Merge content from the existing `config_handlers.go` if it exists
10. Create `internal/dashboard/handlers/tenant_handlers.go`
    - Move tenant CRUD handlers, usage handlers, billing handlers
11. Create `internal/dashboard/handlers/security_handlers.go`
    - Move `handleLogin`, `handleLogout`, `handleRotateKey` (future), API key management

**Phase E — Norm enforcement (1h)**

12. Audit all handlers for a consistent signature pattern
    - Decision: prefer methods on `*Dashboard` when they need server state; standalone functions with explicit dependency injection when stateless
    - Update any inline closures in `registerRoutes()` to call named handlers
13. Ensure no handler file imports `dashboard` package (no circular deps)

**Phase F — Regroup what remains in dashboard.go (1h)**

14. What's left in `dashboard.go` after extraction should be <200 lines: package doc, init helpers, type aliases, embedded FS declarations. Rename the file to `dashboard_core.go` or keep the name as a stub.

### 3.5 Files to modify / create

| File | Action |
|---|---|
| `internal/dashboard/dashboard.go` | Shrink to ~200 lines (core types + embedded FS) |
| `internal/dashboard/server.go` | **Create** — server lifecycle |
| `internal/dashboard/routes.go` | **Create** — URL route registration |
| `internal/dashboard/middleware.go` | **Create** — auth middleware |
| `internal/dashboard/sse.go` | **Create** — SSE broker |
| `internal/dashboard/handlers/stats_handlers.go` | **Create** |
| `internal/dashboard/handlers/event_handlers.go` | **Create** |
| `internal/dashboard/handlers/config_handlers.go` | **Create** (merge existing) |
| `internal/dashboard/handlers/tenant_handlers.go` | **Create** |
| `internal/dashboard/handlers/security_handlers.go` | **Create** |

### 3.6 Testing requirements

- `go test -race -count=1 ./internal/dashboard/...` — zero regressions
- All existing dashboard tests pass without modification (they import `dashboard` package)
- CI coverage does not drop below 95% project / 90% patch
- Manual E2E smoke test: dashboard login, stats page, config page, SSE events, tenant CRUD
- **Critical check:** every route registered before the refactor must still be registered after. Write a regression test (`TestAllRoutesRegistered`) that iterates `registerRoutes()` output and asserts the complete set of method+path pairs.

### 3.7 Risks

| Risk | Mitigation |
|---|---|
| Missing a route during extraction | Write the `TestAllRoutesRegistered` assertion *before* starting the refactor |
| Circular imports between handler files | Plan the dependency structure first; handlers import `Dashboard` struct, not vice versa |
| Merge conflicts with in-flight PRs | Communicate with the team; schedule this refactor in a dedicated window |
| Coverage drop from moved code | The code is moved, not changed — coverprofile should be unaffected. Run `make cover` after |

---

## 4. WP-02: Login rate limiting

**Priority:** P0  
**Audit ref:** S2 (Medium — no dashboard login rate limiting)  
**Effort:** 3–5 hours  
**Risk:** Low — self-contained feature using existing infrastructure

### 4.1 Goal

Add per-IP rate limiting with exponential backoff to the dashboard `/login` POST endpoint so brute-force attacks against dashboard API keys are mitigated.

### 4.2 Rationale

The login handler returns 403 on bad credentials but has no rate limiting or account lockout. An attacker with network access to the dashboard port (default 9443) can try credentials indefinitely. The `ratelimit` package (token bucket) already exists in the codebase — this is wiring it into the login flow.

### 4.3 Preconditions

- Understand the existing `internal/layers/ratelimit/` package API (token bucket)
- Identify where login state is tracked (currently stateless; need an in-memory failure tracker)

### 4.4 Implementation steps

1. **Create `internal/dashboard/login_ratelimit.go`** with:
   - An in-memory per-IP failure counter with configurable window (e.g., 5 failures in 60s)
   - Exponential backoff: after the window, cooldown doubles: 1s, 2s, 4s, 8s, … up to a max (e.g., 5min)
   - `sync.Map` or `sync.RWMutex`-guarded map for concurrent access
   - Periodic cleanup goroutine to evict expired entries (prevent memory leak)

2. **Wire into login handler** (`dashboard.go` — currently inline in `registerRoutes` or `handleLogin`):
   - Before credential verification, check the IP-based rate limiter
   - If rate-limited, return `429 Too Many Requests` with `Retry-After` header
   - On successful login, reset the failure counter for that IP
   - On failed login, increment the failure counter

3. **Add configuration fields** to `DashboardConfig` in `internal/config/config.go`:
   ```yaml
   dashboard:
     login_rate_limit:
       enabled: true
       max_attempts: 5
       window_seconds: 60
       ban_duration_minutes: 5
   ```

4. **Add tests:**
   - Unit test: rapid requests from same IP → blocked after N attempts
   - Unit test: different IPs are independently tracked
   - Unit test: successful login resets counter
   - Unit test: cleanup goroutine evicts expired entries

### 4.5 Files to modify / create

| File | Action |
|---|---|
| `internal/dashboard/login_ratelimit.go` | **Create** |
| `internal/dashboard/dashboard.go` (or split target) | Wire limiter into login handler |
| `internal/config/config.go` | Add `LoginRateLimit` config struct |
| `internal/config/defaults.go` | Add defaults for login rate limit |
| `internal/config/validate.go` | Add validation for login rate limit config |

### 4.6 Testing requirements

- New unit tests covering rate limit logic (above)
- Existing dashboard auth tests still pass
- E2E test: repeated bad logins return 429 after threshold

### 4.7 Risks

| Risk | Mitigation |
|---|---|
| IP spoofing through X-Forwarded-For | Use the same trusted-proxy-aware client IP extraction as the rest of the dashboard |
| Memory leak from failed-login map | Periodic cleanup goroutine with configurable TTL |
| Lock contention on login map | Use `sync.Map` for the top-level (IP → data) map; per-entry mutex for atomic increment+check |

---

## 5. WP-03: Test file consolidation

**Priority:** P1  
**Audit ref:** C2 (Medium — 58+ test padding files), T1 (Medium — not adding real coverage breadth)  
**Effort:** 8–12 hours  
**Risk:** Medium — deleting test files could confuse coverage tooling or miss edge cases

### 5.1 Goal

Reduce the ~58 `*_coverage_test.go` and `*_extra_test.go` files by merging their content into primary test files. Target: ≤ 10 dedicated padding files with clear documentation of what they cover.

### 5.2 Rationale

The sheer number of test padding files makes it hard to find tests by name, inflates `find`/`grep` output, and obscures which tests are actually meaningful. Many of these files exist solely to call functions at the package boundary to satisfy coverage thresholds. They should either be merged into the existing test files or documented as intentional coverage gap-fillers.

### 5.3 Preconditions

- Run `go test -coverprofile=coverage.txt -covermode=atomic ./...` to establish baseline coverage
- Generate a list of all `*_coverage_test.go` and `*_extra_test.go` files grouped by package

### 5.4 Implementation steps

**Phase A — Inventory (1h)**

1. Run: `find . -name '*_coverage_test.go' -o -name '*_extra_test.go' | sort > test-padding-files.txt`
2. For each file, categorize:
   - **Mergable** — contains test functions that logically belong in the primary test file
   - **Edge-case coverage** — contains tests that call obscure code paths; can be merged or left as named files
   - **Generated or deprecated** — can be deleted outright

**Phase B — Merge (6h)**

3. For each package, consolidate mergable content:
   - Move test functions to the primary `*_test.go` file in the same package
   - Rename tests to follow the existing naming convention in the target file
   - Do not rewrite test logic — preserve exact assertions

4. For edge-case coverage files that cannot be merged without making the primary test file too large:
   - Rename to a descriptive name: e.g., `ratelimit_boundary_test.go` instead of `ratelimit_extra_test.go`
   - Add a top-of-file comment: `// Package ratelimit boundary and edge-case tests.`

5. Delete files whose coverage is already covered by merged tests or whose existence is purely vestigial

**Phase C — Verify coverage (1h)**

6. Run `go test -coverprofile=coverage2.txt -covermode=atomic ./...`
7. Compare `coverage.txt` (before) with `coverage2.txt` (after):
   - Project-level coverage must not drop below baseline minus 0.5% (to account for deleted test-only code)
   - If it drops, identify the gap and add a targeted test

### 5.5 Files to modify / create

| Action | Count |
|---|---|
| Delete files | ~30–40 |
| Rename files | ~5–10 |
| Merge into primary test files | ~10–15 |
| New descriptive test files | ~3–5 |

### 5.6 Testing requirements

- `go test -race -count=1 ./...` passes
- Project coverage stays within 0.5% of baseline
- CI coverage gate (95% project, 90% patch) does not trigger a failure

### 5.7 Risks

| Risk | Mitigation |
|---|---|
| Deleting a test file removes coverage for a non-obvious code path | Run coverage comparison before/after; investigate any drop > 0.5% |
| Merge creates duplicate test names | Check for name collisions during merge. Append descriptive suffixes |
| CI coverage gate fails after deletion | Temporarily adjust threshold or add targeted tests before merging PR |

---

## 6. WP-04: API key rotation endpoint

**Priority:** P1  
**Audit ref:** S3 (Medium — no dashboard API key rotation)  
**Effort:** 6–8 hours  
**Risk:** Low — new endpoint with no backwards-compatibility impact

### 6.1 Goal

Add `POST /api/v1/rotate-key` so operators can change the dashboard API key without restarting the process.

### 6.2 Rationale

The dashboard API key is stored in an unencrypted string field set at startup. There is no runtime mechanism to rotate it. If the key is compromised, the operator must restart the entire WAF process — causing a brief window of reduced protection. An online rotation endpoint allows key rotation with zero downtime.

### 6.3 Preconditions

- `Dashboard.apiKey` must be changed from a plain string to an `atomic.Value` for thread-safe hot-swap
- The old key must remain valid for a configurable grace period (default: 60 seconds) during rotation

### 6.4 Implementation steps

1. **Refactor key storage** in `internal/dashboard/dashboard.go`:
   ```go
   // Before
   type Dashboard struct {
       apiKey string  // set at startup, never changed
       ...
   }
   
   // After
   type Dashboard struct {
       apiKey atomic.Value // stores apiKeyHolder
       ...
   }
   
   type apiKeyHolder struct {
       Current   string
       Previous  string        // valid for grace period
       ExpiresAt time.Time     // when Previous expires
   }
   ```
   - Update all reads of `d.apiKey` to load from `d.apiKey.Load().(apiKeyHolder).Current`
   - Update `isAuthenticated()` to check both Current and (if within grace) Previous

2. **Add rotation endpoint** handler:
   - Accepts: `{"current_key": "...", "new_key": "..."}` in POST body
   - Validates `current_key` matches the stored `Current` key (constant-time compare)
   - Validates `new_key` meets minimum length requirements (>= 16 chars)
   - Atomically swaps: `Previous = Current`, `Current = new_key`, sets expiry
   - Returns 200 on success, 403 on wrong current key, 400 on bad new key

3. **Register route** in `registerRoutes()`:
   ```go
   mux.HandleFunc("POST /api/v1/rotate-key", d.handleRotateKey)
   ```

4. **Add tests:**
   - Unit test: rotate with correct current key succeeds
   - Unit test: rotate with wrong current key returns 403
   - Unit test: old key still works within grace period
   - Unit test: old key stops working after grace period
   - Unit test: concurrent rotations don't race

### 6.5 Files to modify / create

| File | Action |
|---|---|
| `internal/dashboard/dashboard.go` | Refactor `apiKey` to `atomic.Value` |
| `internal/dashboard/auth.go` | Update `isAuthenticated()` for two-key check |
| `internal/dashboard/handlers/security_handlers.go` | **Create** (or add to existing handlers file) |
| `internal/dashboard/routes.go` | Add route registration |
| `internal/dashboard/dashboard_test.go` | Add rotation tests |

### 6.6 Testing requirements

- All existing auth tests pass (no regressions from `atomic.Value` refactor)
- New rotation unit tests cover success, failure, and grace period
- E2E test: curl API key rotation, verify old key stops working after grace

### 6.7 Risks

| Risk | Mitigation |
|---|---|
| Race between rotation and active request | `atomic.Value` swap is atomic; old key remains valid for grace period |
| Key stored in plaintext in memory | Acceptable for in-memory secrets; add a doc note for compliance contexts |

---

## 7. WP-05: DeepCopy regeneration documentation

**Priority:** P1  
**Audit ref:** D2 (Low — no DeepCopy regeneration documented)  
**Effort:** 0.5–1 hour  
**Risk:** None

### 7.1 Goal

Document how to regenerate `internal/config/deepcopy_generated.go` so config changes don't silently miss a DeepCopy method.

### 7.2 Rationale

The DeepCopy methods are generated by `tools/deepcopy/main.go` but the generated file is committed. If a developer adds a new field to a config struct without regenerating, the DeepCopy method silently produces a shallow copy — leading to shared-pointer bugs. A documented regeneration workflow prevents this.

### 7.3 Implementation steps

1. Add a comment header to `internal/config/deepcopy_generated.go`:
   ```go
   // Code generated by tools/deepcopy; DO NOT EDIT.
   // Regenerate after adding fields to config structs:
   //   cd tools/deepcopy && go run . > ../../internal/config/deepcopy_generated.go
   ```

2. Add a `Makefile` target:
   ```makefile
   .PHONY: generate-deepcopy
   generate-deepcopy:
   	cd tools/deepcopy && go run . > ../../internal/config/deepcopy_generated.go
   	$(MAKE) fmt
   ```

3. (Optional) Add a CI check that regenerates and diffs, failing if the output changed. This is gated behind a `GENERATE_DEEPCOPY=1` env var to avoid requiring the tool on every build.

### 7.4 Files to modify

| File | Action |
|---|---|
| `internal/config/deepcopy_generated.go` | Add generated-code header with regeneration instructions |
| `Makefile` | Add `generate-deepcopy` target |
| `CLAUDE.md` or `CONTRIBUTING.md` | Optionally mention the target |

---

## 8. WP-06: Legacy static dashboard deprecation

**Priority:** P2  
**Audit ref:** C4 (Low — static dashboard HTML/JS files not deprecated)  
**Effort:** 2–3 hours  
**Risk:** Low

### 8.1 Goal

Deprecate the legacy static dashboard files (`static/index.html`, `static/style.css`, `static/app.js`, `static/config.html`, `static/config.js`, `static/routing.html`, `static/routing.js`) and schedule their removal.

### 8.2 Rationale

These files exist alongside the React SPA for backward compatibility but are maintenance debt. They use manual DOM manipulation patterns, are not tested, and their continued presence confuses contributors about which UI is the canonical one.

### 8.3 Implementation steps

1. **Add deprecation banner** to each legacy HTML file:
   ```html
   <!--
     DEPRECATED: This page is replaced by the React dashboard at /
     It will be removed in v0.6.0. Please migrate to the new dashboard.
   -->
   ```
   And in the rendered UI (visible to users):
   ```html
   <div style="background:#7f1d1d;color:#fca5a5;padding:12px;text-align:center;border-radius:8px;margin:16px">
     ⚠️ This legacy dashboard page is deprecated. Use the <a href="/" style="color:#60a5fa">new dashboard</a> instead.
   </div>
   ```

2. **Update serving logic** to serve the React SPA's `index.html` at `/config` and `/routing` paths with a redirect notice (or a simple redirect to `/?redirect=/config` with a query parameter the React app can read).

3. **Add a CHANGELOG entry** announcing the deprecation and timeline (`v0.6.0` removal target).

4. **Add tracking** — wire the legacy `<meta name="deprecated-page" content="true">` detection into the dashboard's telemetry (if any) so operators know if anyone still uses the legacy pages.

### 8.4 Files to modify

| File | Action |
|---|---|
| `internal/dashboard/static/index.html` | Add deprecation banner |
| `internal/dashboard/static/config.html` | Add deprecation banner |
| `internal/dashboard/static/routing.html` | Add deprecation banner |
| `internal/dashboard/spa_handlers.go` (or dashboard.go) | Update serving/redirect logic |
| `CHANGELOG.md` | Add deprecation notice |

### 8.5 Testing

- Legacy URLs (`/config`, `/routing`) still serve content (with deprecation banner)
- React SPA still serves at `/`
- No 404s introduced for anyone still linking to legacy pages

---

## 9. WP-07: Tenant-level rate limiting

**Priority:** P2  
**Audit ref:** Section 9.2 (no tenant-level rate limiting)  
**Effort:** 8–12 hours  
**Risk:** Medium — touches rate-limiting core and multi-tenant config

### 9.1 Goal

Extend the rate limiter to support per-tenant token buckets so a noisy tenant cannot exhaust rate-limit budget for other tenants.

### 9.2 Rationale

The current rate limiter is global. In a multi-tenant deployment, one tenant's burst traffic can starve all other tenants. Extending to per-tenant buckets provides fair resource distribution.

### 9.3 Preconditions

- WP-02 completed (conceptual foundation — per-IP login rate limiting)
- Understanding of the existing `ratelimit` package: `Bucket`, `Config`, `NewLayer`

### 9.4 Implementation steps

1. **Extend `ratelimit.Config`** to support per-tenant mode:
   ```go
   type Config struct {
       Enabled      bool           `yaml:"enabled"`
       Rate         int            `yaml:"rate"`
       Burst        int            `yaml:"burst"`
       PerTenant    bool           `yaml:"per_tenant"`    // new
       TenantRate   int            `yaml:"tenant_rate"`   // new — per-tenant rate
       TenantBurst  int            `yaml:"tenant_burst"`  // new — per-tenant burst
   }
   ```

2. **Implement `TenantBucketStore`** in the `ratelimit` package:
   - `sync.Map` of tenant ID → `*Bucket`
   - On first request for a tenant, create a new bucket with `TenantRate`/`TenantBurst`
   - Fallback to global bucket when PerTenant is false (preserving existing behavior)
   - Periodic cleanup of idle tenant buckets (configurable TTL)

3. **Wire tenant context** into the rate limit layer:
   - The layer already has access to `ctx.TenantID`
   - Look up the tenant bucket when `PerTenant` is true

4. **Add tests:**
   - Unit test: two tenants don't interfere under per-tenant mode
   - Unit test: global mode is unchanged (regression)
   - Unit test: tenant bucket cleanup expires idle entries
   - Unit test: fallback to global when per-tenant is false

### 9.5 Files to modify / create

| File | Action |
|---|---|
| `internal/layers/ratelimit/ratelimit.go` | Extend `Config`, add `TenantBucketStore` |
| `internal/layers/ratelimit/bucket.go` | (unchanged — bucket logic is reusable) |
| `internal/config/config.go` | Add `PerTenant`, `TenantRate`, `TenantBurst` fields |
| `internal/config/validate.go` | Add validation for new fields |
| `internal/config/defaults.go` | Add defaults |

### 9.6 Risks

| Risk | Mitigation |
|---|---|
| Memory leak from unbounded tenant buckets | Idle bucket cleanup with configurable TTL |
| Performance cost of per-request tenant bucket lookup | `sync.Map` load is ~O(1); benchmark before/after |
| Existing single-tenant deployments see no change | `PerTenant: false` preserves exact existing behavior |

---

## 10. WP-08: REST API mutation audit logging

**Priority:** P2  
**Audit ref:** Section 14.5 (no structured audit logging for dashboard REST API mutations)  
**Effort:** 6–10 hours  
**Risk:** Low

### 10.1 Goal

Add structured audit logging for all mutating REST API endpoints (config changes, tenant CRUD, rule changes, etc.) so operators have an immutable audit trail of who changed what and when.

### 10.2 Rationale

Currently only MCP mutating tool calls are audit-logged. Dashboard REST API mutations (config CRUD, tenant operations, rule updates) are not. For a security appliance that itself enforces policy, having an audit trail of configuration changes is a compliance requirement (SOC 2, ISO 27001, etc.).

### 10.3 Preconditions

- WP-01 (split dashboard.go) — much easier to add middleware to a `routes.go` file
- Understand the existing `AuditContext` pattern from `internal/mcp/server.go`

### 10.4 Implementation steps

1. **Create `internal/dashboard/audit.go`** with:
   ```go
   type AuditEntry struct {
       Timestamp   time.Time
       Method      string // HTTP method
       Path        string // request path
       AuthType    string // session / global_key / tenant_key
       Principal   string // "admin" for session/global, tenant ID for tenant key
       RemoteAddr  string
       Mutation    string // descriptive: "update_waf_config", "delete_tenant", etc.
       Payload     string // truncated request body (PII-safe)
       StatusCode  int
   }
   
   // AuditLog is a ring buffer of recent audit entries.
   type AuditLog struct { ... }
   ```

2. **Add audit middleware** that wraps mutating handlers:
   ```go
   func (d *Dashboard) auditMiddleware(next http.Handler) http.Handler {
       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
           // Only audit mutating methods
           if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
               next.ServeHTTP(w, r)
               return
           }
           // Read body (for logging) — need to restore it for the handler
           body, _ := io.ReadAll(r.Body)
           r.Body = io.NopCloser(bytes.NewReader(body))
           
           // Wrap ResponseWriter to capture status code
           mw := &statusCaptureWriter{ResponseWriter: w}
           next.ServeHTTP(mw, r)
           
           // Log after handler executes
           d.auditLog.Append(AuditEntry{
               Timestamp:  time.Now(),
               Method:     r.Method,
               Path:       r.URL.Path,
               AuthType:   getAuthType(r),
               Principal:  extractPrincipal(r),
               RemoteAddr: r.RemoteAddr,
               Mutation:   classifyMutation(r),
               Payload:    truncateAuditPayload(string(body)),
               StatusCode: mw.statusCode,
           })
       })
   }
   ```

3. **Register middleware** in `registerRoutes()` — wrap all mutating routes or use a sub-router with the middleware applied.

4. **Wire config validation** — ensure the audit log is available at `GET /api/v1/audit` for authorized users (dashboard admins only, not tenant keys).

5. **Add tests:**
   - Unit test: GET request is not logged
   - Unit test: POST/PUT/DELETE requests are logged
   - Unit test: audit endpoint returns log entries
   - Unit test: tenant-scoped key cannot access audit log

### 10.5 Files to modify / create

| File | Action |
|---|---|
| `internal/dashboard/audit.go` | **Create** — `AuditEntry`, `AuditLog`, `auditMiddleware` |
| `internal/dashboard/routes.go` | Wire middleware into routes |
| `internal/dashboard/auth.go` | Add `extractPrincipal()` helper |
| `internal/config/config.go` | Optionally add `audit_log_max_entries` config |

---

## 11. WP-09: Docs/design cleanup

**Priority:** P2  
**Audit ref:** D3 (Low — docs/design/ partially out of date)  
**Effort:** 2–3 hours  
**Risk:** None

### 11.1 Goal

Clean up the `docs/design/` directory by archiving out-of-date planning documents and adding timestamps to point-in-time assessments.

### 11.2 Rationale

The `docs/design/` directory contains early planning documents (`SPECIFICATION.md`, `IMPLEMENTATION.md`, `TASKS.md`) that no longer reflect the codebase accurately. Leaving them as-is misleads new contributors about the current state. Meanwhile, point-in-time documents like `production-readiness-report.md` lack a date, making it unclear whether they're current.

### 11.3 Implementation steps

1. **Archive planning documents:**
   - Move `SPECIFICATION.md`, `IMPLEMENTATION.md`, `TASKS.md` to `docs/design/archive/`
   - Add a `docs/design/archive/README.md` with:
     ```markdown
     # Archived Design Documents
     
     The files in this directory are historical design documents from GuardianWAF's
     early development. They may not reflect the current codebase.
     
     - **SPECIFICATION.md** — Original product specification (pre-v0.1.0)
     - **IMPLEMENTATION.md** — Implementation plan (pre-v0.1.0)
     - **TASKS.md** — Early task breakdown (pre-v0.1.0)
     
     For current documentation, see:
     - [docs/ARCHITECTURE.md](../ARCHITECTURE.md)
     - [docs/configuration.md](../configuration.md)
     - [docs/api-reference.md](../api-reference.md)
     ```

2. **Add metadata to point-in-time docs:**
   - `docs/production-readiness-report.md`: Add a header with date and version
   - `docs/production-deployment.md`: Add a last-reviewed date

3. **Update ADR README index:**
   - Add a table of contents linking all 45 ADRs
   - Group by theme: Architecture, Security, Performance, Ops

### 11.4 Files to modify

| File | Action |
|---|---|
| `docs/design/SPECIFICATION.md` | Move to `docs/design/archive/` |
| `docs/design/IMPLEMENTATION.md` | Move to `docs/design/archive/` |
| `docs/design/TASKS.md` | Move to `docs/design/archive/` |
| `docs/design/archive/README.md` | **Create** |
| `docs/adr/README.md` | Add table of contents |
| `docs/production-readiness-report.md` | Add date+version header |

---

## 12. WP-10: Dashboard dark/light theme toggle

**Priority:** P2  
**Audit ref:** Section 6.2 (no dark/light toggle in React SPA)  
**Effort:** 4–6 hours  
**Risk:** Low

### 12.1 Goal

Add a dark/light theme toggle to the React dashboard SPA, using the CSS variables already defined in the static CSS and applying them via Tailwind v4's `@custom-variant dark` approach.

### 12.2 Rationale

The static CSS has both dark and light theme variables (`:root` for dark, commented sections for light), but the React SPA has no UI control to switch between them. Operators may prefer light mode during the day or have accessibility needs that one theme cannot satisfy.

### 12.3 Implementation steps

1. **Add theme variables to `index.css`** in the React app:
   ```css
   :root {
     /* Dark theme (default) */
     --bg-primary: #0f172a;
     --text-primary: #f1f5f9;
     /* ... all other dark tokens ... */
   }
   
   .light {
     /* Light theme overrides */
     --bg-primary: #f8fafc;
     --text-primary: #0f172a;
     /* ... light overrides ... */
   }
   ```
   (The existing `internal/dashboard/static/style.css` has these already; adapt for the React SPA's Tailwind v4 theme system.)

2. **Create theme context** (`src/hooks/use-theme.ts`):
   ```typescript
   type Theme = 'dark' | 'light'
   
   function getInitialTheme(): Theme {
     const stored = localStorage.getItem('gwaf-theme')
     if (stored === 'light' || stored === 'dark') return stored
     return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
   }
   
   export function useTheme() {
     const [theme, setTheme] = useState<Theme>(getInitialTheme)
     
     useEffect(() => {
       document.documentElement.classList.toggle('light', theme === 'light')
       localStorage.setItem('gwaf-theme', theme)
     }, [theme])
     
     return { theme, toggle: () => setTheme(t => t === 'dark' ? 'light' : 'dark') }
   }
   ```

3. **Add toggle button to the header/layout component**:
   - Use a `Sun`/`Moon` icon from `lucide-react`
   - Place in the dashboard header alongside existing controls

4. **Update Tailwind v4 theme** (`src/index.css`) to use OKLCH design tokens and ensure both themes have sufficient contrast (4.5:1 WCAG AA minimum).

5. **Add tests:**
   - Unit test: theme toggle persists to localStorage
   - Unit test: theme toggle adds/removes `.light` class
   - Unit test: respects `prefers-color-scheme` on initial load

### 12.4 Files to modify / create

| File | Action |
|---|---|
| `internal/dashboard/ui/src/index.css` | Add light theme variables |
| `internal/dashboard/ui/src/hooks/use-theme.ts` | **Create** |
| `internal/dashboard/ui/src/components/layout/header.tsx` | Add toggle button |
| `internal/dashboard/ui/src/components/layout/layout.tsx` | Wire theme context if needed |

---

## 13. WP-11: General code quality items

**Priority:** P1–P2  
**Effort:** 4–6 hours total

This section groups smaller code quality findings that don't warrant a full work package.

### 13.1 Startup warning for `allow_private_upstreams: true`

**Audit ref:** S4  
**Effort:** 30 min

Add a warning log line in `cmd/guardianwaf/serve_lifecycle.go` when the config has `allow_private_upstreams: true` AND `mode: enforce`:

```go
if cfg.AllowPrivateUpstreams != nil && *cfg.AllowPrivateUpstreams && cfg.Mode == "enforce" {
    slog.Warn("allow_private_upstreams is true in enforce mode — " +
        "the WAF can proxy requests to private IP ranges. " +
        "Set to false in production unless required.")
}
```

### 13.2 Sanitizer fallback documentation

**Audit ref:** Section 4.3  
**Effort:** 30 min

Add a doc comment to `RequestContext` in `internal/engine/context.go` (or to the `Detector` interface) documenting the fallback pattern:

```go
// IMPORTANT FOR DETECTOR DEVELOPERS:
// Normalized* fields (NormalizedPath, NormalizedQuery, NormalizedBody,
// NormalizedHeaders) are populated by the sanitizer layer (Order 300).
// When the sanitizer is disabled or has not run, these fields are empty.
// Always fall back to the raw fields (Path, QueryParams, BodyString,
// Headers) when the normalized variant is empty. See sqli.Detector.Process
// for the canonical pattern:
//
//     path := ctx.NormalizedPath
//     if path == "" {
//         path = ctx.Path
//     }
```

### 13.3 Staticcheck QF1 re-evaluation

**Audit ref:** Section 3.3  
**Effort:** 30 min

Review the exclusion for `QF1` in `.golangci.yml`:

1. Temporarily enable QF1 and run `golangci-lint run ./...`
2. Evaluate the suggestions. If most are genuinely cleaner code (not stylistic churn), remove the exclusion and fix the findings.
3. If the bulk is noise/churn, add a comment explaining the decision more thoroughly.

### 13.4 `tenantManagerInterface` type safety

**Audit ref:** Section 9.2  
**Effort:** 2–3h

The `tenantManagerInterface` in `dashboard.go` uses `[]any` and `map[string]any` extensively. Replace these with typed interfaces or concrete types:

- Define `TenantInfo`, `TenantUsage`, `TenantInvoice` as concrete structs in a shared `types` package or `internal/tenant/`
- Update the interface methods to return `TenantInfo`, `TenantUsage`, etc.
- Update callers to use the typed results instead of type-asserting from `any`

This is a breaking change within the internal package but has no external API impact.

---

## 14. WP-12: Strategic / long-term items

**Priority:** P3  
**Audit ref:** Section 16 (P3 recommendations 11–14)  
**Effort:** 40–80 hours total (across all items)

These are long-term strategic improvements that should be evaluated for a future major version.

### 14.1 DeepCopy code generation tool upgrade

**Goal:** Replace the hand-written `tools/deepcopy/main.go` with a more robust solution.
**Options:**
- Extend the existing tool to support nested generics and interface types
- OR relax the zero-dep constraint to use `goverter` or `jinzhu/copier`
- OR use `go generate` with `reflect`-based deep copy

**Decision needed:** Is the zero-dependency constraint absolute, or does it only apply to runtime deps? If build-time codegen tools are acceptable, a `go:generate` solution is simplest.

### 14.2 Layer execution graph

**Goal:** Replace the flat ordered-layer list with a dependency graph so layers can declare what they depend on and what they provide.

**Design sketch:**
```go
type LayerNode struct {
    Layer          Layer
    DependsOn      []string // layer names
    Provides       []string // capabilities (e.g., "sanitization", "normalized_body")
    Order          int      // fallback sort order when no deps
}
```

**Benefits:**
- Detection layers could depend on `"sanitization"` and automatically be ordered after the sanitizer
- Disabling a layer could cascade-disable dependents
- New layers could be inserted without manual order number management

**Downside:** Significant refactor of `Pipeline`, `Engine`, and `LayerRegistry`. Recommend for v1.0.

### 14.3 Mock-based integration tests

**Goal:** Move integration tests from live-server-dependent to mock-based so they run as part of `go test ./...`.

**Approach:**
- Create a `testengine` package that provides a pre-configured `*Engine` with mock event store, mock event bus, and in-memory scheduler
- Replace `tests/integration/integration_test.go` with Go tests that build a mock engine, register layers, send requests, and assert outcomes

**Benefits:**
- Faster CI (no Docker Compose dependency)
- Easier to run locally (`go test` vs `make docker-test`)
- More deterministic (no timing-dependent race conditions)

### 14.4 gRPC/WebSocket protocol-aware detection

**Goal:** Add protocol-aware detection for non-HTTP protocols: gRPC unary/streaming, WebSocket messages, GraphQL mutations.

**Design considerations:**
- gRPC: needs HTTP/2-aware framing + protobuf field extraction
- WebSocket: needs message-level scanning (binary/text frames)
- GraphQL: query depth analysis exists in `apisecurity`; could be extended to schema-aware injection detection

**Recommendation:** Start with GraphQL (incremental improvement to existing layer), then WebSocket, then gRPC.

---

## 15. Dependency graph

```
WP-01 (split dashboard.go)
 ├── WP-04 (key rotation) — recommended but not blocked
 ├── WP-06 (legacy deprecation) — recommended but not blocked
 └── WP-08 (audit logging) — recommended but not blocked

WP-02 (login rate limit)
 └── WP-07 (tenant rate limit) — conceptually depends

WP-03 (test consolidation)
 └── (independent)

WP-05 (DeepCopy docs)
 └── (independent)

WP-09 (docs cleanup)
 └── (independent)

WP-10 (theme toggle)
 └── (independent)

WP-11 (code quality items)
 └── All independent sub-items

WP-12 (strategic)
 └── WP-01 + WP-07 + WP-03 provide the foundation
```

**Parallel work streams (independent):**
- Stream A: WP-01 → WP-04 → WP-06 → WP-08
- Stream B: WP-02 → WP-07
- Stream C: WP-03 + WP-05 + WP-09 + WP-10 + WP-11 (can all run in parallel)

With 2 engineers, Stream A + Stream B can run concurrently (3–4 weeks).
With 1 engineer, follow the priority order: P0 → P1 → P2 → P3.

---

## 16. Effort summary

| Package | Hours | Priority | Dependencies |
|---|---|---|---|
| WP-01: Split dashboard.go | 12–16 | P0 | None |
| WP-02: Login rate limiting | 3–5 | P0 | None |
| WP-03: Test file consolidation | 8–12 | P1 | None |
| WP-04: API key rotation | 6–8 | P1 | WP-01 (rec.) |
| WP-05: DeepCopy docs | 0.5–1 | P1 | None |
| WP-06: Legacy deprecation | 2–3 | P2 | WP-01 (rec.) |
| WP-07: Tenant rate limiting | 8–12 | P2 | WP-02 (concept) |
| WP-08: Audit logging | 6–10 | P2 | WP-01 (rec.) |
| WP-09: Docs cleanup | 2–3 | P2 | None |
| WP-10: Theme toggle | 4–6 | P2 | None |
| WP-11: General code quality | 4–6 | P1-P2 | None |
| WP-12: Strategic items | 40–80 | P3 | WP-01, WP-03, WP-07 |
| **Total** | **95–162** | | |

### Timeline scenario (1 engineer, sequential)

| Week | Focus | Deliverable |
|---|---|---|
| 1 | WP-01 | `dashboard.go` split complete, all tests pass |
| 2 | WP-02 + WP-04 | Login rate limiting + key rotation deployed |
| 3 | WP-03 + WP-05 + WP-06 | Test consolidation + DeepCopy docs + legacy deprecation |
| 4 | WP-07 + WP-08 + WP-10 | Tenant rate limiting + audit logging + theme toggle |
| 5 | WP-09 + WP-11 | Docs cleanup + code quality items |
| 6+ | WP-12 | Begin strategic work (layer graph / mock tests) |

---

## 17. Risk register

| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R01 | Dashboard refactor (WP-01) introduces a route regression | Medium | High | Write `TestAllRoutesRegistered` BEFORE refactoring |
| R02 | Test consolidation (WP-03) drops coverage below CI gate | Medium | Medium | Run coverage comparison before/after; keep fallback threshold |
| R03 | Rate limiting (WP-02) blocks legitimate users behind NAT | Low | Medium | Document the per-IP model; add allowlist config option |
| R04 | Key rotation (WP-04) concurrency bug during atomic swap | Low | High | Grace period design + thorough concurrency tests |
| R05 | Tenant rate limiting (WP-07) memory leak from idle buckets | Low | Medium | Idle bucket cleanup with configurable TTL |
| R06 | All P2/P3 work deferred indefinitely by P0/P1 urgency | Medium | Medium | Assign dedicated "tech debt" sprints; track in kanban |

---

## Appendix A: Quick reference — Audit finding → WP mapping

| Audit ID | Severity | Title | WP |
|---|---|---|---|
| A1 | Medium | serve_lifecycle.go God-object | WP-11 (noted) |
| A2 | Medium | No plugin system | WP-12 (strategic) |
| A3 | Low | All detectors Order 400 | WP-12 (strategic) |
| S1 | Low | crypto/rand fallback | WP-11 (doc only) |
| S2 | Medium | No login rate limiting | **WP-02** |
| S3 | Medium | No key rotation | **WP-04** |
| S4 | Low | allow_private_upstreams default | WP-11 |
| S5 | Low | No MCP tool-level authorization | WP-12 (strategic) |
| C1 | High | dashboard.go 2,009 lines | **WP-01** |
| C2 | Medium | 58 test padding files | **WP-03** |
| C3 | Medium | Inconsistent handler patterns | WP-01 (covered) |
| C4 | Low | Legacy static dashboard | **WP-06** |
| T1 | Medium | Test padding inflation | WP-03 (covered) |
| T2 | Low | E2E not in go test | WP-12 (strategic) |
| T3 | Low | Integration tests need live server | WP-12 (strategic) |
| D1 | Low | 30+ shell scripts | WP-11 (noted) |
| D2 | Low | No DeepCopy docs | **WP-05** |
| D3 | Low | docs/design/ out of date | **WP-09** |

---

*This action plan was generated from the findings in COMPREHENSIVE-AUDIT.md. Estimates are rough engineering hours assuming Go 1.25+ proficiency. Adjust based on team velocity and codebase familiarity.*
