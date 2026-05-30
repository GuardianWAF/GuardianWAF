# GuardianWAF — Refactoring & Improvement Plan (Remaining Work)

> **Status:** Outstanding items only. Completed work has been removed from the body and condensed into the changelog below.
> **Date:** 2026-05-30 (last updated)
> **Health:** `go build ./...` ✅ · `go vet ./...` ✅ · `go test ./...` ✅ (67 pkgs) · touched packages pass `-race`.

This document now tracks **only the work that is still open**. Each finding carries a **severity**, **file:line** references, **why it matters**, and a **recommended action**.

| Severity | Meaning |
|----------|---------|
| 🔴 **HIGH** | Correctness/security-relevant, or a maintainability blocker that compounds with every feature. |
| 🟠 **MEDIUM** | Real debt or a contained latent risk. Schedule deliberately. |
| 🟡 **LOW** | Polish / consistency. Batch into cleanup PRs. |

---

## ✅ Already completed (removed from body)

Applied & verified (build + vet + full test suite green; touched pkgs `-race`):

- **Engine:** extracted shared `statusForAction` / `startRootSpan` / `buildEvent` / `recordStats` / `storeAndPublish` from `Check`/`Middleware` (the safe, behavior-preserving part of the dedup).
- **Detectors:** added `engine.ApplyMultiplier`, applied across all 6 detectors.
- **Cache:** request-derived, 2s-bounded context on the hot path (was `context.Background()`).
- **clustersync:** replication goroutine now tracked by `wg` + cancellable via `m.ctx`; `sendEventToNode` uses `NewRequestWithContext`.
- **Dashboard:** `writeJSON` marshals before writing headers (no truncated 200s) + logs encode failures; added `writeError` envelope.
- **JWT:** `clock_skew_seconds` clamped to `[0, 3600]`.
- **Security fail-loud:** API-key validator init now errors instead of silently disabling auth; CRS parser errors on malformed `phase`/`status`/`skip` instead of defaulting to `0`.
- **MCP:** added `Server.ValidateTools()` + test asserting `AllTools()` ↔ registered handlers match (catches tool-name drift in CI).
- **Client-Side layer wired into the response path** — Magecart/agent-injection body processing + CSP headers were registered in `ctx.Metadata` but never consumed by the engine; now executed (off by default). Fixed a pooled-context closure-capture bug in the process. New tests added.
- **Docs:** reconciled `CLAUDE.md` with reality — corrected the false "29 layers registered in serve" claim to 16 and added a per-layer ✅/❌ "Serve?" column (verified via `go list -deps`).
- **Logging:** `internal/logging` package created (`Logger`, `NewLogger(component)`); all `log.Printf` migrated to structured `slog` in `cluster`, `clustersync`, `tenant`, `layers/*` (10 packages), `mcp`.

**Resolved as non-issues (do not re-open):** apisecurity `mu` (correctly used; config immutable post-construction) · revoked-session GC (ticker already started at `dashboard.go:160`) · JWT `fetchJWKS` `context.Background()` (correct for a shared cache fetch) · `events/file.go:260` swallow (deliberate layered reopen fallback) · `ResolveEnabled` tenant-helper (rejected: net-negative — forces `config` import into ~24 layers + hot-path closure alloc).

---

## 1. Engine & Pipeline

### 1.1 🔴 HIGH — Decide the fate of the ~12 advertised layers absent from the serve binary
- **Where / proof:** `go list -deps ./cmd/guardianwaf` → the serve binary wires **16** layers via `layerregistry`; these packages are **not in the binary at all**: `integrations/v040`, `layers/siem`, `cluster`, `clustersync`, `layers/websocket`, `layers/grpc`, `proxy/grpc`, `layers/zerotrust`, `layers/graphql`, `ml/anomaly`, `layers/botdetect/enhanced`, `layers/canary`, `layers/cache`, `layers/replay`, `discovery`, `ai/remediation`. The `internal/integrations/v040` Integrator that would wire most of them has **zero non-test callers**.
- **Status:** the *docs* are now reconciled (CLAUDE.md fixed). What remains is the **product decision**: ship these or formally drop them.
- **Why it matters:** the config schema still accepts `cluster:`, `graphql:`, `siem:`, `canary:`, `zerotrust:`, `ml_anomaly:`, etc., so operators can "enable" features the binary cannot run — silently ignored (compounds §3.1 config gaps).
- **Recommendation:** decide per feature. To **ship**: wire into `layerregistry` one layer at a time, each with integration tests — **do not** just call the dead Integrator from serve (activates never-run code in a security data path). To **drop**: delete the package + its config block. Either way, make `layerregistry` the single wiring source of truth (see 1.2).

### 1.2 🟠 MEDIUM — Two divergent layer-wiring paths / no single source of truth
- **Where:** library mode `guardianwaf.go:454-580` (`addDefaultLayers`, 6 layers) vs serve mode `cmd/guardianwaf/layers.go` + `layerregistry` (16). No declarative single source for "which layers exist, in what order."
- **Recommendation:** make `layerregistry` authoritative; library mode selects a named subset ("core") instead of hand-rolling `AddLayer` calls. Resolves the 6-vs-16 drift and prevents recurrence of 1.1.

### 1.3 ✅ PARTIALLY RESOLVED — `engine.go` split into 3 files
- **Fixed:** Extracted `event_types.go` (EventStorer, EventPublisher, Stats, PipelineLayerInfo, ChallengeChecker, AccessLogFunc, AccessLogEntry) and `hooks.go` (applyResponseHook, applyCORSHook). engine.go: 624 → 514 lines (-17.6%).
- **Remaining:** Pipeline struct (~150 lines hot-path), Middleware (148 lines), Check (18 lines), NewEngine (43 lines) are all cohesive and tightly coupled — further extraction possible but lower ROI.

### 1.4 ✅ RESOLVED — `Order() int` added to `Layer` interface
- **Fixed:** `Order() int` added to `engine.Layer` interface (layer.go:67). All ~25 layer implementations updated with explicit `Order()` methods. `OrderedLayer` still exists for backward compatibility but is now redundant.

### 1.5 🟡 LOW — Stringly-typed response hooks
- **Where:** `internal/engine/engine.go` reads metadata keys `"response_hook"` / `"response_mask_fn"` (and clientside hooks). Works, but no compile-time safety.
- **Recommendation:** replace string keys with typed fields on `RequestContext` (carefully — reset them in `ReleaseContext` to avoid pooled-context leaks).

### 1.6 🟡 LOW — Ignored `Close()` errors in body decompression
- **Where:** `internal/engine/context.go:234` (gzip), `:244` (deflate).
- **Recommendation:** log at debug, or add a justified `//nolint`.

---

## 2. Layer Subsystem

### 2.1 ✅ PARTIALLY RESOLVED — `jwt.go` split into parse + verify
- **Fixed:** jwt.go (1,195 lines) → jwt.go (450 lines) + jwt_parse.go (493 lines) + jwt_verify.go (255 lines). HTTP client/JWKS logic in jwt_verify.go, parsing in jwt_parse.go, main file has NewJWTValidator + validateSigningMethod + helpers.
- **Remaining smell:** `verifyHMACSignature` takes `crypto.PublicKey` and type-asserts to `[]byte` (jwt_verify.go:253 stub kept for test compatibility).

### 2.2 🟠 MEDIUM — Zero Trust layer is partially wired
- **Where:** `internal/layers/zerotrust/layer.go:66-82` — `RequireMTLS` is checked without inspecting `ctx.Request.TLS` client certs; device attestation configured but not enforced. (Also note: zerotrust isn't in the serve binary — see 1.1.)
- **Recommendation:** complete mTLS validation in `Process()`, or guard behind an explicit "experimental" flag that logs incomplete enforcement.

### 2.3 🟡 LOW — Inconsistent finding construction
- **Where:** some layers use helper constructors (`sqli/patterns.go:103-117`), others inline `engine.Finding{...}` (`websocket/layer.go:74-79`, `grpc/layer.go:76-81`).
- **Recommendation:** standardize on a single `engine.NewFinding(...)`.

### 2.4 🟡 LOW — API-Discovery records status `0` (architectural)
- **Where:** `discovery/layer.go:72` reads `ctx.Metadata["status_code"]`, but nothing writes it and the layer runs *before* the upstream status is known. (Also: discovery isn't in the serve binary — see 1.1.)
- **Recommendation:** if discovery is shipped, record **post-response** (like the access log), not via request-time metadata.

---

## 3. Configuration Package (~17k lines; custom YAML parser is a deliberate zero-dep choice)

### 3.1 ✅ RESOLVED — Config layering now wires all serve-binary features
- **Fixed:** Added `populateGeoIP`, `populateThreatIntel`, `populateCORS`, `populateATOProtection`, `populateAPISecurity`, `populateAPIValidation`, `populateClientSide`, `populateCRS` and wired them into `populateWAF`. All 8 previously-silent fields are now loaded from YAML.
- **Remaining env-wiring gap:** `validate.go` still has ~24 hardcoded `GWAF_*` env vars mapped individually; a reflection-based walker would be more maintainable but is lower priority.
- **Note:** Features not in the serve binary (`cluster`, `siem`, `zerotrust`, `canary`, `cache`, `replay`, `websocket`, `grpc`, `ml_anomaly`, `api_discovery`) are intentionally omitted from `populateWAF` — those config blocks are silently ignored by design (see §1.1).

### 3.2 🟠 MEDIUM — 85 hand-written `DeepCopy()` methods (~712 lines)
- **Where:** `internal/config/config.go:373-1084`. Forgetting a slice/map field on a new struct = silent shared-reference bug across hot-reload snapshots.
- **Recommendation:** generate `DeepCopy` via `//go:generate` and check it in. *(Zero-dep applies to the runtime binary, not a build-time codegen tool — confirm with maintainer.)*

### 3.3 🟠 MEDIUM — Silent type-conversion failures in the parser
- **Where:** e.g. `validate.go:637-639` — `if i, _ := limit.Int(); i > 0` makes `limit: "abc"` silently `0`.
- **Recommendation:** propagate these errors; a WAF should reject a malformed config, not boot with a zeroed limit.

### 3.4 🟠 MEDIUM — Custom YAML parser silently ignores unsupported syntax
- **Where:** `yaml.go` — no anchors/aliases/tags/multi-doc; they're dropped silently.
- **Recommendation:** emit an explicit parse error on `&`/`*` (anchor position), `!!`, `---`. *(Needs token-level detection — a naive substring scan would falsely reject valid values like passwords/regexes/URLs.)* Document the supported subset in `docs/configuration.md`.

### 3.5 🟠 MEDIUM — `defaults.go` is a 1,959-line wall of boilerplate
- **Where:** 369-line `DefaultConfig()` + 27 near-identical `populate*` funcs.
- **Recommendation:** reflection-driven populate via struct tags, or at minimum extract the repeated `nodeBool/nodeInt/parseDuration` field-assignment into a generic helper.

### 3.6 🟡 LOW — Validation patterns are not table-driven
- **Where:** `validate.go` — ~8 repeated enum `switch` validators, ~15 "must be > 0" checks.
- **Recommendation:** `validateEnum(field, value, allowed...)` + `validatePositive(field, value)`; make error strings constants so they're testable.

---

## 4. Dashboard & HTTP API (largest single area of debt)

### 4.1 🔴 HIGH — Dead feature-handler files (non-functional stubs) — RESOLVED
- **What:** `NewCRSHandler`, `NewDLPHandler`, `NewVirtualPatchHandler`, `NewClientSideHandler`, `NewAPIValidationHandler` were never called from non-test code; every `get*Layer()` returned `nil`.
- **Fix:** wired each to real engine layer via `engine.FindLayer(name)` + adapter pattern. Added `Set*Layer()` setters on Dashboard. Fixed type mismatches (int→int64, ListPatterns→GetAllPatterns, Pattern fields→Patterns slice).
- **Status:** ✅ Resolved — 5 handler files now functional.

### 4.2 🔴 HIGH — `dashboard.go` monolith (2,553 lines) — RESOLVED
- **Where:** 70 handler methods, all routes registered in one `New()` (`:162-246`).
- **Fix:** extracted 10 domain-based `register*(mux)` functions. New files: stats_handlers.go, config_handlers.go, acl_handlers.go, rules_handlers.go, misc_handlers.go. routing_handlers.go extended.
- **Status:** ✅ Resolved — dashboard.go: 1642→1582 lines (-60), route block replaced with `d.registerStats(d.mux)` etc.

### 4.3 🔴 HIGH — 15 injected function pointers instead of interfaces — RESOLVED
- **Where:** `dashboard.go:73-95` (`upstreamsFn`, `rebuildFn`, `saveFn`, `rulesFn`, `geoLookupFn`, `aiAnalyzer`, `tenantManager`, `complianceEngine`, …).
- **Fix:** the struct now uses interfaces throughout — `RoutingController`, `UpstreamStatusProvider`, `CertificateProvider`, `RuleStore`, `GeoLookup`, `AlertingStatsProvider`, `aiAnalyzerInterface`, `dockerWatcherInterface`, `tenantManagerInterface`. The `routingControllerAdapter` bridges func pointers for existing callers.
- **Status:** ✅ Resolved — all Dashboard dependencies are interface-typed.

### 4.4 🟠 MEDIUM — `writeError` envelope not yet adopted at all call-sites
- **Where:** `writeError` helper now exists, but ~239 `writeJSON` call-sites still hand-roll error bodies in inconsistent shapes (`{"error":…}` vs `{"status":"ok"}` vs `map[string]string`).
- **Recommendation:** migrate error responses to `writeError` for a single envelope (mechanical, do alongside 4.2).

### 4.5 🟠 MEDIUM — Admin-only authz uses string-prefix matching
- **Where:** `internal/dashboard/auth.go:335-348` — `adminOnlyPrefixes` prefix match can mis-handle sibling routes (`/api/v1/ai` vs `/api/v1/ai_export`).
- **Recommendation:** explicit route→scope mapping (ties into 4.2's per-domain registration).

### 4.6 🟡 LOW — Incomplete CORS preflight coverage
- **Where:** only 3 explicit `OPTIONS` routes (`dashboard.go:178,181,188`).
- **Recommendation:** small CORS middleware that auto-answers preflight for all API routes.

---

## 5. MCP Server

### 5.1 ✅ RESOLVED — `handleWithParams[T]` generic helper eliminates boilerplate
- **Fixed:** `handleWithParams[T any, R any]` generic adapter (handlers.go:54-80) handles getEngine → json.Unmarshal → required-field validation → call in one reusable function. All 44 MCP handlers use it. Drift between schema/handler names is guarded by `ValidateTools()`.

### 5.2 🟡 LOW — No InputSchema validation before unmarshal
- **Recommendation:** optionally validate required fields against the declared `InputSchema` inside the generic helper from 5.1.

---

## 6. Cross-Cutting

### 6.1 🟠 MEDIUM — Finish the ignored-error triage (~149 sites)
- **Status:** the safety-critical ones are fixed (API-key init, CRS parse). Remaining: triage the rest (`_ =` 108, `_, _ =` 41); most are benign but should be batch-annotated or handled.

### 6.2 🟢 DONE — No unified logging strategy
- **Status:** Completed. All `log.Printf` migrated to structured `log/slog` via `internal/logging` package across `cluster`, `clustersync`, `tenant`, `layers/*` (10 packages), `mcp`. Remaining: fmt.Printf panic-recovery fallbacks in `acme`, `geoip`, `tls`, `proxy`, `docker`, `alerting` (low priority), plus README/docs files (excluded).

### 6.3 🟡 LOW — `%w` vs `%v` inconsistency
- **Where:** ~398 `%w` vs ~336 `%v`. Default to `%w` for wrapping; add the `errorlint` linter.

### 6.4 🟢 DONE — `ipacl` auto-ban entry fields mixed atomic/plain
- **Status:** Already fixed. `ExpiresAt` is plain `time.Time` (not `atomic.Value`), protected by `Layer.mu` lock alongside `Count` and `Reason`. Consistent discipline under lock.

---

## 7. Testing, CI & Hygiene

### 7.1 🟠 MED-HIGH — ~40% of test files are coverage padding
- **Counts:** `*_coverage_test.go` 42 · `*_extra*_test.go` 56 · `*_cov2_test.go` 5 (of 258, ~40%).
- **Evidence:** `cmd/guardianwaf/cmd_coverage_test.go` (132 trivial funcs, `_ = result`); `dashboard_extra{,2,3,4}_test.go` (same tests copy-pasted across 4 files); `validate_coverage_test.go` (setter tests, no rule violations); dead handlers kept alive by `dashboard_coverage3_test.go`.
- **Recommendation:** consolidate meaningful assertions into canonical `*_test.go`, delete pure line-touch tests, drop the `extra2/3/4` duplicates (expect ~258 → ~150 files, no real coverage lost). Ban `_coverage/_extra/_cov2` suffixes in CONTRIBUTING.

### 7.2 🟠 MEDIUM — Linter excludes all test files
- **Where:** `.golangci.yml:25-29` excludes `_test.go` from govet/staticcheck/revive — which is *why* padding accumulates.
- **Recommendation:** at least run `ineffassign`/`staticcheck` on tests; add `errcheck`, `errorlint`, `forbidigo`. *(golangci-lint isn't installed locally — triage the surfaced issues before flipping CI, do this with 7.1.)*

### 7.3 🟠 MEDIUM — Coverage floor not enforced
- **Where:** CI `fail_ci_if_error: false`; codecov target 95% is advisory.
- **Recommendation:** enforce a per-PR floor on *new* code (~80%), but only **after** 7.1 (otherwise enforcing a padded number).

### 7.4 🟡 LOW — Misc
- Integration tests are an optional CI job → promote `tests/integration` to required.
- Fuzz smoke `FUZZTIME=5s` → add a nightly 60s+ job, plus fuzz targets for path normalization / header parsing / cookie decoding.
- `go.mod` says `go 1.26.3` while CLAUDE.md references 1.25+ → confirm the pin is intentional and matches CI.

---

## 8. Security-Sensitive Watch-Items (remaining)

The most acute one (API-key fail-loud) is **fixed**. Remaining:
1. 🟠 Silent config drops (§3.1, §3.3) — operator hardening can be silently ignored.
2. 🟠 Half-wired `RequireMTLS` in zerotrust (§2.2) — implies enforcement that isn't happening (and the layer isn't shipped — §1.1).
3. **Policy:** adopt an explicit "fail-closed vs fail-loud" rule for every security-relevant init/config path, and add a test asserting the WAF refuses to start (or warns prominently) when a protection layer fails to initialize.

---

## 9. Suggested Sequence for Remaining Work

1. **Decisions first (unblocks the rest):** §1.1 ship-or-drop the absent layers · §4.1 delete-or-implement the stub handlers · §3.1 confirm config-populate gaps.
2. **Structural (mechanical, high payoff):** §4.2/§4.3 split `dashboard.go` + interfaces · §1.3 slim `engine.go` · §2.1 split `jwt.go` · §1.2/§1.4 single registry + `Order()`.
3. **Config modernization:** §3.2 codegen DeepCopy · §3.1/§3.3/§3.4 env walker + loud-on-unknown + propagate parse errors · §3.5/§3.6 reduce boilerplate / table-driven validation.
4. **Hygiene:** §7.1 consolidate padding tests → §7.2 lint tests → §7.3 coverage floor · §6.2 unify logging · §6.1 finish error triage.

---

## Appendix — Method

Findings verified directly against source; layer-wiring claims verified via `go list -deps ./cmd/guardianwaf` (authoritative transitive graph). Repo metrics at audit time: 490 Go files, ~231k LOC, 258 test files; ~149 ignored errors; ~125 mutex sites. This file lists **remaining** work only — see the changelog at the top for completed items.
