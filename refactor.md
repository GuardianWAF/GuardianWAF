# GuardianWAF — Refactoring & Improvement Plan (Remaining Work)

> **Status:** Outstanding items only. Completed work has been removed from the body and condensed into the changelog below.
> **Date:** 2026-05-29 (last updated)
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

### 1.4 🟠 MEDIUM — `Order()` is not part of the `Layer` interface
- **Where:** interface at `internal/engine/layer.go:64-68`; ~9 layers implement `Order()`, ~16 rely on external `OrderedLayer{Layer, Order}` wrapping.
- **Recommendation:** pick one mechanism. Preferably make `Order() int` part of `Layer` and delete `OrderedLayer`.

### 1.5 🟡 LOW — Stringly-typed response hooks
- **Where:** `internal/engine/engine.go` reads metadata keys `"response_hook"` / `"response_mask_fn"` (and clientside hooks). Works, but no compile-time safety.
- **Recommendation:** replace string keys with typed fields on `RequestContext` (carefully — reset them in `ReleaseContext` to avoid pooled-context leaks).

### 1.6 🟡 LOW — Ignored `Close()` errors in body decompression
- **Where:** `internal/engine/context.go:234` (gzip), `:244` (deflate).
- **Recommendation:** log at debug, or add a justified `//nolint`.

---

## 2. Layer Subsystem

### 2.1 🟠 MEDIUM — `apisecurity/jwt.go` is 1,195 lines
- **Crypto is sound** (rejects `alg:none`, blocks HMAC/asymmetric confusion, JWKS DNS-rebinding re-validation, constant-time HMAC).
- **Smell:** `verifyHMACSignature` takes `crypto.PublicKey` and type-asserts to `[]byte` (`:431-433`).
- **Recommendation:** split into `jwt_parse.go` / `jwt_verify.go` / `jwt_claims.go`; introduce a `VerificationKey` type so symmetric keys aren't passed as `crypto.PublicKey`.

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

### 4.1 🔴 HIGH — Dead feature-handler files (non-functional stubs) — DECISION NEEDED
- **What:** `NewCRSHandler`, `NewDLPHandler`, `NewVirtualPatchHandler`, `NewClientSideHandler`, `NewAPIValidationHandler` are never called from non-test code; every `get*Layer()` returns `nil` (`// This is a simplified version…`), using stub types disconnected from the engine. Real management for these features is via the **MCP tools**.
- **Recommendation:** **Delete** the 5 handler files + their `*_coverage_test.go` companions, OR implement them against the real engine layers. *Left untouched* pending decision (deletion conflicts with the "don't delete tests this session" constraint set earlier).

### 4.2 🔴 HIGH — `dashboard.go` monolith (2,553 lines)
- **Where:** 70 handler methods, all routes registered in one `New()` (`:162-246`).
- **Recommendation:** split by domain (`handlers_stats.go`, `handlers_config.go`, `handlers_routing.go`, `handlers_acl.go`, `handlers_rules.go`, `handlers_alerting.go`, `handlers_compliance.go`), each with a `register(mux)`. Mechanical, low-risk.

### 4.3 🔴 HIGH — 15 injected function pointers instead of interfaces
- **Where:** `dashboard.go:73-95` (`upstreamsFn`, `rebuildFn`, `saveFn`, `rulesFn`, `geoLookupFn`, `aiAnalyzer`, `tenantManager`, `complianceEngine`, …).
- **Recommendation:** group into small interfaces (`RuleStore`, `RoutingController`, `GeoLookup`, …) for testability and a clear dependency surface.

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

### 5.1 🟠 MEDIUM — 44 handlers repeat parameter-unmarshal boilerplate
- **Where:** `internal/mcp/handlers.go`, `handlers_new_features.go` (567 lines): `getEngine()` → nil-check → `json.Unmarshal` → error-wrap → validate → call → `map[string]any{}`.
- **Recommendation:** a generic `register[T any](s, name, func(*Engine, T) (any, error))` that handles engine lookup, typed unmarshalling, and error envelope once. *(Drift between schema/handler names is already guarded by `ValidateTools()` — done.)*

### 5.2 🟡 LOW — No InputSchema validation before unmarshal
- **Recommendation:** optionally validate required fields against the declared `InputSchema` inside the generic helper from 5.1.

---

## 6. Cross-Cutting

### 6.1 🟠 MEDIUM — Finish the ignored-error triage (~149 sites)
- **Status:** the safety-critical ones are fixed (API-key init, CRS parse). Remaining: triage the rest (`_ =` 108, `_, _ =` 41); most are benign but should be batch-annotated or handled.
- **Note:** `events/file.go` log-rotation swallow (originally flagged) is a deliberate layered fallback — leave it, but consider a single error log if *all* fallbacks fail.

### 6.2 🟠 MEDIUM — No unified logging strategy
- **Where:** `log.Printf` (~85), `fmt.Printf` (~26, incl. `tracing/tracing.go:232,237`), `slog` (3, only `http3/`), plus the engine's `LogBuffer`.
- **Recommendation:** standardize on `log/slog` behind a thin project logger; route `LogBuffer` through it; forbid `fmt.Printf` diagnostics via a lint rule. Migrate incrementally.

### 6.3 🟡 LOW — `%w` vs `%v` inconsistency
- **Where:** ~398 `%w` vs ~336 `%v`. Default to `%w` for wrapping; add the `errorlint` linter.

### 6.4 🟡 LOW — `ipacl` auto-ban entry fields mixed atomic/plain
- **Where:** `internal/layers/ipacl/ipacl.go:178-202` — `ExpiresAt` is `atomic.Value`, siblings (`Count`, `Reason`) are plain under the map lock. Safe today (mutation under lock) but fragile.
- **Recommendation:** keep all mutable entry fields under one discipline.

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
