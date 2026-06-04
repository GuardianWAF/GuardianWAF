# GuardianWAF — System Audit Report

**Date:** 2026-06-04 · **Branch:** main
**Method:** `go build/vet/test` + actual binary graph via `go list -deps` + 5 parallel deep-scan agents + manual verification. Every critical finding was confirmed directly against source code.

---

## 0. One-Sentence Summary

> The code **builds, passes `go vet`, and passes the full test suite**, and the detector/crypto/auth core is genuinely solid — but the product suffers from two structural diseases: **(1) ~24% of the code ships in no binary at all (dead/unwired)**, and **(2) several "silently fail-open" paths** — the one thing a WAF must never do: when a protection breaks, it lets traffic through and tells no one.

**Health:** `go build ./...` ✅ · `go vet ./...` ✅ · `go test ./...` ✅ (exit 0) · 62 files uncommitted (all improvements).

**Repo metrics:** 510 Go files · ~80k LOC production · ~154k LOC test (test:prod ≈ 1.9:1) · Go pinned to `1.26.3`.

---

## 1. MOST CRITICAL: Silent Fail-Open Paths (fatal for a WAF)

A WAF's one job: if protection isn't running, **fail closed** — do not pass traffic. The opposite happens in 4 places.

| # | Finding | Evidence | Impact |
|---|---------|----------|--------|
| **C1** 🔴 | **Layer build error → log a warning, keep serving without that layer** | `cmd/guardianwaf/layers.go:18-22` (same pattern for all 16 layers): `if ...err != nil { slog.Warn(...) } else if ok { eng.AddLayer }` | A single bad CIDR in the blacklist, or a bad regex in a custom rule → WAF starts "successfully", healthz green, **but the IP ACL / custom-rules layer is absent.** Only signal: one log line. |
| **C2** 🔴 | **CRS returns "enabled" even when its rule file fails to load — runs with an empty ruleset** | `internal/layers/crs/layer.go:55-58` — `LoadRules` error swallowed into `Warn`, layer returned anyway | Rule file missing/corrupt after deploy → OWASP CRS layer (Order 350) becomes a silent no-op. Dashboard still shows "CRS enabled". |
| **P0** 🔴 | **A YAML file starting with `---` silently drops the ENTIRE config** | Verified by direct run: `---\nlisten: ":12345"` → `err=<nil>`, `listen=":8088"` (default). Parser doesn't understand the `---` document marker (`internal/config/yaml.go:196-222`) | Operator writes a hardening config that begins with `---` (a near-universal YAML convention) → **WAF boots with pure defaults, no error.** |
| **H1** 🟠 | **When the sanitizer is disabled, sqli/lfi/cmdi/ssrf go fully blind on path/query/body** | `sqli.go:56-67` reads only `ctx.Normalized*` (populated by the Sanitizer). Contrast: `xss.go:58-78` and xxe fall back to raw (`NormalizedPath` empty → `ctx.Path`). The other 4 do not. | A tenant disables the sanitizer for performance → `?id=1 UNION SELECT...` and `?file=/etc/passwd` pass unscanned, **but XSS still fires** → a false "the WAF is working" impression. |

**What should have been:** An *enabled* security layer that fails to initialize must prevent serve from starting (or turn healthz red). All 6 detectors should fall back to raw input like XSS does. The parser must return a **ParseError** on `---`/`&`/`*`/`!!`/`<<` instead of silently swallowing them.

---

## 2. Structural Debt: ~24% of the Code Ships Nowhere

Verified via `go list -deps ./cmd/guardianwaf`. **20 internal packages are absent from the serve binary.** ~15,600 LOC of production code + ~32,000 LOC of tests (21% of all test code) exercise **unreachable** code.

**Proven dead (no caller at all, including tests):**
- **`internal/integrations/v040`** — the "Integrator" meant to wire 12 layers is **never called anywhere** (grep confirms; even test files don't import it). 1,158 LOC code + 2,467 LOC test, an island.
- **`internal/feature`** — CLAUDE.md calls it a "live feature-flag subsystem"; **zero importers.** Completely dead.
- **`internal/http3`** — not in the binary even with `-tags http3`; no symbols referenced.
- **`internal/analytics`**, **`ml/features`, `ml/onnx`** — reachable only via dead v040/anomaly → transitively dead.

**"Showcase" layers waiting to be wired through v040:** siem, cluster, clustersync, websocket, grpc, zerotrust, graphql, canary, cache, replay, discovery, ai/remediation. All written, tested, compiling — but **nobody runs them.**

**What should be:** A per-feature decision — either **wire it** (into `layerregistry`, one at a time, with integration tests; calling the dead Integrator from serve is wrong because it would activate never-run code in a security data path), or **delete it** (package + config block). This single move clears ~16k LOC of prod + ~32k LOC of test.

---

## 3. Config & Error-Handling Discipline

| # | Finding | Evidence |
|---|---------|----------|
| P1 🟠 | **52 silent type-conversion drops** — `nodeBoolField`/`nodeIntField` discard the error | `defaults.go` (52 call sites swallow the error). `cors.strict_mode: yess` → stays `false`, no error |
| P1 🟠 | **A typo like `active: ture` → tenant/rule silently DISABLED** | `validate.go:594,616`: `if b,_ := active.Bool(); !b { Active=false }` |
| P1 🟠 | **Anchors/aliases/tags silently mis-parsed** | `b: *x` → becomes the literal string `"*x"`; `<<:` merge key produces a map key literally named `<<` |
| P1 🟠 | **3 real DeepCopy shared-reference bugs** (hot-reload corruption) | `AlertingConfig.Emails` shallow copy; `ComplianceConfig.ScheduledReports` shallow; **`AllowPrivateUpstreams *bool` pointer sharing** — this is the SSRF private-upstream gate! |
| 🟡 | **The real generator is not in the repo** | `deepcopy_generated.go` says "generated by gen_deepcopy.py" but that file isn't in the repo; `tools/deepcopy/main.go` is a different, buggy tool → DeepCopy cannot be regenerated |

**Good news (done right):** Unknown top-level config keys produce a **hard error** (`validate.go:121-176`) — so writing an unwired block like `cluster:`/`zerotrust:` makes startup fail (fail-loud, correct). Startup parse/validate errors `osExit(1)`. Crypto checks `crypto/rand` errors everywhere. *(One exception: flags written into the generic `features:` map are silently inert.)*

---

## 4. Test Quality — The Opposite of the Suspicion

The suspicion was "~40% coverage padding." **The reality is different:** assertion-absence is only **6.1%** (417/6839 functions). The detector/engine/config tests are the **best** in the repo — real attack payloads (UNION, `' OR 1=1`, `/etc/passwd`), tokenizer/parser assertions, 8 packages with real fuzz tests.

**The actual problem:** ~32k LOC of well-written tests **keep dead code alive** (§2). Secondary issues:
- `.golangci.yml:24-29` **excludes all `_test.go`** from govet/staticcheck/revive → which is *why* padding accumulates.
- `extractContext` is copy-pasted across 4 detector packages (prod + test); `*_extra2_test.go` files are branch-completion micro-tests.

**What should be:** Don't hunt for fake assertions (rare). Decide the fate of the dead layers → 32k LOC of tests goes away on its own. Run at least `staticcheck`/`ineffassign` on test files. Ban the `_coverage/_extra/_cov2` suffixes in CONTRIBUTING.

---

## 5. Documentation Lies

| Claim | Reality | Verdict |
|-------|---------|---------|
| "44 MCP tools" (CLAUDE.md, refactor.md) | ~~42~~ **44** — re-verified with `len(AllTools())` == 44. The original audit pass mis-counted; the docs are **correct**. (Lesson: verify before "fixing".) | ✅ TRUE |
| "Go (1.25+)" | `go.mod` pins `go 1.26.3` — won't build on 1.25 | **FALSE** → fixed in CLAUDE.md (now "1.26+") |
| refactor.md §4.2 "dashboard.go 1642→1582" | File is still 1642 lines; the 2553/1642/1582 figures are internally contradictory (refactor was done, metrics fabricated) | **STALE** |
| ADR 0012 GraphQL "Implemented" | GraphQL is absent from the serve binary (CLAUDE.md marks ❌), so "Implemented" overstated it → added a "package only, not wired" note to ADR 0012. (Re-check: ADR 0016 ML is actually "Proposed", not "Implemented" — the original audit pass was wrong about 0016; 0007 and 0016 are both ML-anomaly ADRs but not a status conflict.) | **partly FALSE → fixed** |
| "ZERO dependencies (except quic-go)" | `go.mod` confirms | ✅ TRUE |
| "16 layers serve / 6 library mode / 43 ADRs" | All verified | ✅ TRUE |

Most of refactor.md's ✅ engineering claims (engine/jwt split, Order() interface, slog migration, writeJSON ordering, dashboard register* split) are **genuinely done.** Far more honest than the historical "29 layers" incident; the remaining lies concentrate in tool count, Go version, fabricated line metrics, and "Implemented" status for unwired features.

---

## 6. What Is Solid (credit where due)

- **Detectors are real:** SQLi is tokenizer-based, XSS is parser-based — not naive substring. Recursive URL decode, `%uXXXX`, fullwidth-unicode, HTML entities, null-byte normalization present.
- **IP/trusted-proxy is fail-safe:** empty `trusted_proxies` → XFF never trusted; `0.0.0.0/0` rejected; **no spoof bypass found**.
- **Panic handling is fail-CLOSED:** a layer panic → 500 (request blocked).
- **Dashboard auth crypto is solid:** HMAC-SHA256 session + IP binding, `subtle.ConstantTimeCompare`, PBKDF2 100k iters, CSRF same-origin, per-IP lockout, API keys rejected from query params.
- **Decompression-bomb protection exists:** `LimitReader` + 100:1 ratio check.

---

## 7. Prioritized Action Plan

**Immediate (security — breaks the product promise):**
1. **C1:** An enabled security layer's build error → abort startup (or fail healthz). Change the `layers.go` pattern.
2. **C2:** `crs.NewLayer` must propagate the `LoadRules` error upward.
3. **P0:** Parser must return a ParseError on `---`/`&`/`*`/`!!`/`<<`.
4. **H1:** Add the XSS-style raw fallback to all 6 detectors.
5. **P1-DeepCopy:** Fix the 3 bugs (especially the SSRF-relevant `AllowPrivateUpstreams` pointer), commit the real generator.

**Next (structural — high payoff):**
6. **Dead-code decision:** ship-or-drop the 20 unwired packages. Delete or wire v040 + feature + http3 → clears ~48k LOC.
7. Propagate the config silent type-conversion drops (52 + 11 call sites).

**Hygiene:**
8. Fix the doc lies (44→42, 1.25→1.26, ADR statuses, dashboard metrics).
9. Run the linter on test files; ban the padding suffixes.

---

## 8. Fixes Applied (2026-06-04)

All 5 critical findings fixed and locked in with regression tests. `go build ./...`, `go vet ./...`, `go test ./...` all green.

| # | Fix | Files | Test |
|---|-----|-------|------|
| **C1** | `addLayers` now returns an error and **fails closed** when an enabled security layer can't build. Escape hatch: `GWAF_ALLOW_DEGRADED_START=1` downgrades to a loud warning. All 3 callers propagate the error. | `cmd/guardianwaf/layers.go`, `engine_runtime.go`, `main.go`, `main_default.go` | `cmd/guardianwaf/layers_failclosed_test.go` |
| **C2** | CRS records its rule-load error (`LoadError()`); `buildCRS` propagates it so an enabled-but-unloadable CRS layer aborts startup instead of running empty. | `internal/layers/crs/layer.go`, `internal/runtime/layerregistry/registry.go` | `internal/runtime/layerregistry/crs_failclosed_test.go` |
| **P0** | Parser now **rejects** `---`/`...` document markers, anchors (`&`), alias refs (`*name`), type tags (`!!`), and merge keys (`<<`) with a `ParseError`. Bare `*` and `*.example.com` wildcards still parse. | `internal/config/yaml.go` | `internal/config/yaml_unsupported_test.go` |
| **H1** | sqli/lfi/cmdi/ssrf now fall back to raw `Path`/`QueryParams`/`BodyString` when the sanitizer is disabled (mirroring xss/xxe), closing the blind spot. | `internal/layers/detection/{sqli,lfi,cmdi,ssrf}/*.go` | `*_failopen_test.go` in each pkg |
| **DeepCopy** | Fixed 3 shared-reference bugs: `Config.AllowPrivateUpstreams` (`*bool`), `AlertingConfig.Emails`, `ComplianceConfig.ScheduledReports`. | `internal/config/deepcopy_generated.go` | `internal/config/deepcopy_shared_ref_test.go` |

> ⚠️ **Follow-up:** `deepcopy_generated.go` is marked "DO NOT EDIT" but its generator (`gen_deepcopy.py`) is **not in the repo** — my fix was applied by hand and will be lost if the file is ever regenerated. The real generator must be committed (and fixed to handle nested slices / `*bool` fields) before the next regeneration. Tracked in §3 / refactor.md §3.2.

### Round 2 — config fail-loud hardening (§3, P1)

The config loader no longer silently drops malformed bool/int values: a typo like `strict_mode: yess` or `paranoia_level: abc` now **fails the load loudly** instead of zeroing the field. All 52 previously-discarded `nodeBoolField`/`nodeIntField` errors across 8 `populate*` functions (geoip, threat_intel, cors, ato_protection, api_security, api_validation, client_side, crs) are now accumulated via a `fieldErrs` helper and propagated through `populateWAF`. A null/empty value (`enabled:`) still keeps the default (no error). Doc fix: CLAUDE.md Go version `1.25+` → `1.26+`.

- Files: `internal/config/defaults.go`, `CLAUDE.md`
- Test: `internal/config/populate_failloud_test.go`

### Round 3 — tenant/rule silent-disable hardening (§3, P1)

The most dangerous silent drops are now fail-loud: `parseCustomRule` and `parseTenantDefinition` had inverted-logic drops where a typo (`enabled: ture`, `active: notabool`) parsed to `false` and **silently disabled the custom rule / deactivated the tenant** — a security control turned off by a typo. Both now return an error on a malformed value (explicit `false` still applies; absent keeps the default). All 3 production callers (`appendRulesFromDir`, `loadVirtualHostWAF`, tenant-file loader) propagate the error.

- Files: `internal/config/validate.go` (+ test caller updates in `validate_coverage_test.go`)
- Test: `internal/config/parse_failloud_test.go`

### Round 4 — close the remaining silent-drop tail (§3, P1)

The rest of the silent type-conversion drops are now fail-loud too, so the config subsystem rejects every malformed scalar instead of zeroing it:
- **Durations** (`defaults.go`): a `durationField` helper replaced 8 `parseDuration(...); err == nil` swallows (`cache_ttl`, brute-force/cred-stuffing/password-spray/travel `window` + `block_duration`). A malformed duration now errors instead of silently reverting to the default window/cooldown.
- **Ints** (`validate.go`): upstream target `weight`, per-domain detection `threshold.block`/`.log`, custom-rule `priority`/`score`, and rate-limit-rule `window` now error on a malformed value. Out-of-range values (negative) still keep the default as before — only *parse* failures are rejected, so existing configs are unaffected.

- Files: `internal/config/defaults.go`, `internal/config/validate.go`
- **Truly remaining (low severity):** `impossible_travel` float drops (`max_distance_km`/`max_time_hours` → typo keeps default) and `LoadEnv` `GWAF_*` parse swallows (`validate.go`). Both keep a sane default and disable nothing; left for a future batch.

**Net:** §3's "silent config drop" class is closed for all bool/int/duration fields across the load path. The config loader now fails loud on any malformed scalar, consistent with the C1/C2 fail-closed philosophy.

### Round 5 — tenant API-key authz: deny-list → fail-closed allow-list (§4.5, M2)

Dashboard tenant-key scoping was a **deny-list** (`adminOnlyPrefixes`): any admin endpoint not added to the list was reachable by every tenant key (fail-open on a forgotten route). Replaced with a default-deny **allow-list** (`tenantReadablePrefixes` + `tenantKeyAllows`): a tenant key may reach only the 13 explicitly-listed read-only endpoints; everything else under `/api/` — including any newly added route — is denied by default.

- The allow-list was derived to **preserve current behavior exactly** for every registered route (zero breakage), verified against the authoritative `mux` registrations. Prefix matching uses an exact/`prefix+"/"` boundary, so `/api/v1/statsified` no longer matches `/api/v1/stats`.
- During the audit I verified the non-`/api/v1/` namespaces: `/api/admin/*` uses a separate stronger `isAdminAuthenticated` gate (tenant keys can't reach it — not a vuln), and `/api/dlp/*` + `/api/clientside/*` `RegisterRoutes` are **never called** (dead, unregistered) — so the only tenant-reachable authWrapped routes are `/api/v1/*`.
- Files: `internal/dashboard/auth.go`, `internal/dashboard/dashboard.go` (+ test update in `dashboard_extra4_test.go`)
- Test: `internal/dashboard/tenant_scoping_test.go` (asserts allowed set works, admin/mutating denied, a new endpoint denied by default, and prefix-boundary safety)

### Round 6 — config float drops + DeepCopy safety net

- **Float drops:** added a `floatField` accumulator helper and converted the last two silent type-conversion swallows (`impossible_travel.max_distance_km` / `max_time_hours`). The whole config load path is now fail-loud on any malformed bool/int/float/duration scalar.
- **DeepCopy reflection guard:** added `TestDeepCopy_FullIndependence` (`internal/config/deepcopy_reflect_test.go`) — it densely fills a `Config` via reflection, deep-copies it, and walks both trees asserting **no** slice/map/pointer is shared. This is the safety net for the missing `gen_deepcopy.py` generator: any regeneration or new field that reintroduces a shallow-copy bug is caught for the *entire* config tree, not just the 3 hand-fixed fields. Validated by temporarily reintroducing the `Emails` bug — the test pinpointed `Emails[0].To`/`Events` and failed as expected, then passed after restore.
- Files: `internal/config/defaults.go`; Test: `internal/config/deepcopy_reflect_test.go`

### Round 7 — delete confirmed-dead packages (§2)

Deleted four packages with **zero importers** (verified by grep + `go list -deps`, including `-tags http3`):

| Package | LOC removed | Why dead |
|---------|------------:|----------|
| `internal/integrations/v040` | 3,796 | the Integrator meant to wire the 12 "showcase" layers — zero callers |
| `internal/analytics` | 3,597 | imported only by v040 (transitively dead once v040 went) |
| `internal/feature` | 506 | feature-flag registry — zero importers; docs claimed it was live |
| `internal/http3` | 458 | not in serve deps even with `-tags http3`; no symbol references |
| **Total** | **~8,357** | |

`internal/integrations/` is now empty (removed). `go build ./...`, `go build -tags http3 ./...`, `go vet`, and the full `go test ./...` all pass after deletion. CLAUDE.md updated (removed the Feature Flags section + the 4 package-layout entries + refreshed the layer-catalogue accuracy note).

- **Note — `quic-go` now vestigial:** it was only used by `internal/http3`. It remains in `go.mod` (build still passes); run `go mod tidy` to drop it — left untouched to avoid changing deps without sign-off.
- **Note — 12 showcase layer packages** (siem, cluster, clustersync, websocket, grpc, zerotrust, graphql, canary, cache, replay, discovery, ai/remediation + ml/*) still exist but now have **no wiring path at all** (their only would-be wirer, v040, is gone). They're the obvious next deletion batch if you want them gone.

### Round 8 — delete the orphaned showcase layers (§2, completion)

With v040 gone (Round 7), the 12 "showcase" layers had **no wiring path at all**. Verified each had zero live importers and deleted all of them plus their transitively-dead deps — 17 packages, **~47,000 LOC** (≈15k production + ≈32k of dead-code tests):

`layers/{siem,websocket,grpc,zerotrust,graphql,canary,cache,replay}`, `cluster`, `clustersync`, `proxy/grpc`, `discovery`, `ai/remediation`, `ml/{anomaly,features,onnx}`, `layers/botdetect/enhanced`.

`internal/ml` and `internal/proxy/grpc` dirs removed (empty); `internal/ai` and `internal/layers/botdetect` keep their live code. `go build` (default + `-tags http3`), `go vet`, and the full `go test ./...` all pass. CLAUDE.md layer catalogue rewritten (only the 16 wired layers + JS Challenge remain) and the deleted package-layout entries removed.

The corresponding `WAF.GraphQL` / `WAF.MLAnomaly` / `WAF.APIDiscovery` config structs + their `populate*` funcs remain in the config package (self-contained, parsed-but-inert) — removing them is a separate config-schema refactor; left as a documented follow-up.

**Combined dead-code removal (Rounds 7+8): ~55,000 LOC across 21 packages.**

### Round 9 — true zero-dependency (project's #1 constraint)

`internal/http3` (Round 7) was the only user of `quic-go`. Ran `go mod tidy`: `go.mod` now has **no `require` block** and `go.sum` is **empty** — GuardianWAF is genuinely Go-stdlib-only. Verified `go build ./...`, `go build -tags http3 ./...`, `go vet`, and full `go test ./...` all still pass. CLAUDE.md dependency notes updated to reflect the achieved zero-dep state.

**Truly remaining (low severity / decision-gated):** `LoadEnv` `GWAF_*` parse swallows (runtime env; left deliberately); M1 cmdi `checkEncodedNewline` (detector-FP risk); remove the inert `WAF.GraphQL/MLAnomaly/APIDiscovery` config structs (config-schema refactor); §3.2 commit a real DeepCopy generator (now guarded by the Round-6 reflection test). Everything in the config *file* load path is fail-loud.

---

### Round 10 — end-to-end runtime verification (real binary)

After all the above (55k-LOC deletion + fail-closed/fail-loud changes), verified the actual `serve` binary behaves correctly — not just the unit tests:

- **Full `go test -race ./...`**: clean (exit 0) — no data races introduced anywhere.
- **Binary builds + runs** (`go build ./cmd/guardianwaf`, 17 MB); `validate` on the shipped `guardianwaf.yaml` passes.
- **Detection works:** `check` on `?q=1' UNION SELECT password FROM users--` → `Action: block, Score: 190, 4 findings`.
- **P0 verified:** a config starting with `---` → `validate` exits 1 with "YAML document markers ... are not supported".
- **Config fail-loud verified:** `waf.cors.strict_mode: yess` → `validate` exits 1 with `cannot convert "yess" to bool`.
- **C1+C2 verified:** with CRS enabled + a bad `rule_path`, `serve` **refuses to start** (exit 1): "refusing to start: 1 enabled security layer(s) failed to build ... set GWAF_ALLOW_DEGRADED_START=1 to override". With `GWAF_ALLOW_DEGRADED_START=1` it **starts degraded** (binds and runs) — both sides of the escape hatch confirmed.

Conclusion: the deletions and fail-closed changes are correct in the running product, not just in tests.

**Fuzz robustness (the changed code paths):** ran Go's native fuzzers against the modified parser/detector/normalizer code — **~5M total executions, zero crashes/panics**:
- `FuzzYAMLParser` (158k execs) + `FuzzYAMLParserWithValidation` (124k) — the P0 parser changes hold.
- `FuzzSQLiDetector` (849k) + `FuzzXSSDetector` (1.7M) — the H1 raw-fallback detector paths hold.
- `FuzzNormalizeAll` (2.1M) — the normalization path the detectors depend on holds.

**Full security-surface fuzz pass:** for completeness, also fuzzed the rest of the WAF's parse/security surface — all PASS, no crashes:
`FuzzJWTValidateInput` (auth), `FuzzRadixTreeLookup` (IP-ACL), `FuzzCanonicalizePath` + `FuzzDecodeURLRecursive` (path-traversal/evasion surface), `FuzzSQLiTokenizer`, `FuzzRateLimitRule`, `FuzzJA4Fingerprint`. The entire request-parsing and security-decision surface is fuzz-clean.

---

## Appendix — Verification Log

- `go build ./...` → exit 0; `go vet ./...` → exit 0; `go test ./...` → exit 0.
- C1 confirmed at `cmd/guardianwaf/layers.go:18-22` (warn-and-continue, repeated per layer).
- C2 confirmed at `internal/layers/crs/layer.go:55-58`.
- H1 confirmed: `sqli.go:56-67` reads only `Normalized*`; `xss.go:58-78` has raw fallback.
- P0 confirmed by a probe test inside `internal/config`: leading `---` → `err=nil`, config = defaults.
- §2 confirmed via `go list -deps ./cmd/guardianwaf` + grep for importers (v040, feature: zero).
