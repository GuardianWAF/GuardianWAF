# GuardianWAF — Production Readiness Report

**Assessment date:** 2026-07-24
**Target release:** `0.4.0`
**Assessed base commit:** `e2d91661a30a0a49f5b8ef1fe7e4c6bd5e0ad0bd`
**Assessed source:** the current working tree on top of that commit
**Go toolchain:** Go 1.26.5
**Decision:** **NO-GO for a stable production release**
**Permitted use:** controlled non-production validation only

## Executive decision

GuardianWAF's current working tree has strong local engineering evidence. The backend, frontend, production build, race suite, recovery smoke, container supply-chain smoke, Kubernetes/Helm validation, and the complete Chromium/Firefox/WebKit production-binary E2E suite all passed during this assessment.

That does **not** yet make `0.4.0` releasable. Stable release approval is blocked because:

1. there is no immutable `v0.4.0` candidate corresponding to the tested source;
2. the tested source has 77 tracked changes plus 16 untracked entries and is therefore not reproducible from a commit;
3. the committed dashboard dependency gate currently fails, including three high-severity development/build-chain advisories and one moderate direct runtime advisory;
4. the tag workflow can publish GitHub and container artifacts before image scanning and attestation verification finish, so a failed release can leave public partial artifacts;
5. no exact-candidate final release-evidence bundle exists; the checked-in bundles are stale and pass only the intermediate `--allow-pending` mode; and
6. the documented production Compose overlay still resolves the development `backend` and `backend2` services.

The correct disposition is therefore **NO-GO for stable production**, while continuing candidate hardening and staging validation.

## Scope and interpretation

This report distinguishes three different objects:

| Object | Identity | Decision | Reason |
|---|---|---:|---|
| Current working tree | `e2d9166…` plus local changes | **NO-GO** | Mutable and not reproducible; dependency and release gates are unresolved |
| Committed `HEAD` | `e2d91661a30a0a49f5b8ef1fe7e4c6bd5e0ad0bd` | **NO-GO** | Does not contain the assessed working-tree hardening and has no `v0.4.0` tag |
| Stable `v0.4.0` artifact | Not present | **NOT ASSESSABLE** | No immutable tag, checksums, signed digest, provenance, or final evidence bundle exists |

At assessment time:

- branch: `main`, one commit ahead of `origin/main`;
- `git describe --tags --always --dirty`: `v0.2.0-67-ge2d9166-dirty`;
- tags pointing at `HEAD`: none;
- repository release tags: `v0.2.0`, `v0.1.0`;
- `VERSION`: `0.4.0`;
- working-tree entries: 77 tracked changes and 16 untracked entries;
- `dist/release-evidence/`: stale `ci` and `local-smoke` bundles exist for commit `9de1b94…`; both contain pending markers and are not `0.4.0` sign-off evidence.

A local test result proves behavior of the local snapshot. It does not prove behavior of a future tag unless the snapshot is committed unchanged and all evidence is regenerated against that exact commit and artifact digest.

## Readiness scorecard

| Area | Status | Assessment |
|---|---:|---|
| Go build and unit/integration tests | **PASS** | Build, tests, race tests, vet, and module tidiness passed |
| Frontend build and tests | **PASS** | Vitest, ESLint, TypeScript, and Vite production build passed |
| Browser/API E2E | **PASS** | 540/540 tests passed across Chromium, Firefox, and WebKit against the production binary |
| Coverage | **PASS** | Fresh repository coverage result: 93.8% statements |
| Fuzz/smoke checks | **PASS** | Focused fuzz smoke and application smoke suites passed |
| Backup and restore mechanics | **PASS, LOCAL** | Local backup/restore smoke met the configured RPO/RTO assertions |
| Kubernetes/Helm syntax | **PASS** | Static manifests and chart lint/render validation passed |
| Container build and scan smoke | **PASS, LOCAL** | Runtime image build, SBOM generation, and high/critical container scan smoke passed |
| Dependency risk | **FAIL** | Dashboard `npm audit` reports unresolved advisories; committed CI audit gate is red |
| Release workflow | **FAIL** | Deterministic post-publication path failures exist, and image verification occurs after push |
| Candidate reproducibility | **FAIL** | Tested source is dirty and no `v0.4.0` tag exists |
| Release evidence/provenance | **FAIL** | Only stale, allow-pending bundles exist; no strict exact-candidate bundle passes |
| Production Compose topology | **FAIL** | Production overlay retains development backend services |
| Production defaults | **CONDITIONAL** | Helm defaults favor ease of evaluation over durable, restricted operation |
| Hosted/target-environment proof | **INCOMPLETE** | No exact-candidate hosted CI, target load, prior-version rollback, or external-review/risk-acceptance evidence was available |

## Fresh verification evidence

The following commands were run against the assessed working tree on 2026-07-24.

### Passed

| Command | Result |
|---|---|
| `./scripts/check-prereqs.sh` | Passed: Go 1.26.5, Node.js 24.15.0, npm 11.18.0 |
| `go test ./...` | Passed |
| `go test -race -count=1 ./...` | Passed |
| `go vet ./...` | Passed |
| `go mod tidy -diff` | Passed; no module drift |
| `git ls-files '*.go' -z \| xargs -0 gofmt -s -l` | Passed; no tracked Go files reported |
| `go test -count=1 -coverprofile=… ./...` | Passed; total statement coverage 93.8% |
| `npm test -- --run` in `internal/dashboard/ui` | Passed: 20 files, 152 tests |
| `npm run lint` in `internal/dashboard/ui` | Passed with zero warnings |
| `npm run build` in `internal/dashboard/ui` | Passed |
| `make build` | Passed |
| `./scripts/smoke-test.sh` | Passed |
| `./scripts/fuzz-smoke.sh` | Passed |
| `E2E_PROJECTS=chromium,firefox,webkit E2E_PLAYWRIGHT_DOCKER=true ./scripts/full-e2e.sh` | Passed: 540/540 tests |
| `./scripts/validate-k8s.sh` | Passed: 12 valid, 0 invalid, 1 skipped resource |
| `./scripts/validate-helm.sh` | Passed: chart lint and rendered-resource validation |
| `./scripts/backup-restore-smoke.sh` | Passed; measured restore 0s against 300s RTO target |
| `./scripts/supply-chain-smoke.sh` | Passed; image build, SBOM, and high/critical scan smoke |
| `git diff --check` | Passed |

### Failed or incomplete

| Check | Outcome | Interpretation |
|---|---|---|
| `npm audit` in `internal/dashboard/ui` | Failed: 3 high, 1 moderate | Release blocker; the committed CI gate at `.github/workflows/ci.yml:48-50` would fail |
| `npm audit --omit=dev` | Failed: 1 moderate direct dependency advisory | Runtime dependency risk remains even after excluding development dependencies |
| `make fmt-check` | Failed on untracked `.temp_files` source snapshots | Gate is non-hermetic in a dirty checkout; tracked Go source itself is formatted |
| `govulncheck ./...` | Tool unavailable locally | Must be supplied by hosted exact-candidate evidence |
| `gosec ./...` | Tool unavailable locally | Must be supplied by hosted exact-candidate evidence |
| KinD deployment smoke | No exact-candidate hosted result retained | CI defines a separate KinD job, but the release-evidence job does not depend on it |
| Target-environment load evidence | Not run | Requires the real target environment and production topology |
| Cross-version rollback smoke | Not run with the actual previous release binary | Local same-binary compatibility is insufficient for release sign-off |
| External security review / risk acceptance | Neither final review nor explicit acceptance attached | The verifier permits a matching review or a bounded, owner-approved risk acceptance |

## Release blockers

### R1 — No immutable, reproducible `v0.4.0` candidate

**Severity:** Release blocker
**Evidence:**

- `VERSION` declares `0.4.0`, but no `v0.4.0` tag exists.
- `HEAD` is untagged and the tested tree contains 77 tracked changes plus 16 untracked entries.
- `Makefile:4-7` embeds Git description, commit, and build time; the current build identifies itself as dirty.
- The project verifier expects manifest, commit, checksums, hosted CI, supply-chain, rollback, target-load, and either matching external-review evidence or a bounded explicit risk acceptance (`scripts/verify-release-evidence.sh:293-340`, `scripts/verify-release-evidence.sh:664-730`, `scripts/verify-release-evidence.sh:743-867`).

**Impact:** Results cannot be tied to a source commit or redistributed artifact. A future commit or tag may differ from the tested snapshot.

**Exit criteria:**

1. resolve or intentionally discard all working-tree changes;
2. commit the complete candidate;
3. create an annotated release-candidate tag on that commit;
4. build once from that tag;
5. identify the container by digest and binaries by checksums; and
6. regenerate all evidence against those immutable identifiers.

### R2 — Dashboard dependency audit is failing

**Severity:** Release blocker
**Evidence:**

Fresh `npm audit` reported:

- `brace-expansion`: high, transitive;
- `js-yaml`: high, transitive;
- `postcss`: high, transitive;
- `react-router`: moderate, direct runtime dependency.

The production-only audit still reports the direct `react-router` advisory. CI explicitly runs `npm audit --audit-level=high` at `.github/workflows/ci.yml:48-50`, so the current lockfile cannot produce a fully green required CI run.

**Impact:** The candidate cannot satisfy its own committed dependency gate. The direct runtime advisory also requires an applicability review rather than being dismissed as build-only exposure.

**Exit criteria:**

1. update the affected dependencies and lockfile using the smallest compatible version changes;
2. rerun frontend unit, lint, build, and all-browser E2E tests;
3. require `npm audit --audit-level=high` to pass;
4. document the `react-router` advisory disposition if it remains; and
5. attach the audit output to the exact-candidate evidence bundle.

### R3 — Transactional release workflow implemented; hosted proof pending

**Severity:** Release blocker pending hosted validation
**Current implementation:**

- `stage-binaries` builds archives with GoReleaser `--skip=publish`, creates checksum evidence, and uploads immutable workflow artifacts without GitHub Release write permission.
- `stage-image` pushes only the SHA-scoped candidate image, then signs, scans, and verifies the digest and attestations. No semantic image tag is created in staging.
- `verify-release` joins the staged artifacts, compares invariant manifest fields, reruns checksum and supply-chain evidence verification, and emits one promotion transaction.
- `promote-release` is the only job with GitHub Release write permission. `scripts/promote-release.sh` re-verifies the bundle, creates a private draft, promotes the verified digest, verifies every semantic tag, and publishes the draft last.
- Failure-path tests cover draft rollback, mutable-alias restoration, staged package cleanup, and candidate-only orphan cleanup. `cleanup-staged-image` also compensates when image staging fails after the candidate was pushed.

**Local verification:** Release-contract tests, helper syntax, YAML parsing, checksum-verified `actionlint` v1.7.12, all Go tests, the race suite, `go vet`, module tidiness, and the production build passed.

**Remaining exit criterion:** Run the tag workflow for a new immutable candidate in hosted GitHub Actions and retain evidence that staging, verification, promotion, and compensation behave as designed. Until that exact-candidate hosted proof exists, R3 remains open for stable-release sign-off.

### R4 — No strict exact-candidate release-evidence bundle exists

**Severity:** Release blocker
**Evidence:**

`dist/release-evidence/ci` and `dist/release-evidence/local-smoke` exist, but both describe commit `9de1b944…` from 2026-06-11, set `heavy=0`, contain pending markers, and pass only `verify-release-evidence.sh --allow-pending`. They are stale intermediate bundles, not evidence for the assessed `e2d9166…` working tree or `0.4.0`. The strict verifier requires, among other items:

- hosted CI identity and result;
- exact manifest version and commit;
- release checksums;
- signed image digest;
- provenance and SBOM-attestation verification;
- high/critical vulnerability scan result;
- target load evidence;
- cross-version rollback evidence; and
- a matching external security review or a bounded explicit risk-acceptance record.

The verifier's `--allow-pending` mode is an intermediate assembly mode, not stable sign-off.

**Impact:** There is no auditable exact-candidate chain connecting source, tests, artifact, deployment result, and security disposition.

**Exit criteria:** Generate a heavy bundle for the immutable candidate and pass `./scripts/verify-release-evidence.sh <bundle>` without `--allow-pending` and without pending files.

### R5 — Documented production Compose overlay retains development services

**Severity:** Release blocker for the Compose deployment path
**Evidence:**

- `docker-compose.prod.yml:3` instructs operators to combine the development base file with the production override.
- The base file defines `backend` and `backend2` demo services (`docker-compose.yml:68-105`).
- The production override changes only `guardianwaf` (`docker-compose.prod.yml:5-25`).
- `docker compose -f docker-compose.yml -f docker-compose.prod.yml config --services` resolves `backend`, `backend2`, and `guardianwaf`.

**Impact:** Following the documented production command deploys demonstration workloads into the production topology and can route traffic to unintended local examples.

**Exit criteria:** Provide a standalone production Compose file or explicitly remove/disable demo services in the production profile, then add a CI assertion over the resolved service list and effective configuration.

## High-priority production risks

These items do not invalidate every possible deployment, but they must be explicitly resolved for the chosen production topology.

### P1 — Kubernetes defaults are not durable production defaults

The chart defaults to two replicas, memory event storage, disabled persistence, disabled TLS, disabled NetworkPolicy, and disabled ServiceMonitor (`contrib/k8s/helm/values.yaml:3-20`, `31-36`, `80-110`, `180-209`). The checked-in static deployment also mounts GuardianWAF state from an `emptyDir` (`contrib/k8s/deployment.yaml:95-108`), while its config selects in-memory event storage (`contrib/k8s/configmap.yaml:86-89`). The chart does include probes, resources, security context controls, PDB, HPA, persistence templates, and secret references, which is a strong base. However, an operator can install a superficially healthy multi-replica deployment whose event and audit state is pod-local and ephemeral.

**Required disposition:** Ship and validate a `values-production.yaml` profile and a production static-manifest overlay that enable durable storage, secret-backed credentials, TLS or trusted ingress termination, restricted network policy, monitoring integration, and a verified image digest. Document whether state is shared, replicated, or intentionally per-pod.

### P1 — Production deployment references a tag and Helm cannot express digest-only images

Compose and Kubernetes examples use `ghcr.io/guardianwaf/guardianwaf:0.4.0` (for example, `docker-compose.yml:7` and `contrib/k8s/deployment.yaml:24`). A semantic tag is useful for humans but is mutable at the registry boundary. The Helm template always renders `repository:tag` at `contrib/k8s/helm/templates/deployment.yaml:33`; despite the comment in `values.yaml:8-10`, there is no separate digest value or digest-aware rendering path.

**Required disposition:** Add tested digest-aware image rendering, record the verified digest generated by the release workflow, and deploy that digest while retaining the version tag only as metadata.

### P1 — Local ignored AI configuration can enter Docker build context

`data/ai/ai_config.json` is ignored by Git but not by `.dockerignore`; `Dockerfile` copies the source into the builder. The final runtime image inspected during this assessment did not contain `data/ai`, and `*.key` excludes the local encryption-key file, but a local AI config can still be transmitted to a local or remote BuildKit daemon and retained in builder cache.

**Required disposition:** Exclude `/data/`, AI runtime state, and all local configuration/credential paths from Docker build context. Add a build-context regression test and rotate any credential ever sent to an untrusted/shared builder.

### P1 — Security support policy is stale

`SECURITY.md:3-8` lists only `0.1.x` as supported while the candidate and deployment documentation target `0.4.0`.

**Required disposition:** Define the support window for `0.4.x`, the status of older branches, disclosure SLAs, and release revocation/patch procedures before stable publication.

### P1 — Target load, failover, and real rollback proof are missing

Local tests establish functional correctness but do not prove latency, capacity, disruption behavior, storage semantics, or rollback compatibility in the target topology. The repository provides scripts for target load and rollback evidence, but no exact-candidate outputs were available.

**Required disposition:** Run the target load plan, pod/node disruption tests, and upgrade/rollback smoke using the real previous release binary and production-equivalent state. Record p50/p95/p99 latency, throughput, error rate, resource headroom, event loss, alert delivery, RPO, and RTO.

### P2 — Monitoring assets are present but installation is not end-to-end

The repository includes a metrics contract, Grafana material, Prometheus rules, alert-delivery health metrics, health probes, and runbooks. The Helm chart does not include a ServiceMonitor template even though monitoring is described in values, and alert rules/dashboards are not automatically proven against a live Prometheus/Grafana installation.

**Required disposition:** Either package first-class ServiceMonitor/PrometheusRule/dashboard resources or document a tested external integration. Validate scrape discovery, rule evaluation, alert routing, and a synthetic alert delivery in staging.

### P2 — Repository-wide format target is non-hermetic in dirty checkouts

Tracked Go files are formatted, but `make fmt-check` invokes `gofmt -s -l .` and traverses untracked source snapshots under `.temp_files`. This makes the documented local gate fail for reasons unrelated to the candidate.

**Required disposition:** Restrict format checks to Git-tracked Go files or prune/exclude task scratch directories before invoking the gate.

## Validated strengths

The NO-GO decision should not obscure substantial readiness progress:

- the Go module has no external Go dependencies (`go.mod:7`);
- all third-party GitHub Actions examined are pinned to commit SHAs;
- Go tests and the complete race suite pass;
- total statement coverage is 93.8%;
- frontend unit tests, lint, type checking, and production build pass;
- 540 production-binary browser/API tests pass across Chromium, Firefox, and WebKit;
- tracked Go source is formatted and `go vet` is clean;
- application smoke and focused fuzz smoke pass;
- Kubernetes manifests and the Helm chart validate;
- the container builds as a non-root, minimal runtime image and local SBOM/scan smoke passes;
- backup creation, integrity verification, restore, and RTO assertion pass locally;
- configured file event storage fails startup on initialization error rather than silently falling back to memory (`cmd/guardianwaf/event_store.go:12-35`, `cmd/guardianwaf/engine_runtime.go:12-16`);
- the static Kubernetes profile configures an audit path and hardened mounts, but its `state` volume is explicitly ephemeral `emptyDir` storage (`contrib/k8s/deployment.yaml:95-108`);
- deployment templates include resource requests/limits, readiness/liveness probes, restricted security contexts, HPA/PDB options, secret references, and config-checksum rollout triggers;
- metrics, SLO recording/alert rules, dashboards, runbooks, backup scripts, rollback scripts, and a release-evidence verifier exist.

These strengths reduce remediation scope: the primary gap is now the integrity of the **release transaction and production profile**, not basic application correctness.

## Remediation plan

### Phase 0 — Freeze and identify the candidate

1. Stop changing the candidate while evidence is being generated.
2. Reconcile all 77 tracked changes and 16 untracked entries.
3. Remove assessment scratch artifacts from the release checkout.
4. Commit the intended `0.4.0` source and create an annotated RC tag.
5. Record the full commit SHA before running any release gate.

### Phase 1 — Restore mandatory gates

1. Update dashboard dependencies and lockfile until the high-severity audit gate passes.
2. Review and remediate or formally disposition the direct `react-router` advisory.
3. Rerun frontend tests, lint, build, Go tests/race/vet, fuzz smoke, smoke tests, and 540-test E2E suite.
4. Run hosted `govulncheck`, `gosec`/equivalent SAST, secret scanning, and CodeQL on the exact RC commit.
5. Make the format gate operate only on candidate source.

### Phase 2 — Make release publication transactional

1. Split artifact creation from publication.
2. Build binaries and image once; address them by checksum/digest.
3. Generate SBOM and provenance before promotion.
4. Scan and verify signatures/attestations before publishing public release assets or mutable tags.
5. Publish only after a single aggregate release gate passes.
6. Test and document cleanup for a deliberately failed pre-publication gate.

### Phase 3 — Harden supported production topologies

1. Replace the Compose overlay with a standalone production file and assert its resolved services.
2. Add and test a production Helm values profile.
3. Add digest-aware Helm rendering and pin all production images by verified digest.
4. Enable durable state, audit persistence, TLS/ingress protection, NetworkPolicy, and monitoring for the target environment.
5. Exclude local runtime/AI data from Docker build context.
6. Update `SECURITY.md` for the supported release line.

### Phase 4 — Produce immutable operational evidence

1. Run hosted CI on the RC commit.
2. Run KinD and production-equivalent deployment smoke.
3. Run target load and capacity tests.
4. Exercise pod/node disruption and alert-delivery failure paths.
5. Back up and restore production-equivalent state.
6. Upgrade from and roll back to the actual previous release binary.
7. Obtain independent security review, or create the verifier-supported bounded risk acceptance with an owner, expiry, version, and exact commit.
8. Assemble the heavy release bundle and verify it with no pending files.

## Stable-release exit gate

A release owner may change the verdict to **GO** only when all of the following are true for one immutable commit and artifact set:

- [ ] Clean, committed source tree and annotated `v0.4.0` tag
- [ ] Version synchronized across source, chart, Compose, manifests, release metadata, and runtime output
- [ ] Hosted CI green for the tag commit
- [ ] Go test, race, vet, formatting, lint/SAST, and vulnerability checks green
- [ ] Frontend test, lint, build, and dependency audit green
- [ ] 540-test Chromium/Firefox/WebKit production-binary E2E suite green
- [ ] KinD and production-topology smoke green
- [ ] Standalone production Compose resolves only intended services
- [ ] Production Helm/static-manifest profiles validated with durable state, digest pinning, and restricted security settings
- [ ] Target load/SLO evidence meets documented thresholds
- [ ] Backup/restore and real cross-version rollback evidence pass
- [ ] Container digest, binary checksums, SBOM, signature, and provenance verified
- [ ] High/critical image scan clean or formally accepted with expiry and owner
- [ ] External security review attached and blockers closed, or verifier-compliant bounded risk acceptance approved
- [ ] `verify-release-evidence.sh` passes the final heavy bundle without `--allow-pending`
- [ ] Publication occurs only after every preceding gate passes

## Final verdict

**NO-GO for GuardianWAF `0.4.0` as a stable production release on 2026-07-24.**

The application snapshot demonstrates strong functional quality, but the release candidate is not immutable, the dependency gate is not green, publication is not atomic, the production Compose path is unsafe as documented, and the required evidence chain is incomplete. Resolve R1–R5, harden the selected production topology, and regenerate all evidence against a single tagged commit and digest before reconsidering release approval.
