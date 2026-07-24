# Release Checklist

Pre-release verification steps for GuardianWAF.

## Pre-Release

- [ ] All CI checks pass (build-dashboard, test, lint)
- [ ] Hosted CI `release-evidence` artifact downloaded and attached to the release evidence bundle
- [ ] Source prerequisites pass (`./scripts/check-prereqs.sh`)
- [ ] Frontend tests pass (`cd internal/dashboard/ui && npm test`)
- [ ] Frontend lint clean (`cd internal/dashboard/ui && npm run lint`)
- [ ] Full production-binary Chromium, Firefox, and WebKit dashboard/API E2E suite passes (`make e2e-full-all`)
- [ ] Go tests pass (`go test ./...`)
- [ ] Go tests pass with race detector (`go test -race -count=1 ./...`)
- [ ] Go vet clean (`go vet ./...`)
- [ ] golangci-lint clean (`golangci-lint run ./...`)
- [ ] Focused release benchmark run recorded in `docs/release-performance-evidence.md`
- [ ] Standalone and sidecar proxy load test recorded in `docs/release-performance-evidence.md` (`./scripts/proxy-load-test.sh`)
- [ ] Target deployment load evidence attached to the release bundle (`TARGET_BACKEND_URL=... TARGET_STANDALONE_URL=... ./scripts/target-load-evidence.sh`)
- [ ] Detection quality corpus gate passes and current rates are reflected in `docs/detection-quality.md` (`go test ./internal/layers/detection -run TestDetectionLayer_CorpusQualityBaseline -count=1 -v`)
- [ ] Release evidence bundle generated (`RELEASE_EVIDENCE_HEAVY=1 ./scripts/release-evidence.sh v1.x.x ./previous/guardianwaf-linux-amd64`)
- [ ] Every file under the bundle's `pending/` directory is replaced by real evidence or explicit release-risk acceptance
- [ ] Release evidence bundle verifier passes with no pending files (`./scripts/verify-release-evidence.sh dist/release-evidence/v1.x.x-...`)
- [ ] No uncommitted changes (`git status` clean)
- [ ] Version bumped in relevant files (if applicable)
- [ ] CHANGELOG or release notes drafted

## Build Verification

- [ ] Dashboard build succeeds (`./scripts/build-dashboard.sh`)
- [ ] Full release build succeeds (`./scripts/build.sh v1.x.x`)
- [ ] Docker build succeeds (`docker build -t guardianwaf:v1.x.x .`)
- [ ] Smoke tests pass (`./scripts/smoke-test.sh ./dist/guardianwaf-linux-amd64`)
- [ ] Upgrade/rollback smoke passes against the previous release binary (`./scripts/release-rollback-smoke.sh ./dist/guardianwaf-linux-amd64 ./previous/guardianwaf-linux-amd64`)
- [ ] Binary runs without errors (`./dist/guardianwaf-linux-amd64 serve --help`)
- [ ] Dashboard loads at `http://localhost:9443/` when exposed directly, or through the configured TLS reverse proxy
- [ ] Dashboard hot-reload works (`make ui-dev`)

## Integration Checks

- [ ] Docker Compose test passes (`docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test-runner`)
- [ ] Multi-tenant isolation verified
- [ ] SSE event streaming works in dashboard
- [ ] API endpoints respond correctly (`/api/v1/stats`, `/api/v1/events`)
- [ ] Liveness endpoint responds (`/livez`)
- [ ] Readiness endpoint responds (`/readyz`)
- [ ] Metrics endpoint responds (`/metrics`)
- [ ] Config validation works (`./dist/guardianwaf-linux-amd64 validate -config config.yaml`)
- [ ] Candidate binary can boot the previous release's shared event-state path, and the rollback binary can boot the same path after candidate shutdown
- [ ] Integrity-protected backup/restore smoke passes (`make backup-restore-smoke`)
- [ ] Target-environment restore drill restores config/state/events from an off-host archive, validates replay/readiness, and records RPO ≤ 3600s plus RTO ≤ 300s evidence
- [ ] `promtool check rules` and `promtool test rules` pass for `contrib/prometheus/guardianwaf-rules.yaml`
- [ ] Target Prometheus loads all GuardianWAF rules, `severity=critical` test notification reaches the real on-call pager, and every runbook link resolves

## Security Review Sign-Off

- [ ] Threat model reviewed for this release (`docs/threat-model.md`)
- [ ] External security review scope completed or explicitly risk-accepted (`docs/security-review-scope.md`)
- [ ] All HIGH/CRITICAL external review findings are tracked and remediated before tagging
- [ ] Detection-quality deltas are included in release notes when detector scoring, normalization, or corpus baselines changed
- [ ] Release evidence bundle includes image digest, SBOM, provenance, signature verification, vulnerability scan result, performance evidence, and detection-quality output

## Evidence Bundle

Generate a local release evidence directory before tagging:

```bash
RELEASE_EVIDENCE_HEAVY=1 ./scripts/release-evidence.sh v1.x.x ./previous/guardianwaf-linux-amd64
```

The script writes `dist/release-evidence/<version>-<timestamp>/` with command logs, copied release docs, git state, detection-quality output, Kubernetes/Helm validation, and optional heavy gates such as race tests, release build, smoke tests, rollback smoke, benchmark/load results, and local supply-chain smoke. CI also publishes the fast bundle as the `release-evidence-ci` workflow artifact for hosted-runner proof. When heavy mode runs on a Docker-capable host, `supply-chain/` contains `sbom.spdx.json`, `image-inspect.json`, and `trivy.txt`. The `pending/` directory is part of the release gate: hosted CI, external security review, target-environment load evidence, and tag-time image digest/signature/provenance evidence must be replaced with real artifacts or an explicit risk acceptance before a stable production release.

The final strict verifier requires these replacement artifacts:

- Clean source tree evidence: `git-status.txt` and `git-diff-check.txt` must be empty. The verifier rejects final bundles generated from a dirty worktree or with `git diff --check` findings.
- Manifest evidence: `manifest.txt` must contain `heavy=1`, proving the bundle was generated with `RELEASE_EVIDENCE_HEAVY=1`; final bundle directory names in the generated `<version>-YYYYmmddTHHMMSSZ` form must match `manifest.txt` `version=`.
- Heavy local evidence from `RELEASE_EVIDENCE_HEAVY=1`: `logs/go-race.log`, `logs/build-dashboard.log`, `logs/release-build.log`, `logs/smoke.log`, `logs/release-rollback.log`, `logs/proxy-load.log`, `logs/focused-benchmark.log`, `proxy_load_results.txt`, and `benchmark_results.txt`. The verifier checks these logs for failure markers, requires the rollback smoke log to prove previous-version persistent event writes, candidate upgrade readiness/proxying, rollback readiness/proxying, and final rollback smoke success, rejects any non-zero local proxy-load `errors` line, enforces local proxy-load p99 overhead budgets from `docs/performance-budget.md` (standalone `< 5 ms`, sidecar `< 3 ms`), and requires the focused benchmark output to include every production budget benchmark named in `docs/performance-budget.md`.
- `hosted-ci/ci-run.txt` with exactly one canonical GuardianWAF repository GitHub Actions `https://github.com/guardianwaf/guardianwaf/actions/runs/...` run URL with no query string or extra path, exactly one full 40-character release candidate commit SHA, and exactly one result value equal to `pass`, `passed`, `success`, or `succeeded`.
- `target-load/target_load_results.txt` from `./scripts/target-load-evidence.sh`, including `timestamp_utc=`, `target_label=`, `backend_url=`, `standalone_url=` or `sidecar_url=`, `requests=`, `concurrency=`, `warmup=`, `cpu_count=`, `kernel=`, a `## backend` baseline section, `errors=0`, `latency_p99_ms=`, and `overhead_p99_ms=`. The verifier requires critical metadata fields to appear only once, requires `timestamp_utc` to be a valid UTC timestamp in `YYYY-MM-DDTHH:MM:SSZ` format, requires `target_label` to identify the measured environment instead of generic values such as `target`, `test`, `default`, or `unknown`; requires `requests >= 1000`, `concurrency >= 10`, and `warmup >= 50`; rejects whitespace, hostless, credential-bearing, or fragment-bearing target-load URLs; rejects any non-zero target-load `errors` line; and enforces the target deployment p99 overhead budgets from `docs/performance-budget.md`: standalone `< 5 ms`, sidecar `< 3 ms`.
- `release-artifacts/checksums.txt` from GoReleaser or the `release-binary-checksums` artifact; the release workflow runs `./scripts/verify-release-evidence.sh --check-release-checksums dist/release-evidence/release` before uploading this artifact, and the verifier requires a SHA-256 checksum line for a GuardianWAF artifact whose name matches `manifest.txt` `version=`, rejects any GuardianWAF checksum line for another version, and rejects mixed GuardianWAF artifact versions in the same checksum file.
- `manifest.txt`, `hosted-ci/ci-run.txt`, `supply-chain/image-digest.txt`, `supply-chain/imagetools.txt`, `supply-chain/cosign-verify.txt`, `supply-chain/provenance-verify.txt`, `supply-chain/sbom-attestation-verify.txt`, `supply-chain/sbom.spdx.json`, and `supply-chain/trivy.txt` from the release workflow's `release-supply-chain-evidence` artifact. The release workflow runs `./scripts/verify-release-evidence.sh --check-supply-chain dist/release-evidence/release` before uploading this artifact. The verifier checks that the recorded image digest is a full `sha256:<64 hex>` digest and appears in the `imagetools` output, requires the image digest tag to match `manifest.txt` `version=`, requires `manifest.txt` `git_commit=`, hosted CI commit, and image digest commit to be full 40-character SHAs for the exact same commit, requires the verification evidence files to record the same `image_ref`, release workflow certificate identity, and GitHub Actions OIDC issuer, signature verification output, provenance attestation verification output, SBOM attestation verification output, SPDX marker with at least one package entry, vulnerability scan output, and rejects non-zero HIGH/CRITICAL findings.
- `external-security-review/report.md` or `external-security-review/risk-acceptance.md` with reviewer findings or explicit approver/risk-acceptance text for the same `manifest.txt` `version=` and hosted CI commit. The verifier rejects report finding-table rows where `Severity` is High/Critical and `Status` is open, unfixed, unresolved, or not fixed. Review reports must include valid calendar review dates in `YYYY-MM-DD` format and a reviewer sign-off. Risk-acceptance files must include a valid, non-expired expiration or follow-up date in `YYYY-MM-DD` format, an owner or approver, and a tracked issue, PR, or ticket reference. Start from `docs/templates/security-review-report.md` or `docs/templates/security-risk-acceptance.md`, then replace every `TBD`/blank placeholder before running the verifier.

Before tagging a stable production release, verify the final bundle after replacing `pending/` files with real artifacts or explicit risk acceptance:

```bash
CI_RUN_URL=https://github.com/guardianwaf/guardianwaf/actions/runs/... \
CI_COMMIT=<release-candidate-sha> \
CI_RESULT=passed \
TARGET_LOAD_FILE=target_load_results.txt \
RELEASE_CHECKSUM_FILE=checksums.txt \
RELEASE_SUPPLY_CHAIN_DIR=release-supply-chain-evidence/supply-chain \
SECURITY_REVIEW_REPORT=security-review-report.md \
./scripts/assemble-release-evidence.sh dist/release-evidence/v1.x.x-YYYYmmddTHHMMSSZ

./scripts/verify-release-evidence.sh dist/release-evidence/v1.x.x-YYYYmmddTHHMMSSZ
```

Use `./scripts/verify-release-evidence.sh --allow-pending ...` only for intermediate CI/local bundle checks that still contain files under `pending/`. When `pending/` is empty, the verifier always enforces the full strict release gate even if `--allow-pending` is supplied.

`./scripts/assemble-release-evidence.sh` validates copied or generated hosted CI evidence with `./scripts/verify-release-evidence.sh --check-hosted-ci ...` before clearing `pending/hosted-ci.txt`, copied target-load evidence with `./scripts/verify-release-evidence.sh --check-target-load ...` before clearing `pending/target-environment-load.txt`, copied release checksums with `./scripts/verify-release-evidence.sh --check-release-checksums ...` before clearing `pending/release-artifact-checksums.txt`, copied release supply-chain evidence with `./scripts/verify-release-evidence.sh --check-supply-chain ...` before clearing `pending/image-digest-signature-provenance.txt`, and copied external security review or risk-acceptance evidence with `./scripts/verify-release-evidence.sh --check-external-review ...` before clearing `pending/external-security-review.txt`.

## Release Process

1. Tag the release: `git tag -a v1.x.x -m "Release v1.x.x"`
2. Push the tag: `git push origin v1.x.x`
3. GitHub Actions runs a staged transaction:
   - `stage-binaries` runs prerequisites, dependency audit, format/tidy/race gates, and GoReleaser with `--skip=publish`; it verifies checksums before uploading immutable workflow artifacts.
   - `stage-image` builds only `candidate-<commit-sha>`. SBOM/provenance attestations enabled by Docker Buildx. Keyless image signature created with cosign. The job generates the SPDX SBOM, scans the digest with Trivy, and uploads immutable workflow artifacts. Provenance and SBOM attestations verified with cosign before the transaction can advance. No semantic image tag exists yet.
   - `verify-release` joins both staged artifacts, proves their manifests/checksums match, reruns the checksum and supply-chain evidence verifiers, and emits one promotion transaction artifact.
   - `promote-release` is the only job with GitHub Release write permission. It re-verifies the promotion bundle, creates a private GitHub draft, attaches semantic GHCR tags to the verified digest, verifies every tag, and publishes the draft last.
   - On a promotion failure, `scripts/promote-release.sh` deletes the unpublished draft, restores prior mutable `major`, `minor`, and `latest` aliases, and deletes the staged package version when that cleanup can be proven safe. If image staging is attempted but fails before verification or promotion completes, the always-run `cleanup-staged-image` job invokes `scripts/cleanup-staged-release-image.sh`, which deletes OCI referrers and then the package version only when its sole tag is the SHA-scoped candidate.
4. Verify the GitHub Release page has all archives, `checksums.txt`, `sbom.spdx.json`, and the release-evidence archive.
5. Verify the Docker image is available: `docker pull ghcr.io/guardianwaf/guardianwaf:v1.x.x`.

GitHub Actions artifacts are internal staging surfaces. The SHA-scoped candidate image may be registry-visible, but it is not a supported release identifier and is removed by compensation when the transaction fails. Do not manually publish the draft or attach semantic tags when `verify-release` or `promote-release` fails; resolve the failure and create a new immutable candidate.

## Supply-Chain Verification

After the release workflow finishes, verify the immutable image digest instead of the mutable tag:

```bash
IMAGE=ghcr.io/guardianwaf/guardianwaf:v1.x.x
DIGEST=$(docker buildx imagetools inspect "$IMAGE" --format '{{json .Manifest.Digest}}' | tr -d '"')
IMAGE_BY_DIGEST=ghcr.io/guardianwaf/guardianwaf@"$DIGEST"
```

Verify the keyless signature was issued by this repository's release workflow through GitHub Actions OIDC:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/guardianwaf/guardianwaf/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE_BY_DIGEST"
```

Verify Buildx provenance and SBOM attestations exist:

```bash
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp 'https://github.com/guardianwaf/guardianwaf/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE_BY_DIGEST"

cosign verify-attestation \
  --type spdxjson \
  --certificate-identity-regexp 'https://github.com/guardianwaf/guardianwaf/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE_BY_DIGEST"
```

Download `checksums.txt` and `sbom.spdx.json` from the GitHub Release page, plus the `release-binary-checksums` and `release-supply-chain-evidence` workflow artifacts. Keep `checksums.txt` as `release-artifacts/checksums.txt` in the release evidence bundle. Keep the supply-chain artifact's `supply-chain/image-digest.txt`, `supply-chain/imagetools.txt`, `supply-chain/cosign-verify.txt`, `supply-chain/provenance-verify.txt`, `supply-chain/sbom-attestation-verify.txt`, `supply-chain/sbom.spdx.json`, and `supply-chain/trivy.txt` with the release evidence bundle.

## Post-Release

- [ ] Release notes published on GitHub
- [ ] Documentation updated (getting-started, configuration, deployment-modes)
- [ ] CLAUDE.md updated if architecture changed
- [ ] CONTRIBUTING.md updated if workflow changed
- [ ] Announcement sent (if major release)
