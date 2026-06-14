package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestReleaseWorkflowPublishesVerifiableSupplyChainArtifacts(t *testing.T) {
	root := filepath.Join("..", "..")
	workflow := readTextFixture(t, filepath.Join(root, ".github/workflows/release.yml"))
	topLevel := strings.Split(workflow, "\njobs:\n")[0]

	for _, forbidden := range []string{
		"contents: write",
		"packages: write",
		"id-token: write",
	} {
		if strings.Contains(topLevel, forbidden) {
			t.Fatalf("release workflow grants %q at top level; keep write/OIDC permissions scoped to the job that needs them", forbidden)
		}
	}

	for _, want := range []string{
		"id-token: write",
		"# Default token scope is read-only; release jobs opt in to write/OIDC scopes.",
		"permissions:\n  contents: read",
		"goreleaser:\n    permissions:\n      contents: write",
		"docker:\n    needs: goreleaser\n    permissions:\n      contents: write\n      packages: write\n      id-token: write",
		"docker/build-push-action@",
		"id: build",
		"provenance: true",
		"sbom: true",
		"sigstore/cosign-installer@",
		"cosign sign --yes",
		"ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}",
		"Record release image digest",
		"dist/release-evidence/release/manifest.txt",
		"dist/release-evidence/release/hosted-ci/ci-run.txt",
		"dist/release-evidence/release/supply-chain/image-digest.txt",
		"docker buildx imagetools inspect \"${IMAGE_REF}\"",
		"echo \"image_ref=${IMAGE_REF}\"",
		"certificate_identity_regexp=https://github.com/guardianwaf/guardianwaf/.github/workflows/release.yml@refs/tags/v.*",
		"certificate_oidc_issuer=https://token.actions.githubusercontent.com",
		"Verify signed image digest",
		"cosign verify \\",
		"\"${IMAGE_REF}\" 2>&1",
		"dist/release-evidence/release/supply-chain/cosign-verify.txt",
		"Verify provenance attestation",
		"cosign verify-attestation \\",
		"--type slsaprovenance",
		"dist/release-evidence/release/supply-chain/provenance-verify.txt",
		"Verify SBOM attestation",
		"--type spdxjson",
		"dist/release-evidence/release/supply-chain/sbom-attestation-verify.txt",
		"anchore/syft:v1.38.0",
		"-o spdx-json=/out/dist/release-evidence/release/supply-chain/sbom.spdx.json",
		"cp dist/release-evidence/release/supply-chain/sbom.spdx.json sbom.spdx.json",
		"aquasec/trivy:0.68.1 image",
		"--severity HIGH,CRITICAL",
		"tee dist/release-evidence/release/supply-chain/trivy.txt",
		"Verify release supply-chain evidence",
		"./scripts/verify-release-evidence.sh --check-supply-chain dist/release-evidence/release",
		"if: always()",
		"name: release-supply-chain-evidence",
		"path: dist/release-evidence/release/",
		"softprops/action-gh-release@",
		"files: sbom.spdx.json",
		"version: v2.16.0",
		"Verify release binary checksum evidence",
		"dist/release-evidence/release/release-artifacts/checksums.txt",
		"./scripts/verify-release-evidence.sh --check-release-checksums dist/release-evidence/release",
		"name: release-binary-checksums",
		"path: dist/checksums.txt",
		"if-no-files-found: error",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("release workflow missing %q", want)
		}
	}
}

func TestCIWorkflowPinsActionsToolsAndReleaseGates(t *testing.T) {
	root := filepath.Join("..", "..")
	ci := readTextFixture(t, filepath.Join(root, ".github/workflows/ci.yml"))
	release := readTextFixture(t, filepath.Join(root, ".github/workflows/release.yml"))
	website := readTextFixture(t, filepath.Join(root, ".github/workflows/website.yml"))
	workflows := map[string]string{
		"ci.yml":      ci,
		"release.yml": release,
		"website.yml": website,
	}

	for _, want := range []string{
		"build-dashboard:",
		"run: ./scripts/check-prereqs.sh",
		"run: ./scripts/build-dashboard.sh",
		"go test -race -count=1 -coverprofile=coverage.txt -covermode=atomic",
		"go test -tags http3 ./cmd/guardianwaf",
		"./scripts/smoke-test.sh ./guardianwaf",
		"docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test-runner",
		"docker-compose-integration:",
		"docker compose -f docker-compose.test.yml down --remove-orphans",
		"./scripts/kind-smoke.sh",
		"./scripts/supply-chain-smoke.sh",
		"release-evidence:",
		"RELEASE_EVIDENCE_DIR=dist/release-evidence/ci ./scripts/release-evidence.sh ci",
		"name: release-evidence-ci",
		"path: dist/release-evidence/ci/",
		"FUZZTIME=5s ./scripts/fuzz-smoke.sh",
		"run: go test -race ./...",
		"go run golang.org/x/tools/cmd/deadcode@v0.45.0",
		"go install golang.org/x/perf/cmd/benchstat@v0.0.0-20260610192853-712aea8b4705",
		"go install golang.org/x/vuln/cmd/govulncheck@v1.3.0",
		"go install github.com/securego/gosec/v2/cmd/gosec@v2.27.1",
		"gosec -include=G124 -severity=medium -confidence=medium ./internal/dashboard",
		"gosec -include=G115 -severity=medium -confidence=medium ./internal/engine ./internal/proxy",
		"gosec -include=G115 -severity=medium -confidence=medium ./internal/layers/detection/ssrf",
		"gosec -include=G115 -severity=medium -confidence=medium ./...",
		"gosec -include=G304,G703 -severity=medium -confidence=medium ./internal/config",
		"gosec -include=G114 -severity=medium -confidence=medium ./examples/backend ./examples/library",
		"gosec -include=G404,G124 -severity=medium -confidence=medium ./scripts/attack-simulation",
		"gosec -include=G301,G302 -severity=medium -confidence=medium ./internal/engine ./cmd/guardianwaf",
		"gosec -include=G401,G501,G505 -severity=medium -confidence=medium ./internal/layers/botdetect ./internal/tls",
		"gosec -include=G117 -severity=medium -confidence=medium ./internal/tenant",
		"gosec -include=G304,G703 -severity=medium -confidence=medium ./internal/tenant",
		"gosec -include=G304,G703 -severity=medium -confidence=medium ./internal/events",
		"gosec -include=G304,G703 -severity=medium -confidence=medium ./internal/geoip",
		"gosec -include=G304,G703 -severity=medium -confidence=medium ./internal/engine",
		"gosec -include=G304,G703 -severity=medium -confidence=medium ./internal/ai",
		"gosec -include=G304,G703 -severity=medium -confidence=medium ./internal/compliance",
		"gosec -include=G304,G703 -severity=medium -confidence=medium ./cmd/guardianwaf",
		"gosec -include=G304,G703 -severity=medium -confidence=medium ./internal/layers/ipacl",
		"gosec -include=G304,G703 -severity=medium -confidence=medium ./internal/layers/crs",
		"gosec -include=G304,G703 -severity=medium -confidence=medium ./scripts/attack-simulation ./tests/reliability",
		"gosec -include=G304,G703 -severity=medium -confidence=medium ./...",
		"gosec -include=G704 -severity=medium -confidence=medium ./internal/alerting ./internal/geoip ./internal/layers/apisecurity ./internal/layers/threatintel ./internal/layers/virtualpatch",
		"gosec -include=G710 -severity=medium -confidence=medium ./cmd/guardianwaf ./internal/layers/challenge",
		"gosec -include=G705 -severity=medium -confidence=medium ./internal/mcp ./internal/dashboard ./examples/backend",
		"gosec -include=G204 -severity=medium -confidence=medium ./internal/docker",
		"gosec -no-fail ./...",
		"trufflesecurity/trufflehog@d03d0879a3d03548a000f6eb2640307f0815c3b3",
	} {
		if !strings.Contains(ci, want) {
			t.Fatalf("ci workflow missing %q", want)
		}
	}
	for _, want := range []string{
		"version: v2.16.0",
		"run: ./scripts/check-prereqs.sh",
		"go test -race -count=1 ./...",
		"./scripts/verify-release-evidence.sh --check-release-checksums dist/release-evidence/release",
		"provenance: true",
		"sbom: true",
		"cosign sign --yes",
		"cosign verify-attestation \\",
		"--type slsaprovenance",
		"--type spdxjson",
		"./scripts/verify-release-evidence.sh --check-supply-chain dist/release-evidence/release",
		"release-supply-chain-evidence",
		"anchore/syft:v1.38.0",
		"aquasec/trivy:0.68.1 image",
	} {
		if !strings.Contains(release, want) {
			t.Fatalf("release workflow missing %q", want)
		}
	}
	for name, workflow := range workflows {
		shaPinnedAction := regexp.MustCompile(`@[0-9a-f]{40}(\s|$)`)
		for _, forbidden := range []string{
			"@main",
			"@master",
			"@latest",
			"version: latest",
		} {
			if strings.Contains(workflow, forbidden) {
				t.Fatalf("%s contains unpinned workflow/tool reference %q", name, forbidden)
			}
		}
		for lineNo, line := range strings.Split(workflow, "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "uses: ") && !strings.HasPrefix(trimmed, "- uses: ") {
				continue
			}
			if !shaPinnedAction.MatchString(trimmed) {
				t.Fatalf("%s:%d action is not pinned to a commit SHA: %s", name, lineNo+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestReleaseChecklistDocumentsImageVerification(t *testing.T) {
	root := filepath.Join("..", "..")
	checklist := readTextFixture(t, filepath.Join(root, "docs/release-checklist.md"))

	for _, want := range []string{
		"SBOM/provenance attestations enabled by Docker Buildx",
		"Keyless image signature created with cosign",
		"cosign verify",
		"--certificate-identity-regexp",
		"--certificate-oidc-issuer https://token.actions.githubusercontent.com",
		"cosign verify-attestation",
		"docker buildx imagetools inspect",
		"sbom.spdx.json",
		"release-supply-chain-evidence",
		"supply-chain/image-digest.txt",
		"supply-chain/cosign-verify.txt",
		"supply-chain/provenance-verify.txt",
		"supply-chain/sbom-attestation-verify.txt",
		"supply-chain/trivy.txt",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("release checklist missing %q", want)
		}
	}
}

func TestReleaseChecklistDocumentsSecurityAndDetectionGates(t *testing.T) {
	root := filepath.Join("..", "..")
	checklist := readTextFixture(t, filepath.Join(root, "docs/release-checklist.md"))
	reviewScope := readTextFixture(t, filepath.Join(root, "docs/security-review-scope.md"))
	reviewTemplate := readTextFixture(t, filepath.Join(root, "docs/templates/security-review-report.md"))
	riskTemplate := readTextFixture(t, filepath.Join(root, "docs/templates/security-risk-acceptance.md"))
	script := readTextFixture(t, filepath.Join(root, "scripts/release-evidence.sh"))
	assembleScript := readTextFixture(t, filepath.Join(root, "scripts/assemble-release-evidence.sh"))
	verifyScript := readTextFixture(t, filepath.Join(root, "scripts/verify-release-evidence.sh"))

	for _, want := range []string{
		"Detection quality corpus gate passes and current rates are reflected in `docs/detection-quality.md`",
		"go test ./internal/layers/detection -run TestDetectionLayer_CorpusQualityBaseline -count=1 -v",
		"Hosted CI `release-evidence` artifact downloaded and attached to the release evidence bundle",
		"Release evidence bundle generated (`RELEASE_EVIDENCE_HEAVY=1 ./scripts/release-evidence.sh v1.x.x ./previous/guardianwaf-linux-amd64`)",
		"Every file under the bundle's `pending/` directory is replaced by real evidence or explicit release-risk acceptance",
		"Release evidence bundle verifier passes with no pending files (`./scripts/verify-release-evidence.sh dist/release-evidence/v1.x.x-...`)",
		"Use `./scripts/verify-release-evidence.sh --allow-pending ...` only for intermediate CI/local bundle checks that still contain files under `pending/`",
		"When `pending/` is empty, the verifier always enforces the full strict release gate even if `--allow-pending` is supplied",
		"./scripts/assemble-release-evidence.sh dist/release-evidence/v1.x.x-YYYYmmddTHHMMSSZ",
		"RELEASE_SUPPLY_CHAIN_DIR=release-supply-chain-evidence/supply-chain",
		"TARGET_LOAD_FILE=target_load_results.txt",
		"RELEASE_CHECKSUM_FILE=checksums.txt",
		"./scripts/verify-release-evidence.sh dist/release-evidence/v1.x.x-YYYYmmddTHHMMSSZ",
		"docs/templates/security-review-report.md",
		"docs/templates/security-risk-acceptance.md",
		"supply-chain/` contains `sbom.spdx.json`, `image-inspect.json`, and `trivy.txt`",
		"## Security Review Sign-Off",
		"## Evidence Bundle",
		"Threat model reviewed for this release (`docs/threat-model.md`)",
		"External security review scope completed or explicitly risk-accepted (`docs/security-review-scope.md`)",
		"All HIGH/CRITICAL external review findings are tracked and remediated before tagging",
		"Detection-quality deltas are included in release notes when detector scoring, normalization, or corpus baselines changed",
		"Release evidence bundle includes image digest, SBOM, provenance, signature verification, vulnerability scan result, performance evidence, and detection-quality output",
		"Clean source tree evidence: `git-status.txt` and `git-diff-check.txt` must be empty",
		"The verifier rejects final bundles generated from a dirty worktree or with `git diff --check` findings",
		"Manifest evidence: `manifest.txt` must contain `heavy=1`",
		"proving the bundle was generated with `RELEASE_EVIDENCE_HEAVY=1`",
		"`logs/go-race.log`, `logs/build-dashboard.log`, `logs/release-build.log`, `logs/smoke.log`, `logs/release-rollback.log`, `logs/proxy-load.log`, `logs/focused-benchmark.log`, `proxy_load_results.txt`, and `benchmark_results.txt`",
		"rejects any non-zero local proxy-load `errors` line",
		"enforces local proxy-load p99 overhead budgets from `docs/performance-budget.md`",
		"enforces the target deployment p99 overhead budgets from `docs/performance-budget.md`",
		"standalone `< 5 ms`, sidecar `< 3 ms`",
		"requires the focused benchmark output to include every production budget benchmark named in `docs/performance-budget.md`",
		"GuardianWAF repository GitHub Actions `https://github.com/guardianwaf/guardianwaf/actions/runs/...` run URL",
		"`timestamp_utc=`, `target_label=`, `backend_url=`, `standalone_url=` or `sidecar_url=`, `requests=`, `concurrency=`, `warmup=`",
		"`release-artifacts/checksums.txt` from GoReleaser or the `release-binary-checksums` artifact",
		"the verifier requires a SHA-256 checksum line for a GuardianWAF artifact whose name matches `manifest.txt` `version=`",
		"rejects mixed GuardianWAF artifact versions in the same checksum file",
		"`supply-chain/provenance-verify.txt`, `supply-chain/sbom-attestation-verify.txt`",
		"requires the image digest tag to match `manifest.txt` `version=`",
		"requires `manifest.txt` `git_commit=`, hosted CI commit, and image digest commit to be full 40-character SHAs for the exact same commit",
		"requires the verification evidence files to record the same `image_ref`, release workflow certificate identity, and GitHub Actions OIDC issuer",
		"rejects non-zero HIGH/CRITICAL findings",
		"Provenance and SBOM attestations verified with cosign",
		"Download `checksums.txt` and `sbom.spdx.json` from the GitHub Release page",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("release checklist missing security/detection gate %q", want)
		}
	}
	for _, want := range []string{
		"RELEASE_EVIDENCE_HEAVY",
		"dist/release-evidence",
		"SUPPLY_CHAIN_DIR=\"${OUT_DIR}/supply-chain\"",
		"run_step check-prereqs ./scripts/check-prereqs.sh",
		"run_step go-test go test ./...",
		"run_step go-vet go vet ./...",
		"run_step http3-build-tag go test -tags http3 ./cmd/guardianwaf -count=1",
		"run_step detection-quality go test ./internal/layers/detection -run TestDetectionLayer_CorpusQualityBaseline -count=1 -v",
		"run_step validate-k8s ./scripts/validate-k8s.sh",
		"run_step validate-helm ./scripts/validate-helm.sh",
		"run_step go-race go test -race -count=1 ./...",
		"run_step release-build ./scripts/build.sh",
		"run_step release-rollback ./scripts/release-rollback-smoke.sh",
		"run_step proxy-load ./scripts/proxy-load-test.sh",
		"run_step focused-benchmark ./scripts/benchmark.sh 5",
		"SUPPLY_CHAIN_OUT_DIR=\"${SUPPLY_CHAIN_DIR}\" run_step supply-chain-smoke ./scripts/supply-chain-smoke.sh",
		"record_pending hosted-ci",
		"record_pending external-security-review",
		"record_pending target-environment-load",
		"record_pending release-artifact-checksums",
		"record_pending image-digest-signature-provenance",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("release evidence script missing %q", want)
		}
	}
	for _, want := range []string{
		"CI_RUN_FILE",
		"CI_RUN_URL",
		"CI_COMMIT",
		"CI_RESULT",
		"--check-hosted-ci",
		"TARGET_LOAD_FILE",
		"--check-target-load",
		"RELEASE_CHECKSUM_FILE",
		"--check-release-checksums",
		"RELEASE_SUPPLY_CHAIN_DIR",
		"--check-supply-chain",
		"--check-external-review",
		"SECURITY_REVIEW_REPORT",
		"SECURITY_RISK_ACCEPTANCE",
		"stage_bundle",
		"commit_staged_file",
		"cp -a \"${BUNDLE}/.\" \"${stage}/\"",
		"hosted-ci/ci-run.txt",
		"target-load/target_load_results.txt",
		"release-artifacts/checksums.txt",
		"for file in image-digest.txt imagetools.txt cosign-verify.txt provenance-verify.txt sbom-attestation-verify.txt sbom.spdx.json trivy.txt",
		"\"${stage}/supply-chain/${file}\"",
		"commit_staged_file \"${stage}\" \"supply-chain/${file}\"",
		"external-security-review/report.md",
		"external-security-review/risk-acceptance.md",
		"clear_pending hosted-ci",
		"clear_pending target-environment-load",
		"clear_pending release-artifact-checksums",
		"clear_pending image-digest-signature-provenance",
		"clear_pending external-security-review",
	} {
		if !strings.Contains(assembleScript, want) {
			t.Fatalf("release evidence assembler missing %q", want)
		}
	}
	for _, want := range []string{
		"--allow-pending",
		"--check-hosted-ci",
		"--check-target-load",
		"--check-release-checksums",
		"--check-supply-chain",
		"--check-external-review",
		"CHECK_MODE=\"hosted-ci\"",
		"CHECK_MODE=\"target-load\"",
		"CHECK_MODE=\"release-checksums\"",
		"CHECK_MODE=\"supply-chain\"",
		"CHECK_MODE=\"external-review\"",
		"Hosted CI evidence verified",
		"Target load evidence verified",
		"Release checksum evidence verified",
		"Release supply-chain evidence verified",
		"External security review evidence verified",
		"PENDING_EXISTS=0",
		"if [ \"${PENDING_EXISTS}\" != \"1\" ]; then",
		"require_contains",
		"extract_evidence_value",
		"require_matching_commits",
		"manifest.txt git_commit is not a full 40-character git SHA",
		"require_matching_release_tag",
		"require_no_nonzero_errors",
		"require_load_budget",
		"require_focused_benchmarks",
		"require_trivy_clean",
		"reject_placeholder",
		"require_clean_git_status",
		"release evidence git status is not clean",
		"require_clean_git_diff_check",
		"release evidence git diff check is not clean",
		"require_heavy_manifest",
		"manifest.txt heavy must be 1",
		"require_file README.md",
		"require_file manifest.txt",
		"require_path git-diff-check.txt",
		"require_log_success \"${log}\"",
		"logs/check-prereqs.log",
		"logs/go-test.log",
		"logs/go-vet.log",
		"logs/http3-build-tag.log",
		"logs/detection-quality.log",
		"logs/validate-k8s.log",
		"logs/validate-helm.log",
		"logs/go-race.log",
		"logs/build-dashboard.log",
		"logs/release-build.log",
		"logs/smoke.log",
		"logs/release-rollback.log",
		"logs/proxy-load.log",
		"logs/focused-benchmark.log",
		"require_release_rollback_evidence",
		"previous writes persistent events",
		"candidate upgrade /readyz returns 200",
		"rollback /readyz returns 200",
		"Upgrade and rollback smoke passed",
		"proxy_load_results.txt",
		"benchmark_results.txt",
		"supply-chain/sbom.spdx.json",
		"supply-chain/trivy.txt",
		"supply-chain/cosign-verify.txt",
		"supply-chain/provenance-verify.txt",
		"supply-chain/sbom-attestation-verify.txt",
		"hosted-ci/ci-run.txt",
		"target-load/target_load_results.txt",
		"release-artifacts/checksums.txt",
		"external-security-review/report.md",
		"external-security-review/risk-acceptance.md",
		"require_hosted_ci_evidence",
		"require_unique_evidence_field hosted-ci/ci-run.txt commit",
		"^url: *https://github\\.com/guardianwaf/guardianwaf/actions/runs/[0-9]+[[:space:]]*$",
		"^result: *(pass|passed|success|succeeded)[[:space:]]*$",
		"^commit: *[0-9a-f]{40}[[:space:]]*$",
		"BenchmarkEngine_BenignRequest",
		"BenchmarkEngine_AttackRequest",
		"BenchmarkEngine_LargeHeaders",
		"BenchmarkEngine_LargeBody",
		"BenchmarkEngine_GzipBody",
		"BenchmarkEngine_DeflateBody",
		"BenchmarkEngine_FullPipeline_MultiParam",
		"BenchmarkEngine_Parallel",
		"BenchmarkRouteLookup_ManyRoutes",
		"BenchmarkTenantResolve_ManyTenants",
		"BenchmarkEventStore_HighEventRate",
		"errors=0",
		"latency_p99_ms=",
		"overhead_p99_ms=",
		"require_target_load_metadata",
		"require_unique_target_load_field",
		"^timestamp_utc=[0-9]{4}-[0-9]{2}-[0-9]{2}t[0-9]{2}:[0-9]{2}:[0-9]{2}z$",
		"require_valid_utc_timestamp",
		"must be a valid UTC timestamp in YYYY-MM-DDTHH:MM:SSZ format",
		"target_label must identify the target environment",
		"require_target_load_http_url_field",
		"must not contain whitespace",
		"must not include URL userinfo or credentials",
		"must not include a URL fragment",
		"standalone_url= or sidecar_url=",
		"require_target_load_runtime_context",
		"^cpu_count=[^[:space:]]+",
		"^kernel=.+",
		"^##[[:space:]]+backend$",
		"require_target_load_sample_size",
		"sample size is too small",
		"requests>=1000 concurrency>=10 warmup>=50",
		"local proxy load",
		"target load",
		"missing standalone or sidecar overhead_p99_ms evidence",
		"^[0-9a-f]{64}[[:space:]]+",
		"require_checksums_match_release",
		"pattern = \"guardianwaf[_-]\" artifact_version \"([^0-9]|$)\"",
		"must include a SHA-256 line for GuardianWAF release",
		"contains GuardianWAF artifact from a different release",
		"require_external_review_matches_release",
		"require_external_review_evidence",
		"require_external_review_signoff",
		"require_no_open_high_critical_findings",
		"require_risk_acceptance_tracking",
		"does not reference manifest version",
		"does not reference hosted CI commit",
		"must include review dates in YYYY-MM-DD format",
		"must be a valid YYYY-MM-DD date",
		"must include reviewer sign-off",
		"external security report has open HIGH/CRITICAL finding",
		"must include an expiration or follow-up date",
		"expiration or follow-up date is in the past",
		"must include a tracked follow-up issue",
		"require_unique_evidence_field supply-chain/image-digest.txt image",
		"^image=ghcr\\.io/guardianwaf/guardianwaf:",
		"^image_ref=",
		"^digest=sha256:[0-9a-f]{64}$",
		"^commit=[0-9a-f]{40}$",
		"^tag=",
		"require_supply_chain_evidence",
		"require_release_image_repository",
		"image must match GuardianWAF release tag",
		"image_ref must match GuardianWAF release digest",
		"require_image_digest_matches_imagetools",
		"not a sha256 digest",
		"require_release_oidc_identity",
		"certificate_identity_regexp=https://github\\.com/guardianwaf/guardianwaf/\\.github/workflows/release\\.yml@refs/tags/v\\.\\*",
		"certificate_oidc_issuer=https://token\\.actions\\.githubusercontent\\.com",
		"require_verification_image_ref",
		"image_ref does not match supply-chain/image-digest.txt",
		"release evidence commit mismatch",
		"manifest=${manifest_commit} hosted-ci=${ci_commit}",
		"release evidence tag mismatch",
		"\"spdxVersion\"",
		"require_spdx_package_inventory",
		"\"packages\"[[:space:]]*:",
		"must include at least one package entry",
		"require_cosign_success_marker",
		"require_no_cosign_failure_marker",
		"(Verified OK|The following checks were performed)",
		"contains a cosign verification failure marker",
		"(predicateType|slsa|SLSA|buildDefinition|Verified OK)",
		"(predicateType|spdx|SPDX|packages|Verified OK)",
		"(HIGH|CRITICAL|Total:|Report Summary|Vulnerability)",
		"\\b(HIGH|CRITICAL)[[:space:]]*:[[:space:]]*[1-9][0-9]*\\b",
		"reports HIGH/CRITICAL vulnerabilities",
		"missing external security review report or risk acceptance",
		"still contains placeholder text",
		"Describe the",
		"Set an expiration",
		"pending release evidence remains",
	} {
		if !strings.Contains(verifyScript, want) {
			t.Fatalf("release evidence verifier missing %q", want)
		}
	}
	for _, want := range []string{
		"docs/templates/security-review-report.md",
		"docs/templates/security-risk-acceptance.md",
		"external-security-review/report.md",
		"external-security-review/risk-acceptance.md",
	} {
		if !strings.Contains(reviewScope, want) {
			t.Fatalf("security review scope missing template guidance %q", want)
		}
	}
	for _, want := range []string{
		"# Security Review Report",
		"## Scope Covered",
		"## Findings",
		"## High And Critical Exit Criteria",
		"Reviewer sign-off",
	} {
		if !strings.Contains(reviewTemplate, want) {
			t.Fatalf("security review report template missing %q", want)
		}
	}
	for _, want := range []string{
		"# Security Review Risk Acceptance",
		"## Accepted Risk",
		"## Compensating Controls",
		"## Expiration Or Follow-Up",
		"I accept the documented release risk",
	} {
		if !strings.Contains(riskTemplate, want) {
			t.Fatalf("security risk acceptance template missing %q", want)
		}
	}
	supplyChainSmoke := readTextFixture(t, filepath.Join(root, "scripts/supply-chain-smoke.sh"))
	for _, want := range []string{
		"OUT_DIR=\"${SUPPLY_CHAIN_OUT_DIR:-}\"",
		"cp \"${TMPDIR}/sbom.spdx.json\" \"${OUT_DIR}/sbom.spdx.json\"",
		"docker image inspect \"${IMAGE_NAME}\" >\"${OUT_DIR}/image-inspect.json\"",
		"tee \"${TMPDIR}/trivy.txt\"",
		"cp \"${TMPDIR}/trivy.txt\" \"${OUT_DIR}/trivy.txt\"",
	} {
		if !strings.Contains(supplyChainSmoke, want) {
			t.Fatalf("supply-chain smoke script missing persistent evidence hook %q", want)
		}
	}
}

func TestReleaseEvidenceVerifierEnforcesStrictHeavyAndExternalEvidence(t *testing.T) {
	root := filepath.Join("..", "..")
	bundle := t.TempDir()

	for _, path := range []string{
		"README.md",
		"manifest.txt",
		"docs/release-checklist.md",
		"docs/detection-quality.md",
		"docs/threat-model.md",
		"docs/security-review-scope.md",
		"docs/performance-budget.md",
		"hosted-ci/ci-run.txt",
		"target-load/target_load_results.txt",
		"release-artifacts/checksums.txt",
		"supply-chain/image-digest.txt",
		"supply-chain/imagetools.txt",
		"supply-chain/cosign-verify.txt",
		"supply-chain/provenance-verify.txt",
		"supply-chain/sbom-attestation-verify.txt",
		"supply-chain/sbom.spdx.json",
		"supply-chain/trivy.txt",
		"external-security-review/report.md",
	} {
		writeReleaseEvidenceTestFile(t, bundle, path, releaseEvidenceFixtureContent(path))
	}
	for _, path := range []string{
		"git-status.txt",
		"git-diff-check.txt",
	} {
		writeReleaseEvidenceTestFile(t, bundle, path, "")
	}
	for _, path := range []string{
		"logs/check-prereqs.log",
		"logs/go-test.log",
		"logs/go-vet.log",
		"logs/http3-build-tag.log",
		"logs/detection-quality.log",
		"logs/validate-k8s.log",
		"logs/validate-helm.log",
	} {
		writeReleaseEvidenceTestFile(t, bundle, path, "ok\n")
	}

	cmd := exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier succeeded without heavy evidence; output:\n%s", output)
	}
	if !strings.Contains(string(output), "logs/go-race.log") {
		t.Fatalf("strict verifier failed for the wrong reason, output:\n%s", output)
	}
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), "--allow-pending", bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("allow-pending verifier accepted an incomplete final bundle with no pending blockers; output:\n%s", output)
	}
	if !strings.Contains(string(output), "logs/go-race.log") {
		t.Fatalf("allow-pending without pending failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "pending/hosted-ci.txt", "hosted CI evidence pending\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), "--allow-pending", bundle)
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("allow-pending verifier rejected an intermediate bundle with pending blockers: %v\n%s", err, output)
	}
	if err := os.Remove(filepath.Join(bundle, "pending/hosted-ci.txt")); err != nil {
		t.Fatalf("Remove pending file error: %v", err)
	}

	writeReleaseEvidenceTestFile(t, bundle, "manifest.txt", "version=v1.0.0\ngit_commit=9999999999999999999999999999999999999999\n")

	for _, path := range []string{
		"logs/go-race.log",
		"logs/build-dashboard.log",
		"logs/release-build.log",
		"logs/smoke.log",
		"logs/proxy-load.log",
		"logs/focused-benchmark.log",
	} {
		writeReleaseEvidenceTestFile(t, bundle, path, "ok\n")
	}
	writeReleaseEvidenceTestFile(t, bundle, "logs/release-rollback.log", "ok\n")
	writeReleaseEvidenceTestFile(t, bundle, "proxy_load_results.txt", "## standalone\nerrors=0\nlatency_p99_ms=12\noverhead_p99_ms=3\n")
	writeReleaseEvidenceTestFile(t, bundle, "benchmark_results.txt", releaseEvidenceFocusedBenchmarkFixture())

	writeReleaseEvidenceTestFile(t, bundle, "git-status.txt", " M internal/config/config.go\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted release bundle from dirty git status; output:\n%s", output)
	}
	if !strings.Contains(string(output), "git status is not clean") {
		t.Fatalf("dirty git status failed for the wrong reason, output:\n%s", output)
	}
	writeReleaseEvidenceTestFile(t, bundle, "git-status.txt", "")

	writeReleaseEvidenceTestFile(t, bundle, "git-diff-check.txt", "internal/config/config.go:1: trailing whitespace.\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted release bundle with git diff check output; output:\n%s", output)
	}
	if !strings.Contains(string(output), "git diff check is not clean") {
		t.Fatalf("git diff check evidence failed for the wrong reason, output:\n%s", output)
	}
	writeReleaseEvidenceTestFile(t, bundle, "git-diff-check.txt", "")

	writeReleaseEvidenceTestFile(t, bundle, "manifest.txt", "version=v1.0.0\ngit_commit=1234567890abcdef1234567890abcdef12345678\nheavy=0\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted final bundle without heavy manifest marker; output:\n%s", output)
	}
	if !strings.Contains(string(output), "heavy must be 1") {
		t.Fatalf("heavy manifest evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "manifest.txt", releaseEvidenceFixtureContent("manifest.txt"))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted release rollback log without rollback smoke evidence; output:\n%s", output)
	}
	if !strings.Contains(string(output), "previous writes persistent events") {
		t.Fatalf("release rollback evidence failed for the wrong reason, output:\n%s", output)
	}
	writeReleaseEvidenceTestFile(t, bundle, "logs/release-rollback.log", releaseEvidenceRollbackFixture())

	writeReleaseEvidenceTestFile(t, bundle, "manifest.txt", "version=v1.0.0\ngit_commit=9999999999999999999999999999999999999999\nheavy=1\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted release bundle manifest from a different commit; output:\n%s", output)
	}
	if !strings.Contains(string(output), "manifest=") {
		t.Fatalf("manifest commit evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "manifest.txt", "version=v1.0.0\ngit_commit=1234567890abcdef\nheavy=1\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted release bundle manifest with short commit SHA; output:\n%s", output)
	}
	if !strings.Contains(string(output), "full 40-character git SHA") {
		t.Fatalf("manifest short commit evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "manifest.txt", releaseEvidenceFixtureContent("manifest.txt"))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("strict verifier failed with complete evidence: %v\n%s", err, output)
	}

	mismatchedBundle := filepath.Join(t.TempDir(), "v2.0.0-20260611T120000Z")
	if err := os.MkdirAll(mismatchedBundle, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", mismatchedBundle, err)
	}
	copyReleaseEvidenceTestBundle(t, bundle, mismatchedBundle)
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), mismatchedBundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted release bundle whose directory version does not match manifest; output:\n%s", output)
	}
	if !strings.Contains(string(output), "bundle name version does not match manifest.txt") {
		t.Fatalf("bundle name version mismatch failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/image-digest.txt", strings.Replace(releaseEvidenceFixtureContent("supply-chain/image-digest.txt"), "commit=1234567890abcdef1234567890abcdef12345678", "commit=1234567890abcdef", 1))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted image digest evidence with short commit SHA; output:\n%s", output)
	}
	if !strings.Contains(string(output), "^commit=[0-9a-f]{40}$") {
		t.Fatalf("image digest short commit evidence failed for the wrong reason, output:\n%s", output)
	}
	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/image-digest.txt", releaseEvidenceFixtureContent("supply-chain/image-digest.txt"))

	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/image-digest.txt", strings.Replace(releaseEvidenceFixtureContent("supply-chain/image-digest.txt"), "image=ghcr.io/guardianwaf/guardianwaf:v1.0.0", "image=ghcr.io/other/repo:v1.0.0", 1))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted image digest evidence for another repository image tag; output:\n%s", output)
	}
	if !strings.Contains(string(output), "^image=ghcr\\.io/guardianwaf/guardianwaf:") {
		t.Fatalf("image repository evidence failed for the wrong reason, output:\n%s", output)
	}
	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/image-digest.txt", releaseEvidenceFixtureContent("supply-chain/image-digest.txt"))

	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/image-digest.txt", strings.Replace(releaseEvidenceFixtureContent("supply-chain/image-digest.txt"), "image_ref=ghcr.io/guardianwaf/guardianwaf@", "image_ref=ghcr.io/other/repo@", 1))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted image digest evidence for another repository digest ref; output:\n%s", output)
	}
	if !strings.Contains(string(output), "image_ref must match GuardianWAF release digest") {
		t.Fatalf("image ref repository evidence failed for the wrong reason, output:\n%s", output)
	}
	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/image-digest.txt", releaseEvidenceFixtureContent("supply-chain/image-digest.txt"))

	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/image-digest.txt", releaseEvidenceFixtureContent("supply-chain/image-digest.txt")+"image_ref=ghcr.io/guardianwaf/guardianwaf@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted image digest evidence with duplicate image_ref fields; output:\n%s", output)
	}
	if !strings.Contains(string(output), "exactly one image_ref field") {
		t.Fatalf("duplicate image_ref evidence failed for the wrong reason, output:\n%s", output)
	}
	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/image-digest.txt", releaseEvidenceFixtureContent("supply-chain/image-digest.txt"))

	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/imagetools.txt", "Name: ghcr.io/guardianwaf/guardianwaf:v1.0.0\nDigest: sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted imagetools evidence for a different image digest; output:\n%s", output)
	}
	if !strings.Contains(string(output), "supply-chain/imagetools.txt") {
		t.Fatalf("image digest evidence failed for the wrong reason, output:\n%s", output)
	}
	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/imagetools.txt", releaseEvidenceFixtureContent("supply-chain/imagetools.txt"))

	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/cosign-verify.txt", "Verified OK\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted cosign verification without release workflow OIDC identity evidence; output:\n%s", output)
	}
	if !strings.Contains(string(output), "certificate_identity_regexp") {
		t.Fatalf("cosign identity evidence failed for the wrong reason, output:\n%s", output)
	}
	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/cosign-verify.txt", releaseEvidenceFixtureContent("supply-chain/cosign-verify.txt"))

	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/cosign-verify.txt", strings.Join([]string{
		"image_ref=ghcr.io/guardianwaf/guardianwaf@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"certificate_identity_regexp=https://github.com/guardianwaf/guardianwaf/.github/workflows/release.yml@refs/tags/v.*",
		"certificate_oidc_issuer=https://token.actions.githubusercontent.com",
		"Verified OK",
		"",
	}, "\n"))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted cosign verification for a different image ref; output:\n%s", output)
	}
	if !strings.Contains(string(output), "image_ref does not match") {
		t.Fatalf("cosign image ref evidence failed for the wrong reason, output:\n%s", output)
	}
	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/cosign-verify.txt", releaseEvidenceFixtureContent("supply-chain/cosign-verify.txt"))

	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/sbom.spdx.json", "{\"spdxVersion\":\"SPDX-2.3\",\"packages\":[]}\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted SBOM evidence without package inventory; output:\n%s", output)
	}
	if !strings.Contains(string(output), "at least one package entry") {
		t.Fatalf("SBOM package inventory evidence failed for the wrong reason, output:\n%s", output)
	}
	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/sbom.spdx.json", releaseEvidenceFixtureContent("supply-chain/sbom.spdx.json"))

	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/provenance-verify.txt", strings.Replace(releaseEvidenceFixtureContent("supply-chain/provenance-verify.txt"), "The following checks were performed against token.actions.githubusercontent.com\n", "", 1))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted provenance attestation evidence without cosign success marker; output:\n%s", output)
	}
	if !strings.Contains(string(output), "Verified OK|The following checks were performed") {
		t.Fatalf("provenance success-marker evidence failed for the wrong reason, output:\n%s", output)
	}
	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/provenance-verify.txt", releaseEvidenceFixtureContent("supply-chain/provenance-verify.txt"))

	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/sbom-attestation-verify.txt", strings.Replace(releaseEvidenceFixtureContent("supply-chain/sbom-attestation-verify.txt"), "The following checks were performed against token.actions.githubusercontent.com\n", "", 1))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted SBOM attestation evidence without cosign success marker; output:\n%s", output)
	}
	if !strings.Contains(string(output), "Verified OK|The following checks were performed") {
		t.Fatalf("SBOM attestation success-marker evidence failed for the wrong reason, output:\n%s", output)
	}
	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/sbom-attestation-verify.txt", releaseEvidenceFixtureContent("supply-chain/sbom-attestation-verify.txt"))

	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/cosign-verify.txt", releaseEvidenceFixtureContent("supply-chain/cosign-verify.txt")+"Error: no matching signatures\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted cosign evidence with failure marker; output:\n%s", output)
	}
	if !strings.Contains(string(output), "failure marker") {
		t.Fatalf("cosign failure-marker evidence failed for the wrong reason, output:\n%s", output)
	}
	writeReleaseEvidenceTestFile(t, bundle, "supply-chain/cosign-verify.txt", releaseEvidenceFixtureContent("supply-chain/cosign-verify.txt"))

	writeReleaseEvidenceTestFile(t, bundle, "hosted-ci/ci-run.txt", "commit: 1234567890abcdef1234567890abcdef12345678\nresult: passed\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted hosted CI evidence without GitHub Actions URL; output:\n%s", output)
	}
	if !strings.Contains(string(output), "exactly one url field") {
		t.Fatalf("hosted CI evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "hosted-ci/ci-run.txt", releaseEvidenceFixtureContent("hosted-ci/ci-run.txt")+"commit: 9999999999999999999999999999999999999999\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted hosted CI evidence with duplicate commit fields; output:\n%s", output)
	}
	if !strings.Contains(string(output), "exactly one commit field") {
		t.Fatalf("hosted CI duplicate commit evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "hosted-ci/ci-run.txt", strings.Replace(releaseEvidenceFixtureContent("hosted-ci/ci-run.txt"), "https://github.com/guardianwaf/guardianwaf/actions/runs/1", "https://github.com/other/repo/actions/runs/1", 1))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted hosted CI evidence from a different repository; output:\n%s", output)
	}
	if !strings.Contains(string(output), "github\\.com/guardianwaf/guardianwaf") {
		t.Fatalf("hosted CI repository URL evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "hosted-ci/ci-run.txt", strings.Replace(releaseEvidenceFixtureContent("hosted-ci/ci-run.txt"), "https://github.com/guardianwaf/guardianwaf/actions/runs/1", "https://github.com/guardianwaf/guardianwaf/actions/runs/1?check_suite_focus=true", 1))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted hosted CI evidence with non-canonical run URL; output:\n%s", output)
	}
	if !strings.Contains(string(output), "actions/runs/[0-9]+[[:space:]]*$") {
		t.Fatalf("hosted CI canonical URL evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "hosted-ci/ci-run.txt", strings.Replace(releaseEvidenceFixtureContent("hosted-ci/ci-run.txt"), "result: passed", "result: passed-with-warnings", 1))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted hosted CI evidence with non-exact result value; output:\n%s", output)
	}
	if !strings.Contains(string(output), "pass|passed|success|succeeded") {
		t.Fatalf("hosted CI result evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "hosted-ci/ci-run.txt", strings.Replace(releaseEvidenceFixtureContent("hosted-ci/ci-run.txt"), "1234567890abcdef1234567890abcdef12345678", "1234567890abcdef", 1))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted hosted CI evidence with short commit SHA; output:\n%s", output)
	}
	if !strings.Contains(string(output), "[0-9a-f]{40}") {
		t.Fatalf("hosted CI full SHA evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "hosted-ci/ci-run.txt", releaseEvidenceFixtureContent("hosted-ci/ci-run.txt"))
	writeReleaseEvidenceTestFile(t, bundle, "target-load/target_load_results.txt", "timestamp_utc=2026-06-11T12:00:00Z\ntarget_label=release-candidate\nrequests=1000\nconcurrency=20\nwarmup=50\nbackend_url=https://backend.example.test/healthz\nstandalone_url=https://waf.example.test/healthz\n## standalone\nerrors=0\nlatency_p99_ms=12\noverhead_p99_ms=3\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted target-load evidence without runtime context and backend baseline; output:\n%s", output)
	}
	if !strings.Contains(string(output), "^cpu_count=") {
		t.Fatalf("target-load evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "target-load/target_load_results.txt", strings.ReplaceAll(releaseEvidenceFixtureContent("target-load/target_load_results.txt"), "requests=1000\nconcurrency=20\nwarmup=50", "requests=100\nconcurrency=2\nwarmup=5"))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted target-load evidence with too-small sample size; output:\n%s", output)
	}
	if !strings.Contains(string(output), "sample size is too small") {
		t.Fatalf("target-load sample size evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "target-load/target_load_results.txt", strings.Replace(releaseEvidenceFixtureContent("target-load/target_load_results.txt"), "target_label=release-candidate", "target_label=target", 1))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted target-load evidence with generic target label; output:\n%s", output)
	}
	if !strings.Contains(string(output), "target_label must identify") {
		t.Fatalf("target-load target label evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "target-load/target_load_results.txt", strings.Replace(releaseEvidenceFixtureContent("target-load/target_load_results.txt"), "backend_url=https://backend.example.test/healthz", "backend_url=https://user:pass@backend.example.test/healthz", 1))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted target-load evidence with credential-bearing URL; output:\n%s", output)
	}
	if !strings.Contains(string(output), "must not include URL userinfo or credentials") {
		t.Fatalf("target-load credential URL evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "target-load/target_load_results.txt", strings.Replace(releaseEvidenceFixtureContent("target-load/target_load_results.txt"), "standalone_url=https://waf.example.test/healthz", "standalone_url=https://waf.example.test/healthz bad", 1))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted target-load evidence with whitespace in URL: output:\n%s", output)
	}
	if !strings.Contains(string(output), "must not contain whitespace") {
		t.Fatalf("target-load whitespace URL evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "target-load/target_load_results.txt", strings.Replace(releaseEvidenceFixtureContent("target-load/target_load_results.txt"), "backend_url=https://backend.example.test/healthz", "backend_url=https://backend.example.test/healthz\nbackend_url=https://other-backend.example.test/healthz", 1))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted target-load evidence with duplicate backend_url fields; output:\n%s", output)
	}
	if !strings.Contains(string(output), "duplicate backend_url") {
		t.Fatalf("target-load duplicate metadata evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "target-load/target_load_results.txt", strings.Replace(releaseEvidenceFixtureContent("target-load/target_load_results.txt"), "timestamp_utc=2026-06-11T12:00:00Z", "timestamp_utc=2026-99-99T12:00:00Z", 1))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted target-load evidence with invalid timestamp; output:\n%s", output)
	}
	if !strings.Contains(string(output), "must be a valid UTC timestamp") {
		t.Fatalf("target-load invalid timestamp evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "target-load/target_load_results.txt", releaseEvidenceFixtureContent("target-load/target_load_results.txt"))
	writeReleaseEvidenceTestFile(t, bundle, "release-artifacts/checksums.txt", "0000000000000000000000000000000000000000000000000000000000000001  guardianwaf_0.9.0_linux_amd64.tar.gz\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted checksums from a different release version; output:\n%s", output)
	}
	if !strings.Contains(string(output), "different release") {
		t.Fatalf("checksum evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "release-artifacts/checksums.txt", strings.Join([]string{
		releaseEvidenceFixtureContent("release-artifacts/checksums.txt"),
		"0000000000000000000000000000000000000000000000000000000000000002  guardianwaf_0.9.0_linux_amd64.tar.gz",
		"",
	}, "\n"))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted checksums with mixed GuardianWAF release versions; output:\n%s", output)
	}
	if !strings.Contains(string(output), "different release") {
		t.Fatalf("mixed checksum evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "release-artifacts/checksums.txt", strings.Join([]string{
		"0000000000000000000000000000000000000000000000000000000000000001  unrelated.txt",
		"notes: guardianwaf_1.0.0_linux_amd64.tar.gz",
		"",
	}, "\n"))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted checksum evidence without a GuardianWAF checksum line; output:\n%s", output)
	}
	if !strings.Contains(string(output), "must include a SHA-256 line for GuardianWAF release") {
		t.Fatalf("missing GuardianWAF checksum line evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "release-artifacts/checksums.txt", releaseEvidenceFixtureContent("release-artifacts/checksums.txt"))
	writeReleaseEvidenceTestFile(t, bundle, "external-security-review/report.md", "# Security Review Report\nRelease candidate: v0.9.0\nCommit: 1234567890abcdef1234567890abcdef12345678\nSummary: review completed.\nScope: release evidence verifier.\nFindings: none.\nSeverity: low.\nReviewer sign-off: Security Reviewer.\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted external review for a different release version; output:\n%s", output)
	}
	if !strings.Contains(string(output), "does not reference manifest version") {
		t.Fatalf("external review version evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "external-security-review/report.md", "# Security Review Report\nRelease candidate: v1.0.0\nCommit: 9999999999999999999999999999999999999999\nSummary: review completed.\nScope: release evidence verifier.\nFindings: none.\nSeverity: low.\nReviewer sign-off: Security Reviewer.\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted external review for a different commit; output:\n%s", output)
	}
	if !strings.Contains(string(output), "does not reference hosted CI commit") {
		t.Fatalf("external review commit evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "external-security-review/report.md", strings.Join([]string{
		"# Security Review Report",
		"Release candidate: v1.0.0",
		"Commit: 1234567890abcdef1234567890abcdef12345678",
		"Review dates: 2026-06-11",
		"Summary: review completed.",
		"Scope: release evidence verifier.",
		"Findings:",
		"| ID | Severity | Component | Title | Status | Fix or acceptance |",
		"|---|---|---|---|---|---|",
		"| GWAF-SEC-002 | High | proxy | Review finding | open | pending fix |",
		"Reviewer sign-off: Security Reviewer.",
		"",
	}, "\n"))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted external review with open HIGH finding; output:\n%s", output)
	}
	if !strings.Contains(string(output), "open HIGH/CRITICAL finding") {
		t.Fatalf("external review high-finding evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "external-security-review/report.md", "# Security Review Report\nRelease candidate: v1.0.0\nCommit: 1234567890abcdef1234567890abcdef12345678\nSummary: review completed.\nScope: release evidence verifier.\nFindings: none.\nSeverity: low.\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted external review without review dates/sign-off; output:\n%s", output)
	}
	if !strings.Contains(string(output), "must include review dates") {
		t.Fatalf("external review sign-off evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "external-security-review/report.md", "# Security Review Report\nRelease candidate: v1.0.0\nCommit: 1234567890abcdef1234567890abcdef12345678\nReview dates: 2026-99-99\nSummary: review completed.\nScope: release evidence verifier.\nFindings: none.\nSeverity: low.\nReviewer sign-off: Security Reviewer.\n")
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted external review with invalid review date; output:\n%s", output)
	}
	if !strings.Contains(string(output), "must be a valid YYYY-MM-DD date") {
		t.Fatalf("invalid external review date evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "external-security-review/report.md", "")
	writeReleaseEvidenceTestFile(t, bundle, "external-security-review/risk-acceptance.md", strings.Join([]string{
		"# Security Review Risk Acceptance",
		"Release candidate: v1.0.0",
		"Commit: 1234567890abcdef1234567890abcdef12345678",
		"Approver: Release Owner",
		"Accepted risk: external review gap accepted for this release.",
		"Reason: release owner approval.",
		"",
	}, "\n"))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted risk acceptance without expiration/follow-up tracking; output:\n%s", output)
	}
	if !strings.Contains(string(output), "expiration or follow-up date") {
		t.Fatalf("risk acceptance tracking evidence failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "external-security-review/risk-acceptance.md", strings.Join([]string{
		"# Security Review Risk Acceptance",
		"Release candidate: v1.0.0",
		"Commit: 1234567890abcdef1234567890abcdef12345678",
		"Approver: Release Owner",
		"Accepted risk: external review gap accepted for this release.",
		"Reason: release owner approval.",
		"Follow-up expiration: 2000-01-01",
		"Owner: Release Owner",
		"Tracking: #123",
		"",
	}, "\n"))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted expired risk acceptance; output:\n%s", output)
	}
	if !strings.Contains(string(output), "date is in the past") {
		t.Fatalf("expired risk acceptance failed for the wrong reason, output:\n%s", output)
	}

	writeReleaseEvidenceTestFile(t, bundle, "external-security-review/risk-acceptance.md", strings.Join([]string{
		"# Security Review Risk Acceptance",
		"Release candidate: v1.0.0",
		"Commit: 1234567890abcdef1234567890abcdef12345678",
		"Approver: Release Owner",
		"Accepted risk: external review gap accepted for this release.",
		"Reason: release owner approval.",
		"Follow-up expiration: 2026-99-99",
		"Owner: Release Owner",
		"Tracking: #123",
		"",
	}, "\n"))
	cmd = exec.Command("bash", filepath.Join(root, "scripts/verify-release-evidence.sh"), bundle)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("strict verifier accepted risk acceptance with invalid expiration date; output:\n%s", output)
	}
	if !strings.Contains(string(output), "must be a valid YYYY-MM-DD date") {
		t.Fatalf("invalid risk acceptance date failed for the wrong reason, output:\n%s", output)
	}
}

func TestReleaseEvidenceAssemblerValidatesHostedCIBeforeClearingPending(t *testing.T) {
	root := filepath.Join("..", "..")
	bundle := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "ci-run.txt")
	writeReleaseEvidenceTestFile(t, bundle, "pending/hosted-ci.txt", "hosted CI pending\n")
	if err := os.WriteFile(sourcePath, []byte("url: https://ci.example.test/run/1\ncommit: 1234567890abcdef1234567890abcdef12345678\nresult: passed\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", sourcePath, err)
	}

	cmd := exec.Command("bash", filepath.Join(root, "scripts/assemble-release-evidence.sh"), bundle)
	cmd.Env = append(os.Environ(), "CI_RUN_FILE="+sourcePath)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("assembler accepted invalid hosted CI evidence; output:\n%s", output)
	}
	if !strings.Contains(string(output), "hosted-ci/ci-run.txt") {
		t.Fatalf("assembler hosted CI validation failed for the wrong reason, output:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(bundle, "pending/hosted-ci.txt")); err != nil {
		t.Fatalf("assembler cleared hosted CI pending blocker after invalid evidence: %v\n%s", err, output)
	}

	if err := os.WriteFile(sourcePath, []byte("url: https://github.com/guardianwaf/guardianwaf/actions/runs/1\ncommit: 1234567890abcdef1234567890abcdef12345678\nresult: passed-with-warnings\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", sourcePath, err)
	}

	cmd = exec.Command("bash", filepath.Join(root, "scripts/assemble-release-evidence.sh"), bundle)
	cmd.Env = append(os.Environ(), "CI_RUN_FILE="+sourcePath)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("assembler accepted hosted CI evidence with non-exact result value; output:\n%s", output)
	}
	if !strings.Contains(string(output), "pass|passed|success|succeeded") {
		t.Fatalf("assembler hosted CI result validation failed for the wrong reason, output:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(bundle, "pending/hosted-ci.txt")); err != nil {
		t.Fatalf("assembler cleared hosted CI pending blocker after invalid result: %v\n%s", err, output)
	}
}

func TestReleaseEvidenceAssemblerDoesNotOverwriteExistingEvidenceOnValidationFailure(t *testing.T) {
	root := filepath.Join("..", "..")
	bundle := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "ci-run.txt")
	goodHostedCI := releaseEvidenceFixtureContent("hosted-ci/ci-run.txt")
	writeReleaseEvidenceTestFile(t, bundle, "hosted-ci/ci-run.txt", goodHostedCI)
	writeReleaseEvidenceTestFile(t, bundle, "pending/hosted-ci.txt", "hosted CI pending\n")
	if err := os.WriteFile(sourcePath, []byte("url: https://ci.example.test/run/1\ncommit: 1234567890abcdef1234567890abcdef12345678\nresult: failed\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", sourcePath, err)
	}

	cmd := exec.Command("bash", filepath.Join(root, "scripts/assemble-release-evidence.sh"), bundle)
	cmd.Env = append(os.Environ(), "CI_RUN_FILE="+sourcePath)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("assembler accepted invalid hosted CI evidence; output:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(bundle, "pending/hosted-ci.txt")); err != nil {
		t.Fatalf("assembler cleared hosted CI pending blocker after invalid evidence: %v\n%s", err, output)
	}
	got, readErr := os.ReadFile(filepath.Join(bundle, "hosted-ci/ci-run.txt"))
	if readErr != nil {
		t.Fatalf("ReadFile hosted CI evidence: %v", readErr)
	}
	if string(got) != goodHostedCI {
		t.Fatalf("assembler overwrote existing hosted CI evidence after validation failure:\n%s", got)
	}
}

func TestReleaseEvidenceAssemblerValidatesTargetLoadBeforeClearingPending(t *testing.T) {
	root := filepath.Join("..", "..")
	bundle := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "target_load_results.txt")
	writeReleaseEvidenceTestFile(t, bundle, "pending/target-environment-load.txt", "target load pending\n")
	if err := os.WriteFile(sourcePath, []byte(strings.Replace(releaseEvidenceFixtureContent("target-load/target_load_results.txt"), "target_label=release-candidate", "target_label=target", 1)), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", sourcePath, err)
	}

	cmd := exec.Command("bash", filepath.Join(root, "scripts/assemble-release-evidence.sh"), bundle)
	cmd.Env = append(os.Environ(), "TARGET_LOAD_FILE="+sourcePath)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("assembler accepted invalid target-load evidence; output:\n%s", output)
	}
	if !strings.Contains(string(output), "target_label must identify") {
		t.Fatalf("assembler target-load validation failed for the wrong reason, output:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(bundle, "pending/target-environment-load.txt")); err != nil {
		t.Fatalf("assembler cleared target-load pending blocker after invalid evidence: %v\n%s", err, output)
	}

	if err := os.WriteFile(sourcePath, []byte(strings.Replace(releaseEvidenceFixtureContent("target-load/target_load_results.txt"), "timestamp_utc=2026-06-11T12:00:00Z", "timestamp_utc=2026-99-99T12:00:00Z", 1)), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", sourcePath, err)
	}

	cmd = exec.Command("bash", filepath.Join(root, "scripts/assemble-release-evidence.sh"), bundle)
	cmd.Env = append(os.Environ(), "TARGET_LOAD_FILE="+sourcePath)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("assembler accepted target-load evidence with invalid timestamp; output:\n%s", output)
	}
	if !strings.Contains(string(output), "must be a valid UTC timestamp") {
		t.Fatalf("assembler target-load timestamp validation failed for the wrong reason, output:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(bundle, "pending/target-environment-load.txt")); err != nil {
		t.Fatalf("assembler cleared target-load pending blocker after invalid timestamp: %v\n%s", err, output)
	}
}

func TestReleaseEvidenceAssemblerValidatesChecksumsBeforeClearingPending(t *testing.T) {
	root := filepath.Join("..", "..")
	bundle := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "checksums.txt")
	writeReleaseEvidenceTestFile(t, bundle, "manifest.txt", releaseEvidenceFixtureContent("manifest.txt"))
	writeReleaseEvidenceTestFile(t, bundle, "pending/release-artifact-checksums.txt", "release checksums pending\n")
	if err := os.WriteFile(sourcePath, []byte("0000000000000000000000000000000000000000000000000000000000000001  guardianwaf_0.9.0_linux_amd64.tar.gz\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", sourcePath, err)
	}

	cmd := exec.Command("bash", filepath.Join(root, "scripts/assemble-release-evidence.sh"), bundle)
	cmd.Env = append(os.Environ(), "RELEASE_CHECKSUM_FILE="+sourcePath)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("assembler accepted invalid release checksum evidence; output:\n%s", output)
	}
	if !strings.Contains(string(output), "different release") {
		t.Fatalf("assembler checksum validation failed for the wrong reason, output:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(bundle, "pending/release-artifact-checksums.txt")); err != nil {
		t.Fatalf("assembler cleared checksum pending blocker after invalid evidence: %v\n%s", err, output)
	}

	if err := os.WriteFile(sourcePath, []byte(strings.Join([]string{
		"0000000000000000000000000000000000000000000000000000000000000001  unrelated.txt",
		"notes: guardianwaf_1.0.0_linux_amd64.tar.gz",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", sourcePath, err)
	}

	cmd = exec.Command("bash", filepath.Join(root, "scripts/assemble-release-evidence.sh"), bundle)
	cmd.Env = append(os.Environ(), "RELEASE_CHECKSUM_FILE="+sourcePath)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("assembler accepted checksum evidence without a GuardianWAF checksum line; output:\n%s", output)
	}
	if !strings.Contains(string(output), "must include a SHA-256 line for GuardianWAF release") {
		t.Fatalf("assembler checksum validation failed for the wrong reason, output:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(bundle, "pending/release-artifact-checksums.txt")); err != nil {
		t.Fatalf("assembler cleared checksum pending blocker after missing GuardianWAF checksum line: %v\n%s", err, output)
	}
}

func TestReleaseEvidenceAssemblerValidatesSupplyChainBeforeClearingPending(t *testing.T) {
	root := filepath.Join("..", "..")
	bundle := t.TempDir()
	sourceDir := t.TempDir()
	writeReleaseEvidenceTestFile(t, bundle, "manifest.txt", releaseEvidenceFixtureContent("manifest.txt"))
	writeReleaseEvidenceTestFile(t, bundle, "hosted-ci/ci-run.txt", releaseEvidenceFixtureContent("hosted-ci/ci-run.txt"))
	writeReleaseEvidenceTestFile(t, bundle, "pending/image-digest-signature-provenance.txt", "supply chain pending\n")

	for _, path := range []string{
		"supply-chain/image-digest.txt",
		"supply-chain/imagetools.txt",
		"supply-chain/cosign-verify.txt",
		"supply-chain/provenance-verify.txt",
		"supply-chain/sbom-attestation-verify.txt",
		"supply-chain/sbom.spdx.json",
		"supply-chain/trivy.txt",
	} {
		content := releaseEvidenceFixtureContent(path)
		if path == "supply-chain/sbom.spdx.json" {
			content = "{\"spdxVersion\":\"SPDX-2.3\",\"packages\":[]}\n"
		}
		sourcePath := filepath.Join(sourceDir, strings.TrimPrefix(path, "supply-chain/"))
		if err := os.WriteFile(sourcePath, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", sourcePath, err)
		}
	}

	cmd := exec.Command("bash", filepath.Join(root, "scripts/assemble-release-evidence.sh"), bundle)
	cmd.Env = append(os.Environ(), "RELEASE_SUPPLY_CHAIN_DIR="+sourceDir)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("assembler accepted invalid supply-chain evidence; output:\n%s", output)
	}
	if !strings.Contains(string(output), "at least one package entry") {
		t.Fatalf("assembler supply-chain validation failed for the wrong reason, output:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(bundle, "pending/image-digest-signature-provenance.txt")); err != nil {
		t.Fatalf("assembler cleared supply-chain pending blocker after invalid evidence: %v\n%s", err, output)
	}
}

func TestReleaseEvidenceAssemblerValidatesExternalReviewBeforeClearingPending(t *testing.T) {
	root := filepath.Join("..", "..")
	bundle := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "security-review-report.md")
	writeReleaseEvidenceTestFile(t, bundle, "manifest.txt", releaseEvidenceFixtureContent("manifest.txt"))
	writeReleaseEvidenceTestFile(t, bundle, "hosted-ci/ci-run.txt", releaseEvidenceFixtureContent("hosted-ci/ci-run.txt"))
	writeReleaseEvidenceTestFile(t, bundle, "pending/external-security-review.txt", "external review pending\n")
	if err := os.WriteFile(sourcePath, []byte("# Security Review Report\nRelease candidate: v1.0.0\nCommit: 1234567890abcdef1234567890abcdef12345678\nSummary: review completed.\nScope: release evidence verifier.\nFindings: none.\nSeverity: low.\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", sourcePath, err)
	}

	cmd := exec.Command("bash", filepath.Join(root, "scripts/assemble-release-evidence.sh"), bundle)
	cmd.Env = append(os.Environ(), "SECURITY_REVIEW_REPORT="+sourcePath)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("assembler accepted invalid external review evidence; output:\n%s", output)
	}
	if !strings.Contains(string(output), "must include review dates") {
		t.Fatalf("assembler external review validation failed for the wrong reason, output:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(bundle, "pending/external-security-review.txt")); err != nil {
		t.Fatalf("assembler cleared external review pending blocker after invalid evidence: %v\n%s", err, output)
	}
}

func TestReleaseEvidenceAssemblerRequiresValidHostedCIBeforeExternalReviewPendingClear(t *testing.T) {
	root := filepath.Join("..", "..")
	bundle := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "security-review-report.md")
	writeReleaseEvidenceTestFile(t, bundle, "manifest.txt", releaseEvidenceFixtureContent("manifest.txt"))
	writeReleaseEvidenceTestFile(t, bundle, "hosted-ci/ci-run.txt", strings.Replace(releaseEvidenceFixtureContent("hosted-ci/ci-run.txt"), "1234567890abcdef1234567890abcdef12345678", "1234567890abcdef", 1))
	writeReleaseEvidenceTestFile(t, bundle, "pending/external-security-review.txt", "external review pending\n")
	if err := os.WriteFile(sourcePath, []byte(strings.Join([]string{
		"# Security Review Report",
		"Release candidate: v1.0.0",
		"Commit: 1234567890abcdef",
		"Review dates: 2026-01-01",
		"Summary: review completed.",
		"Scope: release evidence verifier.",
		"Findings: none.",
		"Severity: low.",
		"Reviewer sign-off: Security Reviewer.",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", sourcePath, err)
	}

	cmd := exec.Command("bash", filepath.Join(root, "scripts/assemble-release-evidence.sh"), bundle)
	cmd.Env = append(os.Environ(), "SECURITY_REVIEW_REPORT="+sourcePath)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("assembler accepted external review before hosted CI evidence was valid; output:\n%s", output)
	}
	if !strings.Contains(string(output), "hosted-ci/ci-run.txt") {
		t.Fatalf("assembler external review validation failed for the wrong reason, output:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(bundle, "pending/external-security-review.txt")); err != nil {
		t.Fatalf("assembler cleared external review pending blocker after invalid hosted CI evidence: %v\n%s", err, output)
	}
}

func TestThreatModelDocumentsProductionBoundaries(t *testing.T) {
	root := filepath.Join("..", "..")
	threatModel := readTextFixture(t, filepath.Join(root, "docs/threat-model.md"))
	readme := readTextFixture(t, filepath.Join(root, "README.md"))

	for _, want := range []string{
		"## Trust Boundaries",
		"### Edge Proxy Path",
		"### Dashboard and Admin API",
		"### MCP Interface",
		"### Docker Discovery",
		"### AI Provider Integrations",
		"### Tenant Isolation",
		"### Event, Log, Audit, and Compliance Storage",
		"### Generated Rules, Virtual Patches, and Remediation",
		"### Release and Deployment Supply Chain",
		"## STRIDE Summary",
		"## Assurance Map",
		"Open assurance:",
	} {
		if !strings.Contains(threatModel, want) {
			t.Fatalf("threat model missing %q", want)
		}
	}
	if !strings.Contains(readme, "[Threat Model](docs/threat-model.md)") {
		t.Fatal("README documentation index does not link docs/threat-model.md")
	}
}

func TestDetectionQualityDocsDescribeCorpusGate(t *testing.T) {
	root := filepath.Join("..", "..")
	doc := readTextFixture(t, filepath.Join(root, "docs/detection-quality.md"))
	readme := readTextFixture(t, filepath.Join(root, "README.md"))
	testFile := readTextFixture(t, filepath.Join(root, "internal/layers/detection/detection_test.go"))
	appLogs := readTextFixture(t, filepath.Join(root, "testdata/benign/application_logs.txt"))

	for _, want := range []string{
		"## Corpus Sources",
		"## Regression Gate",
		"testdata/attacks/cmdi.txt",
		"testdata/attacks/lfi.txt",
		"testdata/attacks/nosqli.txt",
		"testdata/attacks/sqli.txt",
		"testdata/attacks/ssrf.txt",
		"testdata/attacks/ssti.txt",
		"testdata/attacks/xss.txt",
		"testdata/attacks/xxe.txt",
		"testdata/benign/application_logs.txt",
		"Combined benign corpus",
		"4/211 at or above block threshold, 1.9%; weighted FP avg 0.40",
		"go test ./internal/layers/detection -run TestDetectionLayer_CorpusQualityBaseline -count=1 -v",
		"at least 20 application-log benign samples",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("detection quality doc missing %q", want)
		}
	}
	if !strings.Contains(readme, "[Detection Quality](docs/detection-quality.md)") {
		t.Fatal("README documentation index does not link docs/detection-quality.md")
	}
	if !strings.Contains(testFile, `path: filepath.Join(root, "benign", "application_logs.txt")`) {
		t.Fatal("detection corpus gate does not include application_logs benign corpus")
	}
	if !strings.Contains(testFile, `context: "benign-log"`) {
		t.Fatal("detection corpus gate does not define benign-log context")
	}
	if countNonCommentLines(appLogs) < 20 {
		t.Fatal("application log benign corpus has fewer than 20 samples")
	}
}

func TestCleanCheckoutDashboardEmbedContract(t *testing.T) {
	root := filepath.Join("..", "..")
	placeholder := readTextFixture(t, filepath.Join(root, "internal/dashboard/dist/placeholder.txt"))
	gitignore := readTextFixture(t, filepath.Join(root, ".gitignore"))
	roadmap := readTextFixture(t, filepath.Join(root, "PRODUCTION_READINESS_ROADMAP.md"))
	readme := readTextFixture(t, filepath.Join(root, "README.md"))
	gettingStarted := readTextFixture(t, filepath.Join(root, "docs/getting-started.md"))
	productionDeployment := readTextFixture(t, filepath.Join(root, "docs/production-deployment.md"))
	releaseChecklist := readTextFixture(t, filepath.Join(root, "docs/release-checklist.md"))
	buildAllScript := readTextFixture(t, filepath.Join(root, "scripts/build.sh"))
	buildScript := readTextFixture(t, filepath.Join(root, "scripts/build-dashboard.sh"))
	prereqScript := readTextFixture(t, filepath.Join(root, "scripts/check-prereqs.sh"))

	for _, want := range []string{
		"keeps the embedded dashboard dist directory present in clean",
		"Run scripts/build-dashboard.sh or scripts/build.sh",
	} {
		if !strings.Contains(placeholder, want) {
			t.Fatalf("dashboard dist placeholder missing %q", want)
		}
	}
	for _, want := range []string{
		"internal/dashboard/dist/",
		"!internal/dashboard/dist/",
		"internal/dashboard/dist/*",
		"!internal/dashboard/dist/placeholder.txt",
	} {
		if !strings.Contains(gitignore, want) {
			t.Fatalf(".gitignore missing dashboard embed exception %q", want)
		}
	}
	for _, want := range []string{
		"internal/dashboard/dist/placeholder.txt",
		"clean-checkout Go compilation",
		"generated React assets remain ignored",
		"Production binaries still require `./scripts/build-dashboard.sh` or `./scripts/build.sh`",
	} {
		if !strings.Contains(roadmap, want) {
			t.Fatalf("roadmap missing clean-checkout dashboard contract %q", want)
		}
	}
	for _, want := range []string{
		"rm -rf \"${EMBED_DIR}\"",
		"cp -R \"${UI_DIR}/dist\" \"${EMBED_DIR}\"",
		"cat > \"${EMBED_DIR}/placeholder.txt\"",
	} {
		if !strings.Contains(buildScript, want) {
			t.Fatalf("dashboard build script missing embed contract step %q", want)
		}
	}
	if !strings.Contains(buildAllScript, "\"${ROOT_DIR}/scripts/check-prereqs.sh\"") {
		t.Fatal("production build script must run scripts/check-prereqs.sh before building")
	}
	if !strings.Contains(buildAllScript, "GWAF_SKIP_PREREQ_CHECK=1 \"${ROOT_DIR}/scripts/build-dashboard.sh\"") {
		t.Fatal("production build script must avoid duplicate prereq checks when calling build-dashboard.sh")
	}
	if strings.Index(buildAllScript, "check-prereqs.sh") > strings.Index(buildAllScript, "build-dashboard.sh") {
		t.Fatal("production build script must check prerequisites before building the dashboard")
	}
	if strings.Contains(roadmap, "A clean checkout cannot compile `internal/dashboard`") {
		t.Fatal("roadmap still claims clean checkout cannot compile the dashboard package")
	}

	for _, want := range []string{
		`MIN_GO="1.26.4"`,
		`MIN_NODE="20.19.0"`,
		"MIN_NPM_MAJOR=10",
		"Go $MIN_GO or newer is required",
		"Node.js $MIN_NODE or newer is required",
		"npm ${MIN_NPM_MAJOR}.x or newer is required",
	} {
		if !strings.Contains(prereqScript, want) {
			t.Fatalf("prerequisite script missing %q", want)
		}
	}
	for name, doc := range map[string]string{
		"README.md":                     readme,
		"docs/getting-started.md":       gettingStarted,
		"docs/production-deployment.md": productionDeployment,
	} {
		for _, want := range []string{
			"Go 1.26.4 or newer",
			"Node.js 20.19.0 or newer",
			"npm 10.x or newer",
			"./scripts/check-prereqs.sh",
			"./scripts/build.sh",
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("%s missing production build prerequisite contract %q", name, want)
			}
		}
	}
	for _, want := range []string{
		"Source prerequisites pass (`./scripts/check-prereqs.sh`)",
		"Dashboard build succeeds (`./scripts/build-dashboard.sh`)",
		"Full release build succeeds (`./scripts/build.sh v1.x.x`)",
	} {
		if !strings.Contains(releaseChecklist, want) {
			t.Fatalf("release checklist missing build prerequisite gate %q", want)
		}
	}
}

func TestPerformanceBudgetDocumentsReleaseBenchmarkContract(t *testing.T) {
	root := filepath.Join("..", "..")
	doc := readTextFixture(t, filepath.Join(root, "docs/performance-budget.md"))
	evidence := readTextFixture(t, filepath.Join(root, "docs/release-performance-evidence.md"))
	checklist := readTextFixture(t, filepath.Join(root, "docs/release-checklist.md"))
	readme := readTextFixture(t, filepath.Join(root, "README.md"))
	script := readTextFixture(t, filepath.Join(root, "scripts/benchmark.sh"))
	proxyLoadScript := readTextFixture(t, filepath.Join(root, "scripts/proxy-load-test.sh"))
	targetLoadScript := readTextFixture(t, filepath.Join(root, "scripts/target-load-evidence.sh"))
	benchmarks := readTextFixture(t, filepath.Join(root, "tests/integration/benchmark_test.go"))
	tenantBenchmarks := readTextFixture(t, filepath.Join(root, "internal/tenant/benchmark_test.go"))

	for _, want := range []string{
		"## Release Evidence",
		"## Budgets",
		"## Required Benchmark Scenarios",
		"## Operational Metrics",
		"## Bounded Overload Contract",
		"## Release Notes Template",
		"BenchmarkEngine_BenignRequest",
		"BenchmarkEngine_AttackRequest",
		"BenchmarkEngine_LargeHeaders",
		"BenchmarkEngine_LargeBody",
		"BenchmarkEngine_GzipBody",
		"BenchmarkEngine_DeflateBody",
		"BenchmarkRouteLookup_ManyRoutes",
		"BenchmarkTenantResolve_ManyTenants",
		"BenchmarkEventStore_HighEventRate",
		"guardianwaf_request_duration_seconds",
		"guardianwaf_event_store_dropped_total",
		"guardianwaf_event_bus_dropped_total",
		"guardianwaf_event_bus_rejected_subscriptions_total",
		"guardianwaf_alert_manager_dropped_total",
		"guardianwaf_alert_manager_max_dispatch",
		"guardianwaf_ai_pending_events",
		"Rate-limit per-IP buckets",
		"ATO per-IP and per-email trackers",
		"Tenant maps and request trackers",
		"PACKAGES='./tests/integration ./internal/tenant'",
		"./scripts/proxy-load-test.sh",
		"./scripts/target-load-evidence.sh",
		"The strict release evidence verifier enforces p99 overhead budgets for both local `proxy_load_results.txt` and target deployment `target_load_results.txt`",
		"standalone proxy `overhead_p99_ms` must be lower than `5 ms`",
		"sidecar proxy `overhead_p99_ms` must be lower than `3 ms`",
		"every load-test `errors=` line must be zero",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("performance budget missing %q", want)
		}
	}
	for _, want := range []string{
		"timestamp_utc=",
		"go_version=",
		"goos=",
		"goarch=",
		"cpu_count=",
		"kernel=",
		"bench_pattern=",
		"go test -bench=\"${BENCH}\"",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("benchmark script missing %q", want)
		}
	}
	for _, want := range []string{
		"standalone=http://127.0.0.1:$SERVE_PORT/",
		"sidecar=http://127.0.0.1:$SIDECAR_PORT/",
		"backend=http://127.0.0.1:$BACKEND_PORT/",
		"latency_p95_ms=",
		"latency_p99_ms=",
		"overhead_p99_ms=",
		"raise SystemExit(f\"{name} load test had {errors} non-200 responses\")",
	} {
		if !strings.Contains(proxyLoadScript, want) {
			t.Fatalf("proxy load test script missing %q", want)
		}
	}
	for _, want := range []string{
		"TARGET_BACKEND_URL",
		"TARGET_STANDALONE_URL",
		"TARGET_SIDECAR_URL",
		"require_positive_integer REQUESTS",
		"must start with http:// or https://",
		"must include a host",
		"must not contain whitespace",
		"must not include URL userinfo or credentials",
		"must not include a URL fragment",
		"TARGET_LABEL must identify the measured target environment",
		"REQUESTS>=1000 CONCURRENCY>=10 WARMUP>=50",
		"target_load_results.txt",
		"GuardianWAF target-load-evidence",
		"latency_p95_ms=",
		"latency_p99_ms=",
		"overhead_p99_ms=",
		"raise SystemExit(f\"{name} load test had {errors} non-200 responses\")",
	} {
		if !strings.Contains(targetLoadScript, want) {
			t.Fatalf("target load evidence script missing %q", want)
		}
	}
	for _, want := range []string{
		"func BenchmarkEngine_LargeHeaders",
		"func BenchmarkEngine_LargeBody",
		"func BenchmarkEngine_GzipBody",
		"func BenchmarkEngine_DeflateBody",
		"func BenchmarkRouteLookup_ManyRoutes",
		"func BenchmarkEventStore_HighEventRate",
	} {
		if !strings.Contains(benchmarks, want) {
			t.Fatalf("benchmark suite missing %q", want)
		}
	}
	if !strings.Contains(tenantBenchmarks, "func BenchmarkTenantResolve_ManyTenants") {
		t.Fatal("tenant benchmark suite missing BenchmarkTenantResolve_ManyTenants")
	}
	if !strings.Contains(readme, "[Performance Budget](docs/performance-budget.md)") {
		t.Fatal("README documentation index does not link docs/performance-budget.md")
	}
	if !strings.Contains(readme, "[Release Performance Evidence](docs/release-performance-evidence.md)") {
		t.Fatal("README documentation index does not link docs/release-performance-evidence.md")
	}
	for _, want := range []string{
		"## 2026-06-11 Local Proxy Load Test",
		"## 2026-06-11 Local Focused Benchmark",
		"go version go1.26.4 linux/amd64",
		"./scripts/proxy-load-test.sh",
		"Standalone proxy",
		"Sidecar proxy",
		"p99 overhead vs backend",
		"PACKAGES='./tests/integration ./internal/tenant'",
		"BenchmarkEngine_BenignRequest",
		"BenchmarkTenantResolve_ManyTenants",
		"guardianwaf_event_store_dropped_total",
		"guardianwaf_event_bus_dropped_total",
		"guardianwaf_event_bus_rejected_subscriptions_total",
		"guardianwaf_alert_manager_dropped_total",
		"guardianwaf_alert_manager_max_dispatch",
		"guardianwaf_ai_pending_events",
		"target deployment environment",
		"./scripts/target-load-evidence.sh",
		"target_load_results.txt",
	} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("release performance evidence missing %q", want)
		}
	}
	if !strings.Contains(checklist, "Focused release benchmark run recorded in `docs/release-performance-evidence.md`") {
		t.Fatal("release checklist does not require focused benchmark evidence")
	}
	if !strings.Contains(checklist, "Standalone and sidecar proxy load test recorded in `docs/release-performance-evidence.md`") {
		t.Fatal("release checklist does not require proxy load evidence")
	}
	if !strings.Contains(checklist, "rejects any non-zero local proxy-load `errors` line") {
		t.Fatal("release checklist does not document local proxy-load error enforcement")
	}
	if !strings.Contains(checklist, "enforces local proxy-load p99 overhead budgets") {
		t.Fatal("release checklist does not document local proxy-load p99 overhead budgets")
	}
	if !strings.Contains(checklist, "Target deployment load evidence attached to the release bundle") {
		t.Fatal("release checklist does not require target deployment load evidence")
	}
	if !strings.Contains(checklist, "rejects any non-zero target-load `errors` line") {
		t.Fatal("release checklist does not document target-load error enforcement")
	}
	if !strings.Contains(checklist, "standalone `< 5 ms`, sidecar `< 3 ms`") {
		t.Fatal("release checklist does not document target-load p99 overhead budgets")
	}
}

func readTextFixture(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	return string(data)
}

func writeReleaseEvidenceTestFile(t *testing.T, root, path, content string) {
	t.Helper()
	fullPath := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", filepath.Dir(fullPath), err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", fullPath, err)
	}
}

func copyReleaseEvidenceTestBundle(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("ReadDir(%q) error = %v", src, err)
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := os.MkdirAll(dstPath, 0o755); err != nil {
				t.Fatalf("MkdirAll(%q) error = %v", dstPath, err)
			}
			copyReleaseEvidenceTestBundle(t, srcPath, dstPath)
			continue
		}
		data, err := os.ReadFile(srcPath)
		if err != nil {
			t.Fatalf("ReadFile(%q) error = %v", srcPath, err)
		}
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q) error = %v", filepath.Dir(dstPath), err)
		}
		if err := os.WriteFile(dstPath, data, 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", dstPath, err)
		}
	}
}

func releaseEvidenceFixtureContent(path string) string {
	switch path {
	case "manifest.txt":
		return "version=v1.0.0\ngit_commit=1234567890abcdef1234567890abcdef12345678\nheavy=1\n"
	case "hosted-ci/ci-run.txt":
		return "url: https://github.com/guardianwaf/guardianwaf/actions/runs/1\ncommit: 1234567890abcdef1234567890abcdef12345678\nresult: passed\n"
	case "target-load/target_load_results.txt":
		return strings.Join([]string{
			"# GuardianWAF target environment load evidence",
			"timestamp_utc=2026-06-11T12:00:00Z",
			"target_label=release-candidate",
			"requests=1000",
			"concurrency=20",
			"warmup=50",
			"backend_url=https://backend.example.test/healthz",
			"standalone_url=https://waf.example.test/healthz",
			"cpu_count=8",
			"kernel=Linux 6.8.0 x86_64 GNU/Linux",
			"",
			"## backend",
			"url=https://backend.example.test/healthz",
			"errors=0",
			"latency_p99_ms=9",
			"",
			"## standalone",
			"url=https://waf.example.test/healthz",
			"errors=0",
			"latency_p99_ms=12",
			"overhead_p99_ms=3",
			"",
		}, "\n")
	case "release-artifacts/checksums.txt":
		return "0000000000000000000000000000000000000000000000000000000000000001  guardianwaf_1.0.0_linux_amd64.tar.gz\n"
	case "supply-chain/image-digest.txt":
		return "image=ghcr.io/guardianwaf/guardianwaf:v1.0.0\nimage_ref=ghcr.io/guardianwaf/guardianwaf@sha256:0000000000000000000000000000000000000000000000000000000000000001\ndigest=sha256:0000000000000000000000000000000000000000000000000000000000000001\ncommit=1234567890abcdef1234567890abcdef12345678\ntag=v1.0.0\n"
	case "supply-chain/imagetools.txt":
		return "Name: ghcr.io/guardianwaf/guardianwaf:v1.0.0\nDigest: sha256:0000000000000000000000000000000000000000000000000000000000000001\n"
	case "supply-chain/cosign-verify.txt":
		return "image_ref=ghcr.io/guardianwaf/guardianwaf@sha256:0000000000000000000000000000000000000000000000000000000000000001\ncertificate_identity_regexp=https://github.com/guardianwaf/guardianwaf/.github/workflows/release.yml@refs/tags/v.*\ncertificate_oidc_issuer=https://token.actions.githubusercontent.com\nVerified OK\nThe following checks were performed against token.actions.githubusercontent.com\n"
	case "supply-chain/provenance-verify.txt":
		return "image_ref=ghcr.io/guardianwaf/guardianwaf@sha256:0000000000000000000000000000000000000000000000000000000000000001\ncertificate_identity_regexp=https://github.com/guardianwaf/guardianwaf/.github/workflows/release.yml@refs/tags/v.*\ncertificate_oidc_issuer=https://token.actions.githubusercontent.com\nThe following checks were performed against token.actions.githubusercontent.com\n{\"predicateType\":\"https://slsa.dev/provenance/v1\",\"predicate\":{\"buildDefinition\":{}}}\n"
	case "supply-chain/sbom-attestation-verify.txt":
		return "image_ref=ghcr.io/guardianwaf/guardianwaf@sha256:0000000000000000000000000000000000000000000000000000000000000001\ncertificate_identity_regexp=https://github.com/guardianwaf/guardianwaf/.github/workflows/release.yml@refs/tags/v.*\ncertificate_oidc_issuer=https://token.actions.githubusercontent.com\nThe following checks were performed against token.actions.githubusercontent.com\n{\"predicateType\":\"https://spdx.dev/Document\",\"predicate\":{\"spdxVersion\":\"SPDX-2.3\",\"packages\":[]}}\n"
	case "supply-chain/sbom.spdx.json":
		return "{\"spdxVersion\":\"SPDX-2.3\",\"packages\":[{\"SPDXID\":\"SPDXRef-Package-guardianwaf\",\"name\":\"guardianwaf\"}]}\n"
	case "supply-chain/trivy.txt":
		return "Report Summary\nTotal: 0 (HIGH: 0, CRITICAL: 0)\n"
	case "external-security-review/report.md":
		return "# Security Review Report\nRelease candidate: v1.0.0\nCommit: 1234567890abcdef1234567890abcdef12345678\nReview dates: 2026-06-11\nSummary: review completed.\nScope: release evidence verifier.\nFindings: none.\nSeverity: low.\nReviewer sign-off: Security Reviewer.\n"
	default:
		return path + "\n"
	}
}

func releaseEvidenceFocusedBenchmarkFixture() string {
	return strings.Join([]string{
		"BenchmarkEngine_BenignRequest-16 1000 1234 ns/op",
		"BenchmarkEngine_AttackRequest-16 1000 1234 ns/op",
		"BenchmarkEngine_LargeHeaders-16 1000 1234 ns/op",
		"BenchmarkEngine_LargeBody-16 1000 1234 ns/op",
		"BenchmarkEngine_GzipBody-16 1000 1234 ns/op",
		"BenchmarkEngine_DeflateBody-16 1000 1234 ns/op",
		"BenchmarkEngine_FullPipeline_MultiParam-16 1000 1234 ns/op",
		"BenchmarkEngine_Parallel-16 1000 1234 ns/op",
		"BenchmarkRouteLookup_ManyRoutes-16 1000 1234 ns/op",
		"BenchmarkTenantResolve_ManyTenants-16 1000 1234 ns/op",
		"BenchmarkEventStore_HighEventRate-16 1000 1234 ns/op",
	}, "\n") + "\n"
}

func releaseEvidenceRollbackFixture() string {
	return strings.Join([]string{
		"# release-rollback",
		"command=./scripts/release-rollback-smoke.sh ./dist/guardianwaf-linux-amd64 ./previous/guardianwaf-linux-amd64",
		"PASS previous validates rollback config",
		"PASS previous /readyz returns 200",
		"PASS previous proxies traffic",
		"PASS previous writes persistent events",
		"PASS candidate upgrade validates rollback config",
		"PASS candidate upgrade /readyz returns 200",
		"PASS candidate upgrade proxies traffic",
		"PASS rollback validates rollback config",
		"PASS rollback /readyz returns 200",
		"PASS rollback proxies traffic",
		"Upgrade and rollback smoke passed",
	}, "\n") + "\n"
}

func countNonCommentLines(data string) int {
	count := 0
	for _, line := range strings.Split(data, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		count++
	}
	return count
}
