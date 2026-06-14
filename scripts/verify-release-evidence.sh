#!/usr/bin/env bash
# Verify a release evidence bundle before stable release sign-off.
# Usage: ./scripts/verify-release-evidence.sh [--allow-pending|--check-hosted-ci|--check-target-load|--check-release-checksums|--check-supply-chain|--check-external-review] dist/release-evidence/v1.x.x-YYYYmmddTHHMMSSZ
set -euo pipefail

ALLOW_PENDING=0
CHECK_MODE=""
while [ "${1:-}" = "--allow-pending" ] || [ "${1:-}" = "--check-hosted-ci" ] || [ "${1:-}" = "--check-target-load" ] || [ "${1:-}" = "--check-release-checksums" ] || [ "${1:-}" = "--check-supply-chain" ] || [ "${1:-}" = "--check-external-review" ]; do
    case "${1:-}" in
        --allow-pending)
            ALLOW_PENDING=1
            ;;
        --check-hosted-ci)
            CHECK_MODE="hosted-ci"
            ;;
        --check-target-load)
            CHECK_MODE="target-load"
            ;;
        --check-release-checksums)
            CHECK_MODE="release-checksums"
            ;;
        --check-supply-chain)
            CHECK_MODE="supply-chain"
            ;;
        --check-external-review)
            CHECK_MODE="external-review"
            ;;
    esac
    shift
done

BUNDLE="${1:-}"
if [ -z "${BUNDLE}" ]; then
    echo "usage: $0 [--allow-pending|--check-hosted-ci|--check-target-load|--check-release-checksums|--check-supply-chain|--check-external-review] <release-evidence-dir>" >&2
    exit 2
fi
if [ ! -d "${BUNDLE}" ]; then
    echo "release evidence directory not found: ${BUNDLE}" >&2
    exit 1
fi

require_file() {
    local path="$1"
    if [ ! -s "${BUNDLE}/${path}" ]; then
        echo "missing or empty evidence file: ${path}" >&2
        exit 1
    fi
}

require_path() {
    local path="$1"
    if [ ! -e "${BUNDLE}/${path}" ]; then
        echo "missing evidence file: ${path}" >&2
        exit 1
    fi
}

require_contains() {
    local path="$1"
    local pattern="$2"
    require_file "${path}"
    if ! grep -qiE "${pattern}" "${BUNDLE}/${path}"; then
        echo "evidence file ${path} does not match required pattern: ${pattern}" >&2
        exit 1
    fi
}

extract_evidence_value() {
    local path="$1"
    local key="$2"
    require_file "${path}"
    awk -v key="${key}" '
        BEGIN { IGNORECASE = 1 }
        $0 ~ "^" key "[[:space:]]*[:=]" {
            sub("^[^:=]+[[:space:]]*[:=][[:space:]]*", "")
            print
            exit
        }
    ' "${BUNDLE}/${path}" | tr '[:upper:]' '[:lower:]'
}

require_unique_evidence_field() {
	local path="$1"
	local key="$2"
	local count
	require_file "${path}"
	count="$(awk -v key="${key}" '
		BEGIN { IGNORECASE = 1; count = 0 }
		$0 ~ "^" key "[[:space:]]*[:=]" { count++ }
		END { print count }
	' "${BUNDLE}/${path}")"
	if [ "${count}" -ne 1 ]; then
		echo "${path} must contain exactly one ${key} field; found ${count}" >&2
		exit 1
	fi
}

require_matching_commits() {
	local manifest_commit
	local ci_commit
	local image_commit
	manifest_commit="$(extract_evidence_value manifest.txt git_commit)"
	ci_commit="$(extract_evidence_value hosted-ci/ci-run.txt commit)"
	image_commit="$(extract_evidence_value supply-chain/image-digest.txt commit)"
	if ! [[ "${manifest_commit}" =~ ^[0-9a-f]{40}$ ]]; then
		echo "manifest.txt git_commit is not a full 40-character git SHA: ${manifest_commit}" >&2
		exit 1
	fi
	if ! [[ "${ci_commit}" =~ ^[0-9a-f]{40}$ ]]; then
		echo "hosted-ci/ci-run.txt commit is not a full 40-character git SHA: ${ci_commit}" >&2
		exit 1
	fi
	if ! [[ "${image_commit}" =~ ^[0-9a-f]{40}$ ]]; then
		echo "supply-chain/image-digest.txt commit is not a full 40-character git SHA: ${image_commit}" >&2
		exit 1
	fi
	if [[ "${manifest_commit}" != "${ci_commit}" ]]; then
		echo "release evidence commit mismatch: manifest=${manifest_commit} hosted-ci=${ci_commit}" >&2
		exit 1
	fi
	if [[ "${ci_commit}" != "${image_commit}" ]]; then
		echo "release evidence commit mismatch: hosted-ci=${ci_commit} supply-chain=${image_commit}" >&2
		exit 1
	fi
}

require_matching_release_tag() {
    local bundle_version
    local image_tag
    bundle_version="$(extract_evidence_value manifest.txt version)"
    image_tag="$(extract_evidence_value supply-chain/image-digest.txt tag)"
    image_tag="${image_tag#refs/tags/}"
    if [ -z "${bundle_version}" ]; then
        echo "manifest.txt version is empty" >&2
        exit 1
    fi
    if [ -z "${image_tag}" ]; then
        echo "supply-chain/image-digest.txt tag is empty" >&2
        exit 1
    fi
	if [ "${bundle_version}" != "${image_tag}" ]; then
		echo "release evidence tag mismatch: manifest=${bundle_version} supply-chain=${image_tag}" >&2
		exit 1
	fi
}

require_release_image_repository() {
	local image
	local image_ref
	local digest
	local tag
	image="$(extract_evidence_value supply-chain/image-digest.txt image)"
	image_ref="$(extract_evidence_value supply-chain/image-digest.txt image_ref)"
	digest="$(extract_evidence_value supply-chain/image-digest.txt digest)"
	tag="$(extract_evidence_value supply-chain/image-digest.txt tag)"
	tag="${tag#refs/tags/}"
	if [ "${image}" != "ghcr.io/guardianwaf/guardianwaf:${tag}" ]; then
		echo "supply-chain/image-digest.txt image must match GuardianWAF release tag: ${image}" >&2
		exit 1
	fi
	if [ "${image_ref}" != "ghcr.io/guardianwaf/guardianwaf@${digest}" ]; then
		echo "supply-chain/image-digest.txt image_ref must match GuardianWAF release digest: ${image_ref}" >&2
		exit 1
	fi
}

require_image_digest_matches_imagetools() {
	local image_digest
	image_digest="$(extract_evidence_value supply-chain/image-digest.txt digest)"
	if ! [[ "${image_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
		echo "supply-chain/image-digest.txt digest is not a sha256 digest: ${image_digest}" >&2
		exit 1
	fi
	require_contains supply-chain/imagetools.txt "$(regex_escape "${image_digest}")"
}

require_release_oidc_identity() {
	local path="$1"
	require_contains "${path}" 'certificate_identity_regexp=https://github\.com/guardianwaf/guardianwaf/\.github/workflows/release\.yml@refs/tags/v\.\*'
	require_contains "${path}" 'certificate_oidc_issuer=https://token\.actions\.githubusercontent\.com'
}

require_verification_image_ref() {
	local path="$1"
	local expected_image_ref
	local actual_image_ref
	expected_image_ref="$(extract_evidence_value supply-chain/image-digest.txt image_ref)"
	actual_image_ref="$(extract_evidence_value "${path}" image_ref)"
	if [ -z "${expected_image_ref}" ]; then
		echo "supply-chain/image-digest.txt image_ref is empty" >&2
		exit 1
	fi
	if [ "${actual_image_ref}" != "${expected_image_ref}" ]; then
		echo "${path} image_ref does not match supply-chain/image-digest.txt: ${actual_image_ref} != ${expected_image_ref}" >&2
		exit 1
	fi
}

require_spdx_package_inventory() {
	local path="supply-chain/sbom.spdx.json"
	require_contains "${path}" '"spdxVersion"'
	require_contains "${path}" '"packages"[[:space:]]*:'
	if ! grep -qiE '"packages"[[:space:]]*:[[:space:]]*\[[[:space:]]*\{' "${BUNDLE}/${path}"; then
		echo "supply-chain/sbom.spdx.json must include at least one package entry" >&2
		exit 1
	fi
}

require_cosign_success_marker() {
	local path="$1"
	require_contains "${path}" '(Verified OK|The following checks were performed)'
}

require_no_cosign_failure_marker() {
	local path="$1"
	require_file "${path}"
	if grep -qiE '(error|failed|failure|invalid signature|no matching signatures|certificate identity.*not|oidc issuer.*not)' "${BUNDLE}/${path}"; then
		echo "${path} contains a cosign verification failure marker" >&2
		exit 1
	fi
}

regex_escape() {
	printf '%s' "$1" | sed 's/[][(){}.^$*+?|\\]/\\&/g'
}

require_valid_yyyy_mm_dd() {
	local value="$1"
	local label="$2"
	local normalized
	if ! [[ "${value}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
		echo "${label} must be a valid YYYY-MM-DD date: ${value}" >&2
		exit 1
	fi
	if ! normalized="$(date -u -d "${value} 00:00:00 UTC" +%F 2>/dev/null)" || [ "${normalized}" != "${value}" ]; then
		echo "${label} must be a valid YYYY-MM-DD date: ${value}" >&2
		exit 1
	fi
}

require_valid_utc_timestamp() {
	local value="$1"
	local label="$2"
	local normalized
	if ! [[ "${value}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
		echo "${label} must be a valid UTC timestamp in YYYY-MM-DDTHH:MM:SSZ format: ${value}" >&2
		exit 1
	fi
	if ! normalized="$(date -u -d "${value}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)" || [ "${normalized}" != "${value}" ]; then
		echo "${label} must be a valid UTC timestamp in YYYY-MM-DDTHH:MM:SSZ format: ${value}" >&2
		exit 1
	fi
}

require_checksums_match_release() {
	local bundle_version
	local artifact_version
	bundle_version="$(extract_evidence_value manifest.txt version)"
	artifact_version="${bundle_version#v}"
	if [ -z "${artifact_version}" ]; then
		echo "manifest.txt version is empty" >&2
		exit 1
	fi
	awk -v artifact_version="${artifact_version}" '
		BEGIN {
			failed = 0
			guardian_seen = 0
			matched = 0
			pattern = "guardianwaf[_-]" artifact_version "([^0-9]|$)"
		}
		/^[0-9a-fA-F]{64}[[:space:]]+/ {
			line = tolower($0)
			if (line ~ /guardianwaf[_-]/) {
				guardian_seen = 1
				if (line ~ pattern) {
					matched = 1
				} else {
					printf "release-artifacts/checksums.txt contains GuardianWAF artifact from a different release: %s\n", $0 > "/dev/stderr"
					failed = 1
				}
			}
		}
		END {
			if (!guardian_seen || !matched) {
				printf "release-artifacts/checksums.txt must include a SHA-256 line for GuardianWAF release %s\n", artifact_version > "/dev/stderr"
				failed = 1
			}
			if (failed) exit 1
		}
	' "${BUNDLE}/release-artifacts/checksums.txt"
}

require_external_review_matches_release() {
	local path="$1"
	local bundle_version
	local ci_commit
	local bundle_version_re
	local ci_commit_re
	bundle_version="$(extract_evidence_value manifest.txt version)"
	ci_commit="$(extract_evidence_value hosted-ci/ci-run.txt commit)"
	bundle_version_re="$(regex_escape "${bundle_version}")"
	ci_commit_re="$(regex_escape "${ci_commit}")"
	require_file "${path}"
	if ! grep -qiE "(^|[^[:alnum:]._-])${bundle_version_re}([^[:alnum:]._-]|$)" "${BUNDLE}/${path}"; then
		echo "external security evidence ${path} does not reference manifest version ${bundle_version}" >&2
		exit 1
	fi
	if ! grep -qiE "(^|[^0-9a-f])${ci_commit_re}([^0-9a-f]|$)" "${BUNDLE}/${path}"; then
		echo "external security evidence ${path} does not reference hosted CI commit ${ci_commit}" >&2
		exit 1
	fi
}

require_no_open_high_critical_findings() {
	local path="$1"
	require_file "${path}"
	awk -F'|' '
		BEGIN { failed = 0 }
		/^[[:space:]]*\|/ {
			row = tolower($0)
			if (row ~ /\|[[:space:]]*(critical|high)[[:space:]]*\|/ &&
				row ~ /\|[[:space:]]*(open|unfixed|unresolved|not[ -]?fixed)[[:space:]]*\|/) {
				printf "external security report has open HIGH/CRITICAL finding: %s\n", $0 > "/dev/stderr"
				failed = 1
			}
		}
		END { if (failed) exit 1 }
	' "${BUNDLE}/${path}"
}

require_external_review_signoff() {
	local path="$1"
	local review_date
	require_file "${path}"
	review_date="$(grep -ioE '^review dates?[[:space:]:-]+.*[0-9]{4}-[0-9]{2}-[0-9]{2}' "${BUNDLE}/${path}" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -n 1 || true)"
	if [ -z "${review_date}" ]; then
		echo "external security report ${path} must include review dates in YYYY-MM-DD format" >&2
		exit 1
	fi
	require_valid_yyyy_mm_dd "${review_date}" "external security report ${path} review date"
	if ! grep -qiE '^reviewer sign-?off[[:space:]:-]+[^[:space:]]' "${BUNDLE}/${path}"; then
		echo "external security report ${path} must include reviewer sign-off" >&2
		exit 1
	fi
}

require_risk_acceptance_tracking() {
	local path="$1"
	local acceptance_date
	local today
	require_file "${path}"
	acceptance_date="$(grep -ioE '(expiration|expires|follow-up)[^0-9]{0,80}[0-9]{4}-[0-9]{2}-[0-9]{2}' "${BUNDLE}/${path}" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -n 1 || true)"
	if [ -z "${acceptance_date}" ]; then
		echo "risk acceptance ${path} must include an expiration or follow-up date in YYYY-MM-DD format" >&2
		exit 1
	fi
	require_valid_yyyy_mm_dd "${acceptance_date}" "risk acceptance ${path} expiration or follow-up date"
	today="${RELEASE_EVIDENCE_TODAY:-$(date -u +%F)}"
	require_valid_yyyy_mm_dd "${today}" "release evidence current date"
	if [[ "${acceptance_date}" < "${today}" ]]; then
		echo "risk acceptance ${path} expiration or follow-up date is in the past: ${acceptance_date}" >&2
		exit 1
	fi
	if ! grep -qiE '(owner|approver)[[:space:]:-]+[^[:space:]]' "${BUNDLE}/${path}"; then
		echo "risk acceptance ${path} must include an owner or approver" >&2
		exit 1
	fi
	if ! grep -qiE '(https://[^[:space:]]+/(issues|pull)/[0-9]+|#[0-9]+|[A-Z][A-Z0-9]+-[0-9]+)' "${BUNDLE}/${path}"; then
		echo "risk acceptance ${path} must include a tracked follow-up issue, PR, or ticket reference" >&2
		exit 1
	fi
}

require_hosted_ci_evidence() {
    require_unique_evidence_field hosted-ci/ci-run.txt url
    require_unique_evidence_field hosted-ci/ci-run.txt result
    require_unique_evidence_field hosted-ci/ci-run.txt commit
    require_contains hosted-ci/ci-run.txt '^url: *https://github\.com/guardianwaf/guardianwaf/actions/runs/[0-9]+[[:space:]]*$'
    require_contains hosted-ci/ci-run.txt '^result: *(pass|passed|success|succeeded)[[:space:]]*$'
    require_contains hosted-ci/ci-run.txt '^commit: *[0-9a-f]{40}[[:space:]]*$'
}

require_no_nonzero_errors() {
    local path="$1"
    require_file "${path}"
    awk -F= '
        BEGIN { failed = 0 }
        tolower($1) == "errors" && ($2 + 0) != 0 {
            printf "%s has non-zero error count: %s\n", FILENAME, $0 > "/dev/stderr"
            failed = 1
        }
        END { if (failed) exit 1 }
    ' "${BUNDLE}/${path}"
}

target_load_field_value() {
    local path="$1"
    local key="$2"
    require_file "${path}"
    awk -v key="${key}" '
        BEGIN { IGNORECASE = 1 }
        $0 ~ "^" key "=" {
            sub("^[^=]+=", "")
            print
            exit
        }
    ' "${BUNDLE}/${path}"
}

require_unique_target_load_field() {
    local path="$1"
    local key="$2"
    local required="${3:-1}"
    local count
    require_file "${path}"
    count="$(awk -v key="${key}" '
        BEGIN { IGNORECASE = 1; count = 0 }
        $0 ~ "^" key "=" { count++ }
        END { print count }
    ' "${BUNDLE}/${path}")"
    if [ "${count}" -gt 1 ]; then
        echo "${path} contains duplicate ${key} fields" >&2
        exit 1
    fi
    if [ "${required}" = "1" ] && [ "${count}" -ne 1 ]; then
        echo "${path} must contain exactly one ${key} field" >&2
        exit 1
    fi
}

require_target_load_http_url_field() {
    local path="$1"
    local key="$2"
    local value
    local authority
    value="$(target_load_field_value "${path}" "${key}")"
    if [ -z "${value}" ]; then
        echo "${path} missing ${key}" >&2
        exit 1
    fi
    if ! [[ "${value}" =~ ^https?:// ]]; then
        echo "${path} ${key} must start with http:// or https://, got: ${value}" >&2
        exit 1
    fi
    if [[ "${value}" =~ [[:space:]] ]]; then
        echo "${path} ${key} must not contain whitespace, got: ${value}" >&2
        exit 1
    fi
    authority="${value#*://}"
    authority="${authority%%[/?#]*}"
    if [ -z "${authority}" ]; then
        echo "${path} ${key} must include a host, got: ${value}" >&2
        exit 1
    fi
    if [[ "${authority}" == *"@"* ]]; then
        echo "${path} ${key} must not include URL userinfo or credentials, got: ${value}" >&2
        exit 1
    fi
    if [[ "${value}" == *"#"* ]]; then
        echo "${path} ${key} must not include a URL fragment, got: ${value}" >&2
        exit 1
    fi
}

require_target_load_metadata() {
    local path="target-load/target_load_results.txt"
	local timestamp_utc
	local target_label
	local proxy_url_seen=0
	for field in timestamp_utc target_label requests concurrency warmup backend_url; do
		require_unique_target_load_field "${path}" "${field}"
	done
	require_unique_target_load_field "${path}" standalone_url 0
	require_unique_target_load_field "${path}" sidecar_url 0
    require_contains "${path}" '^timestamp_utc=[0-9]{4}-[0-9]{2}-[0-9]{2}t[0-9]{2}:[0-9]{2}:[0-9]{2}z$'
	timestamp_utc="$(extract_evidence_value "${path}" timestamp_utc)"
	timestamp_utc="${timestamp_utc^^}"
	require_valid_utc_timestamp "${timestamp_utc}" "target-load/target_load_results.txt timestamp_utc"
    require_contains "${path}" '^target_label=[^[:space:]]+'
	target_label="$(extract_evidence_value "${path}" target_label)"
	if [[ "${target_label}" =~ ^(target|test|default|unknown)$ ]]; then
		echo "target-load/target_load_results.txt target_label must identify the target environment, not generic value: ${target_label}" >&2
		exit 1
	fi
    require_contains "${path}" '^requests=[1-9][0-9]*$'
    require_contains "${path}" '^concurrency=[1-9][0-9]*$'
    require_contains "${path}" '^warmup=[0-9]+$'
    require_target_load_http_url_field "${path}" backend_url
    if grep -qiE '^standalone_url=' "${BUNDLE}/${path}"; then
        require_target_load_http_url_field "${path}" standalone_url
        proxy_url_seen=1
    fi
    if grep -qiE '^sidecar_url=' "${BUNDLE}/${path}"; then
        require_target_load_http_url_field "${path}" sidecar_url
        proxy_url_seen=1
    fi
    if [ "${proxy_url_seen}" != "1" ]; then
        echo "target-load/target_load_results.txt must include standalone_url= or sidecar_url=" >&2
        exit 1
    fi
}

require_target_load_runtime_context() {
	local path="target-load/target_load_results.txt"
	require_contains "${path}" '^cpu_count=[^[:space:]]+'
	require_contains "${path}" '^kernel=.+'
	require_contains "${path}" '^##[[:space:]]+backend$'
}

require_target_load_sample_size() {
	local path="target-load/target_load_results.txt"
	local requests
	local concurrency
	local warmup
	requests="$(extract_evidence_value "${path}" requests)"
	concurrency="$(extract_evidence_value "${path}" concurrency)"
	warmup="$(extract_evidence_value "${path}" warmup)"
	if [ "${requests}" -lt 1000 ] || [ "${concurrency}" -lt 10 ] || [ "${warmup}" -lt 50 ]; then
		echo "target-load/target_load_results.txt sample size is too small: requests=${requests} concurrency=${concurrency} warmup=${warmup}; require requests>=1000 concurrency>=10 warmup>=50" >&2
		exit 1
	fi
}

require_load_budget() {
    local path="$1"
    local label="$2"
    require_file "${path}"
    awk -F= '
        /^##[[:space:]]+/ {
            section = tolower($0)
            sub(/^##[[:space:]]+/, "", section)
            next
        }
        $1 == "overhead_p99_ms" {
            budget = ""
            if (section == "standalone") {
                budget = 5
            } else if (section == "sidecar") {
                budget = 3
            } else {
                next
            }
            seen = 1
            value = $2 + 0
            if (value >= budget) {
                printf "%s %s overhead_p99_ms %.3f exceeds budget < %.3f ms\n", label, section, value, budget > "/dev/stderr"
                failed = 1
            }
        }
        END {
            if (!seen) {
                printf "%s missing standalone or sidecar overhead_p99_ms evidence\n", path > "/dev/stderr"
                exit 1
            }
            if (failed) exit 1
        }
    ' label="${label}" path="${path}" "${BUNDLE}/${path}"
}

require_focused_benchmarks() {
	local path="benchmark_results.txt"
	for benchmark in \
        BenchmarkEngine_BenignRequest \
        BenchmarkEngine_AttackRequest \
        BenchmarkEngine_LargeHeaders \
        BenchmarkEngine_LargeBody \
        BenchmarkEngine_GzipBody \
        BenchmarkEngine_DeflateBody \
        BenchmarkEngine_FullPipeline_MultiParam \
        BenchmarkEngine_Parallel \
        BenchmarkRouteLookup_ManyRoutes \
        BenchmarkTenantResolve_ManyTenants \
        BenchmarkEventStore_HighEventRate; do
		require_contains "${path}" "${benchmark}"
	done
}

require_release_rollback_evidence() {
	local path="logs/release-rollback.log"
	require_contains "${path}" 'previous writes persistent events'
	require_contains "${path}" 'candidate upgrade /readyz returns 200'
	require_contains "${path}" 'candidate upgrade proxies traffic'
	require_contains "${path}" 'rollback /readyz returns 200'
	require_contains "${path}" 'rollback proxies traffic'
	require_contains "${path}" 'Upgrade and rollback smoke passed'
}

require_trivy_clean() {
    local path="supply-chain/trivy.txt"
    require_file "${path}"
    if grep -qiE '\b(HIGH|CRITICAL)[[:space:]]*:[[:space:]]*[1-9][0-9]*\b|\bTotal[[:space:]]*:[[:space:]]*[1-9][0-9]*\b|\|[[:space:]]*(HIGH|CRITICAL)[[:space:]]*\|' "${BUNDLE}/${path}"; then
        echo "supply-chain/trivy.txt reports HIGH/CRITICAL vulnerabilities" >&2
        exit 1
    fi
}

reject_placeholder() {
    local path="$1"
    require_file "${path}"
    if grep -qiE '(^|[[:space:][:punct:]])(TBD|TODO|PLACEHOLDER|example\.com)([[:space:][:punct:]]|$)|Describe the|Explain why|List the|Set an expiration|Release candidate:[[:space:]]*$|Approver:[[:space:]]*$|Review dates:[[:space:]]*$' "${BUNDLE}/${path}"; then
        echo "evidence file ${path} still contains placeholder text" >&2
        exit 1
    fi
}

require_log_success() {
    local path="$1"
    require_file "${path}"
    if grep -qiE '(^FAIL\b|panic:|exit status [1-9]|command not found|No such file or directory)' "${BUNDLE}/${path}"; then
        echo "evidence log contains failure marker: ${path}" >&2
        exit 1
    fi
}

require_clean_git_status() {
	require_path git-status.txt
	if [ -s "${BUNDLE}/git-status.txt" ]; then
		echo "release evidence git status is not clean:" >&2
		cat "${BUNDLE}/git-status.txt" >&2
		exit 1
	fi
}

require_clean_git_diff_check() {
	require_path git-diff-check.txt
	if [ -s "${BUNDLE}/git-diff-check.txt" ]; then
		echo "release evidence git diff check is not clean:" >&2
		cat "${BUNDLE}/git-diff-check.txt" >&2
		exit 1
	fi
}

require_heavy_manifest() {
	local heavy
	heavy="$(extract_evidence_value manifest.txt heavy)"
	if [ "${heavy}" != "1" ]; then
		echo "manifest.txt heavy must be 1 for final strict release evidence: ${heavy}" >&2
		exit 1
	fi
}

require_bundle_name_matches_manifest() {
	local bundle_base
	local manifest_version
	bundle_base="$(basename "${BUNDLE}")"
	manifest_version="$(extract_evidence_value manifest.txt version)"
	if [ -z "${manifest_version}" ]; then
		echo "manifest.txt version is empty" >&2
		exit 1
	fi
	case "${bundle_base}" in
		ci|release)
			return 0
			;;
	esac
	if [[ "${bundle_base}" =~ ^(.+)-[0-9]{8}T[0-9]{6}Z$ ]]; then
		if [ "${BASH_REMATCH[1]}" != "${manifest_version}" ]; then
			echo "release evidence bundle name version does not match manifest.txt: bundle=${BASH_REMATCH[1]} manifest=${manifest_version}" >&2
			exit 1
		fi
	fi
}

require_supply_chain_evidence() {
	require_file manifest.txt
	require_file hosted-ci/ci-run.txt
	require_file supply-chain/image-digest.txt
	require_file supply-chain/imagetools.txt
	require_file supply-chain/cosign-verify.txt
	require_file supply-chain/provenance-verify.txt
	require_file supply-chain/sbom-attestation-verify.txt
	require_file supply-chain/sbom.spdx.json
	require_file supply-chain/trivy.txt
	require_unique_evidence_field supply-chain/image-digest.txt image
	require_unique_evidence_field supply-chain/image-digest.txt image_ref
	require_unique_evidence_field supply-chain/image-digest.txt digest
	require_unique_evidence_field supply-chain/image-digest.txt commit
	require_unique_evidence_field supply-chain/image-digest.txt tag
	require_contains supply-chain/image-digest.txt '^image=ghcr\.io/guardianwaf/guardianwaf:'
	require_contains supply-chain/image-digest.txt '^image_ref='
	require_contains supply-chain/image-digest.txt '^digest=sha256:[0-9a-f]{64}$'
	require_contains supply-chain/image-digest.txt '^commit=[0-9a-f]{40}$'
	require_contains supply-chain/image-digest.txt '^tag='
	require_matching_commits
	require_matching_release_tag
	require_release_image_repository
	require_image_digest_matches_imagetools
	require_spdx_package_inventory
	require_release_oidc_identity supply-chain/cosign-verify.txt
	require_release_oidc_identity supply-chain/provenance-verify.txt
	require_release_oidc_identity supply-chain/sbom-attestation-verify.txt
	require_verification_image_ref supply-chain/cosign-verify.txt
	require_verification_image_ref supply-chain/provenance-verify.txt
	require_verification_image_ref supply-chain/sbom-attestation-verify.txt
	require_no_cosign_failure_marker supply-chain/cosign-verify.txt
	require_no_cosign_failure_marker supply-chain/provenance-verify.txt
	require_no_cosign_failure_marker supply-chain/sbom-attestation-verify.txt
	require_cosign_success_marker supply-chain/cosign-verify.txt
	require_cosign_success_marker supply-chain/provenance-verify.txt
	require_cosign_success_marker supply-chain/sbom-attestation-verify.txt
	require_contains supply-chain/provenance-verify.txt '(predicateType|slsa|SLSA|buildDefinition|Verified OK)'
	require_contains supply-chain/sbom-attestation-verify.txt '(predicateType|spdx|SPDX|packages|Verified OK)'
	require_contains supply-chain/trivy.txt '(HIGH|CRITICAL|Total:|Report Summary|Vulnerability)'
	require_trivy_clean
}

require_external_review_evidence() {
	require_file manifest.txt
	require_file hosted-ci/ci-run.txt
	require_hosted_ci_evidence
	if [ ! -s "${BUNDLE}/external-security-review/report.md" ] && [ ! -s "${BUNDLE}/external-security-review/risk-acceptance.md" ]; then
		echo "missing external security review report or risk acceptance" >&2
		exit 1
	fi
	if [ -s "${BUNDLE}/external-security-review/risk-acceptance.md" ]; then
		require_contains external-security-review/risk-acceptance.md '(accepted|approval|approver|risk)'
		reject_placeholder external-security-review/risk-acceptance.md
		require_external_review_matches_release external-security-review/risk-acceptance.md
		require_risk_acceptance_tracking external-security-review/risk-acceptance.md
	fi
	if [ -s "${BUNDLE}/external-security-review/report.md" ]; then
		require_contains external-security-review/report.md '(finding|review|scope|severity|summary)'
		reject_placeholder external-security-review/report.md
		require_external_review_matches_release external-security-review/report.md
		require_external_review_signoff external-security-review/report.md
		require_no_open_high_critical_findings external-security-review/report.md
	fi
}

if [ "${CHECK_MODE}" = "target-load" ]; then
    require_file target-load/target_load_results.txt
    require_contains target-load/target_load_results.txt 'errors=0'
    require_contains target-load/target_load_results.txt 'latency_p99_ms='
    require_contains target-load/target_load_results.txt 'overhead_p99_ms='
    require_target_load_metadata
    require_target_load_runtime_context
    require_target_load_sample_size
    require_no_nonzero_errors target-load/target_load_results.txt
    require_load_budget target-load/target_load_results.txt "target load"
    echo "Target load evidence verified: ${BUNDLE}"
    exit 0
fi

if [ "${CHECK_MODE}" = "hosted-ci" ]; then
	require_hosted_ci_evidence
	echo "Hosted CI evidence verified: ${BUNDLE}"
	exit 0
fi

if [ "${CHECK_MODE}" = "release-checksums" ]; then
    require_file manifest.txt
    require_file release-artifacts/checksums.txt
    require_contains release-artifacts/checksums.txt '^[0-9a-f]{64}[[:space:]]+'
    require_checksums_match_release
    echo "Release checksum evidence verified: ${BUNDLE}"
    exit 0
fi

if [ "${CHECK_MODE}" = "supply-chain" ]; then
	require_supply_chain_evidence
	echo "Release supply-chain evidence verified: ${BUNDLE}"
	exit 0
fi

if [ "${CHECK_MODE}" = "external-review" ]; then
	require_external_review_evidence
	echo "External security review evidence verified: ${BUNDLE}"
	exit 0
fi

require_file README.md
require_file manifest.txt
require_bundle_name_matches_manifest
require_path git-status.txt
require_path git-diff-check.txt
require_file docs/release-checklist.md
require_file docs/detection-quality.md
require_file docs/threat-model.md
require_file docs/security-review-scope.md
require_file docs/performance-budget.md

for log in \
    logs/check-prereqs.log \
    logs/go-test.log \
    logs/go-vet.log \
    logs/http3-build-tag.log \
    logs/detection-quality.log \
    logs/validate-k8s.log \
    logs/validate-helm.log; do
    require_log_success "${log}"
done

if [ -d "${BUNDLE}/supply-chain" ]; then
    require_file supply-chain/sbom.spdx.json
    require_file supply-chain/trivy.txt
    if [ -f "${BUNDLE}/supply-chain/image-inspect.json" ]; then
        require_file supply-chain/image-inspect.json
    fi
    if [ -f "${BUNDLE}/supply-chain/image-digest.txt" ]; then
        require_file supply-chain/image-digest.txt
        require_file supply-chain/imagetools.txt
        require_file supply-chain/cosign-verify.txt
        require_file supply-chain/provenance-verify.txt
        require_file supply-chain/sbom-attestation-verify.txt
    fi
fi

PENDING_EXISTS=0
if find "${BUNDLE}/pending" -type f -name '*.txt' -print -quit 2>/dev/null | grep -q .; then
	PENDING_EXISTS=1
fi

if [ "${PENDING_EXISTS}" = "1" ] && [ "${ALLOW_PENDING}" != "1" ]; then
	echo "pending release evidence remains:" >&2
	find "${BUNDLE}/pending" -maxdepth 1 -type f -name '*.txt' -print >&2
	exit 1
fi

if [ "${PENDING_EXISTS}" != "1" ]; then
	require_clean_git_status
	require_clean_git_diff_check
	require_heavy_manifest
    for log in \
        logs/go-race.log \
        logs/build-dashboard.log \
        logs/release-build.log \
        logs/smoke.log \
        logs/release-rollback.log \
        logs/proxy-load.log \
        logs/focused-benchmark.log; do
        require_log_success "${log}"
    done
    require_file proxy_load_results.txt
    require_file benchmark_results.txt
    require_file hosted-ci/ci-run.txt
    require_file target-load/target_load_results.txt
    require_file release-artifacts/checksums.txt
    require_file supply-chain/image-digest.txt
    require_file supply-chain/imagetools.txt
    require_file supply-chain/cosign-verify.txt
    require_file supply-chain/provenance-verify.txt
    require_file supply-chain/sbom-attestation-verify.txt
    require_file supply-chain/sbom.spdx.json
    require_file supply-chain/trivy.txt
    require_hosted_ci_evidence
    require_contains proxy_load_results.txt 'overhead_p99_ms='
    require_no_nonzero_errors proxy_load_results.txt
    require_load_budget proxy_load_results.txt "local proxy load"
    require_contains benchmark_results.txt 'BenchmarkEngine_BenignRequest'
    require_focused_benchmarks
	require_release_rollback_evidence
    require_contains target-load/target_load_results.txt 'errors=0'
    require_contains target-load/target_load_results.txt 'latency_p99_ms='
    require_contains target-load/target_load_results.txt 'overhead_p99_ms='
    require_target_load_metadata
	require_target_load_runtime_context
	require_target_load_sample_size
	require_no_nonzero_errors target-load/target_load_results.txt
    require_load_budget target-load/target_load_results.txt "target load"
	require_contains release-artifacts/checksums.txt '^[0-9a-f]{64}[[:space:]]+'
	require_checksums_match_release
	require_supply_chain_evidence
	require_external_review_evidence
fi

echo "Release evidence bundle verified: ${BUNDLE}"
