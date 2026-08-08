#!/usr/bin/env bash
# Promote a verified GuardianWAF release transaction to GitHub Releases and GHCR.
# The GitHub release remains a private draft until immutable image tags are attached.
# Failures compensate by removing the draft, restoring prior mutable aliases, and
# deleting the SHA-scoped staged package version when cleanup can be proven safe.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFIER="${RELEASE_EVIDENCE_VERIFIER:-${SCRIPT_DIR}/verify-release-evidence.sh}"
ASSETS_DIR="${1:-}"
EVIDENCE_DIR="${2:-}"
REPOSITORY="$(printf '%s' "${GITHUB_REPOSITORY:-}" | tr '[:upper:]' '[:lower:]')"
OWNER="${GITHUB_REPOSITORY_OWNER:-}"
RELEASE_TAG="${GITHUB_REF_NAME:-}"
COMMIT="${GITHUB_SHA:-}"
GHCR_REPOSITORY="ghcr.io/${REPOSITORY}"
DRAFT_CREATED=0
IMAGE_PROMOTED=0
PACKAGE_ENDPOINT=""
STAGED_PACKAGE_VERSION_ID=""
declare -A PRIOR_ALIAS_DIGESTS=()

usage() {
  echo "usage: $0 <release-assets-dir> <release-evidence-dir>" >&2
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required" >&2
    exit 1
  fi
}

normalize_digest() {
  local digest="$1"
  digest="${digest#sha256:}"
  if ! [[ "${digest}" =~ ^[0-9a-f]{64}$ ]]; then
    return 1
  fi
  printf 'sha256:%s\n' "${digest}"
}

package_api_base() {
  local package_name="${REPOSITORY#*/}"
  local endpoint
  for endpoint in \
    "/orgs/${OWNER}/packages/container/${package_name}/versions" \
    "/users/${OWNER}/packages/container/${package_name}/versions"; do
    if gh api "${endpoint}?per_page=1" >/dev/null 2>&1; then
      printf '%s\n' "${endpoint}"
      return 0
    fi
  done
  return 1
}

# Print a single "version-id|digest" record for a GHCR tag.
# Return 1 when the tag is absent and 2 when the registry query fails.
find_package_record_by_tag() {
  local endpoint="$1"
  local tag="$2"
  local page=1
  local response
  local match
  while true; do
    if ! response="$(gh api "${endpoint}?per_page=100&page=${page}")"; then
      echo "failed to query GHCR package versions for tag ${tag}" >&2
      return 2
    fi
    match="$(jq -r --arg tag "${tag}" '
      .[]
      | select((.metadata.container.tags // []) | index($tag))
      | "\(.id)|\(.name)"
    ' <<<"${response}" | head -n 1)"
    if [ -n "${match}" ] && [ "${match}" != "null" ]; then
      printf '%s\n' "${match}"
      return 0
    fi
    if [ "$(jq 'length' <<<"${response}")" -lt 100 ]; then
      break
    fi
    page=$((page + 1))
  done
  return 1
}

rollback() {
  local status="$1"
  local alias
  local restoration_failed=0

  if [ "${status}" -eq 0 ]; then
    return
  fi

  echo "release promotion failed; rolling back unpublished artifacts" >&2
  if [ "${DRAFT_CREATED}" -eq 1 ]; then
    # Preflight rejects existing releases, so any release now present belongs to
    # this transaction. Delete it even after an ambiguous client-side API error.
    if ! gh release delete "${RELEASE_TAG}" --yes >/dev/null 2>&1; then
      echo "warning: could not confirm removal of GitHub release ${RELEASE_TAG}; verify manually" >&2
    fi
  fi

  if [ "${IMAGE_PROMOTED}" -eq 1 ]; then
    for alias in "${!PRIOR_ALIAS_DIGESTS[@]}"; do
      if ! docker buildx imagetools create \
        --tag "${alias}" \
        "${GHCR_REPOSITORY}@${PRIOR_ALIAS_DIGESTS[${alias}]}"; then
        echo "error: failed to restore ${alias} to ${PRIOR_ALIAS_DIGESTS[${alias}]}" >&2
        restoration_failed=1
      fi
    done

    if [ "${restoration_failed}" -eq 0 ] && [ -n "${PACKAGE_ENDPOINT}" ] && [ -n "${STAGED_PACKAGE_VERSION_ID}" ]; then
      if cosign clean --force --type all "${GHCR_REPOSITORY}@${expected_digest}"; then
        gh api --method DELETE "${PACKAGE_ENDPOINT}/${STAGED_PACKAGE_VERSION_ID}" || {
          echo "error: failed to remove staged GHCR package version ${STAGED_PACKAGE_VERSION_ID}" >&2
          echo "manual cleanup required for ${GHCR_REPOSITORY}:candidate-${COMMIT}" >&2
        }
      else
        echo "error: failed to remove staged OCI signatures and attestations" >&2
        echo "manual cleanup required for ${GHCR_REPOSITORY}@${EXPECTED_DIGEST}" >&2
      fi
    else
      echo "manual GHCR cleanup required; automatic deletion was not proven safe" >&2
    fi
  fi
}

trap 'status=$?; rollback "${status}"; exit "${status}"' EXIT

if [ -z "${ASSETS_DIR}" ] || [ -z "${EVIDENCE_DIR}" ]; then
  usage
  exit 1
fi
for value in "${REPOSITORY}" "${OWNER}" "${RELEASE_TAG}" "${COMMIT}" "${GH_TOKEN:-}"; do
  if [ -z "${value}" ]; then
    echo "GITHUB_REPOSITORY, GITHUB_REPOSITORY_OWNER, GITHUB_REF_NAME, GITHUB_SHA, and GH_TOKEN are required" >&2
    exit 1
  fi
done
if [ "${REPOSITORY}" != "guardianwaf/guardianwaf" ]; then
  echo "refusing to promote unexpected repository: ${REPOSITORY}" >&2
  exit 1
fi
if ! [[ "${RELEASE_TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "refusing invalid release tag: ${RELEASE_TAG}" >&2
  exit 1
fi
if ! [[ "${COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "refusing invalid release commit: ${COMMIT}" >&2
  exit 1
fi
if [ ! -d "${ASSETS_DIR}" ] || [ ! -d "${EVIDENCE_DIR}" ]; then
  echo "release assets and evidence directories must exist" >&2
  exit 1
fi
if [ ! -x "${VERIFIER}" ]; then
  echo "release evidence verifier is not executable: ${VERIFIER}" >&2
  exit 1
fi

require_command cosign
require_command docker
require_command gh
require_command jq
require_command sha256sum

manifest_version="$(sed -n 's/^version=//p' "${EVIDENCE_DIR}/manifest.txt")"
manifest_commit="$(sed -n 's/^git_commit=//p' "${EVIDENCE_DIR}/manifest.txt")"
image_ref="$(sed -n 's/^image_ref=//p' "${EVIDENCE_DIR}/supply-chain/image-ref.txt")"
if [ "${manifest_version}" != "${RELEASE_TAG}" ]; then
  echo "release manifest version mismatch: ${manifest_version} != ${RELEASE_TAG}" >&2
  exit 1
fi
if [ "${manifest_commit}" != "${COMMIT}" ]; then
  echo "release manifest commit mismatch: ${manifest_commit} != ${COMMIT}" >&2
  exit 1
fi
if ! [[ "${image_ref}" =~ ^ghcr\.io/guardianwaf/guardianwaf@sha256:[0-9a-f]{64}$ ]]; then
  echo "invalid verified image reference: ${image_ref}" >&2
  exit 1
fi
expected_digest="${image_ref#*@}"

# Re-verify after artifact download and immediately before any public mutation.
"${VERIFIER}" --check-release-checksums "${EVIDENCE_DIR}"
"${VERIFIER}" --check-supply-chain "${EVIDENCE_DIR}"
(
  cd "${ASSETS_DIR}"
  sha256sum -c checksums.txt
)

PACKAGE_ENDPOINT="$(package_api_base)" || {
  echo "could not query the GuardianWAF GHCR package" >&2
  exit 1
}
if staged_record="$(find_package_record_by_tag "${PACKAGE_ENDPOINT}" "candidate-${COMMIT}")"; then
  STAGED_PACKAGE_VERSION_ID="${staged_record%%|*}"
  staged_digest="$(normalize_digest "${staged_record#*|}")" || {
    echo "invalid staged package digest: ${staged_record#*|}" >&2
    exit 1
  }
else
  lookup_status=$?
  echo "could not locate the SHA-scoped staged image (lookup status ${lookup_status})" >&2
  exit 1
fi
if [ "${staged_digest}" != "${expected_digest}" ]; then
  echo "staged package digest mismatch: ${staged_digest} != ${expected_digest}" >&2
  exit 1
fi

version_without_v="${RELEASE_TAG#v}"
immutable_tags=(
  "${GHCR_REPOSITORY}:${RELEASE_TAG}"
  "${GHCR_REPOSITORY}:${version_without_v}"
)
mutable_aliases=()
if [[ "${version_without_v}" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  mutable_aliases=(
    "${GHCR_REPOSITORY}:${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
    "${GHCR_REPOSITORY}:${BASH_REMATCH[1]}"
    "${GHCR_REPOSITORY}:latest"
  )
fi
release_tags=("${immutable_tags[@]}" "${mutable_aliases[@]}")

for tag in "${immutable_tags[@]}"; do
  if find_package_record_by_tag "${PACKAGE_ENDPOINT}" "${tag#*:}" >/dev/null; then
    echo "refusing to overwrite existing immutable release image tag: ${tag}" >&2
    exit 1
  else
    lookup_status=$?
    if [ "${lookup_status}" -ne 1 ]; then
      echo "could not prove immutable image tag is absent: ${tag}" >&2
      exit 1
    fi
  fi
done
for alias in "${mutable_aliases[@]}"; do
  if prior_record="$(find_package_record_by_tag "${PACKAGE_ENDPOINT}" "${alias#*:}")"; then
    prior_digest="$(normalize_digest "${prior_record#*|}")" || {
      echo "invalid existing digest for ${alias}: ${prior_record#*|}" >&2
      exit 1
    }
    PRIOR_ALIAS_DIGESTS["${alias}"]="${prior_digest}"
  else
    lookup_status=$?
    if [ "${lookup_status}" -ne 1 ]; then
      echo "could not determine prior digest for mutable alias: ${alias}" >&2
      exit 1
    fi
  fi
done

release_probe=""
if release_probe="$(gh api --include "/repos/${REPOSITORY}/releases/tags/${RELEASE_TAG}" 2>&1)"; then
  echo "refusing to overwrite existing GitHub release: ${RELEASE_TAG}" >&2
  exit 1
fi
if ! grep -qE 'HTTP([/ ][^[:space:]]+)?[[:space:]]+404' <<<"${release_probe}"; then
  echo "could not prove GitHub release tag is absent" >&2
  printf '%s\n' "${release_probe}" >&2
  exit 1
fi

evidence_archive="${ASSETS_DIR}/release-evidence-${RELEASE_TAG}.tgz"
tar -C "${EVIDENCE_DIR}" -czf "${evidence_archive}" .
cp "${EVIDENCE_DIR}/supply-chain/sbom.spdx.json" "${ASSETS_DIR}/sbom.spdx.json"

# Generate release notes from git log, matching goreleaser's changelog filters
# (exclude docs/test/ci/chore commits). --generate-notes would produce only a
# bare compare link, discarding the feat/fix/refactor history.
generate_changelog() {
  local prev_tag
  prev_tag="$(git describe --tags --abbrev=0 "${RELEASE_TAG}^" 2>/dev/null || true)"
  local range="${prev_tag:+${prev_tag}..}${RELEASE_TAG}"

  git log ${range} --format='%s' 2>/dev/null \
    | grep -vE '^(docs|test|ci|chore|merge):' \
    | sort \
    | awk '
      /^feat/     { feat[++f]  = "- " $0 }
      /^fix/      { fix[++x]   = "- " $0 }
      /^refactor/ { ref[++r]   = "- " $0 }
      END {
        if (f) { print "### Features";     for (i=1;i<=f;i++) print feat[i]; print "" }
        if (x) { print "### Fixes";        for (i=1;i<=x;i++) print fix[i];  print "" }
        if (r) { print "### Refactoring";  for (i=1;i<=r;i++) print ref[i];  print "" }
      }
    '
}

CHANGELOG_FILE="$(mktemp)"
generate_changelog > "${CHANGELOG_FILE}"
if [ ! -s "${CHANGELOG_FILE}" ]; then
  echo "warning: changelog is empty, falling back to GitHub auto-generated notes" >&2
  rm -f "${CHANGELOG_FILE}"
  CHANGELOG_FILE=""
fi

# Set rollback state before the API call because the server can create the draft
# even when the client later observes a transport failure.
DRAFT_CREATED=1
if [ -n "${CHANGELOG_FILE}" ]; then
  gh release create "${RELEASE_TAG}" \
    "${ASSETS_DIR}"/* \
    --verify-tag \
    --draft \
    --notes-file "${CHANGELOG_FILE}" \
    --title "GuardianWAF ${RELEASE_TAG}"
else
  gh release create "${RELEASE_TAG}" \
    "${ASSETS_DIR}"/* \
    --verify-tag \
    --draft \
    --generate-notes \
    --title "GuardianWAF ${RELEASE_TAG}"
fi

promotion_args=()
for tag in "${release_tags[@]}"; do
  promotion_args+=(--tag "${tag}")
done
# Set rollback state before the registry call because it can create only a prefix
# of the requested tags before returning an error.
IMAGE_PROMOTED=1
docker buildx imagetools create "${promotion_args[@]}" "${image_ref}"

for tag in "${release_tags[@]}"; do
  docker buildx imagetools inspect "${tag}" | grep -F "${expected_digest}" >/dev/null
done

gh release edit "${RELEASE_TAG}" --draft=false
DRAFT_CREATED=0
IMAGE_PROMOTED=0
trap - EXIT

echo "Published verified release ${RELEASE_TAG} at ${manifest_commit}"
