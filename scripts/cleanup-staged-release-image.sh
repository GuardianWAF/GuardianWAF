#!/usr/bin/env bash
# Remove an orphaned SHA-scoped staging image after a failed release transaction.
# Cleanup is intentionally conservative: it deletes only a package version whose
# complete tag set is exactly candidate-<commit-sha>.
set -euo pipefail

REPOSITORY="${GITHUB_REPOSITORY:-}"
OWNER="${GITHUB_REPOSITORY_OWNER:-}"
COMMIT="${GITHUB_SHA:-}"
CANDIDATE_TAG="candidate-${COMMIT}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required" >&2
    exit 1
  fi
}

if [ "${REPOSITORY}" != "guardianwaf/guardianwaf" ]; then
  echo "refusing to clean unexpected repository: ${REPOSITORY}" >&2
  exit 1
fi
if [ -z "${OWNER}" ] || ! [[ "${COMMIT}" =~ ^[0-9a-f]{40}$ ]] || [ -z "${GH_TOKEN:-}" ]; then
  echo "GITHUB_REPOSITORY_OWNER, GITHUB_SHA, and GH_TOKEN are required" >&2
  exit 1
fi
require_command cosign
require_command gh
require_command jq

package_name="${REPOSITORY#*/}"
endpoint=""
for candidate in \
  "/orgs/${OWNER}/packages/container/${package_name}/versions" \
  "/users/${OWNER}/packages/container/${package_name}/versions"; do
  if gh api "${candidate}?per_page=1" >/dev/null 2>&1; then
    endpoint="${candidate}"
    break
  fi
done
if [ -z "${endpoint}" ]; then
  echo "could not query the GuardianWAF GHCR package" >&2
  exit 1
fi

page=1
match=""
while true; do
  response="$(gh api "${endpoint}?per_page=100&page=${page}")"
  match="$(jq -c --arg tag "${CANDIDATE_TAG}" '
    .[]
    | select((.metadata.container.tags // []) | index($tag))
    | {id: .id, digest: .name, tags: (.metadata.container.tags // [])}
  ' <<<"${response}" | head -n 1)"
  if [ -n "${match}" ]; then
    break
  fi
  if [ "$(jq 'length' <<<"${response}")" -lt 100 ]; then
    echo "no orphaned staged image found for ${CANDIDATE_TAG}"
    exit 0
  fi
  page=$((page + 1))
done

if [ "$(jq '.tags | length' <<<"${match}")" -ne 1 ] || [ "$(jq -r '.tags[0]' <<<"${match}")" != "${CANDIDATE_TAG}" ]; then
  echo "refusing cleanup: package version also carries non-candidate tags" >&2
  printf '%s\n' "${match}" >&2
  exit 1
fi

version_id="$(jq -r '.id' <<<"${match}")"
digest="$(jq -r '.digest' <<<"${match}")"
digest="${digest#sha256:}"
if ! [[ "${digest}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "refusing cleanup: invalid candidate digest" >&2
  exit 1
fi
cosign clean --force --type all "ghcr.io/${REPOSITORY}@sha256:${digest}"
gh api --method DELETE "${endpoint}/${version_id}"
echo "Deleted orphaned staged image and OCI referrers for ${CANDIDATE_TAG}"
