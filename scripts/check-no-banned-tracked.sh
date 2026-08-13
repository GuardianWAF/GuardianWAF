#!/usr/bin/env bash
# check-no-banned-tracked.sh — block accidental commits of paths that must
# never be tracked in the repo root (coverage dumps, stray coverage output,
# ephemeral scanner reports, files accidentally parked inside an Eclipse
# .project/ directory).
#
# Designed to run as a `local` pre-commit hook. Operates only on the
# currently staged changes (--diff-filter=AM) so that already-tracked
# files cleaned up in earlier commits don't re-block every future commit.
#
# Exit 0: clean. Exit 1: at least one banned path is being added/modified.

set -euo pipefail

# Patterns are anchored to the repo root. Trailing slash matches the dir;
# without it we still match individual files by basename anywhere they
# appear at the root.
BANNED_PATTERNS=(
  '^coverage-current/'
  '^coverage-next/'
  '^coverage-pkgs/'
  '^\.coverage-current/'
  '^\.coverage-next/'
  '^\.coverage-pkgs/'
  '^tmpcov\.txt$'
  '^security-report/'
  '^\.project/'
)

# Only newly added (A) or modified (M) staged entries. We deliberately
# ignore deletions (D) — if someone is removing one of these from the
# index we should not block them.
mapfile -t staged < <(git diff --cached --name-only --diff-filter=AM || true)

if [ "${#staged[@]}" -eq 0 ]; then
  exit 0
fi

violations=()
for path in "${staged[@]}"; do
  for pattern in "${BANNED_PATTERNS[@]}"; do
    if [[ "$path" =~ $pattern ]]; then
      violations+=("$path")
      break
    fi
  done
done

if [ "${#violations[@]}" -ne 0 ]; then
  echo "ERROR: refusing to commit banned repo-root paths:" >&2
  for v in "${violations[@]}"; do
    echo "  - $v" >&2
  done
  cat >&2 <<'EOF'

These paths must never be tracked:
  - .coverage-current/, .coverage-next/, .coverage-pkgs/  (coverage dumps)
  - tmpcov.txt                                            (stray coverage)
  - security-report/                                      (ephemeral scans)
  - .project/                                             (Eclipse metadata)

If you really need to add one of these, run it past the repo maintainers
first and document why in the commit message. Otherwise remove from the
index (git rm --cached <path>) and stage a clean change.
EOF
  exit 1
fi

exit 0