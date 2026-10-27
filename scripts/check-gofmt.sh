#!/usr/bin/env bash
# Check repository Go sources, including new files, without traversing ignored
# audit artifacts, dependency trees, or build output.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
unformatted="$(
    git ls-files --cached --others --exclude-standard -z -- '*.go' |
        while IFS= read -r -d '' source; do
            if [ -f "${source}" ]; then
                printf '%s\0' "${source}"
            fi
        done |
        xargs -0 -r gofmt -s -l
)"
if [ -n "${unformatted}" ]; then
    echo '::error::gofmt check failed — format the following Go sources:' >&2
    printf '%s\n' "${unformatted}" >&2
    exit 1
fi
echo 'gofmt check passed.'
