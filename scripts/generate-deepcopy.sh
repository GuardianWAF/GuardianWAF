#!/usr/bin/env bash
# Replace generated source only after both generation and formatting succeed.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
work_dir="$(mktemp -d)"
output="$(mktemp internal/config/.deepcopy.XXXXXX)"
trap 'rm -rf "$work_dir"; rm -f "$output"' EXIT

go build -o "${work_dir}/deepcopy-generator" ./tools/deepcopy/main.go
sources=(internal/config/config.go)
# These files declare the additional types covered by the existing copy API.
for source in internal/config/config_crs.go internal/config/validate.go internal/config/yaml.go; do
    if [ -f "${source}" ]; then
        sources+=("${source}")
    fi
done
"${work_dir}/deepcopy-generator" -complete "${sources[@]}" > "${output}"
gofmt -w "${output}"
chmod 644 "${output}"
mv "${output}" internal/config/deepcopy_generated.go
