#!/usr/bin/env bash
# Validate local build prerequisites for the production build path.
set -euo pipefail

MIN_GO="1.26.5"
MIN_NODE="20.19.0"
MIN_NPM_MAJOR=10

version_ge() {
    local got="$1"
    local min="$2"
    local IFS=.
    local -a g=($got)
    local -a m=($min)

    for i in 0 1 2; do
        local gv="${g[$i]:-0}"
        local mv="${m[$i]:-0}"
        if ((10#$gv > 10#$mv)); then
            return 0
        fi
        if ((10#$gv < 10#$mv)); then
            return 1
        fi
    done
    return 0
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "$cmd is required for the production build path" >&2
        exit 1
    fi
}

require_cmd go
require_cmd npm
require_cmd node
require_cmd git

go_version="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
if [ -z "$go_version" ]; then
    go_version="$(go version | awk '{print $3}' | sed 's/^go//')"
fi
if ! version_ge "$go_version" "$MIN_GO"; then
    echo "Go $MIN_GO or newer is required; found $go_version" >&2
    exit 1
fi

node_version="$(node --version | sed 's/^v//')"
if ! version_ge "$node_version" "$MIN_NODE"; then
    echo "Node.js $MIN_NODE or newer is required for the dashboard build; found $node_version" >&2
    exit 1
fi

npm_version="$(npm --version)"
npm_major="${npm_version%%.*}"
if ((10#$npm_major < MIN_NPM_MAJOR)); then
    echo "npm ${MIN_NPM_MAJOR}.x or newer is required; found $npm_version" >&2
    exit 1
fi

echo "Prerequisites OK: Go $go_version, Node.js $node_version, npm $npm_version"
