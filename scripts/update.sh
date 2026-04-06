#!/bin/bash
# GuardianWAF Update Script
# Usage: curl -sSL https://raw.githubusercontent.com/guardianwaf/guardianwaf/main/scripts/update.sh | bash

set -e

REPO="guardianwaf/guardianwaf"
INSTALL_DIR="/usr/local/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Detect current version
get_current_version() {
    if command -v guardianwaf &> /dev/null; then
        guardianwaf version 2>/dev/null | head -1 || echo "unknown"
    else
        echo "not installed"
    fi
}

# Detect latest version
get_latest_version() {
    local version=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
    echo "${version:-1.1.0}"
}

# Detect architecture
detect_arch() {
    local arch=$(uname -m)
    case $arch in
        x86_64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l) echo "armv7" ;;
        *) echo "amd64" ;;
    esac
}

# Download and install binary
update_binary() {
    local version=$1
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(detect_arch)

    # Windows detection
    if [[ "$OSTYPE" == "cygwin" || "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        os="windows"
    fi

    local ext=""
    if [[ "$os" == "windows" ]]; then
        ext=".zip"
    else
        ext=".tar.gz"
    fi

    local filename="guardianwaf_${version}_${os}_${arch}${ext}"
    local download_url="https://github.com/${REPO}/releases/download/v${version}/${filename}"

    log_info "Stopping GuardianWAF service (if running)..."

    # Try to stop via systemd
    if command -v systemctl &> /dev/null; then
        systemctl stop guardianwaf 2>/dev/null || true
    fi

    # Try to stop via docker
    if command -v docker &> /dev/null; then
        docker stop guardianwaf 2>/dev/null || true
    fi

    log_info "Downloading GuardianWAF v${version} for ${os}/${arch}..."
    curl -fSL "$download_url" -o "/tmp/${filename}"

    log_info "Backing up current binary..."
    if [[ -f "${INSTALL_DIR}/guardianwaf" ]]; then
        cp "${INSTALL_DIR}/guardianwaf" "${INSTALL_DIR}/guardianwaf.backup-$(date +%Y%m%d)"
    fi

    log_info "Installing new version to ${INSTALL_DIR}..."
    mkdir -p "$INSTALL_DIR"

    if [[ "$ext" == ".zip" ]]; then
        unzip -o "/tmp/${filename}" -d "$INSTALL_DIR"
    else
        tar -xzf "/tmp/${filename}" -C "$INSTALL_DIR"
    fi

    chmod +x "${INSTALL_DIR}/guardianwaf"
    rm -f "/tmp/${filename}"

    log_info "GuardianWAF v${version} installed successfully!"

    # Restart service
    log_info "Restarting GuardianWAF service..."

    if command -v systemctl &> /dev/null && systemctl is-active --quiet guardianwaf 2>/dev/null; then
        systemctl start guardianwaf
    elif command -v docker &> /dev/null && docker ps -q --filter "name=guardianwaf" | grep -q .; then
        docker restart guardianwaf
    fi
}

# Update Docker image
update_docker() {
    log_info "Updating GuardianWAF Docker image..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed."
        exit 1
    fi

    docker pull "ghcr.io/${REPO}:latest"

    log_info "Restarting GuardianWAF container..."
    docker restart guardianwaf 2>/dev/null || log_warn "Container not running, start with: docker run -d --name guardianwaf -p 8088:8088 -p 9443:9443 ghcr.io/${REPO}:latest"
}

# Check for updates
check_updates() {
    local current=$1
    local latest=$2

    if [[ "$current" == "not installed" ]]; then
        log_info "GuardianWAF is not installed"
        return 0
    fi

    if [[ "$current" == "$latest" ]]; then
        log_info "You have the latest version: v${current}"
        return 1
    else
        log_info "Update available: v${current} -> v${latest}"
        return 0
    fi
}

# Main update
main() {
    echo "=========================================="
    echo "  GuardianWAF Update Script"
    echo "=========================================="
    echo

    local update_type=${1:-"binary"}
    local target_version=${2:-$(get_latest_version)}
    local current_version=$(get_current_version)
    local latest_version=$(get_latest_version)

    log_info "Current version: ${current_version}"
    log_info "Latest version:  ${latest_version}"
    echo

    # If no version specified, only update if newer available
    if [[ -z "$2" ]]; then
        if ! check_updates "$current_version" "$latest_version"; then
            echo "No update needed."
            exit 0
        fi
        target_version=$latest_version
    fi

    case $update_type in
        docker|--docker)
            update_docker
            ;;
        binary|--binary)
            update_binary "$target_version"
            ;;
        check|--check)
            log_info "Version ${current_version} is ${latest_version}"
            if [[ "$current_version" != "$latest_version" ]]; then
                exit 1
            fi
            ;;
        *)
            update_binary "$target_version"
            ;;
    esac

    echo
    echo "=========================================="
    echo "  Update Complete!"
    echo "=========================================="
    echo

    local new_version=$(get_current_version)
    log_info "Now running: v${new_version}"
    echo
}

main "$@"
