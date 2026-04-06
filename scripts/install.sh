#!/bin/bash
# GuardianWAF Installation Script
# Usage: curl -sSL https://raw.githubusercontent.com/guardianwaf/guardianwaf/main/scripts/install.sh | bash

set -e

REPO="guardianwaf/guardianwaf"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/guardianwaf"
DATA_DIR="/var/lib/guardianwaf"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            echo "debian"
        elif command -v apk &> /dev/null; then
            echo "alpine"
        elif command -v yum &> /dev/null; then
            echo "rhel"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "darwin"
    else
        echo "unknown"
    fi
}

# Detect architecture
detect_arch() {
    local arch=$(uname -m)
    case $arch in
        x86_64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l) echo "armv7" ;;
        *)
            log_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

# Detect latest version
get_latest_version() {
    local version=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
    echo "${version:-1.1.0}"
}

# Download and install binary
install_binary() {
    local version=$1
    local os=$2
    local arch=$3

    local ext=""
    if [[ "$os" == "windows" ]]; then
        ext=".zip"
    else
        ext=".tar.gz"
    fi

    local filename="guardianwaf_${version}_${os}_${arch}${ext}"
    local download_url="https://github.com/${REPO}/releases/download/v${version}/${filename}"

    log_info "Downloading GuardianWAF v${version} for ${os}/${arch}..."
    curl -fSL "$download_url" -o "/tmp/${filename}"

    log_info "Installing to ${INSTALL_DIR}..."
    mkdir -p "$INSTALL_DIR"

    if [[ "$ext" == ".zip" ]]; then
        unzip -o "/tmp/${filename}" -d "$INSTALL_DIR"
    else
        tar -xzf "/tmp/${filename}" -C "$INSTALL_DIR"
    fi

    chmod +x "${INSTALL_DIR}/guardianwaf"
    rm -f "/tmp/${filename}"

    log_info "GuardianWAF v${version} installed successfully!"
}

# Create default config
create_config() {
    log_info "Creating default configuration..."
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"

    if [[ ! -f "${CONFIG_DIR}/guardianwaf.yaml" ]]; then
        cat > "${CONFIG_DIR}/guardianwaf.yaml" << 'EOF'
# GuardianWAF Configuration
version: "1.0"

server:
  listen: ":8088"
  mode: enforce

tls:
  enabled: false
  listen: ":8443"

upstreams:
  - name: default
    targets:
      - url: "http://localhost:3000"

routes:
  - host: "*"
    upstream: default

logging:
  level: info
  format: json

waf:
  detection:
    enabled: true
  bot_detection:
    enabled: true
EOF
        log_info "Default config created at ${CONFIG_DIR}/guardianwaf.yaml"
    else
        log_warn "Config already exists at ${CONFIG_DIR}/guardianwaf.yaml"
    fi
}

# Install Docker image
install_docker() {
    log_info "Installing GuardianWAF via Docker..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    docker pull "ghcr.io/${REPO}:latest"

    log_info "GuardianWAF Docker image installed!"
    log_info "Run with: docker run -d -p 8088:8088 -p 9443:9443 ghcr.io/${REPO}:latest"
}

# Main installation
main() {
    echo "=========================================="
    echo "  GuardianWAF Installation Script"
    echo "=========================================="
    echo

    local install_type=${1:-"binary"}
    local version=${2:-$(get_latest_version)}
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(detect_arch)

    # Convert OS names
    case $os in
        darwin) os="darwin" ;;
        linux) os="linux" ;;
        *) os="linux" ;;
    esac

    # Windows detection
    if [[ "$OSTYPE" == "cygwin" || "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        os="windows"
    fi

    case $install_type in
        docker)
            install_docker
            ;;
        binary|--binary)
            install_binary "$version" "$os" "$arch"
            create_config
            ;;
        *)
            # Default: try binary first, fallback to docker
            if command -v curl &> /dev/null; then
                install_binary "$version" "$os" "$arch"
                create_config
            else
                log_error "curl is required for binary installation"
                log_info "Try Docker installation: $0 docker"
                exit 1
            fi
            ;;
    esac

    echo
    echo "=========================================="
    echo "  Installation Complete!"
    echo "=========================================="
    echo
    echo "Quick start:"
    echo "  Binary:  guardianwaf serve -c ${CONFIG_DIR}/guardianwaf.yaml"
    echo "  Docker:  docker run -d -p 8088:8088 -p 9443:9443 ghcr.io/${REPO}:latest"
    echo
    echo "Documentation: https://github.com/${REPO}#readme"
    echo
}

main "$@"
