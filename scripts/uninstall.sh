#!/bin/bash
# GuardianWAF Uninstall Script
# Usage: sudo bash uninstall.sh [--purge]
#
# This script completely removes GuardianWAF from the system.
# Use --purge to also remove all data and logs.

set -e

# Directories and files to remove
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/guardianwaf"
DATA_DIR="/var/lib/guardianwaf"
LOG_DIR="/var/log/guardianwaf"
SERVICE_DIR="/etc/systemd/system"
CRON_FILE="/etc/cron.d/guardianwaf"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Parse arguments
PURGE=false
if [[ "$1" == "--purge" ]] || [[ "$1" == "-p" ]]; then
    PURGE=true
fi

echo "=========================================="
echo "  GuardianWAF Uninstall Script"
echo "=========================================="
echo

check_root

# Stop and disable service
log_step "Stopping GuardianWAF service..."
if systemctl is-active --quiet guardianwaf 2>/dev/null; then
    systemctl stop guardianwaf
    log_info "Stopped guardianwaf service"
fi

if systemctl is-enabled --quiet guardianwaf 2>/dev/null; then
    systemctl disable guardianwaf
    log_info "Disabled guardianwaf service"
fi

# Remove systemd service file
log_step "Removing systemd service..."
rm -f "${SERVICE_DIR}/guardianwaf.service"
systemctl daemon-reload
log_info "Removed systemd service"

# Remove cron job
log_step "Removing cron jobs..."
rm -f "$CRON_FILE"
log_info "Removed cron jobs"

# Remove binary
log_step "Removing binary..."
rm -f "${INSTALL_DIR}/guardianwaf"
if command -v guardianwaf &> /dev/null; then
    rm -f "$(command -v guardianwaf)"
fi
log_info "Removed binary"

# Remove config (ask for confirmation unless purge)
if [[ -d "$CONFIG_DIR" ]]; then
    if [[ "$PURGE" == true ]]; then
        log_step "Removing configuration..."
        rm -rf "$CONFIG_DIR"
        log_info "Removed ${CONFIG_DIR}"
    else
        log_warn "Keeping configuration at ${CONFIG_DIR}"
        log_warn "Use --purge to remove it"
    fi
fi

# Remove data (only with purge)
if [[ "$PURGE" == true ]]; then
    log_step "Removing data directory..."
    rm -rf "$DATA_DIR"
    log_info "Removed ${DATA_DIR}"

    log_step "Removing logs..."
    rm -rf "$LOG_DIR"
    log_info "Removed ${LOG_DIR}"

    log_step "Removing ACME certificates..."
    rm -rf /etc/letsencrypt/live/guardianwaf 2>/dev/null || true
    rm -rf /etc/letsencrypt/archive/guardianwaf 2>/dev/null || true
    log_info "Removed ACME certificates"
fi

# Remove acme directory if empty
rmdir /etc/letsencrypt/live 2>/dev/null || true
rmdir /etc/letsencrypt/archive 2>/dev/null || true

# Remove Docker container if exists
if command -v docker &> /dev/null; then
    log_step "Removing Docker container..."
    docker rm -f guardianwaf 2>/dev/null || true
    docker rmi -f ghcr.io/guardianwaf/guardianwaf:latest 2>/dev/null || true
    log_info "Removed Docker artifacts"
fi

# Final verification
echo
log_step "Verification..."
if command -v guardianwaf &> /dev/null; then
    log_error "Binary still exists at $(which guardianwaf)"
elif systemctl is-active --quiet guardianwaf 2>/dev/null; then
    log_error "Service still running!"
else
    log_info "GuardianWAF has been completely removed from this system"
fi

echo
if [[ "$PURGE" == true ]]; then
    echo "All data has been purged. To reinstall, run:"
    echo "  curl -sSL https://raw.githubusercontent.com/guardianwaf/guardianwaf/main/scripts/install.sh | bash"
else
    echo "GuardianWAF has been uninstalled but configuration preserved at ${CONFIG_DIR}"
    echo "To fully remove including config, run with --purge:"
    echo "  sudo bash uninstall.sh --purge"
fi
echo
