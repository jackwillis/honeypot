#!/bin/bash
set -e

##############################################################################
# Honeypot Update Script
#
# Quick update script for deploying code changes.
# Much faster than running the full deploy.sh
#
# Usage:
#   sudo ./update.sh
##############################################################################

APP_DIR="/opt/honeypot"
HONEYPOT_USER="honeypot"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root (use sudo)"
    exit 1
fi

cd "$APP_DIR"

log_info "Updating honeypot application..."

##############################################################################
# 1. Pull Latest Code
##############################################################################

log_info "Pulling latest code from git..."

if [ -d .git ]; then
    # Add safe directory exception for git
    git config --global --add safe.directory "$APP_DIR" 2>/dev/null || true

    # Stash any local changes (like .env)
    git stash push -m "Auto-stash before update" -- ':!.env' > /dev/null 2>&1 || true

    # Pull latest
    git pull

    # Pop stash if there were changes
    git stash pop > /dev/null 2>&1 || true
else
    log_error "Not a git repository. Cannot pull updates."
    exit 1
fi

##############################################################################
# 2. Update Dependencies
##############################################################################

log_info "Updating Ruby gems..."

# Update gems directly (simpler for system Ruby)
gem install sinatra -v '~> 4.0' --conservative > /dev/null 2>&1 || true
gem install puma -v '~> 6.0' --conservative > /dev/null 2>&1 || true
gem install rackup -v '~> 2.0' --conservative > /dev/null 2>&1 || true
gem install json -v '~> 2.7' --conservative > /dev/null 2>&1 || true

log_info "Ruby gems updated"

# Fix ownership in case git pull was run as different user
chown -R "$HONEYPOT_USER:$HONEYPOT_USER" "$APP_DIR"

##############################################################################
# 3. Restart Services
##############################################################################

log_info "Restarting services..."

# Restart honeypot
systemctl restart honeypot.service
sleep 1

if systemctl is-active --quiet honeypot.service; then
    log_info "honeypot.service restarted successfully"
else
    log_error "honeypot.service failed to start!"
    systemctl status honeypot.service --no-pager
    exit 1
fi

# Restart web UI
systemctl restart honeypot-web.service
sleep 1

if systemctl is-active --quiet honeypot-web.service; then
    log_info "honeypot-web.service restarted successfully"
else
    log_error "honeypot-web.service failed to start!"
    systemctl status honeypot-web.service --no-pager
    exit 1
fi

##############################################################################
# Done
##############################################################################

echo ""
echo "=========================================================================="
log_info "Update complete!"
echo "=========================================================================="
echo ""
echo "Services Status:"
systemctl status honeypot.service --no-pager -l | head -5
echo ""
systemctl status honeypot-web.service --no-pager -l | head -5
echo ""
echo "Logs:"
echo "  journalctl -u honeypot.service -f"
echo "  journalctl -u honeypot-web.service -f"
echo ""
