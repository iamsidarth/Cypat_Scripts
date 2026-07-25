#!/bin/bash
###############################################################################
#  CyberPatriot — UFW Firewall Setup (Standalone)
#  Run: sudo ./ufw.sh [--allow-http] [--allow-https] [--allow <port>]
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

LOG="/var/log/cypat-ufw-$(date +%Y%m%d-%H%M%S).log"
info()  { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG"; }
pass()  { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$LOG"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG"; }
step()  { echo -e "\n${BOLD}${CYAN}═══ $1 ═══${NC}" | tee -a "$LOG"; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: Run as root (sudo).${NC}"; exit 1
    fi
}

main() {
    local allow_http=false
    local allow_https=false
    local extra_ports=()

    for arg in "$@"; do
        case "$arg" in
            --allow-http) allow_http=true ;;
            --allow-https) allow_https=true ;;
            --allow=*) extra_ports+=("${arg#*=}") ;;
            --help|-h)
                echo "Usage: sudo ./ufw.sh [--allow-http] [--allow-https] [--allow=<port/proto>]"
                echo "  --allow-http     Allow port 80/tcp"
                echo "  --allow-https    Allow port 443/tcp"
                echo "  --allow=8080/tcp Allow a custom port"
                exit 0
                ;;
        esac
    done

    echo -e "${BOLD}${BLUE}╔══ UFW Firewall Setup ══╗${NC}"
    require_root

    step "Installing UFW"
    apt-get update -qq 2>&1 | tee -a "$LOG"
    apt-get install -y ufw -qq 2>&1 | tee -a "$LOG"
    pass "UFW installed"

    step "Default policies"
    ufw --force reset 2>/dev/null || true
    ufw default deny incoming
    ufw default allow outgoing
    pass "Default: deny incoming, allow outgoing"

    step "Allowing essential services"
    ufw allow ssh 2>/dev/null || ufw allow 22/tcp
    info "  SSH (22/tcp) allowed"

    if $allow_http; then
        ufw allow 80/tcp
        info "  HTTP (80/tcp) allowed"
    fi

    if $allow_https; then
        ufw allow 443/tcp
        info "  HTTPS (443/tcp) allowed"
    fi

    for port in "${extra_ports[@]}"; do
        ufw allow "$port"
        info "  $port allowed"
    done

    # DNS (often needed)
    ufw allow 53/udp 2>/dev/null || true

    step "Advanced rules"
    # Rate limit SSH
    ufw limit ssh 2>/dev/null || ufw limit 22/tcp
    info "  SSH rate-limited"

    # Logging
    ufw logging on 2>/dev/null || true
    info "  Logging enabled"

    step "Enabling firewall"
    echo "y" | ufw enable 2>&1 | tee -a "$LOG"
    pass "UFW enabled"

    step "Status"
    ufw status verbose | tee -a "$LOG"

    echo ""
    echo -e "${BOLD}${GREEN}═══ UFW Setup Complete ═══${NC}"
    echo -e "Log: ${LOG}"
}

main "$@"
