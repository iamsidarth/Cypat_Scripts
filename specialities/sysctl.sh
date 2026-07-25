#!/bin/bash
###############################################################################
#  CyberPatriot — Kernel Hardening via sysctl (Standalone)
#  Run: sudo ./sysctl.sh
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BACKUP_DIR="/tmp/cypat-sysctl-backup-$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/cypat-sysctl-$(date +%Y%m%d-%H%M%S).log"
CONF="/etc/sysctl.d/99-cypat.conf"

info()  { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG"; }
pass()  { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$LOG"; }
step()  { echo -e "\n${BOLD}${CYAN}═══ $1 ═══${NC}" | tee -a "$LOG"; }

backup_file() {
    if [[ -f "$1" ]]; then
        mkdir -p "$(dirname "$BACKUP_DIR/$1")"
        cp -a "$1" "$BACKUP_DIR/$1"
        info "Backed up: $1"
    fi
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: Run as root (sudo).${NC}"; exit 1
    fi
}

main() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        echo "Usage: sudo ./sysctl.sh"
        echo "Applies kernel hardening via sysctl"
        exit 0
    fi

    echo -e "${BOLD}${BLUE}╔══ Kernel Hardening (sysctl) ══╗${NC}"
    require_root
    mkdir -p "$BACKUP_DIR"

    backup_file "$CONF"

    cat > "$CONF" <<'SYSCTL'
# CyberPatriot Kernel Hardening
# ==============================

# IPv4 Network Security
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1

# TCP Hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_rfc1337 = 1

# Disable IP forwarding (unless router)
net.ipv4.ip_forward = 0

# ICMP hardening
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Send redirects (prevents MITM via ICMP redirects)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# IPv6 hardening (disable if not needed)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Kernel hardening
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.pid_max = 65536
kernel.unprivileged_bpf_disabled = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 2
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.panic = 10
kernel.panic_on_oops = 1

# Filesystem protections
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 1
fs.protected_regular = 1

# Device security
dev.tty.ldisc_autoload = 0
SYSCTL

    step "Applying sysctl settings"
    sysctl --system 2>&1 | tee -a "$LOG"
    pass "Kernel hardening applied via ${CONF}"

    step "Verifying key settings"
    local checks=(
        "net.ipv4.tcp_syncookies"
        "net.ipv4.conf.all.accept_redirects"
        "net.ipv4.conf.all.accept_source_route"
        "kernel.randomize_va_space"
        "kernel.kptr_restrict"
        "kernel.dmesg_restrict"
        "fs.suid_dumpable"
    )
    for check in "${checks[@]}"; do
        local val; val=$(sysctl -n "$check" 2>/dev/null || echo "N/A")
        info "  ${check} = ${val}"
    done

    echo ""
    echo -e "${BOLD}${GREEN}═══ sysctl Hardening Complete ═══${NC}"
    echo -e "Backups: ${BACKUP_DIR}"
    echo -e "Log:     ${LOG}"
}

main "$@"
