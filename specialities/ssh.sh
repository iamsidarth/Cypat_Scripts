#!/bin/bash
###############################################################################
#  CyberPatriot — SSH Hardening (Standalone)
#  Run: sudo ./ssh.sh [--password-auth] [--port <num>]
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BACKUP_DIR="/tmp/cypat-ssh-backup-$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/cypat-ssh-$(date +%Y%m%d-%H%M%S).log"
PASSWORD_AUTH="no"
SSH_PORT=""

info()  { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG"; }
pass()  { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$LOG"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG"; }
step()  { echo -e "\n${BOLD}${CYAN}═══ $1 ═══${NC}" | tee -a "$LOG"; }

backup_file() {
    local f=$1
    if [[ -f "$f" ]]; then
        mkdir -p "$(dirname "$BACKUP_DIR/$f")"
        cp -a "$f" "$BACKUP_DIR/$f"
        info "Backed up: $f"
    fi
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: Run as root (sudo).${NC}"; exit 1
    fi
}

main() {
    for arg in "$@"; do
        case "$arg" in
            --password-auth) PASSWORD_AUTH="yes" ;;
            --port=*) SSH_PORT="${arg#*=}" ;;
            --help|-h)
                echo "Usage: sudo ./ssh.sh [--password-auth] [--port=<num>]"
                echo "  --password-auth   Keep password authentication (default: disable)"
                echo "  --port=<num>      Change SSH port"
                exit 0
                ;;
        esac
    done

    echo -e "${BOLD}${BLUE}╔══ SSH Hardening ══╗${NC}"
    require_root
    mkdir -p "$BACKUP_DIR"

    if ! dpkg -l openssh-server &>/dev/null; then
        warn "openssh-server not installed. Nothing to harden."
        exit 0
    fi

    step "Backing up configuration"
    backup_file /etc/ssh/sshd_config
    local sshd="/etc/ssh/sshd_config"

    step "Applying SSH hardening"

    declare -A settings=(
        ["PermitRootLogin"]="no"
        ["PermitEmptyPasswords"]="no"
        ["X11Forwarding"]="no"
        ["MaxAuthTries"]="3"
        ["ClientAliveInterval"]="300"
        ["ClientAliveCountMax"]="2"
        ["AllowTcpForwarding"]="no"
        ["Protocol"]="2"
        ["UsePAM"]="yes"
        ["PrintMotd"]="no"
        ["PrintLastLog"]="yes"
        ["LoginGraceTime"]="60"
        ["MaxStartups"]="10:30:60"
        ["MaxSessions"]="10"
        ["StrictModes"]="yes"
        ["HostbasedAuthentication"]="no"
        ["IgnoreRhosts"]="yes"
        ["LogLevel"]="VERBOSE"
        ["PasswordAuthentication"]="$PASSWORD_AUTH"
    )

    for key in "${!settings[@]}"; do
        local val="${settings[$key]}"
        if grep -q "^${key}\s" "$sshd"; then
            sed -i "s/^${key}\s\+.*/${key} ${val}/" "$sshd"
        elif grep -q "^#${key}\s" "$sshd"; then
            sed -i "s/^#${key}\s\+.*/${key} ${val}/" "$sshd"
        else
            echo "${key} ${val}" >> "$sshd"
        fi
        info "  ${key} = ${val}"
    done

    # Port
    if [[ -n "$SSH_PORT" ]]; then
        sed -i "s/^#\?Port\s\+.*/Port ${SSH_PORT}/" "$sshd"
        info "  Port = ${SSH_PORT}"
    fi

    # Banner
    if grep -q "^#Banner" "$sshd"; then
        sed -i 's/^#Banner.*/Banner \/etc\/issue.net/' "$sshd"
    elif ! grep -q "^Banner" "$sshd"; then
        echo "Banner /etc/issue.net" >> "$sshd"
    fi

    # Secure ciphers
    if ! grep -q "^Ciphers" "$sshd"; then
        echo "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> "$sshd"
    fi
    if ! grep -q "^MACs" "$sshd"; then
        echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> "$sshd"
    fi
    if ! grep -q "^KexAlgorithms" "$sshd"; then
        echo "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" >> "$sshd"
    fi

    step "Securing host keys"
    chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
    chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true

    step "Authorized keys audit"
    info "Scanning home directories for authorized_keys..."
    find /home -name "authorized_keys" -type f 2>/dev/null | while read -r ak; do
        info "  Found: $ak"
        cat "$ak" 2>/dev/null | tee -a "$LOG"
    done

    step "Restarting SSH"
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    pass "SSH service restarted"

    echo ""
    echo -e "${BOLD}${GREEN}═══ SSH Hardening Complete ═══${NC}"
    echo -e "Backups: ${BACKUP_DIR}"
    echo -e "Log:     ${LOG}"
    warn "⚠  VERIFY SSH ACCESS BEFORE CLOSING THIS SESSION"
    if [[ "$PASSWORD_AUTH" == "no" ]]; then
        warn "⚠  Password authentication is DISABLED — key-based auth only"
    fi
}

main "$@"
