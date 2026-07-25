#!/bin/bash
###############################################################################
#  CyberPatriot — PAM & Password Policies (Standalone)
#  Run: sudo ./pam.sh
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BACKUP_DIR="/tmp/cypat-pam-backup-$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/cypat-pam-$(date +%Y%m%d-%H%M%S).log"

info()  { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG"; }
pass()  { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$LOG"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG"; }
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

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo "${ID,,}"
    else
        echo "ubuntu"
    fi
}

main() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        echo "Usage: sudo ./pam.sh"
        echo "Configures PAM password policies, lockout, and password aging"
        exit 0
    fi

    echo -e "${BOLD}${BLUE}╔══ PAM & Password Policies ══╗${NC}"
    require_root
    mkdir -p "$BACKUP_DIR"

    local distro; distro=$(detect_distro)
    info "Distro: $distro"

    # ── Password aging (login.defs) ──
    step "Password Aging (/etc/login.defs)"
    backup_file /etc/login.defs

    local aging=(
        "PASS_MAX_DAYS 90"
        "PASS_MIN_DAYS 7"
        "PASS_WARN_AGE 14"
        "LOGIN_RETRIES 5"
        "LOGIN_TIMEOUT 60"
    )
    for s in "${aging[@]}"; do
        local k="${s%% *}"
        local v="${s##* }"
        if grep -q "^${k}\s" /etc/login.defs; then
            sed -i "s/^${k}\s\+.*/${k}\t${v}/" /etc/login.defs
        else
            echo "${k}	${v}" >> /etc/login.defs
        fi
    done
    info "MAX_DAYS=90 MIN_DAYS=7 WARN_AGE=14"

    # Apply to existing users
    info "Applying to existing users..."
    local users; users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd)
    for u in $users; do
        chage -M 90 -m 7 -W 14 "$u" 2>/dev/null || true
        info "  $u: $(chage -l "$u" 2>/dev/null | grep 'Password expires' || echo 'N/A')"
    done
    pass "Password aging configured"

    # ── Password complexity ──
    step "Password Complexity (PAM)"
    if [[ "$distro" == "debian" ]]; then
        apt-get install -y libpam-cracklib -qq 2>&1 | tee -a "$LOG" || true
        backup_file /etc/pam.d/common-password

        local pq="password requisite pam_cracklib.so retry=3 minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=4"
        if ! grep -q "pam_cracklib.so" /etc/pam.d/common-password; then
            sed -i "0,/^password.*pam_unix.so/s//${pq}\n&/" /etc/pam.d/common-password
            info "Added pam_cracklib (minlen=14)"
        else
            sed -i "s/^password\s\+requisite\s\+pam_cracklib.so.*/${pq}/" /etc/pam.d/common-password
            info "Updated pam_cracklib"
        fi
    else
        apt-get install -y libpam-pwquality -qq 2>&1 | tee -a "$LOG" || true
        backup_file /etc/pam.d/common-password

        local pq="password requisite pam_pwquality.so retry=3 minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=4"
        if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
            sed -i "0,/^password.*pam_unix.so/s//${pq}\n&/" /etc/pam.d/common-password
            info "Added pam_pwquality (minlen=14)"
        else
            sed -i "s/^password\s\+requisite\s\+pam_pwquality.so.*/${pq}/" /etc/pam.d/common-password
            info "Updated pam_pwquality"
        fi

        # Also create /etc/security/pwquality.conf for completeness
        backup_file /etc/security/pwquality.conf
        cat > /etc/security/pwquality.conf <<'PWQ'
minlen = 14
ucredit = -1
lcredit = -1
dcredit = -1
ocredit = -1
difok = 4
retry = 3
PWQ
        info "pwquality.conf written"
    fi

    # Password history
    if ! grep "remember=" /etc/pam.d/common-password >/dev/null 2>&1; then
        sed -i "s/\(pam_unix.so.*\)/\1 remember=5/" /etc/pam.d/common-password
        info "Password history: remember=5"
    fi
    pass "Password complexity configured"

    # ── Account lockout ──
    step "Account Lockout (faillock)"
    if [[ "$distro" != "debian" ]]; then
        backup_file /etc/pam.d/common-auth

        if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
            sed -i "0,/^auth/s//auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900\n&/" /etc/pam.d/common-auth
            sed -i "/^auth.*pam_deny.so/i auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900" /etc/pam.d/common-auth
            info "faillock configured: 5 failures = 15 min lockout"
        else
            info "faillock already configured"
        fi

        # faillock to common-account
        backup_file /etc/pam.d/common-account
        if ! grep -q "pam_faillock.so" /etc/pam.d/common-account; then
            echo "account required pam_faillock.so" >> /etc/pam.d/common-account
            info "faillock account hook added"
        fi
        pass "Account lockout configured"
    else
        info "Debian — using pam_tally2"
        backup_file /etc/pam.d/common-auth
        if ! grep -q "pam_tally2.so" /etc/pam.d/common-auth; then
            sed -i "0,/^auth/s//auth required pam_tally2.so deny=5 unlock_time=900 onerr=fail audit\n&/" /etc/pam.d/common-auth
            info "pam_tally2 configured"
        fi
    fi

    # ── Limit root access ──
    step "Root Access Restrictions"
    if [[ -f /etc/securetty ]]; then
        backup_file /etc/securetty
        echo "console" > /etc/securetty
        info "/etc/securetty: root login only on console"
    fi
    pass "Root access restricted"

    # ── Core dumps ──
    step "Disable Core Dumps"
    backup_file /etc/security/limits.conf
    if ! grep -q "hard core 0" /etc/security/limits.conf; then
        echo "*	hard core	0" >> /etc/security/limits.conf
        info "Core dumps disabled (limits.conf)"
    fi

    # Also in systemd
    if [[ -f /etc/systemd/coredump.conf ]]; then
        backup_file /etc/systemd/coredump.conf
        if grep -q "^#Storage=" /etc/systemd/coredump.conf; then
            sed -i 's/^#Storage=.*/Storage=none/' /etc/systemd/coredump.conf
        fi
        if grep -q "^#ProcessSizeMax=" /etc/systemd/coredump.conf; then
            sed -i 's/^#ProcessSizeMax=.*/ProcessSizeMax=0/' /etc/systemd/coredump.conf
        fi
        info "Core dumps disabled (systemd)"
    fi
    pass "Core dumps disabled"

    # ── Summary ──
    echo ""
    echo -e "${BOLD}${GREEN}═══ PAM Policies Complete ═══${NC}"
    echo -e "Backups: ${BACKUP_DIR}"
    echo -e "Log:     ${LOG}"
    echo -e "${YELLOW}Verify:${NC}"
    echo -e "  grep pwquality /etc/pam.d/common-password"
    echo -e "  grep faillock /etc/pam.d/common-auth"
    echo -e "  grep \"^PASS\" /etc/login.defs"
}

main "$@"
