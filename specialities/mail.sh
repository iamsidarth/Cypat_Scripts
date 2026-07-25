#!/bin/bash
###############################################################################
#  CyberPatriot — Mail Server Hardening (Standalone)
#  Run: sudo ./mail.sh
#
#  Hardens Dovecot IMAP/POP3 and Postfix/MLSMTP SMTP servers.
#  Based on Key.PNG and Key copy 6 answer keys.
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BACKUP_DIR="/tmp/cypat-mail-backup-$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/cypat-mail-$(date +%Y%m%d-%H%M%S).log"

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

# ── Dovecot Hardening ──
harden_dovecot() {
    step "Dovecot Hardening"

    if ! command -v dovecot &>/dev/null && ! dpkg -l dovecot-core &>/dev/null 2>&1; then
        info "Dovecot not installed"
        return
    fi

    local conf_dir="/etc/dovecot"
    [[ ! -d "$conf_dir" ]] && conf_dir="/etc/dovecot/dovecot.conf"

    # Main config
    local main_conf="$conf_dir/dovecot.conf"
    local ssl_conf="$conf_dir/conf.d/10-ssl.conf"
    local auth_conf="$conf_dir/conf.d/10-auth.conf"
    local master_conf="$conf_dir/conf.d/10-master.conf"

    # 10-ssl.conf — SSL required
    if [[ -f "$ssl_conf" ]]; then
        backup_file "$ssl_conf"
        sed -i 's/^#\?ssl\s*=\s*.*/ssl = required/' "$ssl_conf"
        if ! grep -q "^ssl = " "$ssl_conf"; then
            echo "ssl = required" >> "$ssl_conf"
        fi

        sed -i 's/^#\?ssl_min_protocol\s*=.*/ssl_min_protocol = TLSv1.2/' "$ssl_conf"
        if ! grep -q "^ssl_min_protocol" "$ssl_conf"; then
            echo "ssl_min_protocol = TLSv1.2" >> "$ssl_conf"
        fi

        # Disable SSLv2/v3
        sed -i 's/^#\?ssl_cipher_list\s*=.*/ssl_cipher_list = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256/' "$ssl_conf"
        info "Dovecot: SSL required, TLSv1.2+"

        pass "Dovecot SSL configured"
    fi

    # 10-auth.conf — disable plaintext auth, debug passwords
    if [[ -f "$auth_conf" ]]; then
        backup_file "$auth_conf"
        sed -i 's/^#\?disable_plaintext_auth\s*=.*/disable_plaintext_auth = yes/' "$auth_conf"
        if ! grep -q "^disable_plaintext_auth" "$auth_conf"; then
            echo "disable_plaintext_auth = yes" >> "$auth_conf"
        fi

        # Disable auth_debug
        sed -i 's/^#\?auth_debug\s*=.*/auth_debug = no/' "$auth_conf"
        sed -i 's/^#\?auth_debug_passwords\s*=.*/auth_debug_passwords = no/' "$auth_conf"
        if ! grep -q "^auth_debug_passwords" "$auth_conf"; then
            echo "auth_debug_passwords = no" >> "$auth_conf"
        fi
        info "Dovecot: plaintext auth=no, debug passwords=no"

        pass "Dovecot auth secured"
    fi

    # Check for mail_log plugin (debug)
    if grep -r "mail_debug" "$conf_dir" 2>/dev/null | grep -qv "^#"; then
        warn "Dovecot mail_debug is enabled — disable if not needed"
    fi

    systemctl restart dovecot 2>/dev/null || true
    pass "Dovecot hardened"
}

# ── Postfix Hardening ──
harden_postfix() {
    step "Postfix Hardening"

    if ! command -v postfix &>/dev/null && ! dpkg -l postfix &>/dev/null 2>&1; then
        info "Postfix not installed"
        return
    fi

    local main_cf="/etc/postfix/main.cf"
    if [[ ! -f "$main_cf" ]]; then
        warn "Postfix main.cf not found"
        return
    fi

    backup_file "$main_cf"

    # Disable VRFY and EXPN commands
    if grep -q "^disable_vrfy_command" "$main_cf"; then
        sed -i 's/^disable_vrfy_command\s*=.*/disable_vrfy_command = yes/' "$main_cf"
    else
        echo "disable_vrfy_command = yes" >> "$main_cf"
    fi

    if ! grep -q "^disable_vrfy_command" "$main_cf"; then
        echo "disable_vrfy_command = yes" >> "$main_cf"
    fi
    info "Postfix: disable_vrfy_command=yes"

    # Restrict relay
    if grep -q "^mynetworks" "$main_cf"; then
        sed -i 's/^mynetworks\s*=.*/mynetworks = 127.0.0.0\/8/' "$main_cf"
    else
        echo "mynetworks = 127.0.0.0/8" >> "$main_cf"
    fi
    info "Postfix: mynetworks restricted to localhost"

    # Set banner
    if grep -q "^smtpd_banner" "$main_cf"; then
        sed -i 's/^smtpd_banner\s*=.*/smtpd_banner = $myhostname ESMTP/' "$main_cf"
    else
        echo 'smtpd_banner = $myhostname ESMTP' >> "$main_cf"
    fi

    # Enable TLS
    if ! grep -q "^smtpd_use_tls" "$main_cf"; then
        echo "smtpd_use_tls = yes" >> "$main_cf"
        echo "smtpd_tls_security_level = may" >> "$main_cf"
        echo "smtp_use_tls = yes" >> "$main_cf"
        echo "smtp_tls_security_level = may" >> "$main_cf"
        info "Postfix: TLS enabled"
    fi

    # Rate limiting
    if ! grep -q "^smtpd_client_connection_rate_limit" "$main_cf"; then
        echo "smtpd_client_connection_rate_limit = 10" >> "$main_cf"
        echo "smtpd_client_message_rate_limit = 30" >> "$main_cf"
        echo "smtpd_client_recipient_rate_limit = 30" >> "$main_cf"
        info "Postfix: rate limiting enabled"
    fi

    systemctl restart postfix 2>/dev/null || true
    pass "Postfix hardened"
}

# ── Sendmail / Exim / MLSMTP ──
harden_other_mail() {
    step "Other Mail Services"

    # Check for MLSMTP
    if [[ -f /etc/mlsmtp/mlsmtp.conf ]] || command -v mlsmtp &>/dev/null; then
        info "MLSMTP detected"
        # Key.PNG: "MLSMTP commands EXPN and VRFY are disabled"
        # Key.PNG: "MLSMTP TLS is enabled on appropriate ports"
        # Key.PNG: "MLSMTP queue workers is not set to zero"
        if [[ -f /etc/mlsmtp/mlsmtp.conf ]]; then
            backup_file /etc/mlsmtp/mlsmtp.conf
            sed -i 's/^#\?noexpn.*/noexpn/' /etc/mlsmtp/mlsmtp.conf 2>/dev/null || true
            sed -i 's/^#\?novrfy.*/novrfy/' /etc/mlsmtp/mlsmtp.conf 2>/dev/null || true
            info "MLSMTP: EXPN/VRFY disabled if configurable"
        fi
    fi

    # Remove sendmail/exim if not required
    if dpkg -l sendmail &>/dev/null 2>&1; then
        warn "Sendmail installed — remove if not required per README"
    fi
    if dpkg -l exim4 &>/dev/null 2>&1; then
        warn "Exim4 installed — remove if not required per README"
    fi
}

# ── POP3/IMAP Service Check ──
check_mail_services() {
    step "Mail Service Ports"
    info "Checking mail-related listening ports..."
    ss -tulnp 2>/dev/null | grep -E ":(25|110|143|465|587|993|995)\s" | tee -a "$LOG" || true

    # Key copy 6: "POP3 service has been disabled or removed"
    # Key copy 6: "SMTP service service has been disabled or removed"
    for svc in dovecot-pop3d courier-pop pop3-server cyrus-pop3d dovecot imapd; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            warn "POP3/IMAP service '$svc' is RUNNING — disable if not required"
        fi
    done
}

main() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        echo "Usage: sudo ./mail.sh"
        echo "Hardens Dovecot, Postfix, and other mail services"
        exit 0
    fi

    echo -e "${BOLD}${BLUE}╔══ Mail Server Hardening ══╗${NC}"
    require_root
    mkdir -p "$BACKUP_DIR"

    check_mail_services
    harden_dovecot
    harden_postfix
    harden_other_mail

    echo ""
    echo -e "${BOLD}${GREEN}═══ Mail Server Hardening Complete ═══${NC}"
    echo -e "Backups: ${BACKUP_DIR}"
    echo -e "Log:     ${LOG}"
}

main "$@"
