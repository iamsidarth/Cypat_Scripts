#!/bin/bash
###############################################################################
#  CyberPatriot — Apache2 Hardening (Standalone)
#  Run: sudo ./apache2.sh
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BACKUP_DIR="/tmp/cypat-apache2-backup-$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/cypat-apache2-$(date +%Y%m%d-%H%M%S).log"

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

main() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        echo "Usage: sudo ./apache2.sh"
        echo "Hardens Apache2 web server"
        exit 0
    fi

    echo -e "${BOLD}${BLUE}╔══ Apache2 Hardening ══╗${NC}"
    require_root
    mkdir -p "$BACKUP_DIR"

    if ! dpkg -l apache2 &>/dev/null && ! command -v apache2 &>/dev/null; then
        warn "Apache2 is not installed. Skipping."
        exit 0
    fi

    local apache_conf="/etc/apache2/apache2.conf"
    local sec_conf="/etc/apache2/conf-available/security.conf"

    # ── Security.conf ──
    step "Configuring security.conf"
    if [[ -f "$sec_conf" ]]; then
        backup_file "$sec_conf"

        # ServerTokens
        if grep -q "^ServerTokens" "$sec_conf"; then
            sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$sec_conf"
        else
            echo "ServerTokens Prod" >> "$sec_conf"
        fi

        # ServerSignature
        if grep -q "^ServerSignature" "$sec_conf"; then
            sed -i 's/^ServerSignature.*/ServerSignature Off/' "$sec_conf"
        else
            echo "ServerSignature Off" >> "$sec_conf"
        fi

        # TraceEnable
        if grep -q "^TraceEnable" "$sec_conf"; then
            sed -i 's/^TraceEnable.*/TraceEnable Off/' "$sec_conf"
        else
            echo "TraceEnable Off" >> "$sec_conf"
        fi

        info "ServerTokens=Prod, ServerSignature=Off, TraceEnable=Off"
        pass "security.conf hardened"
    else
        warn "security.conf not found"
    fi

    # ── Disable directory listing ──
    step "Disabling directory listing"
    if [[ -f "$apache_conf" ]]; then
        backup_file "$apache_conf"

        # Set default directory options
        if grep -q "^<Directory /var/www/>" "$apache_conf"; then
            if ! grep -A5 "^<Directory /var/www/>" "$apache_conf" | grep -q "Options.*-Indexes"; then
                sed -i '/^<Directory \/var\/www\/>/,/^<\/Directory>/s/Options.*/Options -Indexes -FollowSymLinks/' "$apache_conf"
            fi
        fi

        # Also check other Directory blocks
        sed -i 's/Options Indexes/Options -Indexes/g' "$apache_conf" 2>/dev/null || true
        sed -i 's/Options.*Indexes FollowSymLinks/Options -Indexes -FollowSymLinks/g' "$apache_conf" 2>/dev/null || true

        info "Directory listing disabled"
    fi

    # ── Disable unnecessary modules ──
    step "Disabling dangerous modules"
    local bad_modules=("status" "info" "autoindex" "userdir" "include" "cgi" "cgid")
    for mod in "${bad_modules[@]}"; do
        if a2query -m "$mod" 2>/dev/null | grep -q "enabled"; then
            a2dismod "$mod" 2>/dev/null && info "Disabled module: $mod" || true
        fi
    done
    pass "Dangerous modules disabled"

    # ── Security headers ──
    step "Adding security headers"
    local header_conf="/etc/apache2/conf-available/cypat-headers.conf"
    backup_file "$header_conf"

    cat > "$header_conf" <<'HEADERS'
# CyberPatriot Security Headers
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set X-Permitted-Cross-Domain-Policies "none"
    Header set Server "Apache"
</IfModule>
HEADERS

    a2enconf cypat-headers 2>/dev/null || true
    info "Security headers configured"
    pass "Security headers added"

    # ── Check .htaccess files ──
    step "Checking .htaccess files"
    info "Searching for .htaccess files..."
    find /var/www -name ".htaccess" -type f 2>/dev/null | while read -r ht; do
        info "  Found: $ht"
        if grep -qiE "RewriteRule.*http://|RewriteRule.*https://" "$ht" 2>/dev/null; then
            warn "  ⚠ Suspicious rewrite rules in $ht"
            grep -E "RewriteRule" "$ht" | tee -a "$LOG"
        fi
    done

    # ── Remove default pages ──
    step "Removing default index"
    if [[ -f /var/www/html/index.html ]]; then
        backup_file /var/www/html/index.html
        rm /var/www/html/index.html
        info "Removed default index.html"
    fi

    # ── Restrict file permissions ──
    step "Fixing file permissions"
    chown -R www-data:www-data /var/www 2>/dev/null || true
    find /var/www -type d -exec chmod 750 {} \; 2>/dev/null || true
    find /var/www -type f -exec chmod 640 {} \; 2>/dev/null || true
    info "Permissions: dirs=750, files=640, owner=www-data"
    pass "File permissions applied"

    # ── Restart ──
    step "Restarting Apache"
    apache2ctl configtest 2>&1 | tee -a "$LOG" || warn "Config test failed!"
    systemctl restart apache2 2>/dev/null && pass "Apache restarted" || warn "Failed to restart"

    echo ""
    echo -e "${BOLD}${GREEN}═══ Apache2 Hardening Complete ═══${NC}"
    echo -e "Backups: ${BACKUP_DIR}"
    echo -e "Log:     ${LOG}"
}

main "$@"
