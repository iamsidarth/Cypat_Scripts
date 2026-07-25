#!/bin/bash
###############################################################################
#  CyberPatriot — Nginx Hardening (Standalone)
#  Run: sudo ./nginx.sh
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BACKUP_DIR="/tmp/cypat-nginx-backup-$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/cypat-nginx-$(date +%Y%m%d-%H%M%S).log"

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
        echo "Usage: sudo ./nginx.sh"
        echo "Hardens Nginx web server"
        exit 0
    fi

    echo -e "${BOLD}${BLUE}╔══ Nginx Hardening ══╗${NC}"
    require_root
    mkdir -p "$BACKUP_DIR"

    if ! command -v nginx &>/dev/null; then
        warn "Nginx is not installed. Skipping."
        exit 0
    fi

    local nginx_conf; nginx_conf=$(nginx -t 2>&1 | grep -oP '/[^\s]+nginx\.conf' | head -1 || echo "/etc/nginx/nginx.conf")
    if [[ ! -f "$nginx_conf" ]]; then
        nginx_conf="/etc/nginx/nginx.conf"
    fi

    step "Main configuration: $nginx_conf"
    backup_file "$nginx_conf"

    # ── server_tokens off ──
    if grep -q "server_tokens" "$nginx_conf"; then
        sed -i 's/server_tokens\s\+.*/server_tokens off;/' "$nginx_conf"
    else
        sed -i '/http {/a \    server_tokens off;' "$nginx_conf"
    fi
    info "server_tokens off"

    # ── Security headers snippet ──
    step "Security headers"
    local snippet="/etc/nginx/snippets/cypat-headers.conf"
    [[ ! -d /etc/nginx/snippets ]] && mkdir -p /etc/nginx/snippets

    cat > "$snippet" <<'NGINX'
# CyberPatriot Security Headers
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header X-Permitted-Cross-Domain-Policies "none" always;
NGINX

    info "Security headers snippet created at $snippet"
    info "Include this in your server blocks: include snippets/cypat-headers.conf;"
    pass "Security headers configured"

    # ── Disable autoindex ──
    step "Disabling autoindex"
    if grep -r "autoindex on" /etc/nginx/ 2>/dev/null; then
        warn "autoindex ON found — disabling"
        find /etc/nginx -name "*.conf" -exec sed -i 's/autoindex\s\+on/autoindex off/g' {} \;
    fi
    pass "autoindex checked"

    # ── SSL settings if HTTPS certs exist ──
    step "SSL configuration"
    if [[ -d /etc/nginx/ssl ]] || [[ -f /etc/ssl/certs/nginx-selfsigned.crt ]]; then
        local ssl_snippet="/etc/nginx/snippets/cypat-ssl.conf"
        cat > "$ssl_snippet" <<'NGINXSSL'
# CyberPatriot SSL Best Practices
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
NGINXSSL
        info "SSL hardening snippet created at $ssl_snippet"
        pass "SSL configured"
    else
        info "No SSL certs found — skipping SSL hardening"
    fi

    # ── Remove default server if exists ──
    step "Default site"
    if [[ -f /etc/nginx/sites-enabled/default ]]; then
        backup_file /etc/nginx/sites-enabled/default
        rm /etc/nginx/sites-enabled/default
        info "Removed default site"
    fi
    if [[ -f /etc/nginx/conf.d/default.conf ]]; then
        backup_file /etc/nginx/conf.d/default.conf
        rm /etc/nginx/conf.d/default.conf
        info "Removed default.conf"
    fi

    # ── Restrict file permissions ──
    step "File permissions"
    chown -R www-data:www-data /var/www 2>/dev/null || true
    find /etc/nginx -type f -exec chmod 644 {} \; 2>/dev/null || true
    find /etc/nginx -type d -exec chmod 755 {} \; 2>/dev/null || true
    pass "Permissions applied"

    # ── Test & restart ──
    step "Testing & restarting"
    nginx -t 2>&1 | tee -a "$LOG" || warn "Config test failed!"
    systemctl restart nginx 2>/dev/null && pass "Nginx restarted" || warn "Failed to restart"

    echo ""
    echo -e "${BOLD}${GREEN}═══ Nginx Hardening Complete ═══${NC}"
    echo -e "Backups: ${BACKUP_DIR}"
    echo -e "Log:     ${LOG}"
}

main "$@"
