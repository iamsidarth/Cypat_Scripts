#!/bin/bash
###############################################################################
#  CyberPatriot — PHP Hardening (Standalone)
#  Run: sudo ./php.sh
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BACKUP_DIR="/tmp/cypat-php-backup-$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/cypat-php-$(date +%Y%m%d-%H%M%S).log"

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

# Find PHP ini files
find_php_inis() {
    local inis=()
    # Common locations
    for loc in /etc/php/*/apache2/php.ini \
               /etc/php/*/cli/php.ini \
               /etc/php/*/fpm/php.ini \
               /etc/php/*/cgi/php.ini \
               /etc/php.ini; do
        if compgen -G "$loc" >/dev/null 2>&1; then
            for f in $loc; do
                [[ -f "$f" ]] && inis+=("$f")
            done
        fi
    done
    printf '%s\n' "${inis[@]}"
}

main() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        echo "Usage: sudo ./php.sh"
        echo "Hardens PHP configuration"
        exit 0
    fi

    echo -e "${BOLD}${BLUE}╔══ PHP Hardening ══╗${NC}"
    require_root
    mkdir -p "$BACKUP_DIR"

    if ! command -v php &>/dev/null; then
        warn "PHP is not installed. Skipping."
        exit 0
    fi

    info "PHP version: $(php -v 2>/dev/null | head -1)"

    local php_inis
    mapfile -t php_inis < <(find_php_inis)

    if [[ ${#php_inis[@]} -eq 0 ]]; then
        warn "No php.ini files found"
        # Search more broadly
        php_inis=($(php --ini 2>/dev/null | grep -oP '/\S+\.ini' || true))
    fi

    if [[ ${#php_inis[@]} -eq 0 ]]; then
        warn "Still cannot find php.ini. Skipping PHP hardening."
        exit 0
    fi

    step "PHP ini files found"
    printf '  %s\n' "${php_inis[@]}" | tee -a "$LOG"

    for ini in "${php_inis[@]}"; do
        [[ ! -f "$ini" ]] && continue
        step "Hardening: $ini"
        backup_file "$ini"

        local settings=(
            "expose_php = Off"
            "display_errors = Off"
            "display_startup_errors = Off"
            "log_errors = On"
            "allow_url_fopen = Off"
            "allow_url_include = Off"
            "session.cookie_httponly = 1"
            "session.cookie_secure = 1"
            "session.use_strict_mode = 1"
            "session.use_only_cookies = 1"
        )

        for setting in "${settings[@]}"; do
            local key="${setting%% = *}"
            local val="${setting##*= }"

            if grep -q "^${key}\s*=" "$ini"; then
                sed -i "s|^${key}\s*=.*|${key} = ${val}|" "$ini"
                info "  ${key} = ${val}"
            elif grep -q "^;${key}\s*=" "$ini"; then
                sed -i "s|^;${key}\s*=.*|${key} = ${val}|" "$ini"
                info "  ${key} = ${val} (was commented)"
            else
                echo "${key} = ${val}" >> "$ini"
                info "  ${key} = ${val} (added)"
            fi
        done

        # disable_functions (aggressive blocklist)
        local disable_funcs="exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source"
        if grep -q "^disable_functions\s*=" "$ini"; then
            local cur; cur=$(grep "^disable_functions\s*=" "$ini" | cut -d= -f2-)
            # Merge if not already there
            if [[ "$cur" != *"exec"* ]]; then
                sed -i "s|^disable_functions\s*=.*|disable_functions = ${disable_funcs},${cur}|" "$ini"
                info "  disable_functions = merged with existing"
            fi
        elif grep -q "^;disable_functions\s*=" "$ini"; then
            sed -i "s|^;disable_functions\s*=.*|disable_functions = ${disable_funcs}|" "$ini"
            info "  disable_functions = ${disable_funcs}"
        else
            echo "disable_functions = ${disable_funcs}" >> "$ini"
            info "  disable_functions = ${disable_funcs}"
        fi

        # File upload limits
        if grep -q "^file_uploads\s*=" "$ini"; then
            sed -i 's|^file_uploads\s*=.*|file_uploads = Off|' "$ini"
            info "  file_uploads = Off"
        else
            echo "file_uploads = Off" >> "$ini"
            info "  file_uploads = Off"
        fi

        # Disable dangerous functions
        local extra=(
            "max_execution_time = 30"
            "max_input_time = 60"
            "memory_limit = 128M"
            "post_max_size = 8M"
            "upload_max_filesize = 2M"
        )
        for s in "${extra[@]}"; do
            local k="${s%% = *}"
            if ! grep -q "^${k}\s*=" "$ini"; then
                echo "$s" >> "$ini"
                info "  $s"
            fi
        done
    done

    # ── Remove phpinfo files ──
    step "Removing phpinfo / test files"
    find /var/www -name "phpinfo.php" -o -name "info.php" -o -name "test.php" 2>/dev/null | while read -r pf; do
        info "Removing: $pf"
        rm -f "$pf"
    done
    pass "PHP info files removed"

    # ── Restart web server ──
    step "Restarting web server"
    if systemctl is-active --quiet apache2 2>/dev/null; then
        systemctl restart apache2 2>/dev/null && info "Apache restarted"
    fi
    if systemctl is-active --quiet php*-fpm 2>/dev/null; then
        systemctl restart php*-fpm 2>/dev/null && info "PHP-FPM restarted" || true
    fi

    echo ""
    echo -e "${BOLD}${GREEN}═══ PHP Hardening Complete ═══${NC}"
    echo -e "Backups: ${BACKUP_DIR}"
    echo -e "Log:     ${LOG}"
}

main "$@"
