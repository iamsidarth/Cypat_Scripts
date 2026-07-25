#!/bin/bash
###############################################################################
#  CyberPatriot — GRUB Bootloader Hardening (Standalone)
#  Run: sudo ./grub.sh [--password=<pwd>]
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BACKUP_DIR="/tmp/cypat-grub-backup-$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/cypat-grub-$(date +%Y%m%d-%H%M%S).log"
GRUB_PASSWORD=""

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
    for arg in "$@"; do
        case "$arg" in
            --password=*) GRUB_PASSWORD="${arg#*=}" ;;
            --help|-h)
                echo "Usage: sudo ./grub.sh [--password=<pwd>]"
                echo "Hardens GRUB bootloader configuration"
                exit 0
                ;;
        esac
    done

    echo -e "${BOLD}${BLUE}╔══ GRUB Hardening ══╗${NC}"
    require_root
    mkdir -p "$BACKUP_DIR"

    local grub_cfg=""

    # Detect GRUB config location
    if [[ -f /etc/default/grub ]]; then
        grub_cfg="/etc/default/grub"
    elif [[ -f /etc/default/grub.d/grub ]]; then
        grub_cfg="/etc/default/grub.d/grub"
    else
        warn "GRUB config not found. Is GRUB installed?"
        # Check for systemd-boot instead
        if [[ -d /boot/loader ]]; then
            info "systemd-boot detected instead of GRUB"
            step "systemd-boot hardening"
            if [[ -f /boot/loader/loader.conf ]]; then
                backup_file /boot/loader/loader.conf
                sed -i 's/^#\?timeout.*/timeout 3/' /boot/loader/loader.conf 2>/dev/null
                sed -i 's/^#\?editor.*/editor no/' /boot/loader/loader.conf 2>/dev/null
            fi
        fi
        exit 0
    fi

    backup_file "$grub_cfg"

    step "Hardening GRUB configuration"

    # ── Set GRUB timeout ──
    if grep -q "^GRUB_TIMEOUT=" "$grub_cfg"; then
        sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=5/' "$grub_cfg"
    elif grep -q "^#GRUB_TIMEOUT=" "$grub_cfg"; then
        sed -i 's/^#GRUB_TIMEOUT=.*/GRUB_TIMEOUT=5/' "$grub_cfg"
    else
        echo "GRUB_TIMEOUT=5" >> "$grub_cfg"
    fi
    info "GRUB_TIMEOUT=5"

    # ── Disable recovery mode entries ──
    if grep -q "^GRUB_DISABLE_RECOVERY=" "$grub_cfg"; then
        sed -i 's/^GRUB_DISABLE_RECOVERY=.*/GRUB_DISABLE_RECOVERY=true/' "$grub_cfg"
    elif grep -q "^#GRUB_DISABLE_RECOVERY=" "$grub_cfg"; then
        sed -i 's/^#GRUB_DISABLE_RECOVERY=.*/GRUB_DISABLE_RECOVERY=true/' "$grub_cfg"
    else
        echo "GRUB_DISABLE_RECOVERY=true" >> "$grub_cfg"
    fi
    info "GRUB_DISABLE_RECOVERY=true"

    # ── Disable submenu ──
    if grep -q "^GRUB_DISABLE_SUBMENU=" "$grub_cfg"; then
        sed -i 's/^GRUB_DISABLE_SUBMENU=.*/GRUB_DISABLE_SUBMENU=y/' "$grub_cfg"
    elif grep -q "^#GRUB_DISABLE_SUBMENU=" "$grub_cfg"; then
        sed -i 's/^#GRUB_DISABLE_SUBMENU=.*/GRUB_DISABLE_SUBMENU=y/' "$grub_cfg"
    else
        echo "GRUB_DISABLE_SUBMENU=y" >> "$grub_cfg"
    fi
    info "GRUB_DISABLE_SUBMENU=y"

    # ── Kernel command-line hardening ──
    local cmdline_extra="slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on random.trust_cpu=off rng_core.default_quality=500"
    if grep -q "^GRUB_CMDLINE_LINUX=" "$grub_cfg"; then
        local current; current=$(grep "^GRUB_CMDLINE_LINUX=" "$grub_cfg" | cut -d'"' -f2)
        # Only add if not already present
        for param in $cmdline_extra; do
            local pname="${param%%=*}"
            if ! echo "$current" | grep -q "$pname"; then
                current="$current $param"
            fi
        done
        sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"$current\"|" "$grub_cfg"
    else
        echo "GRUB_CMDLINE_LINUX=\"$cmdline_extra\"" >> "$grub_cfg"
    fi
    info "Kernel cmdline hardened (slab_nomerge, init_on_alloc, PTI, etc.)"

    # ── Set GRUB password if provided ──
    if [[ -n "$GRUB_PASSWORD" ]]; then
        step "Setting GRUB password"
        local pwd_hash
        pwd_hash=$(echo -e "$GRUB_PASSWORD\n$GRUB_PASSWORD" | grub-mkpasswd-pbkdf2 2>/dev/null | grep "grub.pbkdf2" || true)

        if [[ -z "$pwd_hash" ]]; then
            # Fallback: generate with python
            pwd_hash=$(python3 -c "
import hashlib, os, base64
salt = os.urandom(64)
dk = hashlib.pbkdf2_hmac('sha512', b'$GRUB_PASSWORD', salt, 10000)
print('grub.pbkdf2.sha512.10000.' + base64.b64encode(salt).decode() + '.' + base64.b64encode(dk).decode())
" 2>/dev/null || echo "")
        fi

        if [[ -n "$pwd_hash" ]]; then
            # Remove any existing superuser/password lines
            sed -i '/^GRUB_SUPERUSER/d' "$grub_cfg" 2>/dev/null || true
            sed -i '/^GRUB_PASSWORD/d' "$grub_cfg" 2>/dev/null || true

            # Check for /etc/grub.d/00_header or custom file
            local grub_pw_file="/etc/grub.d/40_custom"
            if [[ -f "$grub_pw_file" ]]; then
                backup_file "$grub_pw_file"
                if ! grep -q "superusers" "$grub_pw_file"; then
                    cat >> "$grub_pw_file" <<GRUBPW

# CyberPatriot GRUB password protection
set superusers="root"
password_pbkdf2 root $pwd_hash
GRUBPW
                    info "GRUB password set (superuser=root)"
                fi
            fi
            pass "GRUB password configured"
        else
            warn "Could not generate GRUB password hash"
        fi
    fi

    # ── Secure GRUB config files ──
    step "Securing GRUB file permissions"
    chmod 600 "$grub_cfg" 2>/dev/null && info "$grub_cfg → 600" || true
    chmod 600 /etc/grub.d/* 2>/dev/null && info "/etc/grub.d/* → 600" || true

    if [[ -f /boot/grub/grub.cfg ]]; then
        chmod 600 /boot/grub/grub.cfg && info "/boot/grub/grub.cfg → 600" || true
    fi
    if [[ -f /boot/grub2/grub.cfg ]]; then
        chmod 600 /boot/grub2/grub.cfg && info "/boot/grub2/grub.cfg → 600" || true
    fi

    # ── Check for unauthorized GRUB superuser entries ──
    step "Checking for unauthorized GRUB superusers"
    if [[ -f /etc/grub.d/40_custom ]]; then
        local sus_grub
        sus_grub=$(grep -E "superusers|password_pbkdf2" /etc/grub.d/40_custom 2>/dev/null | grep -v "cyberpatriot\|CYBERPATRIOT\|^#" || true)
        if [[ -n "$sus_grub" ]]; then
            warn "Existing GRUB user entries found (review manually):"
            echo "$sus_grub" | tee -a "$LOG"
        fi
    fi

    # ── Update GRUB ──
    step "Updating GRUB"
    if command -v update-grub &>/dev/null; then
        update-grub 2>&1 | tee -a "$LOG" || warn "update-grub failed"
    elif command -v grub-mkconfig &>/dev/null; then
        grub-mkconfig -o /boot/grub/grub.cfg 2>&1 | tee -a "$LOG" || warn "grub-mkconfig failed"
    elif command -v grub2-mkconfig &>/dev/null; then
        grub2-mkconfig -o /boot/grub2/grub.cfg 2>&1 | tee -a "$LOG" || warn "grub2-mkconfig failed"
    else
        warn "Could not find GRUB update command"
    fi

    pass "GRUB hardened"

    echo ""
    echo -e "${BOLD}${GREEN}═══ GRUB Hardening Complete ═══${NC}"
    echo -e "Backups: ${BACKUP_DIR}"
    echo -e "Log:     ${LOG}"
    echo -e "${YELLOW}Verify: cat /etc/default/grub${NC}"
}

main "$@"
