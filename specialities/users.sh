#!/bin/bash
###############################################################################
#  CyberPatriot — User & Group Management (Standalone)
#  Run: sudo ./users.sh [--remove <user>] [--add <user>] [--admin <user>]
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BACKUP_DIR="/tmp/cypat-users-backup-$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/cypat-users-$(date +%Y%m%d-%H%M%S).log"

USERS_TO_REMOVE=(); USERS_TO_ADD=(); USERS_TO_ADMIN=()
DRY_RUN=false

info()  { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG"; }
pass()  { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$LOG"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG"; }
fail()  { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$LOG"; }
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
            --remove=*) IFS=',' read -ra r <<< "${arg#*=}"; USERS_TO_REMOVE+=("${r[@]}") ;;
            --add=*)    IFS=',' read -ra a <<< "${arg#*=}"; USERS_TO_ADD+=("${a[@]}") ;;
            --admin=*)  IFS=',' read -ra ad <<< "${arg#*=}"; USERS_TO_ADMIN+=("${ad[@]}") ;;
            --dry-run)  DRY_RUN=true ;;
            --help|-h)
                echo "Usage: sudo ./users.sh [--remove=u1,u2] [--add=u3,u4] [--admin=u5] [--dry-run]"
                echo "  --remove=u1,u2    Remove these users"
                echo "  --add=u3,u4       Create these users"
                echo "  --admin=u5        Add to sudo group"
                exit 0
                ;;
        esac
    done

    echo -e "${BOLD}${BLUE}╔══ User & Group Audit ══╗${NC}"
    require_root
    mkdir -p "$BACKUP_DIR"

    backup_file /etc/passwd
    backup_file /etc/shadow
    backup_file /etc/group
    backup_file /etc/sudoers

    # ── Audit: List all human users ──
    step "Human users (UID >= 1000)"
    awk -F: '$3 >= 1000 && $3 < 65534 {printf "  %-16s UID=%-5s GID=%-5s HOME=%s SHELL=%s\n", $1, $3, $4, $6, $7}' /etc/passwd | tee -a "$LOG"

    # ── UID 0 check ──
    step "UID 0 accounts"
    local u0; u0=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | tr '\n' ' ')
    if [[ "$u0" == "root " || "$u0" == "root" ]]; then
        pass "Only root has UID 0"
    else
        fail "Multiple UID 0 accounts: $u0"
        warn "These users have full root access — remove unless authorized"
    fi

    # ── Empty passwords ──
    step "Empty / disabled passwords"
    local ep; ep=$(awk -F: '($2 == "" || $2 == "!") && $3 >= 1000 {print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
    if [[ -z "$ep" ]]; then
        pass "No non-root accounts with empty passwords"
    else
        fail "Accounts with empty/disabled passwords: $ep"
    fi

    # ── Sudo access ──
    step "Sudo access"
    info "Members of 'sudo' group:"
    getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' | while read -r u; do
        [[ -n "$u" ]] && echo "  $u" | tee -a "$LOG"
    done

    info "Sudoers file entries:"
    grep -rEh '^[^#].*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | tee -a "$LOG"

    # ── Sensitive groups ──
    step "Sensitive group memberships"
    for grp in adm shadow disk plugdev lxd docker wheel; do
        local m; m=$(getent group "$grp" 2>/dev/null | cut -d: -f4 || true)
        if [[ -n "$m" ]]; then
            warn "Group '$grp' member(s): $m"
        fi
    done

    # ── Remove users ──
    if [[ ${#USERS_TO_REMOVE[@]} -gt 0 ]]; then
        step "Removing users"
        for u in "${USERS_TO_REMOVE[@]}"; do
            u="${u## }"  # trim
            if id "$u" &>/dev/null; then
                if $DRY_RUN; then
                    info "[DRY RUN] Would remove: $u"
                else
                    # Kill user processes
                    pkill -u "$u" 2>/dev/null || true
                    userdel -r "$u" 2>/dev/null && pass "Removed: $u" || fail "Failed to remove: $u"
                fi
            else
                warn "User '$u' does not exist"
            fi
        done
    fi

    # ── Add users ──
    if [[ ${#USERS_TO_ADD[@]} -gt 0 ]]; then
        step "Adding users"
        for u in "${USERS_TO_ADD[@]}"; do
            u="${u## }"
            if id "$u" &>/dev/null; then
                warn "User '$u' already exists"
            else
                if $DRY_RUN; then
                    info "[DRY RUN] Would add: $u"
                else
                    useradd -m -s /bin/bash "$u" && pass "Created: $u" || fail "Failed: $u"
                    # Force password change on first login
                    passwd -e "$u" 2>/dev/null || true
                fi
            fi
        done
    fi

    # ── Admin users ──
    if [[ ${#USERS_TO_ADMIN[@]} -gt 0 ]]; then
        step "Adding to sudo group"
        for u in "${USERS_TO_ADMIN[@]}"; do
            u="${u## }"
            if id "$u" &>/dev/null; then
                if $DRY_RUN; then
                    info "[DRY RUN] Would grant sudo to: $u"
                else
                    usermod -aG sudo "$u" && pass "Granted sudo to: $u" || fail "Failed: $u"
                fi
            else
                fail "User '$u' does not exist — create first"
            fi
        done
    fi

    # ── Lock root ──
    step "Root account"
    if ! $DRY_RUN; then
        passwd -l root 2>/dev/null && info "Root account locked" || true
    fi

    # ── Cleanup: remove nonexistent users from groups ──
    step "Orphaned group memberships"
    for grp in $(getent group | cut -d: -f1); do
        local m; m=$(getent group "$grp" | cut -d: -f4)
        if [[ -n "$m" ]]; then
            IFS=',' read -ra marr <<< "$m"
            for mb in "${marr[@]}"; do
                if ! getent passwd "$mb" &>/dev/null; then
                    warn "Removing nonexistent user '$mb' from group '$grp'"
                    gpasswd -d "$mb" "$grp" 2>/dev/null || true
                fi
            done
        fi
    done

    echo ""
    echo -e "${BOLD}${GREEN}═══ User Audit Complete ═══${NC}"
    echo -e "Backups: ${BACKUP_DIR}"
    echo -e "Log:     ${LOG}"
    echo -e "${YELLOW}Tip: Set passwords for new users with: sudo passwd <user>${NC}"
}

main "$@"
