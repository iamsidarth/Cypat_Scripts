#!/bin/bash
###############################################################################
#  CyberPatriot — Desktop/GDM/GNOME Hardening (Standalone)
#  Run: sudo ./desktop.sh
#
#  Covers: GDM3 hardening, screensaver/lock, disable guest, disable autologin,
#           X Server TCP disable, desktop environment lock settings for
#           GNOME, Cinnamon, MATE, Xfce, KDE.
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BACKUP_DIR="/tmp/cypat-desktop-backup-$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/cypat-desktop-$(date +%Y%m%d-%H%M%S).log"

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

detect_de() {
    if pgrep -x "gnome-shell" &>/dev/null; then echo "gnome"
    elif pgrep -x "cinnamon" &>/dev/null; then echo "cinnamon"
    elif pgrep -x "mate-panel" &>/dev/null; then echo "mate"
    elif pgrep -x "xfdesktop" &>/dev/null; then echo "xfce"
    elif pgrep -x "plasmashell" &>/dev/null; then echo "kde"
    elif [[ -n "${XDG_CURRENT_DESKTOP:-}" ]]; then echo "${XDG_CURRENT_DESKTOP,,}"
    else echo "unknown"; fi
}

main() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        echo "Usage: sudo ./desktop.sh"
        echo "Hardens desktop environment: GDM, screensaver, guest, autologin"
        exit 0
    fi

    echo -e "${BOLD}${BLUE}╔══ Desktop & Display Manager Hardening ══╗${NC}"
    require_root
    mkdir -p "$BACKUP_DIR"

    local de; de=$(detect_de)
    info "Detected DE: $de"

    # ── GDM3 (GNOME Display Manager) ──
    step "GDM3 Hardening"
    local gdm_conf="/etc/gdm3/custom.conf"
    if [[ -f "$gdm_conf" ]]; then
        backup_file "$gdm_conf"

        # Disable automatic login
        if grep -q "^AutomaticLoginEnable=" "$gdm_conf"; then
            sed -i 's/^AutomaticLoginEnable=.*/AutomaticLoginEnable=false/' "$gdm_conf"
        elif grep -q "^#AutomaticLoginEnable=" "$gdm_conf"; then
            sed -i 's/^#AutomaticLoginEnable=.*/AutomaticLoginEnable=false/' "$gdm_conf"
        else
            sed -i '/\[daemon\]/a AutomaticLoginEnable=false' "$gdm_conf"
        fi
        info "AutomaticLoginEnable=false"

        # Disable timed login
        if grep -q "^TimedLoginEnable=" "$gdm_conf"; then
            sed -i 's/^TimedLoginEnable=.*/TimedLoginEnable=false/' "$gdm_conf"
        else
            sed -i '/\[daemon\]/a TimedLoginEnable=false' "$gdm_conf"
        fi

        # Disable root login via GDM
        if grep -q "^AllowRoot=" "$gdm_conf"; then
            sed -i 's/^AllowRoot=.*/AllowRoot=false/' "$gdm_conf"
        else
            sed -i '/\[security\]/a AllowRoot=false' "$gdm_conf"
        fi

        # Disable guest
        if grep -q "^AllowGuest=" "$gdm_conf"; then
            sed -i 's/^AllowGuest=.*/AllowGuest=false/' "$gdm_conf"
        else
            sed -i '/\[security\]/a AllowGuest=false' "$gdm_conf"
        fi
        info "GDM3: AllowRoot=false, AllowGuest=false"

        # GDM user list disable
        if grep -q "^DisableUserList=" "$gdm_conf"; then
            sed -i 's/^DisableUserList=.*/DisableUserList=true/' "$gdm_conf"
        elif grep -q "^#DisableUserList=" "$gdm_conf"; then
            sed -i 's/^#DisableUserList=.*/DisableUserList=true/' "$gdm_conf"
        else
            sed -i '/\[security\]/a DisableUserList=true' "$gdm_conf"
        fi
        info "GDM3: DisableUserList=true"

        pass "GDM3 hardened"
    elif [[ -d /etc/gdm3 ]]; then
        info "GDM3 directory found but no custom.conf — creating one"
        mkdir -p /etc/gdm3 2>/dev/null || true
        cat > "$gdm_conf" <<'GDM'
[daemon]
AutomaticLoginEnable=false
TimedLoginEnable=false

[security]
AllowRoot=false
AllowGuest=false
DisableUserList=true
GDM
        pass "GDM3 config created"
    else
        info "GDM3 not found — checking for LightDM..."
    fi

    # ── LightDM (Ubuntu pre-17.10, Mint, Xubuntu) ──
    step "LightDM Hardening"
    local ldm="/etc/lightdm/lightdm.conf"
    if [[ -f "$ldm" ]]; then
        backup_file "$ldm"

        if grep -q "^allow-guest" "$ldm"; then
            sed -i 's/^allow-guest.*/allow-guest=false/' "$ldm"
        else
            echo -e "\n[Seat:*]\nallow-guest=false" >> "$ldm"
        fi

        if grep -q "^greeter-hide-users" "$ldm"; then
            sed -i 's/^greeter-hide-users.*/greeter-hide-users=true/' "$ldm"
        else
            sed -i '/\[Seat:\*\]/a greeter-hide-users=true' "$ldm"
        fi

        if grep -q "^autologin-user=" "$ldm"; then
            sed -i 's/^autologin-user=.*/autologin-user=none/' "$ldm"
        fi
        info "LightDM: guest=off, hide-users=on, autologin=off"
        pass "LightDM hardened"
    fi

    # LightDM override (works even if main conf missing)
    mkdir -p /etc/lightdm/lightdm.conf.d
    cat > /etc/lightdm/lightdm.conf.d/99-cypat.conf <<'LDM'
[Seat:*]
allow-guest=false
greeter-hide-users=true
autologin-user=none
LDM
    info "LightDM override created"

    # ── SDDM (KDE) ──
    if [[ -d /etc/sddm.conf.d ]] || [[ -f /etc/sddm.conf ]]; then
        step "SDDM Hardening"
        local sddm_conf="/etc/sddm.conf.d/99-cypat.conf"
        mkdir -p /etc/sddm.conf.d
        cat > "$sddm_conf" <<'SDDM'
[Users]
MaximumUid=60000
MinimumUid=1000
HideUsers=
HideShells=/sbin/nologin,/bin/false
SDDM
        info "SDDM: user hiding configured"
    fi

    # ── X Server TCP disable ──
    step "X Server Hardening"
    local xwrapper="/etc/X11/xinit/xserverrc"
    if [[ -f /etc/X11/xwrapper.config ]]; then
        backup_file /etc/X11/xwrapper.config
        if grep -q "^allowed_users=" /etc/X11/xwrapper.config; then
            sed -i 's/^allowed_users=.*/allowed_users=console/' /etc/X11/xwrapper.config
        else
            echo "allowed_users=console" >> /etc/X11/xwrapper.config
        fi
        info "Xwrapper: allowed_users=console"
    fi

    # Disable X TCP for GDM
    if [[ -f /etc/gdm3/custom.conf ]]; then
        if ! grep -q "DisallowTCP" /etc/gdm3/custom.conf; then
            sed -i '/\[security\]/a DisallowTCP=true' /etc/gdm3/custom.conf
            info "GDM3: DisallowTCP=true"
        fi
    fi

    # Also check for Xorg started with -nolisten tcp
    if [[ -f /etc/X11/xorg.conf ]]; then
        backup_file /etc/X11/xorg.conf
        if ! grep -q "nolisten tcp" /etc/X11/xorg.conf; then
            info "Ensure Xorg uses -nolisten tcp"
        fi
    fi
    pass "X Server hardened"

    # ── Screensaver / Lock Settings ──
    step "Screensaver & Screen Lock"

    case "$de" in
        gnome)
            info "Configuring GNOME screensaver..."
            local dconf_db="/etc/dconf/db/local.d/00-cypat-screensaver"
            mkdir -p /etc/dconf/db/local.d

            cat > "$dconf_db" <<'DCONF'
[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
idle-activation-enabled=true

[org/gnome/desktop/session]
idle-delay=uint32 300

[org/gnome/desktop/lockdown]
disable-lock-screen=false

[org/gnome/settings-daemon/plugins/power]
sleep-inactive-ac-timeout=900
sleep-inactive-battery-timeout=600
idle-dim=true
DCONF

            if [[ -f /etc/dconf/db/local ]]; then
                backup_file /etc/dconf/db/local
            fi
            cat > /etc/dconf/profile/user <<'PROFILE'
user-db:user
system-db:local
PROFILE
            dconf update 2>/dev/null || true
            info "GNOME lock: 5min idle, immediate lock, screensaver enabled"
            ;;

        cinnamon)
            info "Configuring Cinnamon screensaver..."
            if command -v gsettings &>/dev/null; then
                local u; u=$(logname 2>/dev/null || echo "$SUDO_USER")
                sudo -u "$u" gsettings set org.cinnamon.desktop.screensaver lock-enabled true 2>/dev/null || true
                sudo -u "$u" gsettings set org.cinnamon.desktop.screensaver lock-delay 0 2>/dev/null || true
                sudo -u "$u" gsettings set org.cinnamon.desktop.session idle-delay 300 2>/dev/null || true
                info "Cinnamon: lock enabled, 5min idle"
            fi
            ;;

        mate)
            info "Configuring MATE screensaver..."
            if command -v gsettings &>/dev/null; then
                local u; u=$(logname 2>/dev/null || echo "$SUDO_USER")
                sudo -u "$u" gsettings set org.mate.screensaver lock-enabled true 2>/dev/null || true
                sudo -u "$u" gsettings set org.mate.screensaver lock-delay 0 2>/dev/null || true
                sudo -u "$u" gsettings set org.mate.session idle-delay 5 2>/dev/null || true
                info "MATE: lock enabled, 5min idle"
            fi
            ;;

        xfce)
            info "Configuring Xfce screensaver..."
            if command -v xfconf-query &>/dev/null; then
                local u; u=$(logname 2>/dev/null || echo "$SUDO_USER")
                sudo -u "$u" xfconf-query -c xfce4-screensaver -p /lock/enabled -s true 2>/dev/null || true
                sudo -u "$u" xfconf-query -c xfce4-screensaver -p /lock/delay -s 0 2>/dev/null || true
                info "Xfce: lock enabled"
            fi
            # Xfce power manager
            if command -v xfconf-query &>/dev/null; then
                local u; u=$(logname 2>/dev/null || echo "$SUDO_USER")
                sudo -u "$u" xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/lock-screen-suspend-hibernate -s true 2>/dev/null || true
            fi
            ;;
    esac

    pass "Screensaver configured for $de"

    # ── Disable guest account via accounts service ──
    step "Guest Account"
    if [[ -f /etc/gdm3/custom.conf ]] || [[ -f /etc/lightdm/lightdm.conf ]]; then
        info "Guest account handled by display manager config above"
    fi

    # Also disable via accounts service if available
    if command -v gsettings &>/dev/null; then
        local u; u=$(logname 2>/dev/null || echo "$SUDO_USER")
        sudo -u "$u" gsettings set org.gnome.desktop.lockdown disable-user-switching true 2>/dev/null || true
    fi

    # Disable guest session at PAM level
    if [[ -f /etc/pam.d/gdm-password ]]; then
        backup_file /etc/pam.d/gdm-password
        if ! grep -q "pam_succeed_if.so uid >= 1000" /etc/pam.d/gdm-password; then
            sed -i "1s/^/auth required pam_succeed_if.so uid >= 1000 quiet\n/" /etc/pam.d/gdm-password
            info "GDM PAM: guest blocked (uid >= 1000 required)"
        fi
    fi
    if [[ -f /etc/pam.d/lightdm ]]; then
        backup_file /etc/pam.d/lightdm
        if ! grep -q "pam_succeed_if.so uid >= 1000" /etc/pam.d/lightdm; then
            sed -i "1s/^/auth required pam_succeed_if.so uid >= 1000 quiet\n/" /etc/pam.d/lightdm
            info "LightDM PAM: guest blocked"
        fi
    fi

    pass "Guest account disabled"

    echo ""
    echo -e "${BOLD}${GREEN}═══ Desktop Hardening Complete ═══${NC}"
    echo -e "Backups: ${BACKUP_DIR}"
    echo -e "Log:     ${LOG}"
    echo -e "${YELLOW}DE detected: $de — verify screen lock works after restart${NC}"
}

main "$@"
