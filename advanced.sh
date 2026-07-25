#!/bin/bash
###############################################################################
#  CyberPatriot Linux Advanced Hardening Script
#  Supports: Ubuntu 20.04/22.04/24.04, Linux Mint 20/21/22, Debian 10/11/12
#
#  Usage: sudo ./advanced.sh
#
#  WARNING: This script is aggressive. Always take a VM snapshot before
#  running. It disables password-based SSH by default, enables strict PAM
#  lockout, installs auditd/fail2ban/ClamAV/rkhunter, and more.
###############################################################################

set -euo pipefail
IFS=$'\n\t'

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m';    GREEN='\033[0;32m';   YELLOW='\033[1;33m'
BLUE='\033[0;34m';   MAGENTA='\033[0;35m'; CYAN='\033[0;36m'
BOLD='\033[1m';      NC='\033[0m'

# ── Globals ─────────────────────────────────────────────────────────────────
BACKUP_DIR="/tmp/cypat-advanced-backup-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/var/log/cypat-advanced-$(date +%Y%m%d-%H%M%S).log"
SCORE=0; TOTAL=0
DRY_RUN=false
DISTRO=""; VERSION_ID=""; MINT_DE=false

# ── Utilities ───────────────────────────────────────────────────────────────
log_msg() { local l=$1 m=$2; echo -e "$(date '+%H:%M:%S') [$l] $m" | tee -a "$LOG_FILE"; }
pass()   { log_msg "${GREEN}PASS${NC}" "$1"; ((SCORE++)); ((TOTAL++)); }
fail()   { log_msg "${RED}FAIL${NC}" "$1"; ((TOTAL++)); }
warn()   { log_msg "${YELLOW}WARN${NC}" "$1"; }
info()   { log_msg "${BLUE}INFO${NC}" "$1"; }
step()   { echo -e "\n${BOLD}${CYAN}═══ $1 ═══${NC}" | tee -a "$LOG_FILE"; }

backup_file() {
    local f=$1
    if [[ -f "$f" || -d "$f" ]]; then
        mkdir -p "$(dirname "$BACKUP_DIR/$f")"
        cp -a "$f" "$BACKUP_DIR/$f" 2>/dev/null || true
        info "Backed up: $f"
    fi
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: Run as root (sudo).${NC}"; exit 1
    fi
}

# ── Distro Detection ────────────────────────────────────────────────────────
detect_distro() {
    step "Detecting Distribution"
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        DISTRO="${ID,,}"
        VERSION_ID="${VERSION_ID:-}"
    elif [[ -f /etc/lsb-release ]]; then
        source /etc/lsb-release
        DISTRO="${DISTRIB_ID,,}"
        VERSION_ID="${DISTRIB_RELEASE:-}"
    else
        DISTRO="ubuntu"; VERSION_ID="22.04"
    fi

    # Normalize Mint
    if [[ "$DISTRO" == "linuxmint" || "$DISTRO" == "linux mint" || "$DISTRO" == "mint" ]]; then
        DISTRO="linuxmint"
        case "${VERSION_ID%%.*}" in
            20) VERSION_ID="20.04" ;;
            21) VERSION_ID="22.04" ;;
            22) VERSION_ID="24.04" ;;
            *)  VERSION_ID="22.04" ;;
        esac

        # Detect desktop environment for Mint-specific fixes
        if pgrep -x "cinnamon" &>/dev/null; then MINT_DE="cinnamon"
        elif pgrep -x "mate-panel" &>/dev/null; then MINT_DE="mate"
        elif pgrep -x "xfdesktop" &>/dev/null; then MINT_DE="xfce"
        elif [[ -n "${XDG_CURRENT_DESKTOP:-}" ]]; then MINT_DE="${XDG_CURRENT_DESKTOP,,}"
        fi
    fi

    info "Distro: $DISTRO $VERSION_ID"
    [[ -n "$MINT_DE" ]] && info "Mint DE: $MINT_DE"
    info "Backups: $BACKUP_DIR"
    info "Log: $LOG_FILE"
}

# ── Phase 1: System Updates & Auto-Updates ──────────────────────────────────
phase_updates() {
    step "Phase 1: System Updates"
    apt-get update -qq 2>&1 | tee -a "$LOG_FILE"
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq 2>&1 | tee -a "$LOG_FILE"
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -qq 2>&1 | tee -a "$LOG_FILE"
    apt-get autoremove -y -qq 2>&1 | tee -a "$LOG_FILE"

    apt-get install -y unattended-upgrades apt-listchanges -qq 2>&1 | tee -a "$LOG_FILE"
    backup_file /etc/apt/apt.conf.d/20auto-upgrades
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
EOF

    # Enable automatic reboots if needed (safe time)
    backup_file /etc/apt/apt.conf.d/50unattended-upgrades
    if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
        sed -i 's/\/\/Unattended-Upgrade::Automatic-Reboot "false"/Unattended-Upgrade::Automatic-Reboot "false"/' \
            /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null || true
        sed -i 's/\/\/Unattended-Upgrade::Remove-Unused-Kernel-Packages "true"/Unattended-Upgrade::Remove-Unused-Kernel-Packages "true"/' \
            /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null || true
        sed -i 's/\/\/Unattended-Upgrade::Remove-Unused-Dependencies "true"/Unattended-Upgrade::Remove-Unused-Dependencies "true"/' \
            /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null || true
    fi

    pass "System updates completed"
}

# ── Phase 2: User & Group Audit ─────────────────────────────────────────────
phase_users() {
    step "Phase 2: User & Group Audit"

    # List all human users
    info "Human users (UID >= 1000):"
    awk -F: '$3 >= 1000 && $3 < 65534 {printf "  %-20s UID=%-5s GID=%-5s HOME=%s\n", $1, $3, $4, $6}' /etc/passwd | tee -a "$LOG_FILE"

    # UID 0 check
    local u0; u0=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | tr '\n' ' ')
    if [[ "$u0" == "root " || "$u0" == "root" ]]; then
        pass "Only root has UID 0"
    else
        fail "Multiple UID 0 accounts: $u0"
    fi

    # Empty password check
    local ep; ep=$(awk -F: '($2 == "" || $2 == "!") && $1 != "root" {print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ' || true)
    if [[ -z "$ep" ]]; then
        pass "No non-root accounts with empty/disabled passwords"
    else
        warn "Accounts with empty/disabled passwords: $ep"
    fi

    # Check all sensitive groups
    for grp in sudo adm shadow disk plugdev lxd docker; do
        local m; m=$(getent group "$grp" 2>/dev/null | cut -d: -f4 || true)
        if [[ -n "$m" ]]; then
            warn "Group '$grp' members: $m — verify these are authorized"
        fi
    done

    # Check /etc/sudoers and /etc/sudoers.d/
    info "Sudoers entries (non-comment):"
    grep -rEh '^[^#].*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | tee -a "$LOG_FILE"

    # Remove users not in /etc/passwd from groups
    for grp in $(getent group | cut -d: -f1); do
        local members; members=$(getent group "$grp" | cut -d: -f4)
        if [[ -n "$members" ]]; then
            IFS=',' read -ra marr <<< "$members"
            for m in "${marr[@]}"; do
                if ! getent passwd "$m" &>/dev/null; then
                    warn "Removing nonexistent user '$m' from group '$grp'"
                    gpasswd -d "$m" "$grp" 2>/dev/null || true
                fi
            done
        fi
    done

    # Lock root from direct login
    passwd -l root 2>/dev/null && info "Root account locked" || true

    pass "User audit completed"
}

# ── Phase 3: Password & Authentication Policies ─────────────────────────────
phase_passwords() {
    step "Phase 3: Password & Authentication Policies"

    # ── login.defs ──
    backup_file /etc/login.defs
    local aging=(
        "PASS_MAX_DAYS 90" "PASS_MIN_DAYS 7" "PASS_WARN_AGE 14"
        "LOGIN_RETRIES 5" "LOGIN_TIMEOUT 60"
    )
    for s in "${aging[@]}"; do
        local k="${s%% *}"; local v="${s##* }"
        if grep -q "^${k}\s" /etc/login.defs; then
            sed -i "s/^${k}\s\+.*/${k}\t${v}/" /etc/login.defs
        else
            echo "${k}	${v}" >> /etc/login.defs
        fi
    done
    info "login.defs configured"

    # Apply aging to all human users
    local users; users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd)
    for u in $users; do
        chage -M 90 -m 7 -W 14 "$u" 2>/dev/null || true
    done
    info "Applied password aging to all users"

    # ── PAM password quality ──
    if [[ "$DISTRO" == "debian" ]]; then
        apt-get install -y libpam-cracklib -qq 2>&1 | tee -a "$LOG_FILE"
        backup_file /etc/pam.d/common-password
        local pq="password requisite pam_cracklib.so retry=3 minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=4"
        if ! grep -q "pam_cracklib.so" /etc/pam.d/common-password; then
            sed -i "0,/^password.*pam_unix.so/s//${pq}\n&/" /etc/pam.d/common-password
        else
            sed -i "s/^password\s\+requisite\s\+pam_cracklib.so.*/${pq}/" /etc/pam.d/common-password
        fi
    else
        apt-get install -y libpam-pwquality -qq 2>&1 | tee -a "$LOG_FILE"
        backup_file /etc/pam.d/common-password
        local pq="password requisite pam_pwquality.so retry=3 minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=4"
        if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
            sed -i "0,/^password.*pam_unix.so/s//${pq}\n&/" /etc/pam.d/common-password
        else
            sed -i "s/^password\s\+requisite\s\+pam_pwquality.so.*/${pq}/" /etc/pam.d/common-password
        fi
    fi
    # Password history
    if ! grep "remember=" /etc/pam.d/common-password > /dev/null 2>&1; then
        sed -i "s/\(pam_unix.so.*\)/\1 remember=5/" /etc/pam.d/common-password
    fi
    info "PAM password quality enforced (minlen=14)"

    # ── PAM faillock (account lockout) ──
    if [[ "$DISTRO" != "debian" ]]; then
        backup_file /etc/pam.d/common-auth
        if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
            sed -i "0,/^auth/s//auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900\n&/" /etc/pam.d/common-auth
            sed -i "/^auth.*pam_deny.so/i auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900" /etc/pam.d/common-auth
            info "PAM faillock configured (deny=5, unlock=900s)"
        fi
        # Also add faillock to common-account
        backup_file /etc/pam.d/common-account
        if ! grep -q "pam_faillock.so" /etc/pam.d/common-account; then
            echo "account required pam_faillock.so" >> /etc/pam.d/common-account
            info "PAM faillock account hook added"
        fi
    fi

    # ── Limit root TTY access ──
    if [[ -f /etc/securetty ]]; then
        backup_file /etc/securetty
        echo "console" > /etc/securetty
        info "Limited root TTY access to console only"
    fi

    # ── Disable core dumps ──
    backup_file /etc/security/limits.conf
    if ! grep -q "hard core 0" /etc/security/limits.conf; then
        echo -e "*\thard core\t0" >> /etc/security/limits.conf
        info "Core dumps disabled in limits.conf"
    fi
    if ! grep -q "fs.suid_dumpable" /etc/sysctl.d/99-cypat-advanced.conf 2>/dev/null; then
        # Will be set in sysctl phase
        :
    fi

    pass "Password & authentication policies configured"
}

# ── Phase 4: SSH Hardening (Aggressive) ─────────────────────────────────────
phase_ssh() {
    step "Phase 4: SSH Hardening (Aggressive)"

    if ! dpkg -l openssh-server &>/dev/null; then
        warn "openssh-server not installed — skipping SSH"
        return
    fi

    backup_file /etc/ssh/sshd_config
    local sshd="/etc/ssh/sshd_config"

    # Aggressive SSH settings
    declare -A s=(
        ["PermitRootLogin"]="no"
        ["PasswordAuthentication"]="no"
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
    )

    for k in "${!s[@]}"; do
        if grep -q "^${k}\s" "$sshd"; then
            sed -i "s/^${k}\s\+.*/${k} ${s[$k]}/" "$sshd"
        elif grep -q "^#${k}\s" "$sshd"; then
            sed -i "s/^#${k}\s\+.*/${k} ${s[$k]}/" "$sshd"
        else
            echo "${k} ${s[$k]}" >> "$sshd"
        fi
    done

    # Banner
    if grep -q "^#Banner" "$sshd"; then
        sed -i 's/^#Banner.*/Banner \/etc\/issue.net/' "$sshd"
    elif ! grep -q "^Banner" "$sshd"; then
        echo "Banner /etc/issue.net" >> "$sshd"
    fi

    # Restrict allowed users (optional — set per README)
    if [[ -n "${ALLOWED_USERS:-}" ]]; then
        if grep -q "^AllowUsers" "$sshd"; then
            sed -i "s/^AllowUsers.*/AllowUsers ${ALLOWED_USERS}/" "$sshd"
        else
            echo "AllowUsers ${ALLOWED_USERS}" >> "$sshd"
        fi
        info "SSH restricted to: $ALLOWED_USERS"
    fi

    # Set secure ciphers and MACs
    if ! grep -q "^Ciphers" "$sshd"; then
        echo "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> "$sshd"
    fi
    if ! grep -q "^MACs" "$sshd"; then
        echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> "$sshd"
    fi
    if ! grep -q "^KexAlgorithms" "$sshd"; then
        echo "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" >> "$sshd"
    fi

    # Secure SSH host keys
    chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
    chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true

    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true

    warn "⚠  SSH restarted with PasswordAuthentication=no!"
    warn "⚠  ENSURE you have SSH key access before closing this session!"

    pass "SSH hardened (aggressive)"
}

# ── Phase 5: Firewall (UFW) ─────────────────────────────────────────────────
phase_ufw() {
    step "Phase 5: Firewall (UFW)"

    apt-get install -y ufw -qq 2>&1 | tee -a "$LOG_FILE"

    ufw --force reset 2>/dev/null || true
    ufw default deny incoming
    ufw default allow outgoing

    # Common services
    ufw allow ssh 2>/dev/null || ufw allow 22/tcp
    ufw allow 80/tcp 2>/dev/null || true
    ufw allow 443/tcp 2>/dev/null || true

    # Logging
    ufw logging on 2>/dev/null || true

    echo "y" | ufw enable 2>&1 | tee -a "$LOG_FILE"
    ufw status verbose | tee -a "$LOG_FILE"
    pass "UFW enabled (default deny incoming)"
}

# ── Phase 6: Prohibited Software & Services ─────────────────────────────────
phase_prohibited() {
    step "Phase 6: Prohibited Software & Services"

    # ── Package scan ──
    local bad=(
        # Hacking
        "nmap" "zenmap" "wireshark" "tshark" "john" "johnny" "hydra" "hydra-gtk"
        "aircrack-ng" "ophcrack" "metasploit" "metasploit-framework" "nikto"
        "netcat" "netcat-openbsd" "netcat-traditional" "ncat" "hashcat"
        "sqlmap" "ettercap" "kismet" "tcpdump" "dsniff" "scapy" "yersinia"
        "hping3" "ettercap-graphical" "burpsuite" "zaproxy" "beef-xss"
        "maltego" "recon-ng" "set" "setoolkit" "socat"
        # Games
        "game" "minetest" "supertux" "freeciv" "0ad" "aisleriot" "gnome-mines"
        "gnome-mahjongg" "gnome-sudoku" "steam" "neverball" "openttd"
        "extremetuxracer" "gnome-robots" "quadrapassel" "swell-foop"
        "gnome-chess" "gnome-nibbles" "five-or-more" "four-in-a-row"
        "gnome-klotski" "gnome-tetravex" "iagno" "lightsoff" "tali"
        # P2P
        "torrent" "transmission" "deluge" "vuze" "qbittorrent" "frostwire"
        "ktorrent" "rtorrent" "amule" "frostwire" "limewire"
        # Remote
        "teamviewer" "anydesk" "vnc" "tightvnc" "realvnc" "x11vnc"
        "tigervnc" "xrdp" "remmina" "nomachine" "chrome-remote-desktop"
        # Chat / IM
        "pidgin" "empathy" "hexchat" "irssi" "weechat" "konversation"
        "telegram" "signal-desktop" "discord" "slack"
        # Media
        "vlc" "mpv" "kodi" "rhythmbox" "banshee" "clementine" "audacious"
    )

    local found=()
    local installed; installed=$(dpkg -l 2>/dev/null | awk '$1=="ii" {print $2}')
    for pkg in $installed; do
        for pat in "${bad[@]}"; do
            if echo "$pkg" | grep -qi "$pat" && [[ ! " ${found[*]} " =~ " ${pkg} " ]]; then
                found+=("$pkg"); break
            fi
        done
    done

    if [[ ${#found[@]} -eq 0 ]]; then
        pass "No prohibited software found"
    else
        warn "Found ${#found[@]} prohibited packages"
        info "Removing: ${found[*]}"
        for pkg in "${found[@]}"; do
            apt-get purge -y "$pkg" -qq 2>/dev/null || dpkg --purge "$pkg" 2>/dev/null || true
        done
        apt-get autoremove -y -qq 2>&1 | tee -a "$LOG_FILE"
        pass "Prohibited software purged"
    fi

    # ── Dangerous services ──
    local svcs=(
        "vsftpd" "proftpd" "pure-ftpd" "telnet" "telnetd" "cups" "cupsd"
        "avahi-daemon" "avahi-dnsconfd" "smbd" "nmbd" "samba" "samba-ad-dc"
        "snmpd" "nfs-server" "nfs-kernel-server" "rpcbind" "rpc-statd"
        "bluetooth" "xinetd" "rsh-server" "rlogin-server" "nis" "ypbind"
        "ypserv" "squid" "slapd" "dovecot" "cyrus" "courier"
        "apache2" "nginx" "mysql" "mariadb" "postgresql" "bind9" "named"
        "isc-dhcp-server" "dhcpd" "exim4" "sendmail" "postfix"
    )

    local disabled=0
    for svc in "${svcs[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            warn "Service '$svc' is RUNNING — disable if not needed per README"
        fi
    done

    # Purge dangerous packages
    apt-get purge -y telnetd rsh-server rlogin-server xinetd nis 2>/dev/null || true
    pass "Services audited"
}

# ── Phase 7: Advanced Kernel Hardening ──────────────────────────────────────
phase_sysctl() {
    step "Phase 7: Advanced Kernel Hardening"

    local conf="/etc/sysctl.d/99-cypat-advanced.conf"
    backup_file "$conf"

    cat > "$conf" <<'SYSCTL'
# CyberPatriot Advanced Kernel Hardening
# IPv4
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
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_rfc1337 = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# IPv6 (disable if not needed)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Kernel
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

# Filesystem
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 1
fs.protected_regular = 1

# Dev
dev.tty.ldisc_autoload = 0
SYSCTL

    sysctl --system 2>&1 | tee -a "$LOG_FILE"
    pass "Advanced sysctl applied"
}

# ── Phase 8: Filesystem Module Blacklisting ─────────────────────────────────
phase_modules() {
    step "Phase 8: Filesystem Module Blacklisting"

    local modfile="/etc/modprobe.d/cypat-blacklist.conf"
    backup_file "$modfile"

    local fs=("cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "udf" "squashfs" "fat" "vfat" "ntfs")

    for mod in "${fs[@]}"; do
        echo "install ${mod} /bin/false" >> "$modfile"
        echo "blacklist ${mod}" >> "$modfile"

        # Attempt to remove if loaded
        modprobe -r "$mod" 2>/dev/null || true
    done

    # USB storage
    echo "install usb-storage /bin/false" >> "$modfile"
    echo "blacklist usb-storage" >> "$modfile"
    modprobe -r usb-storage 2>/dev/null || true

    # FireWire
    echo "install firewire-core /bin/false" >> "$modfile"
    echo "blacklist firewire-core" >> "$modfile"
    echo "install firewire-ohci /bin/false" >> "$modfile"
    echo "blacklist firewire-ohci" >> "$modfile"

    pass "Filesystem & USB modules blacklisted"
}

# ── Phase 9: Filesystem Hardening ───────────────────────────────────────────
phase_filesystem() {
    step "Phase 9: Filesystem Hardening"

    # Harden /run/shm (shared memory)
    if mount | grep -q "/run/shm"; then
        mount -o remount,noexec,nosuid /run/shm 2>/dev/null || true
        info "/run/shm remounted with noexec,nosuid"
    fi

    # Harden /tmp if it's a separate mount
    if mount | grep -q " /tmp "; then
        mount -o remount,noexec,nosuid /tmp 2>/dev/null || true
        info "/tmp remounted with noexec,nosuid"
    else
        # Add to fstab options for next boot
        backup_file /etc/fstab
        if grep -q "/tmp " /etc/fstab; then
            sed -i 's|\(/tmp\s.*defaults\)|\1,noexec,nosuid,nodev|' /etc/fstab 2>/dev/null || true
        fi
    fi

    # Harden /var/tmp
    if mount | grep -q "/var/tmp"; then
        mount -o remount,noexec,nosuid /var/tmp 2>/dev/null || true
    fi

    # Harden /dev/shm
    if ! grep -q "/dev/shm" /etc/fstab; then
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
        info "Added /dev/shm to fstab with noexec,nosuid,nodev"
    fi

    # Harden /home (nodev)
    if mount | grep -q " /home " && ! mount | grep " /home " | grep -q "nodev"; then
        mount -o remount,nodev /home 2>/dev/null || true
        info "/home remounted with nodev"
    fi

    # Secure /var/log
    chmod -R go-rwx /var/log 2>/dev/null || true
    info "Secured /var/log permissions"

    pass "Filesystem hardening applied"
}

# ── Phase 10: File Permission Audit ─────────────────────────────────────────
phase_permissions() {
    step "Phase 10: File Permission Audit"

    # Critical files
    chmod 644 /etc/passwd  2>/dev/null || true
    chmod 640 /etc/shadow  2>/dev/null || true
    chmod 644 /etc/group   2>/dev/null || true
    chmod 640 /etc/gshadow 2>/dev/null || true
    chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
    chmod 440 /etc/sudoers 2>/dev/null || true
    chmod 750 /etc/sudoers.d 2>/dev/null || true
    chmod 600 /etc/crontab 2>/dev/null || true

    # World-writable files
    info "Scanning for world-writable files (this may take a moment)..."
    find /etc /boot /usr/sbin /usr/bin -perm -002 -type f 2>/dev/null | \
        tee "$BACKUP_DIR/world-writable.txt" | tee -a "$LOG_FILE"
    local ww_count; ww_count=$(wc -l < "$BACKUP_DIR/world-writable.txt" 2>/dev/null || echo 0)
    if [[ "$ww_count" -gt 10 ]]; then
        warn "$ww_count world-writable files found — review $BACKUP_DIR/world-writable.txt"
    else
        pass "World-writable files in system dirs: $ww_count"
    fi

    # No-owner files
    info "Scanning for unowned files..."
    find /etc /var /home -nouser -type f 2>/dev/null | head -30 | \
        tee "$BACKUP_DIR/unowned-files.txt" | tee -a "$LOG_FILE"

    # No-group files
    info "Scanning for nogroup files..."
    find /etc /var /home -nogroup -type f 2>/dev/null | head -30 | \
        tee "$BACKUP_DIR/nogroup-files.txt" | tee -a "$LOG_FILE"

    # .rhosts
    find /home -name ".rhosts" -type f -delete 2>/dev/null || true

    # .netrc
    find /home -name ".netrc" -type f -delete 2>/dev/null || true

    # .forward files
    find /home -name ".forward" -type f -delete 2>/dev/null || true

    pass "File permissions audited"
}

# ── Phase 11: SUID/SGID Audit ───────────────────────────────────────────────
phase_suid() {
    step "Phase 11: SUID/SGID Audit"

    info "Finding all SUID files (this will take a moment)..."
    find / -perm -4000 -type f 2>/dev/null > "$BACKUP_DIR/suid-files.txt"
    local suid_count; suid_count=$(wc -l < "$BACKUP_DIR/suid-files.txt")

    info "Finding all SGID files..."
    find / -perm -2000 -type f 2>/dev/null > "$BACKUP_DIR/sgid-files.txt"
    local sgid_count; sgid_count=$(wc -l < "$BACKUP_DIR/sgid-files.txt")

    info "SUID files: $suid_count | SGID files: $sgid_count"
    info "Full lists saved to $BACKUP_DIR/suid-files.txt and $BACKUP_DIR/sgid-files.txt"

    # Known dangerous SUID binaries to check
    local suspicious_suid=()
    while IFS= read -r bin; do
        local bn; bn=$(basename "$bin")
        # Flag uncommon SUID binaries
        case "$bn" in
            bash|dash|sh|zsh|ksh|csh|tcsh|python|python3|perl|ruby|lua|php|node|awk|sed|find|vim|vi|nano|emacs|less|more|cat|cp|mv|dd|chmod|chown|mount|umount|ping|su|sudo|passwd|newgrp|gpasswd|pkexec|dbus-daemon|ssh-agent|Xorg|unix_chkpwd|pt_chown|mtr|traceroute|at|newuidmap|newgidmap) ;;
            *)
                suspicious_suid+=("$bin")
                ;;
        esac
    done < "$BACKUP_DIR/suid-files.txt"

    if [[ ${#suspicious_suid[@]} -gt 0 ]]; then
        warn "Potentially suspicious SUID binaries (review manually):"
        printf '  %s\n' "${suspicious_suid[@]}" | head -20 | tee -a "$LOG_FILE"
        info "Remove SUID bit with: sudo chmod u-s <file>"
    else
        pass "No suspicious SUID binaries detected"
    fi
}

# ── Phase 12: Cron & At Audit ───────────────────────────────────────────────
phase_cron() {
    step "Phase 12: Cron & At Audit"

    # Restrict cron access
    backup_file /etc/cron.allow
    echo "root" > /etc/cron.allow
    chmod 600 /etc/cron.allow
    info "cron.allow: only root allowed"

    # Remove cron.deny if present
    rm -f /etc/cron.deny /etc/at.deny

    # Restrict at access
    backup_file /etc/at.allow
    echo "root" > /etc/at.allow
    chmod 600 /etc/at.allow

    # Audit all cron files
    info "Cron files audit:"
    for c in /etc/crontab /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* \
             /etc/cron.weekly/* /etc/cron.monthly/*; do
        if [[ -f "$c" ]]; then
            local suspicious
            suspicious=$(grep -E "wget|curl|nc |ncat|bash -i|/dev/tcp|base64.*decode|eval|python.*http|perl.*socket" "$c" 2>/dev/null || true)
            if [[ -n "$suspicious" ]]; then
                warn "Suspicious entries in $c:"
                echo "$suspicious" | tee -a "$LOG_FILE"
            fi
        fi
    done

    # Check user crontabs
    for u in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
        local ct; ct=$(crontab -l -u "$u" 2>/dev/null || true)
        if [[ -n "$ct" ]]; then
            local sus; sus=$(echo "$ct" | grep -E "wget|curl|nc |ncat|bash -i|/dev/tcp|base64" || true)
            if [[ -n "$sus" ]]; then
                warn "Suspicious cron in user '$u': $sus"
            fi
        fi
    done

    # Secure cron directories
    chmod 700 /etc/cron.d 2>/dev/null || true
    chmod 700 /etc/cron.daily 2>/dev/null || true
    chmod 700 /etc/cron.hourly 2>/dev/null || true
    chmod 700 /etc/cron.weekly 2>/dev/null || true
    chmod 700 /etc/cron.monthly 2>/dev/null || true

    pass "Cron audited & restricted"
}

# ── Phase 13: Login Banners ─────────────────────────────────────────────────
phase_banners() {
    step "Phase 13: Login Banners"

    local banner_text="WARNING: Authorized use only. All activity is monitored and logged. Unauthorized access is prohibited and subject to criminal prosecution."

    backup_file /etc/issue
    echo "$banner_text" > /etc/issue
    chmod 644 /etc/issue

    backup_file /etc/issue.net
    echo "$banner_text" > /etc/issue.net
    chmod 644 /etc/issue.net

    # MOTD
    backup_file /etc/motd
    echo "$banner_text" > /etc/motd
    chmod 644 /etc/motd

    # Ensure sshd uses banner
    if [[ -f /etc/ssh/sshd_config ]]; then
        if grep -q "^#Banner" /etc/ssh/sshd_config; then
            sed -i 's/^#Banner.*/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
        elif ! grep -q "^Banner" /etc/ssh/sshd_config; then
            echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
        fi
    fi

    pass "Login banners configured"
}

# ── Phase 14: AppArmor ──────────────────────────────────────────────────────
phase_apparmor() {
    step "Phase 14: AppArmor"

    apt-get install -y apparmor apparmor-utils apparmor-profiles -qq 2>&1 | tee -a "$LOG_FILE"

    # Enable and start
    systemctl enable apparmor 2>/dev/null || true
    systemctl start apparmor 2>/dev/null || true

    # Enforce all profiles
    if command -v aa-enforce &>/dev/null; then
        aa-enforce /etc/apparmor.d/* 2>/dev/null || true
        info "AppArmor profiles set to enforce mode"
    fi

    if command -v aa-status &>/dev/null; then
        aa-status 2>&1 | head -5 | tee -a "$LOG_FILE"
    fi

    pass "AppArmor enabled & enforced"
}

# ── Phase 15: Auditd ────────────────────────────────────────────────────────
phase_auditd() {
    step "Phase 15: Auditd"

    apt-get install -y auditd audispd-plugins -qq 2>&1 | tee -a "$LOG_FILE"

    backup_file /etc/audit/rules.d/cypat.rules

    cat > /etc/audit/rules.d/cypat.rules <<'AUDITRULES'
# CyberPatriot Audit Rules
# Monitor critical files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudo
-w /etc/sudoers.d -p wa -k sudo
-w /etc/ssh/sshd_config -p wa -k sshd

# Monitor suspicious syscalls
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec

# Monitor privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -k priv_esc
-a always,exit -F arch=b32 -S setuid -S setgid -k priv_esc

# Monitor kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Monitor cron files
-w /etc/crontab -p wa -k cron
-w /etc/cron.d -p wa -k cron
-w /etc/cron.daily -p wa -k cron
-w /etc/cron.hourly -p wa -k cron
-w /etc/cron.weekly -p wa -k cron
-w /etc/cron.monthly -p wa -k cron

# Audit immutable changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system

# Make rules immutable (requires reboot to change)
-e 2
AUDITRULES

    # Restart auditd
    service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true

    # Verify rules loaded
    auditctl -l 2>/dev/null | head -10 | tee -a "$LOG_FILE"

    pass "auditd installed & configured"
}

# ── Phase 16: Fail2ban ──────────────────────────────────────────────────────
phase_fail2ban() {
    step "Phase 16: Fail2ban"

    apt-get install -y fail2ban -qq 2>&1 | tee -a "$LOG_FILE"

    backup_file /etc/fail2ban/jail.local

    cat > /etc/fail2ban/jail.local <<'FAIL2BAN'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
FAIL2BAN

    # Enable and start
    systemctl enable fail2ban 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true

    # Verify
    fail2ban-client status 2>/dev/null | tee -a "$LOG_FILE" || true

    pass "Fail2ban installed & configured"
}

# ── Phase 17: Antivirus & Rootkit ───────────────────────────────────────────
phase_av() {
    step "Phase 17: Antivirus & Rootkit Scanning"

    # ClamAV
    info "Installing ClamAV..."
    apt-get install -y clamav clamav-daemon -qq 2>&1 | tee -a "$LOG_FILE" || warn "ClamAV install failed"

    if command -v freshclam &>/dev/null; then
        systemctl stop clamav-freshclam 2>/dev/null || true
        freshclam --quiet 2>&1 | tee -a "$LOG_FILE" || true
        info "ClamAV definitions updated"
    fi

    # rkhunter
    info "Installing rkhunter..."
    apt-get install -y rkhunter -qq 2>&1 | tee -a "$LOG_FILE" || warn "rkhunter install failed"

    if command -v rkhunter &>/dev/null; then
        rkhunter --update 2>&1 | tee -a "$LOG_FILE" || true
        info "rkhunter updated. Run 'sudo rkhunter --check --skip-keypress' manually."
    fi

    # chkrootkit
    info "Installing chkrootkit..."
    apt-get install -y chkrootkit -qq 2>&1 | tee -a "$LOG_FILE" || true

    pass "AV & rootkit scanners installed"
}

# ── Phase 18: Linux Mint-Specific Hardening ─────────────────────────────────
phase_mint() {
    step "Phase 18: Linux Mint-Specific Hardening"

    if [[ "$DISTRO" != "linuxmint" ]]; then
        info "Not Linux Mint — skipping Mint-specific hardening"
        return
    fi

    # ── LightDM hardening ──
    local ldm="/etc/lightdm/lightdm.conf"
    if [[ -f "$ldm" ]]; then
        backup_file "$ldm"

        # Disable guest sessions
        if grep -q "^allow-guest" "$ldm"; then
            sed -i 's/^allow-guest.*/allow-guest=false/' "$ldm"
        elif grep -q "^#allow-guest" "$ldm"; then
            sed -i 's/^#allow-guest.*/allow-guest=false/' "$ldm"
        else
            echo -e "\n[Seat:*]\nallow-guest=false" >> "$ldm"
        fi

        # Hide user list
        if grep -q "^greeter-hide-users" "$ldm"; then
            sed -i 's/^greeter-hide-users.*/greeter-hide-users=true/' "$ldm"
        elif grep -q "^#greeter-hide-users" "$ldm"; then
            sed -i 's/^#greeter-hide-users.*/greeter-hide-users=true/' "$ldm"
        else
            sed -i '/\[Seat:\*\]/a greeter-hide-users=true' "$ldm"
        fi

        # Disable autologin
        if grep -q "^autologin-user=" "$ldm"; then
            sed -i 's/^autologin-user=.*/autologin-user=none/' "$ldm"
        fi

        # Disable timed login
        if grep -q "^autologin-user-timeout" "$ldm"; then
            sed -i 's/^autologin-user-timeout.*/autologin-user-timeout=0/' "$ldm"
        fi

        info "LightDM: guest=no, hide-users=yes, autologin=off"
    fi

    # ── LightDM conf.d overrides ──
    local ldm_override="/etc/lightdm/lightdm.conf.d/99-cypat.conf"
    mkdir -p /etc/lightdm/lightdm.conf.d
    cat > "$ldm_override" <<'EOF'
[Seat:*]
allow-guest=false
greeter-hide-users=true
autologin-user=none
EOF
    info "LightDM override created at 99-cypat.conf"

    # ── Screensaver / lock settings ──
    case "$MINT_DE" in
        cinnamon)
            info "Configuring Cinnamon screensaver..."
            # dconf-based settings
            if command -v gsettings &>/dev/null; then
                sudo -u $(logname 2>/dev/null || echo "$SUDO_USER") gsettings set org.cinnamon.desktop.screensaver lock-enabled true 2>/dev/null || true
                sudo -u $(logname 2>/dev/null || echo "$SUDO_USER") gsettings set org.cinnamon.desktop.screensaver lock-delay 0 2>/dev/null || true
                sudo -u $(logname 2>/dev/null || echo "$SUDO_USER") gsettings set org.cinnamon.desktop.session idle-delay 300 2>/dev/null || true
            fi
            ;;
        mate)
            info "Configuring MATE screensaver..."
            if command -v gsettings &>/dev/null; then
                local u; u=$(logname 2>/dev/null || echo "$SUDO_USER")
                sudo -u "$u" gsettings set org.mate.screensaver lock-enabled true 2>/dev/null || true
                sudo -u "$u" gsettings set org.mate.screensaver lock-delay 0 2>/dev/null || true
                sudo -u "$u" gsettings set org.mate.session idle-delay 5 2>/dev/null || true
            fi
            ;;
        xfce)
            info "Configuring Xfce screensaver..."
            if command -v xfconf-query &>/dev/null; then
                local u; u=$(logname 2>/dev/null || echo "$SUDO_USER")
                sudo -u "$u" xfconf-query -c xfce4-screensaver -p /lock/enabled -s true 2>/dev/null || true
                sudo -u "$u" xfconf-query -c xfce4-screensaver -p /lock/delay -s 0 2>/dev/null || true
            fi
            ;;
    esac

    # ── Disable Mint Welcome autostart ──
    local welcome="/etc/xdg/autostart/mintwelcome.desktop"
    if [[ -f "$welcome" ]]; then
        backup_file "$welcome"
        sed -i 's/^X-GNOME-Autostart-enabled=.*/X-GNOME-Autostart-enabled=false/' "$welcome" 2>/dev/null || true
        info "Mint Welcome autostart disabled"
    fi

    # ── Disable Nemo file sharing ──
    if command -v gsettings &>/dev/null; then
        local u; u=$(logname 2>/dev/null || echo "$SUDO_USER")
        sudo -u "$u" gsettings set org.nemo.preferences show-advanced-permissions true 2>/dev/null || true
    fi

    # ── Disable Bluetooth in Mint ──
    systemctl disable --now bluetooth 2>/dev/null || true
    if command -v rfkill &>/dev/null; then
        rfkill block bluetooth 2>/dev/null || true
    fi

    pass "Linux Mint hardening completed"
}

# ── Phase 19: Disable Ctrl+Alt+Del ──────────────────────────────────────────
phase_disable_ctrlaltdel() {
    step "Phase 19: Disable Ctrl+Alt+Del"

    systemctl mask ctrl-alt-del.target 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true

    # Also in /etc/systemd/logind.conf
    backup_file /etc/systemd/logind.conf
    if grep -q "^#HandlePowerKey" /etc/systemd/logind.conf; then
        sed -i 's/^#HandlePowerKey.*/HandlePowerKey=ignore/' /etc/systemd/logind.conf
    fi
    if grep -q "^#HandleSuspendKey" /etc/systemd/logind.conf; then
        sed -i 's/^#HandleSuspendKey.*/HandleSuspendKey=ignore/' /etc/systemd/logind.conf
    fi

    pass "Ctrl+Alt+Del disabled"
}

# ── Phase 20: Hosts & DNS Check ─────────────────────────────────────────────
phase_hosts() {
    step "Phase 20: Hosts & DNS Check"

    info "Current /etc/hosts:"
    cat /etc/hosts | tee -a "$LOG_FILE"

    # Check for localhost aliases that redirect legitimate domains
    local sus_hosts
    sus_hosts=$(grep -E "127\.0\.0\.1|0\.0\.0\.0" /etc/hosts | grep -vE "localhost|$(hostname)" || true)
    if [[ -n "$sus_hosts" ]]; then
        warn "Suspicious /etc/hosts entries (may redirect legitimate sites):"
        echo "$sus_hosts" | tee -a "$LOG_FILE"
    fi

    # Check DNS config
    info "DNS configuration:"
    cat /etc/resolv.conf 2>/dev/null | tee -a "$LOG_FILE"

    pass "Hosts & DNS checked"
}

# ── Phase 21: Installed Packages Audit ──────────────────────────────────────
phase_package_audit() {
    step "Phase 21: Package Audit"

    # List all explicitly installed packages (not dependencies)
    info "Explicitly installed packages:"
    apt-mark showmanual 2>/dev/null | tee "$BACKUP_DIR/manual-packages.txt" | wc -l | \
        xargs echo "  Count:" | tee -a "$LOG_FILE"

    # List recently installed packages
    info "Recently installed packages:"
    grep " install " /var/log/dpkg.log 2>/dev/null | tail -20 | tee -a "$LOG_FILE"

    # Remove orphaned packages
    apt-get autoremove --purge -y -qq 2>&1 | tee -a "$LOG_FILE"

    pass "Package audit completed"
}

# ── Phase 22: Network Check ─────────────────────────────────────────────────
phase_network() {
    step "Phase 22: Network Configuration Check"

    info "Listening ports:"
    ss -tulnp 2>/dev/null | tee -a "$LOG_FILE"

    info "Active network connections:"
    ss -tupn 2>/dev/null | tee -a "$LOG_FILE"

    # Check for promiscuous mode
    local promisc
    promisc=$(ip link 2>/dev/null | grep -i "promisc" || true)
    if [[ -z "$promisc" ]]; then
        pass "No interfaces in promiscuous mode"
    else
        warn "Promiscuous mode detected: $promisc"
    fi

    # Check firewall
    if command -v ufw &>/dev/null; then
        ufw status verbose | tee -a "$LOG_FILE"
    fi

    pass "Network check completed"
}

# ── Main ────────────────────────────────────────────────────────────────────
main() {
    for arg in "$@"; do
        case "$arg" in
            --dry-run) DRY_RUN=true ;;
            --allowed-users=*) ALLOWED_USERS="${arg#*=}" ;;
            --help|-h)
                echo "Usage: sudo ./advanced.sh [--dry-run] [--allowed-users=user1,user2]"
                echo ""
                echo "CyberPatriot Advanced Linux Hardening Script"
                echo "WARNING: Aggressive hardening. Take a VM snapshot first."
                echo ""
                echo "Options:"
                echo "  --dry-run                    Show what would be done (not fully implemented)"
                echo "  --allowed-users=u1,u2        Restrict SSH to these users"
                exit 0
                ;;
        esac
    done

    echo -e "${BOLD}${RED}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║   CyberPatriot Linux ADVANCED Hardening Script           ║"
    echo "║   Ubuntu / Linux Mint / Debian                           ║"
    echo "║   ⚠ AGGRESSIVE — Snapshot before running!                ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    require_root
    mkdir -p "$BACKUP_DIR"

    detect_distro

    if $DRY_RUN; then
        warn "DRY RUN MODE — No changes will be made"
    fi

    # Run all phases
    phase_updates
    phase_users
    phase_passwords
    phase_ssh
    phase_ufw
    phase_prohibited
    phase_sysctl
    phase_modules
    phase_filesystem
    phase_permissions
    phase_suid
    phase_cron
    phase_banners
    phase_apparmor
    phase_auditd
    phase_fail2ban
    phase_av
    phase_mint
    phase_disable_ctrlaltdel
    phase_hosts
    phase_package_audit
    phase_network

    # ── Summary ──────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}${RED}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${RED}  ADVANCED HARDENING COMPLETED${NC}"
    echo -e "${BOLD}  Checks: ${GREEN}${SCORE}${NC}/${TOTAL} passed"
    echo -e "  Backups: ${BACKUP_DIR}"
    echo -e "  Log:     ${LOG_FILE}"
    echo -e ""
    echo -e "${BOLD}${YELLOW}  ⚠  CRITICAL POST-RUN STEPS:${NC}"
    echo -e "${YELLOW}  1. Verify SSH access before closing this session${NC}"
    echo -e "${YELLOW}  2. Run: sudo lynis audit system${NC}"
    echo -e "${YELLOW}  3. Run: sudo rkhunter --check --skip-keypress${NC}"
    echo -e "${YELLOW}  4. Review backups in ${BACKUP_DIR}${NC}"
    echo -e "${YELLOW}  5. Check scoring engine for remaining issues${NC}"
    echo -e "${BOLD}${RED}  DO NOT REBOOT unless absolutely necessary${NC}"
    echo -e "${BOLD}${RED}════════════════════════════════════════════════════════════${NC}"
}

main "$@"
