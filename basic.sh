#!/bin/bash
###############################################################################
#  CyberPatriot Linux Basic Hardening Script
#  Supports: Ubuntu 20.04/22.04/24.04, Linux Mint 20/21/22, Debian 10/11/12
#
#  Usage: sudo ./basic.sh
#
#  This script handles the most common, high-impact hardening steps that
#  score points quickly. It is designed to be safe and not break critical
#  services — always read the competition README first before running.
###############################################################################

set -euo pipefail
IFS=$'\n\t'

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m';    GREEN='\033[0;32m';   YELLOW='\033[1;33m'
BLUE='\033[0;34m';   MAGENTA='\033[0;35m'; CYAN='\033[0;36m'
BOLD='\033[1m';      NC='\033[0m'

# ── Globals ─────────────────────────────────────────────────────────────────
BACKUP_DIR="/tmp/cypat-backup-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/var/log/cypat-basic-$(date +%Y%m%d-%H%M%S).log"
SCORE=0
TOTAL=0
DRY_RUN=false
DISTRO=""
DISTRO_VERSION=""
VERSION_ID=""

# ── Utility Functions ───────────────────────────────────────────────────────

log_msg() {
    local level=$1 msg=$2
    echo -e "$(date '+%H:%M:%S') [$level] $msg" | tee -a "$LOG_FILE"
}

pass()  { log_msg "${GREEN}PASS${NC}" "$1"; ((SCORE++)); ((TOTAL++)); }
fail()  { log_msg "${RED}FAIL${NC}" "$1"; ((TOTAL++)); }
warn()  { log_msg "${YELLOW}WARN${NC}" "$1"; }
info()  { log_msg "${BLUE}INFO${NC}" "$1"; }
step()  { echo -e "\n${BOLD}${CYAN}═══ $1 ═══${NC}" | tee -a "$LOG_FILE"; }

backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR/$(dirname "$file")"
        cp -a "$file" "$BACKUP_DIR/$file"
        info "Backed up: $file"
    fi
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: This script must be run as root (use sudo).${NC}"
        exit 1
    fi
}

check_dry_run() {
    if $DRY_RUN; then
        warn "DRY RUN — no changes made. Re-run without --dry-run to apply."
        return 0
    fi
    return 1
}

# ── Distro Detection ────────────────────────────────────────────────────────

detect_distro() {
    step "Detecting Distribution"

    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        DISTRO="${ID,,}"           # lowercase: ubuntu, linuxmint, debian
        VERSION_ID="${VERSION_ID:-}"
        DISTRO_VERSION="$VERSION_ID"
    elif [[ -f /etc/lsb-release ]]; then
        source /etc/lsb-release
        DISTRO="${DISTRIB_ID,,}"
        DISTRO_VERSION="${DISTRIB_RELEASE:-}"
    else
        warn "Cannot detect distro. Assuming Ubuntu."
        DISTRO="ubuntu"
        DISTRO_VERSION="22.04"
    fi

    # Normalize Linux Mint
    if [[ "$DISTRO" == "linuxmint" || "$DISTRO" == "linux mint" || "$DISTRO" == "mint" ]]; then
        DISTRO="linuxmint"
        # Mint 21 = Ubuntu 22.04 base, Mint 20 = Ubuntu 20.04 base, Mint 22 = Ubuntu 24.04 base
        local mint_ver="${DISTRO_VERSION%%.*}"
        case "$mint_ver" in
            20) DISTRO_VERSION="20.04" ;;  # ~Ubuntu 20.04
            21) DISTRO_VERSION="22.04" ;;  # ~Ubuntu 22.04
            22) DISTRO_VERSION="24.04" ;;  # ~Ubuntu 24.04
            *)  DISTRO_VERSION="22.04" ;;  # assume jammy-era
        esac
    fi

    info "Detected: $DISTRO (version $DISTRO_VERSION)"
    info "Backup directory: $BACKUP_DIR"
    info "Log file: $LOG_FILE"
}

# ── Phase 1: System Updates ─────────────────────────────────────────────────

phase_update() {
    step "Phase 1: System Updates"

    info "Updating package lists..."
    apt-get update -qq 2>&1 | tee -a "$LOG_FILE" || warn "apt update had warnings"

    info "Installing security updates..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq 2>&1 | tee -a "$LOG_FILE" || warn "apt upgrade had warnings"

    info "Removing unused packages..."
    apt-get autoremove -y -qq 2>&1 | tee -a "$LOG_FILE"

    # Enable automatic security updates
    info "Enabling unattended security updates..."
    apt-get install -y unattended-upgrades -qq 2>&1 | tee -a "$LOG_FILE"

    if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
        backup_file /etc/apt/apt.conf.d/20auto-upgrades
    fi

    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    pass "System updates completed"
}

# ── Phase 2: User & Group Management ────────────────────────────────────────

phase_users() {
    step "Phase 2: User & Group Management"

    # List all human users (UID >= 1000)
    info "Human users on system:"
    awk -F: '$3 >= 1000 && $3 < 65534 {print "  "$1" (UID="$3")"}' /etc/passwd | tee -a "$LOG_FILE"

    # Check for UID 0 accounts (should only be root)
    local uid0_count
    uid0_count=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | wc -l)
    if [[ "$uid0_count" -eq 1 ]]; then
        pass "Only root has UID 0"
    else
        warn "Multiple UID 0 accounts found!"
        awk -F: '$3 == 0 {print "  "$1}' /etc/passwd | tee -a "$LOG_FILE"
    fi

    # Check for users with empty passwords
    local empty_pw
    empty_pw=$(awk -F: '($2 == "" || $2 == "!") && $3 >= 1000 {print $1}' /etc/shadow 2>/dev/null || true)
    if [[ -z "$empty_pw" ]]; then
        pass "No users with empty passwords"
    else
        warn "Users with empty/disabled passwords: $empty_pw"
    fi

    # Check sudo group members
    info "Sudo group members:"
    getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' | while read -r u; do
        [[ -n "$u" ]] && echo "  $u"
    done | tee -a "$LOG_FILE"

    # Check other sensitive groups
    for grp in adm shadow disk plugdev; do
        local members
        members=$(getent group "$grp" 2>/dev/null | cut -d: -f4 || true)
        if [[ -n "$members" ]]; then
            warn "Group '$grp' has members: $members — review these"
        fi
    done

    # Lock root from direct login if sudo exists
    if command -v sudo &>/dev/null; then
        passwd -l root 2>/dev/null && info "Root account locked (use sudo)" || true
    fi

    pass "User audit completed"
}

# ── Phase 3: Password Policies ──────────────────────────────────────────────

phase_passwords() {
    step "Phase 3: Password Policies"

    # Configure password aging in /etc/login.defs
    backup_file /etc/login.defs

    local aging_settings=(
        "PASS_MAX_DAYS 90"
        "PASS_MIN_DAYS 7"
        "PASS_WARN_AGE 14"
    )

    for setting in "${aging_settings[@]}"; do
        local key="${setting%% *}"
        local val="${setting##* }"
        if grep -q "^${key}\s" /etc/login.defs; then
            sed -i "s/^${key}\s\+.*/${key}\t${val}/" /etc/login.defs
        else
            echo "${key}	${val}" >> /etc/login.defs
        fi
    done
    info "Password aging: MAX=90 MIN=7 WARN=14"

    # Apply aging to existing human users
    local users
    users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd)
    for user in $users; do
        chage -M 90 -m 7 -W 14 "$user" 2>/dev/null || true
    done
    info "Applied password aging to existing users"

    # Install and configure libpam-pwquality (Ubuntu/Mint) or libpam-cracklib (Debian)
    if [[ "$DISTRO" == "debian" ]]; then
        # Debian uses libpam-cracklib
        apt-get install -y libpam-cracklib -qq 2>&1 | tee -a "$LOG_FILE"
        backup_file /etc/pam.d/common-password

        # Check if cracklib is already configured
        if ! grep -q "pam_cracklib.so" /etc/pam.d/common-password; then
            local cracklib_line="password requisite pam_cracklib.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"
            sed -i "0,/^password.*pam_unix.so/s//${cracklib_line}\n&/" /etc/pam.d/common-password
            info "Added pam_cracklib configuration"
        else
            sed -i "s/^password\s\+requisite\s\+pam_cracklib.so.*/password requisite pam_cracklib.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/" /etc/pam.d/common-password
            info "Updated pam_cracklib configuration"
        fi
    else
        # Ubuntu/Mint use libpam-pwquality
        apt-get install -y libpam-pwquality -qq 2>&1 | tee -a "$LOG_FILE"
        backup_file /etc/pam.d/common-password

        if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
            local pwqual_line="password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"
            sed -i "0,/^password.*pam_unix.so/s//${pwqual_line}\n&/" /etc/pam.d/common-password
            info "Added pam_pwquality configuration"
        else
            sed -i "s/^password\s\+requisite\s\+pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/" /etc/pam.d/common-password
            info "Updated pam_pwquality configuration"
        fi
    fi

    # Enable password history (remember=5)
    if grep -q "pam_unix.so" /etc/pam.d/common-password; then
        if ! grep "remember=" /etc/pam.d/common-password > /dev/null 2>&1; then
            sed -i "s/\(pam_unix.so.*\)/\1 remember=5/" /etc/pam.d/common-password
            info "Enabled password history (remember=5)"
        fi
    fi

    # Basic account lockout via faillock (Ubuntu/Mint)
    if [[ "$DISTRO" != "debian" ]]; then
        backup_file /etc/pam.d/common-auth
        if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
            local faillock_pre="auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900"
            local faillock_fail="auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900"
            # Insert before pam_deny
            sed -i "/^auth.*pam_deny.so/i ${faillock_fail}" /etc/pam.d/common-auth
            sed -i "0,/^auth/s//${faillock_pre}\n&/" /etc/pam.d/common-auth
            info "Added PAM faillock (5 attempts, 15min lockout)"
        fi
    fi

    pass "Password policies configured"
}

# ── Phase 4: SSH Hardening ──────────────────────────────────────────────────

phase_ssh() {
    step "Phase 4: SSH Hardening"

    if ! dpkg -l openssh-server &>/dev/null; then
        warn "openssh-server not installed — skipping SSH hardening"
        return
    fi

    backup_file /etc/ssh/sshd_config
    local sshd="/etc/ssh/sshd_config"

    declare -A ssh_settings=(
        ["PermitRootLogin"]="no"
        ["PermitEmptyPasswords"]="no"
        ["X11Forwarding"]="no"
        ["MaxAuthTries"]="3"
        ["ClientAliveInterval"]="300"
        ["ClientAliveCountMax"]="2"
        ["AllowTcpForwarding"]="no"
        ["Protocol"]="2"
    )

    # NOTE: PasswordAuthentication is NOT disabled by default in the basic
    # script because many competition images require it. Set to 'no' manually
    # if the README allows key-based auth only.
    ssh_settings["PasswordAuthentication"]="yes"  # keep password auth

    for key in "${!ssh_settings[@]}"; do
        local val="${ssh_settings[$key]}"
        if grep -q "^${key}\s" "$sshd"; then
            sed -i "s/^${key}\s\+.*/${key} ${val}/" "$sshd"
        elif grep -q "^#${key}\s" "$sshd"; then
            sed -i "s/^#${key}\s\+.*/${key} ${val}/" "$sshd"
        else
            echo "${key} ${val}" >> "$sshd"
        fi
    done

    # Set login banner if /etc/issue.net exists
    if [[ -f /etc/issue.net ]]; then
        if grep -q "^#Banner" "$sshd"; then
            sed -i 's/^#Banner.*/Banner \/etc\/issue.net/' "$sshd"
        elif ! grep -q "^Banner" "$sshd"; then
            echo "Banner /etc/issue.net" >> "$sshd"
        fi
    fi

    # Restart SSH (but warn about testing)
    info "SSH configuration written. Restarting sshd..."
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true

    warn "SSH restarted — verify you can still connect before closing this session!"
    pass "SSH hardened"
}

# ── Phase 5: Firewall (UFW) ─────────────────────────────────────────────────

phase_ufw() {
    step "Phase 5: Firewall Configuration (UFW)"

    apt-get install -y ufw -qq 2>&1 | tee -a "$LOG_FILE"

    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH by default
    ufw allow ssh 2>/dev/null || ufw allow 22/tcp

    # Allow HTTP/HTTPS (common competition services)
    ufw allow 80/tcp 2>/dev/null || true
    ufw allow 443/tcp 2>/dev/null || true

    info "UFW rules configured. Enabling firewall..."
    echo "y" | ufw enable 2>&1 | tee -a "$LOG_FILE"

    ufw status verbose | tee -a "$LOG_FILE"
    pass "UFW firewall enabled"
}

# ── Phase 6: Prohibited Software Removal ─────────────────────────────────────

phase_prohibited_software() {
    step "Phase 6: Prohibited Software Scan & Removal"

    local prohibited_patterns=(
        # Hacking tools
        "nmap" "wireshark" "john" "hydra" "aircrack" "ophcrack"
        "metasploit" "nikto" "netcat" "hashcat" "sqlmap" "ettercap"
        "kismet" "tcpdump" "ettercap" "burp" "zaproxy" "beef"
        "maltego" "recon-ng" "set" "social-engineer"
        # Games
        "game" "minetest" "supertux" "freeciv" "0ad" "aisleriot"
        "gnome-mines" "steam" "gnome-games" "neverball" "openttd"
        # Torrent / P2P
        "torrent" "transmission" "deluge" "vuze" "qbittorrent" "frostwire"
        # Remote access
        "teamviewer" "anydesk" "vnc" "tightvnc" "realvnc" "x11vnc"
        "tigervnc" "xrdp" "remmina"
    )

    local found_packages=()
    for pattern in "${prohibited_patterns[@]}"; do
        local matches
        matches=$(dpkg -l 2>/dev/null | awk '$1=="ii" {print $2}' | grep -iE "$pattern" || true)
        if [[ -n "$matches" ]]; then
            while IFS= read -r pkg; do
                found_packages+=("$pkg")
            done <<< "$matches"
        fi
    done

    if [[ ${#found_packages[@]} -eq 0 ]]; then
        pass "No prohibited software found"
    else
        warn "Found prohibited packages: ${found_packages[*]}"
        info "Purging prohibited packages..."
        for pkg in "${found_packages[@]}"; do
            info "Removing: $pkg"
            apt-get purge -y "$pkg" -qq 2>&1 | tee -a "$LOG_FILE" || warn "Failed to remove $pkg"
        done
        apt-get autoremove -y -qq 2>&1 | tee -a "$LOG_FILE"
        pass "Prohibited software removed"
    fi
}

# ── Phase 7: Dangerous Services ─────────────────────────────────────────────

phase_dangerous_services() {
    step "Phase 7: Disable Dangerous Services"

    local dangerous_services=(
        "vsftpd" "proftpd" "pure-ftpd"        # FTP
        "telnet" "telnetd"                      # Telnet
        "cups" "cupsd"                          # Printing
        "avahi-daemon" "avahi-dnsconfd"        # mDNS
        "smbd" "nmbd" "samba" "samba-ad-dc"    # Samba
        "snmpd"                                 # SNMP
        "nfs-server" "nfs-kernel-server" "rpcbind" "rpc-statd"  # NFS
        "bluetooth"                             # Bluetooth
        "xinetd"                                # xinetd
        "rsh-server" "rlogin-server"           # R-services
        "nis" "ypbind" "ypserv"                # NIS
        "squid"                                 # Proxy
        "sendmail" "postfix"                    # Mail (if not required)
    )

    local disabled_count=0
    for svc in "${dangerous_services[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl disable --now "$svc" 2>/dev/null && {
                info "Disabled: $svc"
                ((disabled_count++))
            } || true
        fi
        if dpkg -l | grep -qw "$svc" 2>/dev/null; then
            warn "$svc package is installed — consider purging if not needed"
        fi
    done

    # Purge telnetd and r-services explicitly
    apt-get purge -y telnetd rsh-server rlogin-server xinetd 2>/dev/null || true

    info "Disabled $disabled_count dangerous services"
    pass "Dangerous services checked"
}

# ── Phase 8: Basic Kernel Hardening (sysctl) ─────────────────────────────────

phase_sysctl() {
    step "Phase 8: Kernel Hardening (sysctl)"

    local sysctl_conf="/etc/sysctl.d/99-cypat-basic.conf"
    backup_file "$sysctl_conf"

    cat > "$sysctl_conf" <<'SYSCTL'
# CyberPatriot Basic Kernel Hardening
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
net.ipv4.conf.all.log_martians = 1
SYSCTL

    sysctl --system 2>&1 | tee -a "$LOG_FILE"
    pass "Kernel hardening applied"
}

# ── Phase 9: Basic Malware Check ─────────────────────────────────────────────

phase_malware() {
    step "Phase 9: Basic Malware & Backdoor Check"

    # Check for suspicious listening ports
    info "Listening ports:"
    ss -tulnp 2>/dev/null | tee -a "$LOG_FILE" || netstat -tulnp 2>/dev/null | tee -a "$LOG_FILE"

    # Check for reverse shell processes
    local suspicious_procs
    suspicious_procs=$(ps aux 2>/dev/null | grep -Ei "nc |ncat|netcat|bash -i|/dev/tcp|/dev/udp" | grep -v grep || true)
    if [[ -z "$suspicious_procs" ]]; then
        pass "No suspicious processes found"
    else
        warn "Suspicious processes detected:"
        echo "$suspicious_procs" | tee -a "$LOG_FILE"
        warn "Review the above processes manually"
    fi

    # Check crontabs for suspicious entries
    info "Checking crontabs..."
    local suspicious_cron
    suspicious_cron=$( (
        crontab -l 2>/dev/null || true
        cat /etc/crontab 2>/dev/null || true
        cat /etc/cron.d/* 2>/dev/null || true
    ) | grep -Ei "wget|curl|nc |ncat|bash -i|/dev/tcp|base64.*decode|eval" | grep -v '^#' || true)

    if [[ -z "$suspicious_cron" ]]; then
        pass "No suspicious cron entries"
    else
        warn "Suspicious cron entries found:"
        echo "$suspicious_cron" | tee -a "$LOG_FILE"
    fi

    # Check for recently modified files (< 3 days) in key directories
    info "Recently modified files in /etc, /home, /tmp:"
    find /etc /home /tmp /var/tmp -mtime -3 -type f 2>/dev/null | head -30 | tee -a "$LOG_FILE"

    # Check for hidden files in /home
    info "Hidden files in home directories:"
    find /home -maxdepth 2 -name ".*" -type f 2>/dev/null | tee -a "$LOG_FILE"

    pass "Malware check completed"
}

# ── Phase 10: File Permissions ───────────────────────────────────────────────

phase_file_perms() {
    step "Phase 10: Critical File Permissions"

    # Fix critical file permissions
    chmod 644 /etc/passwd && info "/etc/passwd → 644" || true
    chmod 640 /etc/shadow && info "/etc/shadow → 640" || true
    chmod 644 /etc/group && info "/etc/group → 644" || true
    chmod 640 /etc/gshadow 2>/dev/null && info "/etc/gshadow → 640" || true

    # Secure SSH host keys
    chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true

    # Find world-writable files in /etc (potential backdoors)
    local ww_files
    ww_files=$(find /etc -perm -002 -type f 2>/dev/null || true)
    if [[ -n "$ww_files" ]]; then
        warn "World-writable files in /etc (review manually):"
        echo "$ww_files" | tee -a "$LOG_FILE"
    else
        pass "No world-writable files in /etc"
    fi

    pass "File permissions hardened"
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
    # Parse arguments
    for arg in "$@"; do
        case "$arg" in
            --dry-run) DRY_RUN=true ;;
            --help|-h)
                echo "Usage: sudo ./basic.sh [--dry-run]"
                echo ""
                echo "CyberPatriot Basic Linux Hardening Script"
                echo "Covers: updates, users, passwords, SSH, UFW, prohibited"
                echo "        software, dangerous services, sysctl, malware check,"
                echo "        and file permissions."
                exit 0
                ;;
        esac
    done

    echo -e "${BOLD}${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║     CyberPatriot Linux Basic Hardening Script            ║"
    echo "║     Ubuntu / Linux Mint / Debian                         ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    require_root
    mkdir -p "$BACKUP_DIR"

    detect_distro

    if $DRY_RUN; then
        warn "RUNNING IN DRY-RUN MODE — No changes will be made"
    fi

    # Run all phases
    phase_update
    phase_users
    phase_passwords
    phase_ssh
    phase_ufw
    phase_prohibited_software
    phase_dangerous_services
    phase_sysctl
    phase_malware
    phase_file_perms

    # ── Summary ──────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  SCRIPT COMPLETED${NC}"
    echo -e "${BOLD}  Score: ${GREEN}${SCORE}${NC}/${TOTAL} checks passed"
    echo -e "  Backups: ${BACKUP_DIR}"
    echo -e "  Log:     ${LOG_FILE}"
    echo -e "${BOLD}${YELLOW}  ⚠  REBOOT NOT recommended unless necessary${NC}"
    echo -e "${BOLD}  ⚠  Verify SSH access before closing this session${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════${NC}"

    if [[ $SCORE -lt $TOTAL ]]; then
        warn "Some checks failed — review the log and address manually."
    fi
}

main "$@"
