#!/bin/bash
###############################################################################
#  CyberPatriot — Service Management (Standalone)
#  Run: sudo ./systemctl.sh [--keep apache2,ssh]
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

LOG="/var/log/cypat-systemctl-$(date +%Y%m%d-%H%M%S).log"
KEEP_LIST=()
DRY_RUN=false

info()  { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG"; }
pass()  { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$LOG"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG"; }
step()  { echo -e "\n${BOLD}${CYAN}═══ $1 ═══${NC}" | tee -a "$LOG"; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: Run as root (sudo).${NC}"; exit 1
    fi
}

in_keep_list() {
    local svc=$1
    for k in "${KEEP_LIST[@]}"; do
        [[ "${k,,}" == "${svc,,}" ]] && return 0
    done
    return 1
}

main() {
    for arg in "$@"; do
        case "$arg" in
            --keep=*)
                IFS=',' read -ra parts <<< "${arg#*=}"
                for p in "${parts[@]}"; do
                    KEEP_LIST+=("${p## }")  # trim leading space
                done
                ;;
            --dry-run) DRY_RUN=true ;;
            --help|-h)
                echo "Usage: sudo ./systemctl.sh [--keep=ssh,apache2] [--dry-run]"
                echo "  --keep=svc1,svc2   Services to keep running"
                echo "  --dry-run          Show what would be disabled"
                exit 0
                ;;
        esac
    done

    echo -e "${BOLD}${BLUE}╔══ Service Management ══╗${NC}"
    require_root

    local user_keep=("${KEEP_LIST[@]}")
    # Always keep these system-critical services
    KEEP_LIST+=("systemd" "dbus" "polkit" "accounts-daemon" "rsyslog"
                "systemd-journald" "systemd-logind" "systemd-resolved"
                "systemd-timesyncd" "systemd-udevd" "NetworkManager"
                "networkd-dispatcher" "ModemManager" "udisks2"
                "upower" "rtkit-daemon" "colord" "unattended-upgrades"
                "cron" "anacron" "atd" "ssh" "sshd" "ufw")

    step "Current running services"
    systemctl list-units --type=service --state=running --no-legend 2>/dev/null | \
        awk '{print $1}' | tee -a "$LOG"
    info "See log for full list"

    step "Enabled services at boot"
    systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | \
        awk '{print $1}' | tee -a "$LOG"

    step "Listening ports (identify exposed services)"
    ss -tulnp 2>/dev/null | tee -a "$LOG" || netstat -tulnp 2>/dev/null | tee -a "$LOG"

    step "Dangerous services to disable"

    local dangerous=(
        # FTP
        "vsftpd" "proftpd" "pure-ftpd" "wu-ftpd"
        # Telnet
        "telnet" "telnetd" "telnet.socket"
        # Printing
        "cups" "cupsd" "cups-browsed"
        # mDNS / Zeroconf
        "avahi-daemon" "avahi-dnsconfd" "avahi-daemon.socket"
        # Samba / Windows networking
        "smbd" "nmbd" "samba" "samba-ad-dc" "winbind"
        # SNMP
        "snmpd" "snmptrapd"
        # NFS / RPC
        "nfs-server" "nfs-kernel-server" "nfs-blkmap" "rpcbind" "rpc-statd"
        "rpcbind.socket"
        # Bluetooth
        "bluetooth"
        # xinetd superserver
        "xinetd"
        # R-services
        "rsh-server" "rlogin-server" "rexec" "rsh.socket" "rlogin.socket"
        # NIS
        "nis" "ypbind" "ypserv" "ypxfrd"
        # Proxy
        "squid"
        # Mail (unless specifically required)
        "sendmail" "postfix" "exim4" "dovecot" "cyrus-imapd"
        # Directory
        "slapd"
        # DNS (unless required)
        "bind9" "named"
        # DHCP
        "isc-dhcp-server" "dhcpd" "dhcpd6"
        # Database (unless required)
        "mysql" "mariadb" "postgresql" "mongod"
        # Web (unless required)
        "apache2" "httpd" "nginx" "lighttpd"
        # Misc
        "apport" "whoopsie"
    )

    local disabled=0; local skipped=0
    for svc in "${dangerous[@]}"; do
        if in_keep_list "$svc"; then
            info "Keeping: $svc (in keep list)"
            ((skipped++))
            continue
        fi

        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            if $DRY_RUN; then
                info "[DRY RUN] Would disable: $svc"
                ((disabled++))
            else
                systemctl disable --now "$svc" 2>/dev/null && {
                    info "Disabled: $svc"
                    ((disabled++))
                } || true
            fi
        fi
    done

    info "Disabled: $disabled | Kept: $skipped"

    step "Purge dangerous packages"
    if ! $DRY_RUN; then
        apt-get purge -y telnetd rsh-server rlogin-server xinetd nis 2>/dev/null || true
        info "Purged: telnetd, rsh-server, rlogin-server, xinetd, nis"
    fi

    step "Review"
    warn "Manually review remaining services. Per the competition README,"
    warn "only keep services that are explicitly required."

    echo ""
    echo -e "${BOLD}${GREEN}═══ Service Audit Complete ═══${NC}"
    echo -e "Log: ${LOG}"
    echo -e "${YELLOW}Keep-list: ${user_keep[*]:-none}${NC}"
}

main "$@"
