#!/bin/bash
###############################################################################
#  CyberPatriot — vsftpd Hardening (Standalone)
#  Run: sudo ./vsftpd.sh
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BACKUP_DIR="/tmp/cypat-vsftpd-backup-$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/cypat-vsftpd-$(date +%Y%m%d-%H%M%S).log"

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
        echo "Usage: sudo ./vsftpd.sh"
        echo "Hardens vsftpd FTP server"
        echo ""
        echo "NOTE: Only run this if the competition README requires FTP."
        echo "If FTP is not required, disable vsftpd instead:"
        echo "  sudo systemctl disable --now vsftpd"
        exit 0
    fi

    echo -e "${BOLD}${BLUE}╔══ vsftpd Hardening ══╗${NC}"
    require_root
    mkdir -p "$BACKUP_DIR"

    if ! dpkg -l vsftpd &>/dev/null; then
        warn "vsftpd is not installed. Skipping."
        exit 0
    fi

    local conf="/etc/vsftpd.conf"
    if [[ ! -f "$conf" ]]; then
        conf="/etc/vsftpd/vsftpd.conf"
    fi

    if [[ ! -f "$conf" ]]; then
        warn "vsftpd.conf not found. Skipping."
        exit 0
    fi

    backup_file "$conf"

    step "Applying vsftpd hardening"

    # Disable anonymous access
    sed -i 's/^anonymous_enable=.*/anonymous_enable=NO/' "$conf"
    if ! grep -q "^anonymous_enable" "$conf"; then
        echo "anonymous_enable=NO" >> "$conf"
    fi
    info "anonymous_enable=NO"

    # Enable local users
    sed -i 's/^local_enable=.*/local_enable=YES/' "$conf"
    if ! grep -q "^local_enable" "$conf"; then
        echo "local_enable=YES" >> "$conf"
    fi
    info "local_enable=YES"

    # Enable write only if required
    sed -i 's/^write_enable=.*/write_enable=NO/' "$conf"
    if ! grep -q "^write_enable" "$conf"; then
        echo "write_enable=NO" >> "$conf"
    fi
    info "write_enable=NO"

    # Chroot jail
    sed -i 's/^#\?chroot_local_user=.*/chroot_local_user=YES/' "$conf"
    if ! grep -q "^chroot_local_user" "$conf"; then
        echo "chroot_local_user=YES" >> "$conf"
    fi
    info "chroot_local_user=YES"

    # Disable upload of hidden files
    sed -i 's/^#\?hide_ids=.*/hide_ids=YES/' "$conf"
    if ! grep -q "^hide_ids" "$conf"; then
        echo "hide_ids=YES" >> "$conf"
    fi

    # Anonymous user restrictions
    if ! grep -q "^anon_upload_enable" "$conf"; then
        echo "anon_upload_enable=NO" >> "$conf"
    fi
    if ! grep -q "^anon_mkdir_write_enable" "$conf"; then
        echo "anon_mkdir_write_enable=NO" >> "$conf"
    fi
    if ! grep -q "^anon_other_write_enable" "$conf"; then
        echo "anon_other_write_enable=NO" >> "$conf"
    fi
    if ! grep -q "^anon_world_readable_only" "$conf"; then
        echo "anon_world_readable_only=YES" >> "$conf"
    fi
    # Ensure anonymous user is mapped to a non-root account
    if ! grep -q "^ftp_username" "$conf"; then
        echo "ftp_username=ftp" >> "$conf"
    fi
    info "Anonymous FTP: upload=no, mkdir=no, write=no, ftp_username=ftp"

    # PASV passive mode security
    if ! grep -q "^pasv_enable" "$conf"; then
        echo "pasv_enable=YES" >> "$conf"
    fi
    if ! grep -q "^pasv_min_port" "$conf"; then
        echo "pasv_min_port=50000" >> "$conf"
        echo "pasv_max_port=50100" >> "$conf"
        info "PASV port range: 50000-50100"
    fi
    if ! grep -q "^pasv_promiscuous" "$conf"; then
        echo "pasv_promiscuous=NO" >> "$conf"
    fi
    if ! grep -q "^pasv_addr_resolve" "$conf"; then
        echo "pasv_addr_resolve=NO" >> "$conf"
    fi

    # Connection limits
    if ! grep -q "^max_clients" "$conf"; then
        echo "max_clients=10" >> "$conf"
        info "max_clients=10"
    fi
    if ! grep -q "^max_per_ip" "$conf"; then
        echo "max_per_ip=3" >> "$conf"
        info "max_per_ip=3"
    fi
    if ! grep -q "^connect_from_port_20" "$conf"; then
        echo "connect_from_port_20=YES" >> "$conf"
    fi

    # Enable logging
    sed -i 's/^#\?xferlog_enable=.*/xferlog_enable=YES/' "$conf"
    if ! grep -q "^xferlog_enable" "$conf"; then
        echo "xferlog_enable=YES" >> "$conf"
    fi
    sed -i 's/^#\?log_ftp_protocol=.*/log_ftp_protocol=YES/' "$conf"
    if ! grep -q "^log_ftp_protocol" "$conf"; then
        echo "log_ftp_protocol=YES" >> "$conf"
    fi
    info "Logging enabled"

    # Force SSL/TLS
    if ! grep -q "^ssl_enable" "$conf"; then
        echo "ssl_enable=YES" >> "$conf"
        echo "require_ssl_reuse=NO" >> "$conf"
        echo "ssl_tlsv1=YES" >> "$conf"
        echo "ssl_sslv2=NO" >> "$conf"
        echo "ssl_sslv3=NO" >> "$conf"
        info "SSL/TLS enabled (cert must be configured separately)"
    fi

    # Disable ASCII mode (prevents certain exploits)
    if ! grep -q "^ascii_upload_enable" "$conf"; then
        echo "ascii_upload_enable=NO" >> "$conf"
    fi
    if ! grep -q "^ascii_download_enable" "$conf"; then
        echo "ascii_download_enable=NO" >> "$conf"
    fi

    # User restrictions
    if ! grep -q "^userlist_enable" "$conf"; then
        echo "userlist_enable=YES" >> "$conf"
        echo "userlist_deny=NO" >> "$conf"
        echo "userlist_file=/etc/vsftpd.userlist" >> "$conf"
        info "User list enabled: only users in /etc/vsftpd.userlist allowed"
        touch /etc/vsftpd.userlist
    fi

    # Restrict to specific users
    if ! grep -q "^ftpd_banner" "$conf"; then
        echo 'ftpd_banner=Authorized users only' >> "$conf"
        info "Banner set"
    fi

    # Set secure file permissions
    chmod 600 "$conf" 2>/dev/null || true
    info "vsftpd.conf permissions set to 600"

    step "Restarting vsftpd"
    systemctl restart vsftpd 2>/dev/null && pass "vsftpd restarted" || warn "Failed to restart"

    echo ""
    echo -e "${BOLD}${GREEN}═══ vsftpd Hardening Complete ═══${NC}"
    echo -e "Backups: ${BACKUP_DIR}"
    echo -e "Log:     ${LOG}"
    echo -e "${YELLOW}Note: Add authorized users to /etc/vsftpd.userlist${NC}"
}

main "$@"
