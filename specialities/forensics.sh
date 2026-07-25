#!/bin/bash
###############################################################################
#  CyberPatriot — Forensic Question Helper (Standalone)
#  Run: sudo ./forensics.sh
#
#  Gathers evidence to help answer forensic questions BEFORE hardening.
#  Does NOT modify the system — read-only.
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

REPORT_DIR="/tmp/cypat-forensics-$(date +%Y%m%d-%H%M%S)"

info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
pass()  { echo -e "${GREEN}[PASS]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
step()  { echo -e "\n${BOLD}${CYAN}═══ $1 ═══${NC}"; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: Run as root (sudo) to read all files.${NC}"; exit 1
    fi
}

main() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        echo "Usage: sudo ./forensics.sh"
        echo "Gathers forensic evidence — run BEFORE any hardening scripts"
        exit 0
    fi

    echo -e "${BOLD}${BLUE}╔══ Forensic Evidence Collection ══╗${NC}"
    echo -e "${YELLOW}Run this FIRST — before any changes to the system!${NC}"
    require_root
    mkdir -p "$REPORT_DIR"

    # ── README on Desktop ──
    step "README Files"
    info "Searching for README files..."
    for home in /home/*; do
        find "$home/Desktop" -iname "readme*" -type f 2>/dev/null | while read -r f; do
            info "Found: $f"
            cp "$f" "$REPORT_DIR/" 2>/dev/null || true
            echo "=== $f ==="
            head -50 "$f"
            echo "..."
        done
    done
    # Also check /root/Desktop
    find /root/Desktop -iname "readme*" -type f 2>/dev/null | while read -r f; do
        info "Found: $f"
        cp "$f" "$REPORT_DIR/" 2>/dev/null || true
    done

    # ── Forensic questions on Desktop ──
    step "Forensic Question Files"
    find /home/*/Desktop -iname "*forensic*" -type f 2>/dev/null | while read -r f; do
        info "Found: $f"
        cp "$f" "$REPORT_DIR/" 2>/dev/null || true
        echo "=== Contents of $f ==="
        cat "$f"
    done
    find /root/Desktop -iname "*forensic*" -type f 2>/dev/null | while read -r f; do
        info "Found: $f"
        cp "$f" "$REPORT_DIR/" 2>/dev/null || true
    done

    # ── Base64 Encoded Strings ──
    step "Base64 Decoder (common forensic question)"
    info "Searching for base64 strings in Desktop files..."
    find /home/*/Desktop -type f 2>/dev/null | while read -r f; do
        local b64
        b64=$(grep -oP '[A-Za-z0-9+/=]{20,}' "$f" 2>/dev/null | head -5 || true)
        if [[ -n "$b64" ]]; then
            info "Potential base64 in $f:"
            echo "$b64" | while read -r line; do
                echo "  Encoded: $line"
                echo "  Decoded: $(echo "$line" | base64 -d 2>/dev/null || echo '(invalid)')"
            done
        fi
    done

    # ── Users & Groups ──
    step "User Accounts"
    info "Human users (UID >= 1000):"
    awk -F: '$3 >= 1000 && $3 < 65534 {printf "  %-16s UID=%-5s HOME=%s\n", $1, $3, $6}' /etc/passwd | tee "$REPORT_DIR/users.txt"

    info "Users with UID 0:"
    awk -F: '$3 == 0 {print "  "$1}' /etc/passwd | tee -a "$REPORT_DIR/users.txt"

    info "Sudo group members:"
    getent group sudo 2>/dev/null | tee -a "$REPORT_DIR/users.txt"

    info "Users with empty passwords:"
    awk -F: '($2 == "" || $2 == "!") && $1 != "root" {print "  "$1}' /etc/shadow 2>/dev/null | tee "$REPORT_DIR/empty-passwords.txt"

    # ── Hidden Users (no home dir, shell = /bin/bash) ──
    info "Potentially hidden users (bash shell, no standard home):"
    awk -F: '$7 ~ /bash|sh/ && $6 !~ /^\/home/ && $3 >= 1000 {print "  "$1" (UID="$3", HOME="$6")"}' /etc/passwd | tee "$REPORT_DIR/hidden-users.txt"

    # ── Recently modified files ──
    step "Recently Modified Files (< 7 days)"
    find /etc /home /tmp /var -mtime -7 -type f 2>/dev/null | head -50 | tee "$REPORT_DIR/recent-files.txt"

    # ── Bash History ──
    step "Shell History"
    for home in /home/* /root; do
        local u; u=$(basename "$home")
        for hist in "$home/.bash_history" "$home/.zsh_history" "$home/.mysql_history" "$home/.psql_history" "$home/.python_history" "$home/.node_repl_history" "$home/.wget-hsts"; do
            if [[ -f "$hist" ]]; then
                info "$hist ($(wc -l < "$hist") lines)"
                tail -30 "$hist" > "$REPORT_DIR/history-${u}-$(basename "$hist").txt"
            fi
        done
    done

    # ── Browser History / Artifacts ──
    step "Browser Artifacts"
    for home in /home/*; do
        local u; u=$(basename "$home")
        # Firefox
        for ff in "$home/.mozilla/firefox/"*"/places.sqlite"; do
            if [[ -f "$ff" ]]; then
                info "Firefox history: $ff"
                cp "$ff" "$REPORT_DIR/firefox-${u}-places.sqlite" 2>/dev/null || true
                # Try to dump URLs
                sqlite3 "$ff" "SELECT url, title, datetime(last_visit_date/1000000,'unixepoch') FROM moz_places ORDER BY last_visit_date DESC LIMIT 30;" 2>/dev/null | tee "$REPORT_DIR/firefox-${u}-history.txt" || true
            fi
        done

        # Chrome/Chromium
        for chrome in "$home/.config/google-chrome/Default/History" "$home/.config/chromium/Default/History" "$home/.var/app/com.google.Chrome/config/google-chrome/Default/History"; do
            if [[ -f "$chrome" ]]; then
                info "Chrome history: $chrome"
                cp "$chrome" "$REPORT_DIR/chrome-${u}-History" 2>/dev/null || true
                sqlite3 "$chrome" "SELECT url, title, datetime(last_visit_time/1000000-11644473600,'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 30;" 2>/dev/null | tee "$REPORT_DIR/chrome-${u}-history.txt" || true
            fi
        done
    done

    # ── Auth Log ──
    step "Auth Log Analysis"
    if [[ -f /var/log/auth.log ]]; then
        info "Recent sudo usage:"
        grep "sudo" /var/log/auth.log 2>/dev/null | tail -20 | tee "$REPORT_DIR/sudo-usage.txt"

        info "Failed logins:"
        grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20 | tee "$REPORT_DIR/failed-logins.txt"

        info "Successful logins:"
        grep "Accepted password\|Accepted publickey" /var/log/auth.log 2>/dev/null | tail -20 | tee "$REPORT_DIR/successful-logins.txt"

        info "New users created:"
        grep "new user" /var/log/auth.log 2>/dev/null | tee "$REPORT_DIR/new-users.txt"
        grep "useradd" /var/log/auth.log 2>/dev/null | tee -a "$REPORT_DIR/new-users.txt"
    fi

    # ── Prohibited Files ──
    step "Prohibited Files"
    info "MP3 files:"
    find /home -iname "*.mp3" -type f 2>/dev/null | tee "$REPORT_DIR/mp3-files.txt"

    info "MP4/video files:"
    find /home -iname "*.mp4" -o -iname "*.avi" -o -iname "*.mkv" -o -iname "*.mov" 2>/dev/null | tee "$REPORT_DIR/media-files.txt"

    info "Image files (non-standard locations):"
    find /tmp /var/tmp /etc /root -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" -o -iname "*.gif" 2>/dev/null | tee "$REPORT_DIR/suspicious-images.txt"

    # ── Listening Ports ──
    step "Listening Ports & Services"
    ss -tulnp 2>/dev/null | tee "$REPORT_DIR/ports.txt" || netstat -tulnp 2>/dev/null | tee "$REPORT_DIR/ports.txt"

    info "Enabled services:"
    systemctl list-unit-files --state=enabled 2>/dev/null | grep -v "static" | tee "$REPORT_DIR/enabled-services.txt"

    # ── Cron jobs ──
    step "Scheduled Tasks"
    {
        echo "=== /etc/crontab ===" && cat /etc/crontab 2>/dev/null
        echo "=== /etc/cron.d/ ===" && ls -la /etc/cron.d/ 2>/dev/null && cat /etc/cron.d/* 2>/dev/null
        echo "=== /etc/cron.daily/ ===" && ls /etc/cron.daily/ 2>/dev/null
        echo "=== /etc/cron.hourly/ ===" && ls /etc/cron.hourly/ 2>/dev/null
        echo "=== /etc/cron.weekly/ ===" && ls /etc/cron.weekly/ 2>/dev/null
        echo "=== /etc/cron.monthly/ ===" && ls /etc/cron.monthly/ 2>/dev/null
        for u in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
            echo "=== Crontab for $u ==="
            crontab -l -u "$u" 2>/dev/null || echo "(none)"
        done
    } > "$REPORT_DIR/cron-jobs.txt"
    info "Cron jobs saved to cron-jobs.txt"

    # ── SUID/SGID ──
    step "SUID/SGID Binaries"
    find / -perm -4000 -type f 2>/dev/null | sort > "$REPORT_DIR/suid.txt"
    find / -perm -2000 -type f 2>/dev/null | sort > "$REPORT_DIR/sgid.txt"
    info "SUID: $(wc -l < "$REPORT_DIR/suid.txt") files"
    info "SGID: $(wc -l < "$REPORT_DIR/sgid.txt") files"

    # ── SSH authorized_keys ──
    step "SSH Keys"
    find /home /root -name "authorized_keys" -type f 2>/dev/null | while read -r ak; do
        info "  $ak"
        cat "$ak" 2>/dev/null | sed 's/^/    /'
        cp "$ak" "$REPORT_DIR/auth-keys-$(echo "$ak" | tr '/' '_')" 2>/dev/null
    done

    # ── Suspicious files in common locations ──
    step "Suspicious Files"
    info "Executables in /tmp:"
    find /tmp -type f -executable 2>/dev/null | tee "$REPORT_DIR/tmp-executables.txt"

    info "Files in /dev/shm:"
    ls -la /dev/shm 2>/dev/null | tee "$REPORT_DIR/dev-shm.txt"

    info "World-writable files in /etc:"
    find /etc -perm -002 -type f 2>/dev/null | tee "$REPORT_DIR/etc-world-writable.txt"

    # ── Hidden files in home ──
    info "Hidden files in home dirs (potential backdoors):"
    find /home -maxdepth 3 -name ".*" -type f 2>/dev/null | grep -vE "\.(bashrc|profile|bash_logout|bash_history|zshrc|zsh_history|cache|config|local|ssh|gnupg|mozilla|thunderbird|Xauthority|ICEauthority|dmrc|gtkrc)" | tee "$REPORT_DIR/hidden-files.txt"

    # ── Installed packages ──
    step "Recently Installed Packages"
    grep " install " /var/log/dpkg.log 2>/dev/null | tail -30 | tee "$REPORT_DIR/recent-packages.txt"

    # ── Kernel modules ──
    step "Loaded Kernel Modules"
    lsmod 2>/dev/null | tee "$REPORT_DIR/kernel-modules.txt"

    # ── /etc/hosts ──
    step "DNS / Hosts File"
    cat /etc/hosts 2>/dev/null | tee "$REPORT_DIR/hosts.txt"
    cat /etc/resolv.conf 2>/dev/null | tee "$REPORT_DIR/resolv.txt"

    echo ""
    echo -e "${BOLD}${GREEN}═══ Forensic Collection Complete ═══${NC}"
    echo -e "All reports saved to: ${BOLD}${REPORT_DIR}${NC}"
    echo ""
    echo -e "${BOLD}${YELLOW}Key files to review:${NC}"
    echo -e "  ${REPORT_DIR}/users.txt"
    echo -e "  ${REPORT_DIR}/failed-logins.txt"
    echo -e "  ${REPORT_DIR}/mp3-files.txt"
    echo -e "  ${REPORT_DIR}/recent-files.txt"
    echo -e "  ${REPORT_DIR}/cron-jobs.txt"
    echo -e "  ${REPORT_DIR}/ports.txt"
    echo -e "  ${REPORT_DIR}/hidden-files.txt"
    echo -e "  ${REPORT_DIR}/suid.txt"
    echo -e "  ${REPORT_DIR}/firefox-*-history.txt"
    echo ""
    echo -e "${YELLOW}Tip: Search for base64 strings in Desktop files:${NC}"
    echo -e "  grep -r '[A-Za-z0-9+/=]\{20,\}' ~/Desktop/"
}

main "$@"
