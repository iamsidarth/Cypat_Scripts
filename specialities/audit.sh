#!/bin/bash
###############################################################################
#  CyberPatriot — Audit & Logging Setup (Standalone)
#  Run: sudo ./audit.sh
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BACKUP_DIR="/tmp/cypat-audit-backup-$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/cypat-audit-$(date +%Y%m%d-%H%M%S).log"

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
        echo "Usage: sudo ./audit.sh"
        echo "Sets up auditd, fail2ban, and logging"
        exit 0
    fi

    echo -e "${BOLD}${BLUE}╔══ Audit & Logging Setup ══╗${NC}"
    require_root
    mkdir -p "$BACKUP_DIR"

    # ── auditd ──
    step "Installing & Configuring auditd"
    apt-get install -y auditd audispd-plugins -qq 2>&1 | tee -a "$LOG" || {
        warn "Could not install auditd"; return
    }

    backup_file /etc/audit/rules.d/cypat.rules
    cat > /etc/audit/rules.d/cypat.rules <<'AUDIT'
# CyberPatriot Audit Rules
# Critical identity files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/sudoers.d -p wa -k sudo_changes

# SSH config
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Process execution (for backdoor detection)
-a always,exit -F arch=b64 -S execve -k exec_log
-a always,exit -F arch=b32 -S execve -k exec_log

# Privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -k priv_esc
-a always,exit -F arch=b32 -S setuid -S setgid -k priv_esc

# Kernel module loading
-w /sbin/insmod -p x -k module_load
-w /sbin/rmmod -p x -k module_unload
-w /sbin/modprobe -p x -k module_load

# Cron changes
-w /etc/crontab -p wa -k cron_changes
-w /etc/cron.d -p wa -k cron_changes
-w /etc/cron.daily -p wa -k cron_changes
-w /etc/cron.hourly -p wa -k cron_changes
-w /etc/cron.weekly -p wa -k cron_changes
-w /etc/cron.monthly -p wa -k cron_changes

# Login records
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/syslog -p wa -k syslog
-w /var/log/kern.log -p wa -k kern_log

# Hostname/domain changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system_changes
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system_changes

# Network config changes
-w /etc/hosts -p wa -k hosts_file
-w /etc/resolv.conf -p wa -k dns_config

# PAM changes
-w /etc/pam.d -p wa -k pam_changes
-w /etc/security -p wa -k security_config

# Make rules immutable (requires reboot to change)
-e 2
AUDIT

    service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
    info "auditd restarted"

    # Verify
    info "Active audit rules:"
    auditctl -l 2>/dev/null | head -20 | tee -a "$LOG"
    pass "auditd configured"

    # ── fail2ban ──
    step "Installing & Configuring fail2ban"
    apt-get install -y fail2ban -qq 2>&1 | tee -a "$LOG" || {
        warn "Could not install fail2ban"; return
    }

    backup_file /etc/fail2ban/jail.local
    cat > /etc/fail2ban/jail.local <<'F2B'
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
F2B

    systemctl enable fail2ban 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true

    info "fail2ban status:"
    fail2ban-client status 2>/dev/null | tee -a "$LOG" || true
    pass "fail2ban configured"

    # ── Log file permissions ──
    step "Securing log files"
    chmod -R go-rwx /var/log 2>/dev/null || true
    chmod 640 /var/log/auth.log 2>/dev/null || true
    chmod 640 /var/log/syslog 2>/dev/null || true
    chmod 640 /var/log/kern.log 2>/dev/null || true
    info "Log permissions secured"

    # ── Check auth logs for brute force ──
    step "Checking auth.log for brute-force attempts"
    if [[ -f /var/log/auth.log ]]; then
        local bf_count
        bf_count=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo 0)
        if [[ "$bf_count" -gt 50 ]]; then
            warn "$bf_count failed password attempts detected!"
            info "Top offending IPs:"
            grep "Failed password" /var/log/auth.log 2>/dev/null | \
                grep -oP 'from \S+' | sort | uniq -c | sort -rn | head -10 | tee -a "$LOG"
        else
            info "Failed password attempts: $bf_count"
        fi
    else
        info "/var/log/auth.log not found"
    fi

    # ── Logrotate check ──
    step "Checking logrotate"
    if [[ -f /etc/logrotate.conf ]]; then
        info "logrotate config present"
    else
        warn "logrotate not configured"
    fi

    # ── Quick Lynis install ──
    step "Lynis audit tool"
    if command -v lynis &>/dev/null; then
        info "Lynis is already installed"
    else
        info "Installing Lynis..."
        apt-get install -y lynis -qq 2>&1 | tee -a "$LOG" || {
            # Fallback: install from git
            info "apt install failed — cloning from git..."
            git clone https://github.com/CISOfy/lynis.git /tmp/lynis 2>/dev/null || true
        }
    fi
    pass "Lynis available — run: sudo lynis audit system"

    echo ""
    echo -e "${BOLD}${GREEN}═══ Audit & Logging Setup Complete ═══${NC}"
    echo -e "Backups: ${BACKUP_DIR}"
    echo -e "Log:     ${LOG}"
    echo ""
    echo -e "${BOLD}${YELLOW}Post-setup checks:${NC}"
    echo -e "  sudo auditctl -l                     # list audit rules"
    echo -e "  sudo fail2ban-client status sshd     # fail2ban SSH jail"
    echo -e "  sudo lynis audit system              # full system audit"
    echo -e "  sudo ausearch -k priv_esc            # search audit logs"
}

main "$@"
