# CyberPatriot Linux Hardening Toolkit

**For Ubuntu, Linux Mint, and Debian systems**

This toolkit automates common CyberPatriot Linux hardening tasks. It's built from analysis of past competition rounds (CyPat 16, 17, 18) and incorporates CIS benchmarks and community best practices.

---

## Quick Start

```bash
# 1. Take a VM snapshot first!

# 2. Read the competition README — know which users & services are required

# 3. Answer forensic questions FIRST (before running any scripts)

# 4. Run the basic hardening script
sudo ./basic.sh

# 5. For deeper hardening, run the advanced script
sudo ./advanced.sh

# 6. Run service-specific scripts as needed
sudo ./specialities/ssh.sh
sudo ./specialities/apache2.sh
```

---

## File Structure

```
Cypat/
├── basic.sh                  # Basic hardening (safe, high-impact)
├── advanced.sh               # Advanced hardening (aggressive, comprehensive)
├── README.md                 # This file
└── specialities/             # Service-specific hardening scripts
    ├── ssh.sh                # SSH server hardening
    ├── ufw.sh                # UFW firewall configuration
    ├── sysctl.sh             # Kernel/sysctl hardening
    ├── systemctl.sh          # Service management (disable dangerous services)
    ├── users.sh              # User & group management
    ├── pam.sh                # PAM password policies & lockout
    ├── apache2.sh            # Apache2 web server hardening
    ├── nginx.sh              # Nginx web server hardening
    ├── vsftpd.sh             # VSFTPD FTP server hardening
    ├── mysql.sh              # MySQL/MariaDB hardening
    ├── php.sh                # PHP hardening
    ├── malware.sh            # Malware/backdoor hunting
    └── audit.sh              # Auditd, Fail2ban, logging setup
```

---

## Script Details

### `basic.sh` — Basic Hardening

**What it does (10 phases):**

| Phase | Description |
|-------|-------------|
| 1 | System updates & auto-updates |
| 2 | User/group audit (UID 0, empty passwords, sudo members) |
| 3 | Password policies (aging, PAM complexity, account lockout) |
| 4 | SSH hardening (PermitRootLogin=no, MaxAuthTries=3, etc.) |
| 5 | UFW firewall (deny incoming, allow SSH/HTTP/HTTPS) |
| 6 | Prohibited software removal (hacking tools, games, P2P) |
| 7 | Dangerous services disabled (FTP, Telnet, CUPS, Samba, etc.) |
| 8 | Basic kernel hardening via sysctl |
| 9 | Basic malware check (processes, crontabs, recent files) |
| 10 | Critical file permissions |


### `advanced.sh` — Advanced Hardening

**Everything in basic, plus (22 phases):**

| Phase | Description |
|-------|-------------|
| 1-6 | Same as basic (updates, users, passwords, SSH, UFW, prohibited) |
| 7 | Advanced sysctl (IPv6 disable, kernel hardening, FS protection) |
| 8 | Filesystem module blacklisting (cramfs, USB storage, FireWire) |
| 9 | Filesystem hardening (/tmp, /dev/shm noexec, /var/log perms) |
| 10 | File permission audit (world-writable, unowned files) |
| 11 | SUID/SGID audit (full scan with suspicious binary detection) |
| 12 | Cron & at audit (restrict to root, scan for suspicious entries) |
| 13 | Login banners (/etc/issue, /etc/issue.net, /etc/motd) |
| 14 | AppArmor (install, enable, enforce all profiles) |
| 15 | Auditd (install + curated rules for critical files/syscalls) |
| 16 | Fail2ban (SSH brute-force protection, 3 strikes = 1hr ban) |
| 17 | ClamAV + rkhunter + chkrootkit installation |
| 18 | Linux Mint-specific (LightDM, screensaver, Mint Welcome) |
| 19 | Disable Ctrl+Alt+Del |
| 20 | /etc/hosts & DNS check for redirects |
| 21 | Package audit (manual packages, recent installs) |
| 22 | Network check (listening ports, promiscuous mode) |

> **⚠ WARNING:** The advanced script disables password-based SSH login by default (`PasswordAuthentication=no`). Use `--allowed-users=user1,user2` to restrict SSH access. Ensure you have SSH key access configured!

### Specialities Scripts

Each speciality script is **standalone** — you can run it by itself without running basic or advanced:

| Script | Key Actions |
|--------|------------|
| `ssh.sh` | Hardens SSH config, cipher/MAC/Kex restriction, host key permissions |
| `ufw.sh` | Install UFW, default deny, allow services, enable logging, rate-limit SSH |
| `sysctl.sh` | IPv4/IPv6 hardening, TCP hardening, kernel protections, FS protection |
| `systemctl.sh` | Audit running/enabled services, disable dangerous ones, `--keep=` option |
| `users.sh` | Audit users, remove/add users, manage sudo, `--remove=`, `--add=`, `--admin=` flags |
| `pam.sh` | Password aging, cracklib/pwquality, faillock/tally2, core dump disable |
| `apache2.sh` | ServerTokens, ServerSignature, TraceEnable, directory listing, security headers |
| `nginx.sh` | server_tokens, security headers, autoindex, SSL ciphers, default site removal |
| `vsftpd.sh` | Anonymous disable, chroot jail, TLS, user restrictions, logging, max connections |
| `mysql.sh` | bind-address=localhost, local-infile=0, secure_file_priv, remove anonymous users |
| `php.sh` | expose_php, allow_url_fopen, disable_functions, session hardening |
| `malware.sh` | Process scanning, cron audit, SUID/SGID, hidden files, authorized_keys, shell configs |
| `audit.sh` | auditd rules, fail2ban, log permissions, brute-force detection, Lynis install |

---

## Usage Patterns

### Pattern 1: Competition Workflow (Recommended)

```bash
# 1. Read the README file on the Desktop
cat ~/Desktop/README* 2>/dev/null || cat /home/*/Desktop/README* 2>/dev/null

# 2. Answer forensic questions (use the checklist below)

# 3. Quick user audit
sudo ./specialities/users.sh

# 4. If README lists users to remove/add:
sudo ./specialities/users.sh --remove=hacker,guest --add=jdoe --admin=jdoe

# 5. Basic hardening (fast, safe)
sudo ./basic.sh

# 6. Service-specific hardening (for required services only)
sudo ./specialities/ssh.sh
sudo ./specialities/apache2.sh     # if web server required
sudo ./specialities/mysql.sh       # if database required

# 7. Advanced hardening (aggressive)
sudo ./advanced.sh

# 8. Malware hunting
sudo ./specialities/malware.sh

# 9. Final audit
sudo ./specialities/audit.sh
sudo lynis audit system
```

### Pattern 2: Targeted Service Hardening

```bash
# Only SSH and firewall
sudo ./specialities/ssh.sh --password-auth
sudo ./specialities/ufw.sh --allow-http --allow-https

# Only web stack
sudo ./specialities/apache2.sh
sudo ./specialities/php.sh
sudo ./specialities/mysql.sh

# Only kernel and services
sudo ./specialities/sysctl.sh
sudo ./specialities/systemctl.sh --keep=ssh,apache2
```

### Pattern 3: Quick First-Round Sprint

```bash
# Maximum speed for early rounds (less thorough, fast points)
sudo ./specialities/users.sh
sudo ./specialities/ufw.sh
sudo ./specialities/systemctl.sh
sudo ./specialities/sysctl.sh
sudo ./specialities/pam.sh
sudo ./specialities/ssh.sh
```

---

## Distro Support

| Feature | Ubuntu 20.04+ | Mint 20+ | Debian 10+ |
|---------|:---:|:---:|:---:|
| User audit | ✅ | ✅ | ✅ |
| Password policies | ✅ (pwquality) | ✅ (pwquality) | ✅ (cracklib) |
| SSH hardening | ✅ | ✅ | ✅ |
| UFW | ✅ | ✅ | ✅ |
| AppArmor | ✅ | ✅ | ✅ (partial) |
| PAM faillock | ✅ | ✅ | ⚠️ (tally2) |
| auditd | ✅ | ✅ | ✅ |
| LightDM hardening | — | ✅ | — |
| Screensaver lock | — | ✅ (C/M/X) | — |

---

## Forensic Questions Checklist

Answer these BEFORE running any scripts:

```bash
# Users & groups
cat /etc/passwd | awk -F: '$3>=1000'       # Human users
getent group sudo                            # Who has sudo?
awk -F: '($2 == "")' /etc/shadow            # Empty passwords

# System info
uname -a && lsb_release -a                  # OS version
uptime && who                                # Who's logged in?

# Network
ss -tulnp                                    # Listening ports
ufw status verbose                           # Firewall status

# Files
find /home -name "*.mp3" -o -name "*.mp4"   # Prohibited media
find / -mtime -7 -type f 2>/dev/null        # Recent changes
find /home -name ".*" -type f               # Hidden files

# Logs
grep "Failed password" /var/log/auth.log | tail -20
tail -50 /var/log/syslog
last -20                                      # Login history

# Browser & bash history
cat ~/.bash_history | tail -50
cat ~/.zsh_history 2>/dev/null | tail -50

# Services
systemctl list-units --type=service --state=running
systemctl list-unit-files --state=enabled

# Scheduled tasks
crontab -l 2>/dev/null; ls /etc/cron.*
```

---

## Important Warnings

1. **ALWAYS take a VM snapshot** before running any scripts
2. **Read the competition README first** — know authorized users and required services
3. **Answer forensic questions BEFORE hardening** — changes can break answers
4. **Do NOT reboot** unless absolutely necessary — may break scoring engine
5. **Verify SSH access** before closing your terminal (especially after advanced.sh)
6. **Some scripts are aggressive** — review the backups in `/tmp/cypat-*-backup-*` if something breaks
7. **Test in practice rounds first** — don't run unknown scripts in competition

---

## Logs & Backups

All scripts create:
- **Timestamped backups** in `/tmp/cypat-*-backup-YYYYMMDD-HHMMSS/`
- **Detailed logs** in `/var/log/cypat-*-YYYYMMDD-HHMMSS.log`

To revert a change:
```bash
# Find the backup
ls -d /tmp/cypat-*-backup-*

# Restore a specific file
sudo cp /tmp/cypat-basic-backup-20260101-120000/etc/ssh/sshd_config /etc/ssh/sshd_config
sudo systemctl restart ssh
```

---

## Post-Run Verification

```bash
# Check firewall
sudo ufw status verbose

# Check listening ports
sudo ss -tulnp

# Check running services
systemctl list-units --type=service --state=running

# Check password policies
grep "^PASS" /etc/login.defs
grep pwquality /etc/pam.d/common-password

# Check SSH config
sudo sshd -T | grep -E "permitroot|passwordauth|maxauthtries|x11forwarding"

# Check sysctl
sudo sysctl -a | grep -E "syncookies|accept_redirects|randomize_va_space"

# Run Lynis
sudo lynis audit system

# Check for remaining prohibited files
find /home -name "*.mp3" -o -name "*.mp4" 2>/dev/null
sudo find / -perm -4000 -type f 2>/dev/null
```

---

## Credits

Built from analysis of:
- CyberPatriot Seasons 16, 17, 18 competition solutions
- CIS Benchmarks for Ubuntu, Debian, and Linux Mint
- [Ripper1004/CyberPatriot-Security-Script](https://github.com/Ripper1004/CyberPatriot-Security-Script)
- [matteopolak/cyber](https://github.com/matteopolak/cyber)
- [kxlieannh/cyberpatriotsscripts](https://github.com/kxlieannh/cyberpatriotsscripts)
- [ysl-o/CyberPatriot-18-2405](https://github.com/ysl-o/CyberPatriot-18-2405)
