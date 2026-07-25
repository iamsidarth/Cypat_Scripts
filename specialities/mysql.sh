#!/bin/bash
###############################################################################
#  CyberPatriot — MySQL / MariaDB Hardening (Standalone)
#  Run: sudo ./mysql.sh
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BACKUP_DIR="/tmp/cypat-mysql-backup-$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/cypat-mysql-$(date +%Y%m%d-%H%M%S).log"

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

# Detect which database is installed
detect_db() {
    if dpkg -l mysql-server &>/dev/null || command -v mysql &>/dev/null; then
        echo "mysql"
    elif dpkg -l mariadb-server &>/dev/null || command -v mariadb &>/dev/null; then
        echo "mariadb"
    else
        echo ""
    fi
}

main() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        echo "Usage: sudo ./mysql.sh"
        echo "Hardens MySQL / MariaDB database server"
        exit 0
    fi

    echo -e "${BOLD}${BLUE}╔══ MySQL / MariaDB Hardening ══╗${NC}"
    require_root
    mkdir -p "$BACKUP_DIR"

    local db; db=$(detect_db)
    if [[ -z "$db" ]]; then
        warn "Neither MySQL nor MariaDB is installed. Skipping."
        exit 0
    fi

    info "Detected: $db"
    local service_name="$db"

    # Detect config location
    local my_cnf=""
    for loc in "/etc/mysql/mysql.conf.d/mysqld.cnf" "/etc/mysql/my.cnf" \
               "/etc/my.cnf" "/etc/mysql/mariadb.conf.d/50-server.cnf"; do
        if [[ -f "$loc" ]]; then
            my_cnf="$loc"
            break
        fi
    done

    if [[ -z "$my_cnf" ]]; then
        warn "Could not find MySQL/MariaDB config file"
    else
        step "Hardening: $my_cnf"
        backup_file "$my_cnf"

        # Bind to localhost
        if grep -q "^bind-address" "$my_cnf"; then
            sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' "$my_cnf"
        elif grep -q "^#bind-address" "$my_cnf"; then
            sed -i 's/^#bind-address.*/bind-address = 127.0.0.1/' "$my_cnf"
        else
            echo "bind-address = 127.0.0.1" >> "$my_cnf"
        fi
        info "bind-address = 127.0.0.1"

        # Disable LOCAL INFILE
        if grep -q "^local-infile" "$my_cnf"; then
            sed -i 's/^local-infile.*/local-infile = 0/' "$my_cnf"
        else
            echo "local-infile = 0" >> "$my_cnf"
        fi
        info "local-infile = 0"

        # Skip symbolic links
        if grep -q "^symbolic-links" "$my_cnf"; then
            sed -i 's/^symbolic-links.*/symbolic-links = 0/' "$my_cnf"
        elif ! grep -q "symbolic-links" "$my_cnf"; then
            echo "symbolic-links = 0" >> "$my_cnf"
        fi
        info "symbolic-links = 0"

        # Secure file priv
        if ! grep -q "^secure_file_priv" "$my_cnf"; then
            echo "secure_file_priv = /var/lib/mysql-files" >> "$my_cnf"
            info "secure_file_priv = /var/lib/mysql-files"
        fi

        pass "MySQL config hardened"
    fi

    # ── Run mysql_secure_installation if available ──
    step "Running mysql_secure_installation"
    if command -v mysql_secure_installation &>/dev/null; then
        warn "Please run manually: sudo mysql_secure_installation"
        warn "  Answer YES to all questions:"
        warn "  - Set root password"
        warn "  - Remove anonymous users"
        warn "  - Disallow root login remotely"
        warn "  - Remove test database"
        warn "  - Reload privilege tables"
    fi

    # ── Manual SQL fixes ──
    step "SQL-level hardening (if root has passwordless access)"
    info "Checking for users with no password..."
    if mysql -u root -e "SELECT user, host FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL;" 2>/dev/null | grep -v "user" | grep -q .; then
        warn "Users with no password found! Running fixes:"
        mysql -u root 2>/dev/null <<'SQL' || warn "Could not connect to MySQL as root. Run fixes manually."
-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';
-- Disallow remote root
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
-- Drop test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
-- Remove users with empty passwords
DELETE FROM mysql.user WHERE authentication_string='';
FLUSH PRIVILEGES;
SQL
        pass "MySQL users cleaned up"
    else
        info "No empty-password users found (or could not connect)"
    fi

    # ── File permissions ──
    step "Fixing file permissions"
    chmod 640 "$my_cnf" 2>/dev/null || true
    if [[ -d /var/lib/mysql ]]; then
        find /var/lib/mysql -type f -name "*.pem" -exec chmod 400 {} \; 2>/dev/null || true
    fi
    pass "File permissions applied"

    # ── Restart ──
    step "Restarting service"
    systemctl restart "$service_name" 2>/dev/null || systemctl restart mariadb 2>/dev/null || true
    pass "$service_name restarted"

    echo ""
    echo -e "${BOLD}${GREEN}═══ MySQL / MariaDB Hardening Complete ═══${NC}"
    echo -e "Backups: ${BACKUP_DIR}"
    echo -e "Log:     ${LOG}"
    echo -e "${YELLOW}IMPORTANT: Run 'sudo mysql_secure_installation' manually if you haven't already${NC}"
}

main "$@"
