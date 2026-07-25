#!/bin/bash
###############################################################################
#  CyberPatriot — Docker Security Hardening (Standalone)
#  Run: sudo ./docker.sh
#
#  Based on Key copy 2 answer key — removes docker group membership,
#  checks for privileged containers, socket mounts, dangerous capabilities,
#  and untrusted registries.
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BACKUP_DIR="/tmp/cypat-docker-backup-$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/cypat-docker-$(date +%Y%m%d-%H%M%S).log"

info()  { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG"; }
pass()  { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$LOG"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG"; }
fail()  { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$LOG"; }
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
        echo "Usage: sudo ./docker.sh"
        echo "Hardens Docker — removes dangerous permissions, audits containers"
        exit 0
    fi

    echo -e "${BOLD}${BLUE}╔══ Docker Security ══╗${NC}"
    require_root
    mkdir -p "$BACKUP_DIR"

    if ! command -v docker &>/dev/null; then
        warn "Docker is not installed. Skipping."
        exit 0
    fi

    info "Docker version: $(docker --version 2>/dev/null || echo 'unknown')"

    # ── Docker group audit ──
    step "Docker group audit"
    local docker_members
    docker_members=$(getent group docker 2>/dev/null | cut -d: -f4 || true)
    if [[ -n "$docker_members" ]]; then
        warn "Users in docker group (Docker = root equivalent!): $docker_members"
        IFS=',' read -ra dmarr <<< "$docker_members"
        for dm in "${dmarr[@]}"; do
            info "Removing $dm from docker group..."
            gpasswd -d "$dm" docker 2>/dev/null && info "  Removed $dm" || warn "  Failed to remove $dm"
        done
        if [[ -z "$(getent group docker | cut -d: -f4)" ]]; then
            pass "Docker group cleaned — no non-root members"
        fi
    else
        pass "No users in docker group"
    fi

    # ── Container audit ──
    step "Container security audit"

    if docker ps -q 2>/dev/null | grep -q .; then
        info "Running containers found. Auditing each..."

        docker ps --format '{{.Names}}' 2>/dev/null | while read -r c; do
            info "Container: $c"
            local inspect; inspect=$(docker inspect "$c" 2>/dev/null || echo "{}")

            # Check privileged mode
            if echo "$inspect" | grep -q '"Privileged": true'; then
                fail "  ⚠ Container $c is running in PRIVILEGED mode!"
            fi

            # Check for docker socket mount
            if docker exec "$c" test -S /var/run/docker.sock 2>/dev/null; then
                fail "  ⚠ Container $c has docker socket mounted!"
            fi

            # Check for dangerous capabilities
            local caps; caps=$(echo "$inspect" | grep -oP '"CapAdd":\s*\[[^]]*\]' || true)
            if echo "$caps" | grep -qiE "SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_OVERRIDE"; then
                fail "  ⚠ Container $c has dangerous capabilities: $caps"
            fi

            # Check for host network
            if echo "$inspect" | grep -q '"NetworkMode": "host"'; then
                warn "  ⚠ Container $c uses host networking"
            fi

            # Check for host PID namespace
            if echo "$inspect" | grep -q '"PidMode": "host"'; then
                warn "  ⚠ Container $c uses host PID namespace"
            fi

            # Check for root user
            local container_user; container_user=$(docker exec "$c" whoami 2>/dev/null || echo "unknown")
            if [[ "$container_user" == "root" ]]; then
                warn "  ⚠ Container $c is running as root"
            fi
        done
    else
        info "No running containers"
    fi

    # ── Docker daemon config audit ──
    step "Docker daemon configuration"
    local daemon_json="/etc/docker/daemon.json"

    if [[ -f "$daemon_json" ]]; then
        backup_file "$daemon_json"
        info "Current daemon.json:"
        cat "$daemon_json" | tee -a "$LOG"

        # Check for insecure registries
        if grep -q "insecure-registries" "$daemon_json"; then
            warn "insecure-registries found in daemon.json — review"
        fi

        # Check for user namespace remap
        if ! grep -q "userns-remap" "$daemon_json"; then
            warn "userns-remap not configured — consider enabling"
        fi
    else
        info "No daemon.json — creating hardened config"
        cat > "$daemon_json" <<'DOCKERCONF'
{
  "icc": false,
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
DOCKERCONF
        info "Created hardened daemon.json"
    fi

    # ── Docker compose audit ──
    step "Docker Compose files"
    find /home /root /opt /var -name "docker-compose*.yml" -o -name "docker-compose*.yaml" 2>/dev/null | while read -r dc; do
        info "Found: $dc"

        # Check for privileged
        if grep -q "privileged: true" "$dc" 2>/dev/null; then
            fail "  ⚠ privileged: true in $dc"
        fi

        # Check for docker socket mount
        if grep -q "/var/run/docker.sock" "$dc" 2>/dev/null; then
            fail "  ⚠ docker.sock mount in $dc"
        fi

        # Check for cap_add
        if grep -q "cap_add:" "$dc" 2>/dev/null; then
            warn "  cap_add entries in $dc — review"
        fi

        # Check for exposed ports
        if grep -q "ports:" "$dc" 2>/dev/null; then
            info "  Has port mappings — review are they needed"
        fi
    done

    # ── Unused images/volumes cleanup ──
    step "Cleanup"
    info "Dangling images:"
    docker images -f "dangling=true" -q 2>/dev/null | wc -l | xargs echo "  Count:" | tee -a "$LOG"

    info "Unused volumes:"
    docker volume ls -qf "dangling=true" 2>/dev/null | wc -l | xargs echo "  Count:" | tee -a "$LOG"

    pass "Docker audit completed"

    echo ""
    echo -e "${BOLD}${GREEN}═══ Docker Security Complete ═══${NC}"
    echo -e "Backups: ${BACKUP_DIR}"
    echo -e "Log:     ${LOG}"
    echo -e "${YELLOW}Manual actions to consider:${NC}"
    echo -e "  - Remove unused containers: docker container prune"
    echo -e "  - Remove unused images: docker image prune -a"
    echo -e "  - Enable Docker Content Trust: export DOCKER_CONTENT_TRUST=1"
}

main "$@"
