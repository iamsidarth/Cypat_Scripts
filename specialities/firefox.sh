#!/bin/bash
###############################################################################
#  CyberPatriot — Firefox Hardening (Standalone)
#  Run: sudo ./firefox.sh
#
#  Applies hardened Firefox settings via policies.json for all users.
#  Covers: block dangerous downloads, HTTPS-only mode, disable telemetry,
#           OCSP enabled, disable password saving, etc.
###############################################################################
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BACKUP_DIR="/tmp/cypat-firefox-backup-$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/cypat-firefox-$(date +%Y%m%d-%H%M%S).log"

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
        echo "Usage: sudo ./firefox.sh"
        echo "Hardens Firefox via system-wide policies.json"
        exit 0
    fi

    echo -e "${BOLD}${BLUE}╔══ Firefox Hardening ══╗${NC}"
    require_root
    mkdir -p "$BACKUP_DIR"

    if ! command -v firefox &>/dev/null && ! dpkg -l firefox &>/dev/null 2>&1; then
        warn "Firefox is not installed. Skipping."
        exit 0
    fi

    # Install firefox if on path
    local firefox_version
    firefox_version=$(firefox --version 2>/dev/null || echo "unknown")
    info "Firefox: $firefox_version"

    # ── Determine policies.json locations ──
    step "Deploying policies.json"

    local policy_dirs=()
    # System-wide locations
    if [[ -d /etc/firefox ]]; then
        policy_dirs+=("/etc/firefox")
    fi
    if [[ -d /etc/firefox-esr ]]; then
        policy_dirs+=("/etc/firefox-esr")
    fi

    # Snap-based firefox (Ubuntu)
    if [[ -d /snap/firefox ]]; then
        mkdir -p /etc/firefox 2>/dev/null || true
        policy_dirs+=("/etc/firefox")
    fi

    # Distro-specific
    for dir in /usr/lib/firefox /usr/lib/firefox-esr /usr/lib64/firefox \
               /opt/firefox /usr/share/firefox; do
        if [[ -d "$dir" ]]; then
            mkdir -p "$dir/distribution" 2>/dev/null || true
            policy_dirs+=("$dir/distribution")
        fi
    done

    # Default: always deploy to /etc/firefox
    mkdir -p /etc/firefox/policies 2>/dev/null || true
    policy_dirs+=("/etc/firefox")

    # ── Create policies.json ──
    local policy_json
    policy_json=$(cat <<'POLICY'
{
  "policies": {
    "BlockAboutAddons": true,
    "BlockAboutConfig": true,
    "BlockAboutProfiles": true,
    "BlockAboutSupport": true,
    "Cookies": {
      "AcceptThirdParty": "never",
      "ExpireAtSessionEnd": false,
      "RejectTracker": true
    },
    "DisableBuiltinPDFViewer": false,
    "DisableDeveloperTools": true,
    "DisableFeedbackCommands": true,
    "DisableFirefoxAccounts": true,
    "DisableFirefoxScreenshots": false,
    "DisableFirefoxStudies": true,
    "DisableForgetButton": false,
    "DisableFormHistory": true,
    "DisableMasterPasswordCreation": false,
    "DisablePasswordReveal": false,
    "DisablePocket": true,
    "DisablePrivateBrowsing": false,
    "DisableProfileImport": true,
    "DisableProfileRefresh": true,
    "DisableSafeMode": true,
    "DisableSecurityBypass": {
      "InvalidCertificate": true,
      "SafeBrowsing": true
    },
    "DisableSetDesktopBackground": true,
    "DisableSystemAddonUpdate": true,
    "DisableTelemetry": true,
    "DisplayBookmarksToolbar": false,
    "DisplayMenuBar": true,
    "DNSOverHTTPS": {
      "Enabled": false
    },
    "DontCheckDefaultBrowser": true,
    "EnableTrackingProtection": {
      "Cryptomining": true,
      "Fingerprinting": true,
      "Value": true
    },
    "EncryptedMediaExtensions": {
      "Enabled": false
    },
    "Extensions": {
      "Install": [],
      "Locked": []
    },
    "FirefoxHome": {
      "Highlights": false,
      "Pocket": false,
      "Snippets": false,
      "SponsoredPocket": false,
      "SponsoredTopSites": false
    },
    "NetworkPrediction": false,
    "NewTabPage": false,
    "NoDefaultBookmarks": true,
    "OfferToSaveLogins": false,
    "OfferToSaveLoginsDefault": false,
    "OverrideFirstRunPage": "",
    "OverridePostUpdatePage": "",
    "PasswordManagerEnabled": false,
    "Permissions": {
      "Autoplay": {
        "Default": "block-audio-video"
      },
      "Camera": {
        "BlockNewRequests": true
      },
      "Location": {
        "BlockNewRequests": true
      },
      "Microphone": {
        "BlockNewRequests": true
      },
      "Notifications": {
        "BlockNewRequests": true
      }
    },
    "PictureInPicture": {
      "Enabled": false
    },
    "PopupBlocking": {
      "Default": true
    },
    "Preferences": {
      "browser.contentblocking.category": {
        "Value": "strict",
        "Status": "locked"
      },
      "browser.safebrowsing.malware.enabled": {
        "Value": true,
        "Status": "locked"
      },
      "browser.safebrowsing.phishing.enabled": {
        "Value": true,
        "Status": "locked"
      },
      "browser.safebrowsing.downloads.enabled": {
        "Value": true,
        "Status": "locked"
      },
      "dom.security.https_only_mode": {
        "Value": true,
        "Status": "locked"
      },
      "security.OCSP.enabled": {
        "Value": 1,
        "Status": "locked"
      },
      "security.OCSP.require": {
        "Value": true,
        "Status": "locked"
      },
      "browser.download.alwaysOpenPanel": {
        "Value": true,
        "Status": "locked"
      },
      "extensions.update.enabled": {
        "Value": true,
        "Status": "locked"
      }
    },
    "PromptForDownloadLocation": true,
    "SanitizeOnShutdown": {
      "Cache": true,
      "Cookies": false,
      "Downloads": true,
      "FormData": true,
      "History": false,
      "Sessions": false,
      "SiteSettings": false,
      "OfflineApps": true
    },
    "SearchSuggestEnabled": false,
    "SSLErrorOverrideAllowed": false,
    "SupportMenu": {
      "Title": "IT Support",
      "URL": "https://support.internal"
    },
    "UserMessaging": {
      "WhatsNew": false,
      "ExtensionRecommendations": false,
      "FeatureRecommendations": false,
      "UrlbarInterventions": false,
      "SkipOnboarding": true,
      "MoreFromMozilla": false
    },
    "WebsiteFilter": {
      "Block": []
    }
  }
}
POLICY
)

    # Write policies.json to all applicable locations
    for dir in "${policy_dirs[@]}"; do
        mkdir -p "$dir" 2>/dev/null || continue
        if [[ -f "$dir/policies.json" ]]; then
            backup_file "$dir/policies.json"
        fi
        echo "$policy_json" > "$dir/policies.json"
        chmod 644 "$dir/policies.json"
        info "Wrote: $dir/policies.json"
    done

    pass "Firefox policies.json deployed"

    # ── Update Firefox ──
    step "Updating Firefox"
    apt-get install -y --only-upgrade firefox 2>/dev/null || true
    apt-get install -y --only-upgrade firefox-esr 2>/dev/null || true

    # Snap-based
    if [[ -d /snap/firefox ]]; then
        snap refresh firefox 2>/dev/null || true
    fi

    # Also check Chromium
    if command -v chromium &>/dev/null || command -v chromium-browser &>/dev/null; then
        info "Chromium detected — applying hardened policies"
        mkdir -p /etc/chromium/policies/managed 2>/dev/null || true
        cat > /etc/chromium/policies/managed/cypat.json <<'CHROMIUM'
{
  "SafeBrowsingEnabled": true,
  "SafeBrowsingProtectionLevel": 1,
  "PasswordManagerEnabled": false,
  "DefaultPopupsSetting": 2,
  "AutofillAddressEnabled": false,
  "AutofillCreditCardEnabled": false,
  "BlockThirdPartyCookies": true,
  "DefaultGeolocationSetting": 2,
  "BrowserAddPersonEnabled": false,
  "BrowserGuestModeEnabled": false,
  "MetricsReportingEnabled": false,
  "CloudReportingEnabled": false,
  "UrlKeyedAnonymizedDataCollectionEnabled": false,
  "ExtensionInstallBlocklist": ["*"],
  "DeveloperToolsAvailability": 2
}
CHROMIUM
        chmod 644 /etc/chromium/policies/managed/cypat.json
        info "Chromium policies deployed"
    fi

    pass "Firefox hardened"

    echo ""
    echo -e "${BOLD}${GREEN}═══ Firefox Hardening Complete ═══${NC}"
    echo -e "Backups: ${BACKUP_DIR}"
    echo -e "Log:     ${LOG}"
    echo -e "${YELLOW}Note: Users must restart Firefox for policies to take effect${NC}"
}

main "$@"
