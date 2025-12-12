#!/bin/bash

#############################################################################
# STIG Remediation Script
# STIG ID: UBTU-24-300022
# Rule ID: SV-270708r1066613
# Severity: CAT I
# Title: Disable remote X connections on Ubuntu 24.04 LTS
#############################################################################

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# STIG Information
STIG_ID="UBTU-24-300022"
RULE_ID="SV-270708r1066613"
SEVERITY="CAT I"
TITLE="Ubuntu 24.04 LTS remote X connections must be disabled"

# SSH config
SSH_CONFIG="/etc/ssh/sshd_config"
BACKUP_DIR="/root/stig_backups"

# Flags
FORCE=false
BACKUP=true
VERIFY=true

#############################################################################
# Functions
#############################################################################

print_header() {
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}         STIG Remediation - ${STIG_ID}${NC}"
    echo -e "${MAGENTA}         Disable X11 Forwarding${NC}"
    echo -e "${MAGENTA}         Severity: ${SEVERITY} (CRITICAL)${NC}"
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
    -f, --force        Skip confirmation prompts
    --no-backup        Skip configuration backup
    --no-verify        Skip post-remediation verification
    -h, --help         Display this help message

Examples:
    $0                 # Interactive remediation with backup
    $0 --force         # Automatic remediation
    $0 --force --no-backup  # Without backup
    
EOF
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}ERROR: This script must be run as root or with sudo${NC}"
        exit 1
    fi
}

check_ssh_installed() {
    if ! command -v sshd &> /dev/null; then
        echo -e "${YELLOW}SSH server is not installed${NC}"
        echo -e "${YELLOW}This remediation is not applicable${NC}"
        exit 0
    fi
    
    if [ ! -f "${SSH_CONFIG}" ]; then
        echo -e "${RED}ERROR: SSH configuration file not found: ${SSH_CONFIG}${NC}"
        exit 1
    fi
}

get_current_config() {
    local value=$(sudo sshd -T 2>/dev/null | grep -i "^x11forwarding" | awk '{print tolower($2)}')
    if [ -z "${value}" ]; then
        value=$(grep -i "^[[:space:]]*X11Forwarding" "${SSH_CONFIG}" 2>/dev/null | grep -v "^#" | tail -1 | awk '{print tolower($2)}')
    fi
    echo "${value}"
}

check_current_status() {
    echo -e "${CYAN}Checking current X11Forwarding configuration...${NC}"
    echo ""
    
    local current_value=$(get_current_config)
    
    echo "  Current X11Forwarding: ${current_value:-not set}"
    echo "  Required X11Forwarding: no"
    echo ""
    
    if [ "${current_value}" = "no" ]; then
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}         SYSTEM IS ALREADY COMPLIANT${NC}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
        echo ""
        return 1
    fi
    
    echo -e "${RED}NON-COMPLIANT CONFIGURATION DETECTED${NC}"
    return 0
}

backup_config() {
    if [ "${BACKUP}" = false ]; then
        return 0
    fi
    
    echo -e "${CYAN}Creating configuration backup...${NC}"
    
    mkdir -p "${BACKUP_DIR}"
    local backup_file="${BACKUP_DIR}/sshd_config_$(date +%Y%m%d_%H%M%S).bak"
    
    if cp -p "${SSH_CONFIG}" "${backup_file}"; then
        echo -e "${GREEN}  ✓ Backup created: ${backup_file}${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}  ✗ Backup failed${NC}"
        return 1
    fi
}

remove_conflicting_entries() {
    echo -e "${CYAN}Removing conflicting X11Forwarding entries...${NC}"
    
    # Remove all existing X11Forwarding lines (commented and uncommented)
    sed -i '/^[[:space:]]*#\?[[:space:]]*X11Forwarding/Id' "${SSH_CONFIG}"
    
    echo -e "${GREEN}  ✓ Removed existing X11Forwarding entries${NC}"
    echo ""
}

configure_x11_forwarding() {
    echo -e "${CYAN}Configuring X11Forwarding...${NC}"
    echo ""
    
    # Remove existing entries
    remove_conflicting_entries
    
    # Add new configuration at the end of the file
    echo "" >> "${SSH_CONFIG}"
    echo "# STIG ${STIG_ID}: Disable X11 Forwarding" >> "${SSH_CONFIG}"
    echo "X11Forwarding no" >> "${SSH_CONFIG}"
    
    echo -e "${GREEN}  ✓ Added 'X11Forwarding no' to ${SSH_CONFIG}${NC}"
    echo ""
}

test_ssh_config() {
    echo -e "${CYAN}Testing SSH configuration syntax...${NC}"
    
    if sshd -t 2>/dev/null; then
        echo -e "${GREEN}  ✓ SSH configuration syntax is valid${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}  ✗ SSH configuration has syntax errors${NC}"
        sshd -t
        echo ""
        return 1
    fi
}

restart_ssh_service() {
    echo -e "${CYAN}Restarting SSH service...${NC}"
    
    if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
        echo -e "${GREEN}  ✓ SSH service restarted successfully${NC}"
        
        # Wait for service to be fully up
        sleep 2
        
        if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
            echo -e "${GREEN}  ✓ SSH service is active${NC}"
            echo ""
            return 0
        else
            echo -e "${RED}  ✗ SSH service failed to start${NC}"
            echo ""
            return 1
        fi
    else
        echo -e "${RED}  ✗ Failed to restart SSH service${NC}"
        echo ""
        return 1
    fi
}

verify_remediation() {
    if [ "${VERIFY}" = false ]; then
        return 0
    fi
    
    echo -e "${CYAN}Verifying remediation...${NC}"
    echo ""
    
    local x11_value=$(sshd -T 2>/dev/null | grep -i "^x11forwarding" | awk '{print tolower($2)}')
    
    local verification_passed=true
    
    echo "  Checking X11Forwarding configuration..."
    if [ "${x11_value}" = "no" ]; then
        echo -e "${GREEN}    ✓ X11Forwarding = no${NC}"
    else
        echo -e "${RED}    ✗ X11Forwarding = ${x11_value}${NC}"
        verification_passed=false
    fi
    
    # Check for multiple entries
    local entry_count=$(grep -i "^[[:space:]]*X11Forwarding" "${SSH_CONFIG}" 2>/dev/null | grep -v "^#" | wc -l)
    if [ "${entry_count}" -eq 1 ]; then
        echo -e "${GREEN}    ✓ Single X11Forwarding entry found${NC}"
    elif [ "${entry_count}" -gt 1 ]; then
        echo -e "${RED}    ✗ Multiple X11Forwarding entries found${NC}"
        verification_passed=false
    fi
    
    echo ""
    
    if [ "${verification_passed}" = true ]; then
        echo -e "${GREEN}  ✓ Verification PASSED${NC}"
        return 0
    else
        echo -e "${RED}  ✗ Verification FAILED${NC}"
        return 1
    fi
}

print_success() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}         REMEDIATION COMPLETED SUCCESSFULLY${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${GREEN}Configuration Applied:${NC}"
    echo "  ✓ X11Forwarding set to 'no'"
    echo "  ✓ SSH service restarted"
    echo "  ✓ Configuration verified"
    echo "  ✓ System is now compliant with STIG ${STIG_ID}"
    echo ""
    
    echo -e "${GREEN}Security Improvements:${NC}"
    echo "  ✓ X11 display server not exposed to attacks"
    echo "  ✓ Keystroke monitoring prevented"
    echo "  ✓ Reduced attack surface"
    echo "  ✓ Enhanced SSH security"
    echo "  ✓ Complies with NIST SP 800-53"
    echo ""
    
    echo -e "${CYAN}Important Notes:${NC}"
    echo "  • X11 forwarding is now disabled"
    echo "  • GUI applications cannot be forwarded over SSH"
    echo "  • Existing SSH sessions are not affected"
    echo "  • New connections will use updated configuration"
    echo ""
    
    echo -e "${CYAN}If X11 Forwarding is Required:${NC}"
    echo "  • Document the operational requirement with ISSO"
    echo "  • Enable X11UseLocalhost to limit exposure"
    echo "  • Use ForwardX11Trusted no for untrusted connections"
    echo "  • Implement additional security controls"
    echo ""
}


#############################################################################
# Main Execution
#############################################################################

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--force) FORCE=true; shift ;;
        --no-backup) BACKUP=false; shift ;;
        --no-verify) VERIFY=false; shift ;;
        -h|--help) print_usage; exit 0 ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; print_usage; exit 1 ;;
    esac
done

clear
print_header
check_root
check_ssh_installed

if ! check_current_status; then
    exit 0
fi

# Confirmation
if [ "${FORCE}" = false ]; then
    echo -e "${YELLOW}This will modify ${SSH_CONFIG} and restart SSH service${NC}"
    echo -e "${YELLOW}Active SSH sessions will not be interrupted${NC}"
    echo ""
    read -p "Proceed with remediation? (yes/no): " confirmation
    if [ "${confirmation}" != "yes" ]; then
        echo "Cancelled"
        exit 0
    fi
    echo ""
fi

# Execute remediation
backup_config
configure_x11_forwarding

if ! test_ssh_config; then
    echo -e "${RED}Configuration test failed - rolling back${NC}"
    if [ "${BACKUP}" = true ]; then
        latest_backup=$(ls -t "${BACKUP_DIR}"/sshd_config_*.bak 2>/dev/null | head -1)
        if [ -n "${latest_backup}" ]; then
            cp "${latest_backup}" "${SSH_CONFIG}"
            echo "Restored from backup"
        fi
    fi
    exit 1
fi

if ! restart_ssh_service; then
    echo -e "${RED}Failed to restart SSH service${NC}"
    exit 1
fi

if verify_remediation; then
    print_success
    exit 0
else
    echo -e "${RED}Remediation completed but verification failed${NC}"
    exit 1
fi
