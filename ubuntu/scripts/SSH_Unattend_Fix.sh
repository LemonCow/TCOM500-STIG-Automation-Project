#!/bin/bash

#############################################################################
# STIG Remediation Script
# STIG ID: UBTU-24-300031
# Rule ID: SV-270717r1067177
# Severity: CAT I
# Title: Prevent unattended/automatic login via SSH
#############################################################################

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# STIG Information
STIG_ID="UBTU-24-300031"
RULE_ID="SV-270717r1067177"
SEVERITY="CAT I"
TITLE="Ubuntu 24.04 LTS must not allow unattended or automatic login via SSH"

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
    echo -e "${MAGENTA}---------------------------------------------------------------${NC}"
    echo -e "${MAGENTA}         STIG Remediation - ${STIG_ID}${NC}"
    echo -e "${MAGENTA}         Prevent SSH Unattended/Automatic Login${NC}"
    echo -e "${MAGENTA}         Severity: ${SEVERITY} (Critical)${NC}"
    echo -e "${MAGENTA}---------------------------------------------------------------${NC}"
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
    local param=$1
    sshd -T 2>/dev/null | grep -i "^${param}" | awk '{print tolower($2)}' || \
    grep -i "^${param}" "${SSH_CONFIG}" | tail -1 | awk '{print tolower($2)}'
}

check_current_status() {
    echo -e "${CYAN}Checking current SSH configuration...${NC}"
    echo ""
    
    local permit_empty=$(get_current_config "permitemptypasswords")
    local permit_env=$(get_current_config "permituserenvironment")
    
    echo "  Current PermitEmptyPasswords: ${permit_empty:-not set}"
    echo "  Current PermitUserEnvironment: ${permit_env:-not set}"
    echo ""
    echo "  Required PermitEmptyPasswords: no"
    echo "  Required PermitUserEnvironment: no"
    echo ""
    
    if [ "${permit_empty}" = "no" ] && [ "${permit_env}" = "no" ]; then
        echo -e "${GREEN}---------------------------------------------------------------${NC}"
        echo -e "${GREEN}         SYSTEM IS ALREADY COMPLIANT${NC}"
        echo -e "${GREEN}---------------------------------------------------------------${NC}"
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
        echo -e "${GREEN}  ? Backup created: ${backup_file}${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}  ? Backup failed${NC}"
        return 1
    fi
}

configure_ssh_parameter() {
    local param=$1
    local value=$2
    local config_file=$3
    
    # Remove existing commented and uncommented lines
    sed -i "/^[#[:space:]]*${param}/d" "${config_file}"
    
    # Add new configuration at the end
    echo "${param} ${value}" >> "${config_file}"
}

apply_remediation() {
    echo -e "${CYAN}Applying SSH configuration changes...${NC}"
    echo ""
    
    # Configure PermitEmptyPasswords
    echo "  Configuring PermitEmptyPasswords..."
    configure_ssh_parameter "PermitEmptyPasswords" "no" "${SSH_CONFIG}"
    echo -e "${GREEN}    ? PermitEmptyPasswords set to 'no'${NC}"
    
    # Configure PermitUserEnvironment
    echo "  Configuring PermitUserEnvironment..."
    configure_ssh_parameter "PermitUserEnvironment" "no" "${SSH_CONFIG}"
    echo -e "${GREEN}    ? PermitUserEnvironment set to 'no'${NC}"
    
    echo ""
}

test_ssh_config() {
    echo -e "${CYAN}Testing SSH configuration syntax...${NC}"
    
    if sshd -t 2>/dev/null; then
        echo -e "${GREEN}  ? SSH configuration syntax is valid${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}  ? SSH configuration has syntax errors${NC}"
        sshd -t
        echo ""
        return 1
    fi
}

restart_ssh_service() {
    echo -e "${CYAN}Restarting SSH service...${NC}"
    
    if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
        echo -e "${GREEN}  ? SSH service restarted successfully${NC}"
        
        # Wait for service to be fully up
        sleep 2
        
        if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
            echo -e "${GREEN}  ? SSH service is active${NC}"
            echo ""
            return 0
        else
            echo -e "${RED}  ? SSH service failed to start${NC}"
            echo ""
            return 1
        fi
    else
        echo -e "${RED}  ? Failed to restart SSH service${NC}"
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
    
    local permit_empty=$(sshd -T 2>/dev/null | grep -i "^permitemptypasswords" | awk '{print tolower($2)}')
    local permit_env=$(sshd -T 2>/dev/null | grep -i "^permituserenvironment" | awk '{print tolower($2)}')
    
    local verification_passed=true
    
    echo "  Checking PermitEmptyPasswords..."
    if [ "${permit_empty}" = "no" ]; then
        echo -e "${GREEN}    ? PermitEmptyPasswords = no${NC}"
    else
        echo -e "${RED}    ? PermitEmptyPasswords = ${permit_empty}${NC}"
        verification_passed=false
    fi
    
    echo "  Checking PermitUserEnvironment..."
    if [ "${permit_env}" = "no" ]; then
        echo -e "${GREEN}    ? PermitUserEnvironment = no${NC}"
    else
        echo -e "${RED}    ? PermitUserEnvironment = ${permit_env}${NC}"
        verification_passed=false
    fi
    
    echo ""
    
    if [ "${verification_passed}" = true ]; then
        echo -e "${GREEN}  ? Verification PASSED${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}  ? Verification FAILED${NC}"
        echo ""
        return 1
    fi
}

print_success() {
    echo -e "${GREEN}---------------------------------------------------------------${NC}"
    echo -e "${GREEN}         REMEDIATION COMPLETED SUCCESSFULLY${NC}"
    echo -e "${GREEN}---------------------------------------------------------------${NC}"
    echo ""
    
    echo -e "${GREEN}Configuration Applied:${NC}"
    echo "  ? PermitEmptyPasswords set to 'no'"
    echo "  ? PermitUserEnvironment set to 'no'"
    echo "  ? SSH service restarted"
    echo "  ? Configuration verified"
    echo ""
    
    echo -e "${GREEN}Security Improvements:${NC}"
    echo "  ? Empty passwords are not permitted"
    echo "  ? User environment variables cannot be set"
    echo "  ? Unattended/automatic login prevented"
    echo "  ? Complies with NIST SP 800-53 CM-6"
    echo ""
    
    echo -e "${CYAN}Important Notes:${NC}"
    echo "  • Changes are effective immediately"
    echo "  • Existing SSH sessions are not affected"
    echo "  • New connections will use updated configuration"
    echo "  • Run compliance check to verify"
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
    read -p "Proceed with remediation? (yes/no): " confirmation
    if [ "${confirmation}" != "yes" ]; then
        echo "Cancelled"
        exit 0
    fi
    echo ""
fi

# Execute remediation
backup_config
apply_remediation

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
    generate_report
    exit 0
else
    echo -e "${RED}Remediation completed but verification failed${NC}"
    exit 1
fi
