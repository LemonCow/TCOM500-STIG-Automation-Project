#!/bin/bash

#############################################################################
# STIG Compliance Check Script
# STIG ID: UBTU-24-300031
# Rule ID: SV-270717r1067177
# Severity: CAT I
# Title: Ubuntu 24.04 LTS must not allow unattended or automatic login via SSH
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

# SSH config paths
SSH_CONFIG="/etc/ssh/sshd_config"
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"

# Expected values
EXPECTED_PERMIT_EMPTY_PASSWORDS="no"
EXPECTED_PERMIT_USER_ENVIRONMENT="no"

# Results tracking
COMPLIANT=true
FINDINGS=()
PERMIT_EMPTY_PASSWORDS_VALUE=""
PERMIT_USER_ENVIRONMENT_VALUE=""
PERMIT_EMPTY_PASSWORDS_FOUND=false
PERMIT_USER_ENVIRONMENT_FOUND=false

#############################################################################
# Functions
#############################################################################

print_header() {
    echo -e "${MAGENTA}---------------------------------------------------------------${NC}"
    echo -e "${MAGENTA}         STIG Compliance Check - ${STIG_ID}${NC}"
    echo -e "${MAGENTA}         SSH Unattended/Automatic Login Prevention${NC}"
    echo -e "${MAGENTA}         Severity: ${SEVERITY}${NC}"
    echo -e "${MAGENTA}---------------------------------------------------------------${NC}"
    echo ""
}

print_info() {
    echo -e "${CYAN}STIG Information:${NC}"
    echo "  STIG ID:   ${STIG_ID}"
    echo "  Rule ID:   ${RULE_ID}"
    echo "  Severity:  ${SEVERITY}"
    echo "  Title:     ${TITLE}"
    echo ""
}

check_ssh_installed() {
    echo -e "${CYAN}Checking SSH installation...${NC}"
    
    if ! command -v sshd &> /dev/null; then
        echo -e "${YELLOW}  ! SSH server is not installed${NC}"
        echo -e "${YELLOW}  This check is not applicable${NC}"
        echo ""
        return 1
    fi
    
    if [ ! -f "${SSH_CONFIG}" ]; then
        echo -e "${RED}  ? SSH configuration file not found: ${SSH_CONFIG}${NC}"
        COMPLIANT=false
        FINDINGS+=("SSH configuration file missing")
        return 1
    fi
    
    echo -e "${GREEN}  ? SSH server is installed${NC}"
    echo -e "${GREEN}  ? Configuration file exists: ${SSH_CONFIG}${NC}"
    echo ""
    return 0
}

get_effective_ssh_config() {
    local parameter=$1
    local value=""
    
    # Check if sshd supports -T option for testing configuration
    if sshd -T &>/dev/null; then
        value=$(sshd -T 2>/dev/null | grep -i "^${parameter}" | awk '{print tolower($2)}')
    fi
    
    # If sshd -T didn't work, parse config files manually
    if [ -z "${value}" ]; then
        # Check main config file (last occurrence wins)
        if [ -f "${SSH_CONFIG}" ]; then
            value=$(grep -i "^${parameter}" "${SSH_CONFIG}" | tail -1 | awk '{print tolower($2)}')
        fi
        
        # Check include directory (files processed in lexical order)
        if [ -d "${SSH_CONFIG_DIR}" ]; then
            for conf_file in "${SSH_CONFIG_DIR}"/*.conf; do
                if [ -f "${conf_file}" ]; then
                    local file_value=$(grep -i "^${parameter}" "${conf_file}" | tail -1 | awk '{print tolower($2)}')
                    if [ -n "${file_value}" ]; then
                        value="${file_value}"
                    fi
                fi
            done
        fi
    fi
    
    echo "${value}"
}

check_ssh_configuration() {
    echo -e "${CYAN}Checking SSH configuration parameters...${NC}"
    echo ""
    
    # Get effective configuration values
    PERMIT_EMPTY_PASSWORDS_VALUE=$(get_effective_ssh_config "permitemptypasswords")
    PERMIT_USER_ENVIRONMENT_VALUE=$(get_effective_ssh_config "permituserenvironment")
    
    # Check PermitEmptyPasswords
    echo "  Checking PermitEmptyPasswords..."
    if [ -n "${PERMIT_EMPTY_PASSWORDS_VALUE}" ]; then
        PERMIT_EMPTY_PASSWORDS_FOUND=true
        echo "    Current value: ${PERMIT_EMPTY_PASSWORDS_VALUE}"
        echo "    Expected value: ${EXPECTED_PERMIT_EMPTY_PASSWORDS}"
        
        if [ "${PERMIT_EMPTY_PASSWORDS_VALUE}" = "${EXPECTED_PERMIT_EMPTY_PASSWORDS}" ]; then
            echo -e "${GREEN}    ? PermitEmptyPasswords is correctly set to 'no'${NC}"
        else
            echo -e "${RED}    ? PermitEmptyPasswords is NOT set to 'no'${NC}"
            COMPLIANT=false
            FINDINGS+=("PermitEmptyPasswords is set to '${PERMIT_EMPTY_PASSWORDS_VALUE}' (expected: no)")
        fi
    else
        echo -e "${RED}    ? PermitEmptyPasswords is not configured${NC}"
        COMPLIANT=false
        FINDINGS+=("PermitEmptyPasswords is not configured (must be explicitly set to 'no')")
    fi
    echo ""
    
    # Check PermitUserEnvironment
    echo "  Checking PermitUserEnvironment..."
    if [ -n "${PERMIT_USER_ENVIRONMENT_VALUE}" ]; then
        PERMIT_USER_ENVIRONMENT_FOUND=true
        echo "    Current value: ${PERMIT_USER_ENVIRONMENT_VALUE}"
        echo "    Expected value: ${EXPECTED_PERMIT_USER_ENVIRONMENT}"
        
        if [ "${PERMIT_USER_ENVIRONMENT_VALUE}" = "${EXPECTED_PERMIT_USER_ENVIRONMENT}" ]; then
            echo -e "${GREEN}    ? PermitUserEnvironment is correctly set to 'no'${NC}"
        else
            echo -e "${RED}    ? PermitUserEnvironment is NOT set to 'no'${NC}"
            COMPLIANT=false
            FINDINGS+=("PermitUserEnvironment is set to '${PERMIT_USER_ENVIRONMENT_VALUE}' (expected: no)")
        fi
    else
        echo -e "${RED}    ? PermitUserEnvironment is not configured${NC}"
        COMPLIANT=false
        FINDINGS+=("PermitUserEnvironment is not configured (must be explicitly set to 'no')")
    fi
    echo ""
}

check_conflicting_settings() {
    echo -e "${CYAN}Checking for conflicting settings...${NC}"
    echo ""
    
    local conflicts_found=false
    
    # Check all config files for conflicts
    local all_configs=("${SSH_CONFIG}")
    if [ -d "${SSH_CONFIG_DIR}" ]; then
        while IFS= read -r -d '' file; do
            all_configs+=("${file}")
        done < <(find "${SSH_CONFIG_DIR}" -type f -name "*.conf" -print0)
    fi
    
    for config_file in "${all_configs[@]}"; do
        if [ ! -f "${config_file}" ]; then
            continue
        fi
        
        # Check for multiple PermitEmptyPasswords entries
        local empty_pass_count=$(grep -c -i "^PermitEmptyPasswords" "${config_file}" 2>/dev/null || echo "0")
        if [ "${empty_pass_count}" -gt 1 ]; then
            echo -e "${YELLOW}  ! Multiple PermitEmptyPasswords entries in ${config_file}${NC}"
            conflicts_found=true
        fi
        
        # Check for multiple PermitUserEnvironment entries
        local user_env_count=$(grep -c -i "^PermitUserEnvironment" "${config_file}" 2>/dev/null || echo "0")
        if [ "${user_env_count}" -gt 1 ]; then
            echo -e "${YELLOW}  ! Multiple PermitUserEnvironment entries in ${config_file}${NC}"
            conflicts_found=true
        fi
    done
    
    if [ "${conflicts_found}" = false ]; then
        echo -e "${GREEN}  ? No conflicting settings found${NC}"
    else
        FINDINGS+=("Multiple conflicting SSH configuration entries detected")
    fi
    echo ""
}

check_ssh_service_status() {
    echo -e "${CYAN}Checking SSH service status...${NC}"
    echo ""
    
    if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
        echo -e "${GREEN}  ? SSH service is active${NC}"
        
        # Show listening ports
        if command -v ss &>/dev/null; then
            echo ""
            echo "  SSH listening on:"
            ss -tlnp | grep sshd | while read -r line; do
                echo "    ${line}"
            done
        fi
    else
        echo -e "${YELLOW}  ! SSH service is not running${NC}"
    fi
    echo ""
}

print_results() {
    echo -e "${MAGENTA}---------------------------------------------------------------${NC}"
    echo -e "${MAGENTA}                    COMPLIANCE RESULTS${NC}"
    echo -e "${MAGENTA}---------------------------------------------------------------${NC}"
    echo ""
    
    if [ "${COMPLIANT}" = true ]; then
        echo -e "${GREEN}? STATUS: COMPLIANT${NC}"
        echo ""
        echo -e "${GREEN}System Assessment:${NC}"
        echo "  ? PermitEmptyPasswords is set to 'no'"
        echo "  ? PermitUserEnvironment is set to 'no'"
        echo "  ? Unattended/automatic login is prevented"
        echo "  ? Complies with NIST SP 800-53 CM-6"
        echo "  ? Meeting CAT I security requirement"
        echo ""
        echo -e "${CYAN}Current Configuration:${NC}"
        echo "  PermitEmptyPasswords: ${PERMIT_EMPTY_PASSWORDS_VALUE}"
        echo "  PermitUserEnvironment: ${PERMIT_USER_ENVIRONMENT_VALUE}"
        echo ""
        echo -e "${CYAN}Recommendation:${NC}"
        echo "  • Continue to maintain this secure configuration"
        echo "  • Regularly audit SSH configuration"
        echo "  • Monitor for unauthorized configuration changes"
        echo ""
    else
        echo -e "${RED}? STATUS: NON-COMPLIANT${NC}"
        echo ""
        echo -e "${RED}CRITICAL SECURITY ISSUE DETECTED:${NC}"
        echo "  ? SSH may allow unattended or automatic login"
        echo "  ? Empty passwords may be permitted"
        echo "  ? User environment variables may be set"
        echo "  ? Does NOT meet NIST SP 800-53 requirements"
        echo ""
        
        echo -e "${YELLOW}Current Configuration:${NC}"
        echo "  PermitEmptyPasswords: ${PERMIT_EMPTY_PASSWORDS_VALUE:-NOT SET}"
        echo "  PermitUserEnvironment: ${PERMIT_USER_ENVIRONMENT_VALUE:-NOT SET}"
        echo ""
        
        echo -e "${YELLOW}Required Configuration:${NC}"
        echo "  PermitEmptyPasswords: no"
        echo "  PermitUserEnvironment: no"
        echo ""
        
        if [ ${#FINDINGS[@]} -gt 0 ]; then
            echo -e "${RED}Findings:${NC}"
            for finding in "${FINDINGS[@]}"; do
                echo "  • ${finding}"
            done
            echo ""
        fi
        
        echo -e "${YELLOW}Security Impact:${NC}"
        echo "  • Potential for unauthorized access"
        echo "  • Accounts with empty passwords may be accessible"
        echo "  • Environment variables could be exploited"
        echo "  • Privilege escalation risk"
        echo ""
        
        echo -e "${YELLOW}IMMEDIATE ACTION REQUIRED:${NC}"
        echo "  1. Run remediation: sudo ./SSH_Unattend_Fix.sh"
        echo "  2. Or manually edit: ${SSH_CONFIG}"
        echo "     Add/modify:"
        echo "       PermitEmptyPasswords no"
        echo "       PermitUserEnvironment no"
        echo "  3. Restart SSH: sudo systemctl restart ssh"
        echo "  4. Verify: sudo sshd -T | grep -E 'permitemptypasswords|permituserenvironment'"
        echo ""
    fi
}


#############################################################################
# Main Execution
#############################################################################

# Check if running on Ubuntu 24.04
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ ! "${VERSION_ID}" =~ ^24\.04 ]]; then
        echo -e "${YELLOW}Warning: This script is designed for Ubuntu 24.04 LTS${NC}"
        echo -e "${YELLOW}Current version: ${VERSION_ID}${NC}"
        echo ""
    fi
fi

# Display header
print_header
print_info

# Check if SSH is installed
if ! check_ssh_installed; then
    echo -e "${YELLOW}SSH is not installed - STIG check not applicable${NC}"
    echo ""
    exit 0
fi

# Perform checks
check_ssh_configuration
check_conflicting_settings
check_ssh_service_status

# Display results
print_results

# Exit with appropriate code
if [ "${COMPLIANT}" = true ]; then
    exit 0
else
    exit 1
fi
