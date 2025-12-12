#!/bin/bash

#############################################################################
# STIG Compliance Check Script
# STIG ID: UBTU-24-300022
# Rule ID: SV-270708r1066613
# Severity: CAT I
# Title: Ubuntu 24.04 LTS remote X connections must be disabled
#############################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# STIG Information
STIG_ID="UBTU-24-300022"
RULE_ID="SV-270708r1066613"
SEVERITY="CAT I"
TITLE="Ubuntu 24.04 LTS remote X connections must be disabled"

# SSH config paths
SSH_CONFIG="/etc/ssh/sshd_config"
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"

# Expected value
EXPECTED_VALUE="no"

# Results tracking
COMPLIANT=true
FINDINGS=()
X11_FORWARDING_VALUE=""
X11_FORWARDING_FOUND=false
CONFLICT_DETECTED=false

#############################################################################
# Functions
#############################################################################

print_header() {
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}         STIG Compliance Check - ${STIG_ID}${NC}"
    echo -e "${MAGENTA}         X11 Forwarding Configuration Check${NC}"
    echo -e "${MAGENTA}         Severity: ${SEVERITY} (CRITICAL)${NC}"
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_info() {
    echo -e "${CYAN}STIG Information:${NC}"
    echo "  STIG ID:   ${STIG_ID}"
    echo "  Rule ID:   ${RULE_ID}"
    echo "  Severity:  ${SEVERITY}"
    echo "  Title:     ${TITLE}"
    echo ""
    echo -e "${CYAN}Purpose:${NC}"
    echo "  • Prevent X11 display server exposure to attacks"
    echo "  • Protect against keystroke monitoring"
    echo "  • Reduce attack surface by disabling unnecessary services"
    echo "  • Prevent unauthorized access to local X11 display"
    echo ""
}

check_os_version() {
    echo -e "${CYAN}Checking Operating System Version...${NC}"
    
    if [ ! -f /etc/os-release ]; then
        echo -e "${RED}  ✗ Cannot determine OS version${NC}"
        FINDINGS+=("Cannot determine OS version - /etc/os-release not found")
        return 1
    fi
    
    . /etc/os-release
    
    echo "  OS Name:    ${NAME}"
    echo "  OS Version: ${VERSION}"
    echo "  Version ID: ${VERSION_ID}"
    echo ""
    
    if [[ ! "${VERSION_ID}" =~ ^24\.04 ]]; then
        echo -e "${YELLOW}  ! Warning: This script is designed for Ubuntu 24.04 LTS${NC}"
        echo -e "${YELLOW}    Current version: ${VERSION_ID}${NC}"
        FINDINGS+=("System is not Ubuntu 24.04 LTS (detected: ${VERSION_ID})")
    else
        echo -e "${GREEN}  ✓ Ubuntu 24.04 LTS detected${NC}"
    fi
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
        echo -e "${RED}  ✗ SSH configuration file not found: ${SSH_CONFIG}${NC}"
        COMPLIANT=false
        FINDINGS+=("SSH configuration file missing")
        return 1
    fi
    
    echo -e "${GREEN}  ✓ SSH server is installed${NC}"
    echo -e "${GREEN}  ✓ Configuration file exists: ${SSH_CONFIG}${NC}"
    echo ""
    return 0
}

get_effective_x11_config() {
    local value=""
    local config_files=()
    local all_values=()
    
    # Build list of config files to check (in order of precedence)
    config_files+=("${SSH_CONFIG}")
    
    if [ -d "${SSH_CONFIG_DIR}" ]; then
        while IFS= read -r -d '' file; do
            config_files+=("${file}")
        done < <(find "${SSH_CONFIG_DIR}" -type f -name "*.conf" -print0 | sort -z)
    fi
    
    # Check all config files
    for config_file in "${config_files[@]}"; do
        if [ -f "${config_file}" ]; then
            # Get X11Forwarding values (case-insensitive, excluding comments)
            while IFS= read -r line; do
                if [ -n "${line}" ]; then
                    local file_value=$(echo "${line}" | awk '{print tolower($2)}')
                    all_values+=("${config_file}:${file_value}")
                    value="${file_value}"  # Last occurrence wins
                fi
            done < <(grep -i "^[[:space:]]*X11Forwarding" "${config_file}" 2>/dev/null | grep -v "^#")
        fi
    done
    
    # Check for conflicts (different values across files)
    if [ ${#all_values[@]} -gt 1 ]; then
        local first_val=$(echo "${all_values[0]}" | cut -d':' -f2)
        for entry in "${all_values[@]}"; do
            local current_val=$(echo "${entry}" | cut -d':' -f2)
            if [ "${current_val}" != "${first_val}" ]; then
                CONFLICT_DETECTED=true
                break
            fi
        done
    fi
    
    echo "${value}"
}

check_x11_forwarding() {
    echo -e "${CYAN}Checking X11Forwarding configuration...${NC}"
    echo ""
    
    # Search for X11Forwarding in all SSH config files
    echo "  Searching SSH configuration files..."
    echo ""
    
    local search_results=$(sudo grep -ir "x11forwarding" /etc/ssh/sshd_config* 2>/dev/null | grep -v "^#")
    
    if [ -n "${search_results}" ]; then
        echo "  Found X11Forwarding entries:"
        echo "${search_results}" | while IFS= read -r line; do
            echo "    ${line}"
        done
        echo ""
    else
        echo -e "${YELLOW}  ! No X11Forwarding entries found${NC}"
        echo ""
    fi
    
    # Get effective configuration value
    X11_FORWARDING_VALUE=$(get_effective_x11_config)
    
    if [ -n "${X11_FORWARDING_VALUE}" ]; then
        X11_FORWARDING_FOUND=true
        echo "  Effective Configuration:"
        echo "    Current value: ${X11_FORWARDING_VALUE}"
        echo "    Expected value: ${EXPECTED_VALUE}"
        echo ""
        
        if [ "${X11_FORWARDING_VALUE}" = "${EXPECTED_VALUE}" ]; then
            echo -e "${GREEN}  ✓ X11Forwarding is correctly set to 'no'${NC}"
        else
            echo -e "${RED}  ✗ X11Forwarding is NOT set to 'no'${NC}"
            COMPLIANT=false
            FINDINGS+=("X11Forwarding is set to '${X11_FORWARDING_VALUE}' (expected: no)")
        fi
    else
        echo -e "${RED}  ✗ X11Forwarding is not explicitly configured${NC}"
        COMPLIANT=false
        X11_FORWARDING_FOUND=false
        FINDINGS+=("X11Forwarding is not configured (must be explicitly set to 'no')")
    fi
    echo ""
}

check_conflicts() {
    if [ "${CONFLICT_DETECTED}" = true ]; then
        echo -e "${CYAN}Checking for conflicting settings...${NC}"
        echo ""
        echo -e "${YELLOW}  ! Multiple conflicting X11Forwarding values detected${NC}"
        echo ""
        
        # Show all occurrences
        echo "  All X11Forwarding entries found:"
        sudo grep -ir "^[[:space:]]*X11Forwarding" /etc/ssh/sshd_config* 2>/dev/null | grep -v "^#" | while IFS= read -r line; do
            echo "    ${line}"
        done
        echo ""
        
        COMPLIANT=false
        FINDINGS+=("Multiple conflicting X11Forwarding entries detected")
    fi
}

check_x11_packages() {
    echo -e "${CYAN}Checking X11 related packages...${NC}"
    echo ""
    
    local x11_packages=("xserver-xorg" "xorg" "x11-common")
    local installed_packages=()
    
    for package in "${x11_packages[@]}"; do
        if dpkg -l 2>/dev/null | grep -q "^ii.*${package}"; then
            installed_packages+=("${package}")
            echo -e "${YELLOW}  ! X11 package installed: ${package}${NC}"
        fi
    done
    
    if [ ${#installed_packages[@]} -eq 0 ]; then
        echo -e "${GREEN}  ✓ No X11 server packages installed${NC}"
    else
        echo ""
        echo -e "${YELLOW}  Note: X11 packages are installed on this system${NC}"
        echo -e "${YELLOW}  If not required, consider removing X11 packages${NC}"
    fi
    echo ""
}

check_ssh_service() {
    echo -e "${CYAN}Checking SSH service status...${NC}"
    echo ""
    
    if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
        echo -e "${GREEN}  ✓ SSH service is active${NC}"
        
        # Show listening ports
        if command -v ss &>/dev/null; then
            echo ""
            echo "  SSH listening on:"
            ss -tlnp 2>/dev/null | grep sshd | while read -r line; do
                echo "    ${line}"
            done
        fi
    else
        echo -e "${YELLOW}  ! SSH service is not running${NC}"
    fi
    echo ""
}

check_x11_display() {
    echo -e "${CYAN}Checking X11 display environment...${NC}"
    echo ""
    
    if [ -n "${DISPLAY}" ]; then
        echo -e "${YELLOW}  ! DISPLAY environment variable is set: ${DISPLAY}${NC}"
    else
        echo -e "${GREEN}  ✓ DISPLAY environment variable is not set${NC}"
    fi
    
    if [ -n "${XAUTHORITY}" ]; then
        echo -e "${YELLOW}  ! XAUTHORITY environment variable is set: ${XAUTHORITY}${NC}"
    else
        echo -e "${GREEN}  ✓ XAUTHORITY environment variable is not set${NC}"
    fi
    echo ""
}

print_results() {
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}                    COMPLIANCE RESULTS${NC}"
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if [ "${COMPLIANT}" = true ]; then
        echo -e "${GREEN}✓ STATUS: COMPLIANT${NC}"
        echo ""
        echo -e "${GREEN}System Assessment:${NC}"
        echo "  ✓ X11Forwarding is set to 'no'"
        echo "  ✓ Remote X connections are disabled"
        echo "  ✓ X11 display server not exposed to attacks"
        echo "  ✓ Complies with NIST SP 800-53"
        echo "  ✓ Meeting CAT I security requirement"
        echo ""
        echo -e "${CYAN}Current Configuration:${NC}"
        echo "  X11Forwarding: ${X11_FORWARDING_VALUE}"
        echo ""
        echo -e "${CYAN}Security Benefits:${NC}"
        echo "  • Protected against X11 display server attacks"
        echo "  • Prevented keystroke monitoring via X11"
        echo "  • Reduced attack surface"
        echo "  • Enhanced SSH security"
        echo ""
        echo -e "${CYAN}Recommendation:${NC}"
        echo "  • Continue to maintain this secure configuration"
        echo "  • Regularly audit SSH configuration"
        echo "  • Monitor for unauthorized configuration changes"
        echo "  • Only enable X11Forwarding if documented mission requirement"
        echo ""
        
    else
        echo -e "${RED}✗ STATUS: NON-COMPLIANT${NC}"
        echo ""
        echo -e "${RED}CRITICAL SECURITY ISSUE DETECTED:${NC}"
        echo "  ✗ X11Forwarding is not properly configured"
        echo "  ✗ System may be vulnerable to X11 attacks"
        echo "  ✗ X11 display server may be exposed"
        echo "  ✗ Does NOT meet NIST SP 800-53 requirements"
        echo ""
        
        echo -e "${YELLOW}Current Configuration:${NC}"
        if [ "${X11_FORWARDING_FOUND}" = true ]; then
            echo "  X11Forwarding: ${X11_FORWARDING_VALUE} (Expected: no)"
        else
            echo "  X11Forwarding: NOT SET (Expected: no)"
        fi
        echo ""
        
        if [ ${#FINDINGS[@]} -gt 0 ]; then
            echo -e "${RED}Findings:${NC}"
            for finding in "${FINDINGS[@]}"; do
                echo "  • ${finding}"
            done
            echo ""
        fi
        
        echo -e "${YELLOW}Security Impact:${NC}"
        echo "  • X11 display server exposed to potential attacks"
        echo "  • Risk of keystroke monitoring"
        echo "  • Potential unauthorized access to local display"
        echo "  • Increased attack surface"
        echo "  • Man-in-the-middle attack vulnerability"
        echo ""
        
        echo -e "${YELLOW}IMMEDIATE ACTION REQUIRED:${NC}"
        echo "  1. Run remediation script:"
        echo "     sudo ./Remote_x_Fix.sh"
        echo ""
        echo "  2. Or manually configure:"
        echo "     sudo vi /etc/ssh/sshd_config"
        echo "     Add/modify: X11Forwarding no"
        echo "     sudo systemctl restart ssh"
        echo ""
        echo "  3. Verify configuration:"
        echo "     sudo sshd -T | grep -i x11forwarding"
        echo ""
        
        if [ "${CONFLICT_DETECTED}" = true ]; then
            echo -e "${RED}  WARNING: Multiple conflicting entries found!${NC}"
            echo -e "${RED}  Review all SSH config files and remove duplicates${NC}"
            echo ""
        fi
    fi
}


#############################################################################
# Main Execution
#############################################################################

# Check if running as root (for some checks)
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${YELLOW}Note: Some checks require root privileges. Run with sudo for complete checks.${NC}"
    echo ""
fi

# Check OS version
check_os_version

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
check_x11_forwarding
check_conflicts
check_x11_packages
check_ssh_service
check_x11_display

# Display results
print_results

# Exit with appropriate code
if [ "${COMPLIANT}" = true ]; then
    exit 0
else
    exit 1
fi
