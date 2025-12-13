#!/bin/bash

#########################################################################
# Ubuntu 24.04 LTS STIG Remediation Script
# STIG ID: UBTU-24-100030
# Rule: Remove telnet package
# Severity: CAT I
#########################################################################

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# STIG Information
STIG_ID="UBTU-24-100030"
SEVERITY="CAT I"

# Counters
REMOVED_COUNT=0
FAILED_COUNT=0

print_header() {
    echo -e "${CYAN}======================================${NC}"
    echo -e "${CYAN}STIG ${STIG_ID} Remediation${NC}"
    echo -e "${CYAN}Remove Telnet Packages${NC}"
    echo -e "${CYAN}Severity: ${SEVERITY}${NC}"
    echo -e "${CYAN}======================================${NC}"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}ERROR: Must run as root (use sudo)${NC}"
        exit 1
    fi
}

stop_telnet_services() {
    echo -e "${CYAN}Stopping telnet services...${NC}"
    
    # Stop systemd services
    for service in telnet.socket telnetd.socket telnet telnetd inetutils-telnetd; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo "  Stopping $service..."
            systemctl stop "$service" 2>/dev/null
            systemctl disable "$service" 2>/dev/null
        fi
    done
    
    # Kill any running telnet daemon
    if pgrep -x "telnetd" > /dev/null; then
        echo "  Killing telnetd processes..."
        pkill -9 telnetd
    fi
    
    echo -e "${GREEN}  ✓ Services stopped${NC}"
    echo ""
}

remove_telnet_packages() {
    echo -e "${CYAN}Checking for telnet packages...${NC}"
    echo ""
    
    # *** FIX: Use correct package detection ***
    # The issue was using grep with package names that might not match exactly
    
    # List of all possible telnet packages
    local packages=(
        "telnetd"
        "telnet"
        "telnet-server" 
        "inetutils-telnetd"
        "inetutils-telnet"
        "krb5-telnetd"
    )
    
    local found_packages=()
    
    # Check which packages are actually installed
    for package in "${packages[@]}"; do
        # Use dpkg-query for precise package checking
        if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
            found_packages+=("$package")
            echo -e "${YELLOW}  Found: $package${NC}"
        fi
    done
    
    if [ ${#found_packages[@]} -eq 0 ]; then
        echo -e "${GREEN}  ✓ No telnet packages found${NC}"
        echo ""
        return 0
    fi
    
    echo ""
    echo -e "${YELLOW}Packages to remove: ${#found_packages[@]}${NC}"
    for pkg in "${found_packages[@]}"; do
        echo "  - $pkg"
    done
    echo ""
    
    # Remove found packages
    for package in "${found_packages[@]}"; do
        echo -e "${CYAN}Removing $package...${NC}"
        
        # Use --purge to remove config files too
        if DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y "$package" 2>&1 | grep -v "^Reading"; then
            echo -e "${GREEN}  ✓ Successfully removed $package${NC}"
            ((REMOVED_COUNT++))
        else
            echo -e "${RED}  ✗ Failed to remove $package${NC}"
            ((FAILED_COUNT++))
        fi
        echo ""
    done
}

cleanup_config_files() {
    echo -e "${CYAN}Cleaning up configuration files...${NC}"
    
    # Remove inetd telnet entries
    if [ -f /etc/inetd.conf ]; then
        if grep -q "^telnet" /etc/inetd.conf 2>/dev/null; then
            echo "  Removing telnet from inetd.conf..."
            sed -i.bak '/^telnet/d' /etc/inetd.conf
            echo -e "${GREEN}  ✓ Cleaned inetd.conf${NC}"
        fi
    fi
    
    # Remove xinetd telnet config
    if [ -f /etc/xinetd.d/telnet ]; then
        echo "  Removing xinetd telnet config..."
        rm -f /etc/xinetd.d/telnet
        echo -e "${GREEN}  ✓ Removed xinetd config${NC}"
    fi
    
    echo ""
}

cleanup_dependencies() {
    echo -e "${CYAN}Cleaning up unused dependencies...${NC}"
    
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y > /dev/null 2>&1
    
    echo -e "${GREEN}  ✓ Cleanup complete${NC}"
    echo ""
}

verify_removal() {
    echo -e "${CYAN}Verifying removal...${NC}"
    echo ""
    
    local verification_passed=true
    
    # Check for any remaining telnet packages
    local check_packages=("telnetd" "telnet" "inetutils-telnetd" "telnet-server")
    
    for package in "${check_packages[@]}"; do
        if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
            echo -e "${RED}  ✗ $package is still installed${NC}"
            verification_passed=false
        else
            echo -e "${GREEN}  ✓ $package not installed${NC}"
        fi
    done
    
    # Check for telnet port listening
    if command -v ss &> /dev/null; then
        if ss -tuln 2>/dev/null | grep -E ':23\s' > /dev/null; then
            echo -e "${RED}  ✗ Port 23 still listening${NC}"
            verification_passed=false
        else
            echo -e "${GREEN}  ✓ Port 23 not listening${NC}"
        fi
    fi
    
    # Check for telnet processes
    if pgrep -x "telnetd" > /dev/null 2>&1; then
        echo -e "${RED}  ✗ telnetd process still running${NC}"
        verification_passed=false
    else
        echo -e "${GREEN}  ✓ No telnetd processes${NC}"
    fi
    
    echo ""
    
    if [ "$verification_passed" = true ]; then
        return 0
    else
        return 1
    fi
}

#########################################################################
# Main Execution
#########################################################################

clear
print_header
check_root

# Warning
echo -e "${RED}WARNING: CRITICAL SECURITY REMEDIATION${NC}"
echo -e "${YELLOW}This will remove all telnet packages${NC}"
echo ""
echo "Telnet transmits data in CLEAR TEXT (including passwords)"
echo "Use SSH instead for secure remote access"
echo ""

read -p "Continue? (yes/no): " response
if [[ ! "$response" =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "Cancelled"
    exit 0
fi
echo ""

# Update package cache
echo -e "${CYAN}Updating package cache...${NC}"
apt-get update -qq
echo ""

# Execute remediation
stop_telnet_services
remove_telnet_packages
cleanup_config_files
cleanup_dependencies

# Verify
if verify_removal; then
    REMEDIATION_SUCCESS=true
else
    REMEDIATION_SUCCESS=false
fi

# Summary
echo -e "${CYAN}======================================${NC}"
echo -e "${CYAN}REMEDIATION SUMMARY${NC}"
echo -e "${CYAN}======================================${NC}"
echo "Packages Removed: ${REMOVED_COUNT}"
echo "Failed Removals: ${FAILED_COUNT}"
echo ""

if [ "$REMEDIATION_SUCCESS" = true ] && [ "$FAILED_COUNT" -eq 0 ]; then
    echo -e "${GREEN}======================================${NC}"
    echo -e "${GREEN}REMEDIATION SUCCESSFUL${NC}"
    echo -e "${GREEN}======================================${NC}"
    echo -e "${GREEN}System is now compliant with STIG ${STIG_ID}${NC}"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo "  • Verify SSH is working: systemctl status ssh"
    echo "  • Test remote access: ssh user@hostname"
    echo "  • Run check script to verify compliance"
    exit 0
else
    echo -e "${RED}======================================${NC}"
    echo -e "${RED}REMEDIATION INCOMPLETE${NC}"
    echo -e "${RED}======================================${NC}"
    echo ""
    echo -e "${YELLOW}Manual removal:${NC}"
    echo "  sudo apt-get remove --purge telnetd telnet inetutils-telnetd"
    exit 1
fi
