#!/bin/bash

#########################################################################
# Ubuntu 24.04 LTS STIG Remediation Script
# STIG ID: UBTU-24-100030
# Rule: Remove telnet package
# Severity: CAT I
# Version: 1.0
#########################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# STIG Information
STIG_ID="UBTU-24-100030"
TITLE="Remove telnet package from Ubuntu 24.04 LTS"
SEVERITY="CAT I"

# Counters
REMOVED_COUNT=0
FAILED_COUNT=0
NOT_INSTALLED_COUNT=0


#########################################################################
# Functions
#########################################################################

print_header() {
    echo -e "${CYAN}"
    echo "============================================"
    echo "STIG ${STIG_ID} Remediation Script"
    echo "Remove Telnet Packages"
    echo "Severity: ${SEVERITY}"
    echo "============================================"
    echo -e "${NC}"
}

print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}


stop_telnet_service() {
    print_info "Checking for running telnet services..."
    
    # Check for systemd telnet service
    if systemctl is-active --quiet telnet.socket 2>/dev/null; then
        print_info "Stopping telnet.socket..."
        systemctl stop telnet.socket
        systemctl disable telnet.socket
        print_success "Telnet socket stopped and disabled"
    fi
    
    if systemctl is-active --quiet telnet 2>/dev/null; then
        print_info "Stopping telnet service..."
        systemctl stop telnet
        systemctl disable telnet
        print_success "Telnet service stopped and disabled"
    fi
    
    # Check for inetd-based telnet
    if systemctl is-active --quiet inetd 2>/dev/null; then
        print_info "Checking inetd configuration..."
        if grep -q "^telnet" /etc/inetd.conf 2>/dev/null; then
            print_info "Disabling telnet in inetd.conf..."
            sed -i 's/^telnet/#telnet/' /etc/inetd.conf
            systemctl restart inetd
            print_success "Telnet disabled in inetd"
        fi
    fi
    
    echo ""
}

remove_telnet_packages() {
    local packages_to_remove=(
        "telnetd"
        "telnet-server"
        "inetutils-telnetd"
    )
    
    print_info "Scanning for telnet packages..."
    echo ""
    
    for package in "${packages_to_remove[@]}"; do
        if dpkg -l 2>/dev/null | grep -q "^ii.*${package}"; then
            echo -e "${YELLOW}Found: ${package}${NC}"
            
            print_info "Removing ${package}..."
            
            if apt remove -y "${package}" 2>&1 | tee /tmp/apt_remove_$$.log; then
                print_success "Successfully removed ${package}"
                ((REMOVED_COUNT++))
            else
                print_error "Failed to remove ${package}"
                cat /tmp/apt_remove_$$.log
                ((FAILED_COUNT++))
            fi
            
            rm -f /tmp/apt_remove_$$.log
            echo ""
        else
            echo -e "${GREEN}Not installed: ${package}${NC}"
            ((NOT_INSTALLED_COUNT++))
        fi
    done
    
    # Also check for telnet client (less critical but should be noted)
    if dpkg -l 2>/dev/null | grep -q "^ii.*\stelnet\s"; then
        print_warning "Telnet client package detected"
        echo "The telnet client is less critical than the server, but should be removed for security."
        
        if [ "$FORCE" = true ]; then
            response="y"
        else
            read -p "Remove telnet client? (y/N): " response
        fi
        
        if [[ "$response" =~ ^[Yy]$ ]]; then
            print_info "Removing telnet client..."
            if apt remove -y telnet; then
                print_success "Successfully removed telnet client"
                ((REMOVED_COUNT++))
            else
                print_error "Failed to remove telnet client"
                ((FAILED_COUNT++))
            fi
        fi
        echo ""
    fi
}

cleanup_dependencies() {
    print_info "Cleaning up unused dependencies..."
    
    if apt autoremove -y; then
        print_success "Unused dependencies removed"
    else
        print_warning "Failed to remove some dependencies"
    fi
    echo ""
}

verify_removal() {
    print_info "Verifying telnet packages are removed..."
    echo ""
    
    local verification_passed=true
    local packages_to_check=(
        "telnetd"
        "telnet-server"
        "inetutils-telnetd"
    )
    
    for package in "${packages_to_check[@]}"; do
        if dpkg -l 2>/dev/null | grep -q "^ii.*${package}"; then
            print_error "${package} is still installed"
            verification_passed=false
        else
            print_success "${package} is not installed"
        fi
    done
    
    # Check for listening telnet port
    if command -v ss &> /dev/null; then
        if ss -tuln 2>/dev/null | grep -E ':23\s'; then
            print_error "Port 23 (telnet) is still listening"
            verification_passed=false
        else
            print_success "Port 23 (telnet) is not listening"
        fi
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

print_header

# Check if running as root
check_root

# Check if running on Ubuntu
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ ! "$ID" == "ubuntu" ]]; then
        print_warning "This script is designed for Ubuntu systems"
        print_warning "Current OS: $PRETTY_NAME"
        echo ""
    fi
fi


# Warning message
echo -e "${RED}WARNING: CRITICAL SECURITY REMEDIATION${NC}"
echo -e "${RED}========================================${NC}"
echo -e "${YELLOW}This script will remove telnet packages from the system.${NC}"
echo ""
echo -e "${YELLOW}Why This is Critical:${NC}"
echo "  - Telnet transmits all data (including passwords) in clear text"
echo "  - Telnet does not meet DOD/NIST security requirements"
echo "  - Telnet is vulnerable to eavesdropping and MITM attacks"
echo ""
echo -e "${YELLOW}What Will Be Done:${NC}"
echo "  1. Stop any running telnet services"
echo "  2. Remove telnet server packages (telnetd, inetutils-telnetd)"
echo "  3. Optional: Remove telnet client package"
echo "  4. Clean up unused dependencies"
echo "  5. Verify complete removal"
echo ""
echo -e "${CYAN}Secure Alternatives:${NC}"
echo "  - Use SSH for remote access (already installed by default)"
echo "  - Use SFTP/SCP for file transfer"
echo ""

if [ "$FORCE" = false ]; then
    read -p "Do you want to continue? (y/N): " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        print_info "Remediation cancelled by user"
        exit 0
    fi
    echo ""
fi

# Update package cache
print_info "Updating package cache..."
if apt update -qq; then
    print_success "Package cache updated"
else
    print_warning "Failed to update package cache (continuing anyway)"
fi
echo ""

# Stop telnet services
stop_telnet_service

# Remove telnet packages
remove_telnet_packages

# Clean up dependencies
cleanup_dependencies

# Verify removal
if verify_removal; then
    REMEDIATION_SUCCESS=true
else
    REMEDIATION_SUCCESS=false
fi


# Print summary
echo -e "${CYAN}"
echo "============================================"
echo "REMEDIATION SUMMARY"
echo "============================================"
echo -e "${NC}"
echo "Packages Removed: ${REMOVED_COUNT}"
echo "Packages Not Installed: ${NOT_INSTALLED_COUNT}"
echo "Failed Removals: ${FAILED_COUNT}"
echo ""

if [ "$REMEDIATION_SUCCESS" = true ] && [ "$FAILED_COUNT" -eq 0 ]; then
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}REMEDIATION SUCCESSFUL${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}System should now be compliant with STIG ${STIG_ID}${NC}"
    echo -e "${GREEN}All telnet packages have been removed${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo "  1. Verify compliance with check script:"
    echo "     ./Telnet_Check.sh"
    echo "  2. Ensure SSH is configured and working:"
    echo "     systemctl status ssh"
    echo "  3. Test remote access using SSH instead of telnet"
    echo "  4. Update any documentation referencing telnet"
    exit_code=0
else
    echo -e "${RED}============================================${NC}"
    echo -e "${RED}REMEDIATION INCOMPLETE${NC}"
    echo -e "${RED}============================================${NC}"
    echo -e "${RED}Some packages may still be installed${NC}"
    echo ""
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo "  1. Check for package holds: apt-mark showhold"
    echo "  2. Try manual removal: sudo apt remove --purge telnetd"
    echo "  3. Check for errors: sudo apt -f install"
    echo "  4. Review system logs: sudo journalctl -xe"
    exit_code=1
fi


exit $exit_code
