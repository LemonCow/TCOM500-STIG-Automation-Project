#!/bin/bash

#########################################################################
# Ubuntu 24.04 LTS STIG Compliance Check Script
# STIG ID: UBTU-24-100030
# Rule: Telnet package must not be installed
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
TITLE="Ubuntu 24.04 LTS must not have the telnet package installed"
SEVERITY="CAT I"

# Result structure
STATUS="Not_Reviewed"
FINDING=false
DETAILS=()
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

#########################################################################
# Functions
#########################################################################

print_header() {
    echo -e "${CYAN}"
    echo "============================================"
    echo "STIG Compliance Check: ${STIG_ID}"
    echo "Telnet Package Installation Check"
    echo "Severity: ${SEVERITY}"
    echo "============================================"
    echo -e "${NC}"
}

print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[FINDING]${NC} $1"
}

check_telnet_packages() {
    print_info "Checking for telnet-related packages..."
    echo ""
    
    # List of telnet-related packages to check
    local telnet_packages=(
        "telnetd"
        "telnet-server"
        "inetutils-telnetd"
        "telnet"
    )
    
    local found_packages=()
    local critical_found=false
    
    for package in "${telnet_packages[@]}"; do
        # Check if package is installed
        if dpkg -l 2>/dev/null | grep -q "^ii.*${package}"; then
            local package_info=$(dpkg -l | grep "^ii.*${package}" | awk '{print $2, $3}')
            found_packages+=("${package}")
            
            echo -e "  ${RED}[FOUND]${NC} Package: ${package}"
            echo -e "    Status: Installed"
            echo -e "    Info: ${package_info}"
            
            # Telnetd/telnet-server are critical findings
            if [[ "${package}" == "telnetd" ]] || [[ "${package}" == "telnet-server" ]] || [[ "${package}" == "inetutils-telnetd" ]]; then
                critical_found=true
                echo -e "    ${RED}Severity: CRITICAL (Server component)${NC}"
                DETAILS+=("CRITICAL: ${package} (telnet server) is installed")
            else
                echo -e "    ${YELLOW}Severity: WARNING (Client component)${NC}"
                DETAILS+=("WARNING: ${package} (telnet client) is installed")
            fi
            echo ""
        fi
    done
    
    # Check for running telnet service
    print_info "Checking for running telnet services..."
    echo ""
    
    if systemctl list-units --type=service --all 2>/dev/null | grep -i telnet; then
        print_error "Telnet service found in systemd"
        DETAILS+=("Telnet service detected in systemd")
        critical_found=true
    else
        print_success "No telnet services found in systemd"
    fi
    echo ""
    
    # Check for telnet listening on ports
    print_info "Checking for telnet ports (23)..."
    echo ""
    
    if command -v ss &> /dev/null; then
        if ss -tuln 2>/dev/null | grep -E ':23\s'; then
            print_error "Port 23 (telnet) is listening"
            DETAILS+=("Port 23 is in listening state")
            critical_found=true
        else
            print_success "Port 23 (telnet) is not listening"
        fi
    elif command -v netstat &> /dev/null; then
        if netstat -tuln 2>/dev/null | grep -E ':23\s'; then
            print_error "Port 23 (telnet) is listening"
            DETAILS+=("Port 23 is in listening state")
            critical_found=true
        else
            print_success "Port 23 (telnet) is not listening"
        fi
    else
        print_warning "Cannot check listening ports (ss/netstat not available)"
    fi
    echo ""
    
    # Determine compliance status
    if [ ${#found_packages[@]} -eq 0 ]; then
        STATUS="NotAFinding"
        FINDING=false
        DETAILS+=("No telnet packages detected on the system")
        return 0
    else
        STATUS="Open"
        FINDING=true
        
        if [ "$critical_found" = true ]; then
            DETAILS+=("FINDING: Telnet server package(s) installed - Critical security risk")
        fi
        
        return 1
    fi
}

print_security_info() {
    echo -e "${CYAN}"
    echo "============================================"
    echo "SECURITY INFORMATION"
    echo "============================================"
    echo -e "${NC}"
    echo -e "${YELLOW}Why Telnet is Prohibited:${NC}"
    echo "  - Transmits ALL data (including passwords) in CLEAR TEXT"
    echo "  - No encryption or authentication security"
    echo "  - Vulnerable to eavesdropping and man-in-the-middle attacks"
    echo "  - Does not meet DOD security requirements"
    echo ""
    echo -e "${YELLOW}Secure Alternatives:${NC}"
    echo "  - SSH (Secure Shell) - Encrypted remote access"
    echo "  - SFTP - Encrypted file transfer"
    echo "  - SCP - Secure copy"
    echo ""
    echo -e "${YELLOW}Related Security Controls:${NC}"
    echo "  - CCI-000197: Passwords must be transmitted over cryptographically-protected channels"
    echo "  - NIST SP 800-53: IA-5 (1) (c)"
    echo ""
}


print_summary() {
    echo -e "${CYAN}"
    echo "============================================"
    echo "COMPLIANCE SUMMARY"
    echo "============================================"
    echo -e "${NC}"
    echo "STIG ID: ${STIG_ID}"
    echo "Severity: ${SEVERITY}"
    echo "Status: ${STATUS}"
    echo "Finding: ${FINDING}"
    echo "Timestamp: ${TIMESTAMP}"
    echo ""
    echo -e "${CYAN}Details:${NC}"
    for detail in "${DETAILS[@]}"; do
        echo "  - ${detail}"
    done
    echo ""
    
    if [ "${FINDING}" = true ]; then
        echo -e "${RED}[RESULT] System is NOT COMPLIANT with STIG ${STIG_ID}${NC}"
        echo -e "${RED}Telnet package(s) are installed on the system${NC}"
        echo ""
        echo -e "${YELLOW}Remediation Required:${NC}"
        echo "  Run the remediation script to remove telnet packages:"
        echo "    sudo ./Telnet_Fix.sh"
        echo ""
        echo "  Or manually remove with:"
        echo "    sudo apt remove telnetd telnet inetutils-telnetd"
        echo "    sudo apt autoremove"
    else
        echo -e "${GREEN}[RESULT] System is COMPLIANT with STIG ${STIG_ID}${NC}"
        echo -e "${GREEN}No telnet packages detected${NC}"
    fi
    echo ""
}

#########################################################################
# Main Execution
#########################################################################

print_header

# Check if running on Ubuntu
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ ! "$ID" == "ubuntu" ]]; then
        print_warning "This script is designed for Ubuntu systems"
        print_warning "Current OS: $PRETTY_NAME"
        echo ""
    fi
    
    if [[ ! "$VERSION_ID" == "24.04" ]]; then
        print_warning "This STIG is specifically for Ubuntu 24.04 LTS"
        print_warning "Current version: $VERSION_ID"
        echo ""
    fi
fi

# Perform the check
check_telnet_packages
check_result=$?

# Print security information
print_security_info

# Print summary
print_summary

# Exit with appropriate code
exit $check_result
