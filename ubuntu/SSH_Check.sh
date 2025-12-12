#!/bin/bash

#########################################################################
# Ubuntu 24.04 LTS STIG Compliance Check Script
# STIG ID: UBTU-24-100800
# Rule: SSH must be installed
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
STIG_ID="UBTU-24-100800"
TITLE="Ubuntu 24.04 LTS must have SSH installed"
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
    echo "SSH Installation Verification"
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

check_ssh_packages() {
    print_info "Checking for OpenSSH packages..."
    echo ""
    
    # Check for openssh-server (required)
    local server_installed=false
    local client_installed=false
    local sftp_installed=false
    
    # Check openssh-server
    if dpkg -l 2>/dev/null | grep -q "^ii.*openssh-server"; then
        local server_version=$(dpkg -l | grep "^ii.*openssh-server" | awk '{print $3}')
        print_success "openssh-server is installed"
        echo "    Package: openssh-server"
        echo "    Version: ${server_version}"
        echo "    Status: ii (installed)"
        DETAILS+=("openssh-server ${server_version} is installed")
        server_installed=true
    else
        print_error "openssh-server is NOT installed"
        DETAILS+=("FINDING: openssh-server is not installed")
    fi
    echo ""
    
    # Check openssh-client (typically installed by default)
    if dpkg -l 2>/dev/null | grep -q "^ii.*openssh-client"; then
        local client_version=$(dpkg -l | grep "^ii.*openssh-client" | awk '{print $3}')
        print_success "openssh-client is installed"
        echo "    Package: openssh-client"
        echo "    Version: ${client_version}"
        echo "    Status: ii (installed)"
        DETAILS+=("openssh-client ${client_version} is installed")
        client_installed=true
    else
        print_warning "openssh-client is not installed (recommended but not required for compliance)"
        DETAILS+=("WARNING: openssh-client is not installed")
    fi
    echo ""
    
    # Check openssh-sftp-server (part of secure file transfer)
    if dpkg -l 2>/dev/null | grep -q "^ii.*openssh-sftp-server"; then
        local sftp_version=$(dpkg -l | grep "^ii.*openssh-sftp-server" | awk '{print $3}')
        print_success "openssh-sftp-server is installed"
        echo "    Package: openssh-sftp-server"
        echo "    Version: ${sftp_version}"
        echo "    Status: ii (installed)"
        DETAILS+=("openssh-sftp-server ${sftp_version} is installed")
        sftp_installed=true
    else
        print_info "openssh-sftp-server is not installed (optional for SFTP support)"
        DETAILS+=("INFO: openssh-sftp-server is not installed")
    fi
    echo ""
    
    # Determine compliance based on openssh-server presence
    if [ "$server_installed" = true ]; then
        STATUS="NotAFinding"
        FINDING=false
        return 0
    else
        STATUS="Open"
        FINDING=true
        return 1
    fi
}

check_ssh_service() {
    print_info "Checking SSH service status..."
    echo ""
    
    # Check if SSH service exists and its status
    if systemctl list-unit-files 2>/dev/null | grep -q "ssh.service\|sshd.service"; then
        
        # Check if service is enabled
        if systemctl is-enabled ssh 2>/dev/null || systemctl is-enabled sshd 2>/dev/null; then
            local enabled_status=$(systemctl is-enabled ssh 2>/dev/null || systemctl is-enabled sshd 2>/dev/null)
            print_success "SSH service is enabled (${enabled_status})"
            DETAILS+=("SSH service is enabled")
        else
            print_warning "SSH service is not enabled (will not start on boot)"
            DETAILS+=("WARNING: SSH service is not enabled")
        fi
        
        # Check if service is running
        if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
            print_success "SSH service is running"
            DETAILS+=("SSH service is active")
            
            # Get service status details
            if command -v systemctl &> /dev/null; then
                local service_status=$(systemctl status ssh 2>/dev/null || systemctl status sshd 2>/dev/null | grep "Active:" | awk '{print $2, $3}')
                echo "    Status: ${service_status}"
            fi
        else
            print_warning "SSH service is not running"
            DETAILS+=("WARNING: SSH service is installed but not running")
        fi
    else
        print_error "SSH service not found in systemd"
        DETAILS+=("FINDING: SSH service not available")
    fi
    echo ""
}

check_ssh_port() {
    print_info "Checking SSH port status..."
    echo ""
    
    # Check if SSH is listening on port 22 (or custom port)
    if command -v ss &> /dev/null; then
        local listening_ports=$(ss -tlnp 2>/dev/null | grep sshd)
        if [ -n "$listening_ports" ]; then
            print_success "SSH is listening on network ports"
            echo "$listening_ports" | while IFS= read -r line; do
                local port=$(echo "$line" | awk '{print $4}' | grep -oP ':\K[0-9]+$')
                echo "    Port: ${port}"
            done
            DETAILS+=("SSH daemon is listening on network ports")
        else
            print_warning "SSH daemon is not listening on any ports"
            DETAILS+=("WARNING: SSH service not listening on network")
        fi
    elif command -v netstat &> /dev/null; then
        if netstat -tlnp 2>/dev/null | grep -q sshd; then
            print_success "SSH is listening on network ports"
            DETAILS+=("SSH daemon is listening on network ports")
        else
            print_warning "SSH daemon is not listening on any ports"
            DETAILS+=("WARNING: SSH service not listening on network")
        fi
    else
        print_info "Cannot check listening ports (ss/netstat not available)"
    fi
    echo ""
}

check_ssh_config() {
    print_info "Checking SSH configuration..."
    echo ""
    
    if [ -f /etc/ssh/sshd_config ]; then
        print_success "SSH server configuration file exists"
        echo "    Path: /etc/ssh/sshd_config"
        
        # Check file permissions (should be 600 or 644)
        local perms=$(stat -c %a /etc/ssh/sshd_config 2>/dev/null)
        echo "    Permissions: ${perms}"
        
        if [ "$perms" = "600" ] || [ "$perms" = "644" ]; then
            DETAILS+=("SSH config file has secure permissions (${perms})")
        else
            print_warning "SSH config file permissions may be insecure (${perms})"
            DETAILS+=("WARNING: SSH config permissions are ${perms}")
        fi
        
        # Check for host keys
        if ls /etc/ssh/ssh_host_*_key &>/dev/null; then
            local key_count=$(ls /etc/ssh/ssh_host_*_key 2>/dev/null | wc -l)
            print_success "SSH host keys present (${key_count} keys)"
            DETAILS+=("SSH host keys are configured")
        else
            print_warning "SSH host keys may not be configured"
            DETAILS+=("WARNING: SSH host keys not found")
        fi
    else
        print_warning "SSH server configuration file not found"
        DETAILS+=("WARNING: /etc/ssh/sshd_config not found")
    fi
    echo ""
}

print_security_info() {
    echo -e "${CYAN}"
    echo "============================================"
    echo "SECURITY INFORMATION"
    echo "============================================"
    echo -e "${NC}"
    echo -e "${YELLOW}Why SSH is Required:${NC}"
    echo "  - Provides encrypted remote access (confidentiality)"
    echo "  - Protects data integrity during transmission"
    echo "  - Replaces insecure protocols (telnet, rsh, rlogin)"
    echo "  - Meets NIST SP 800-53 SC-8 requirements"
    echo ""
    echo -e "${YELLOW}SSH Components:${NC}"
    echo "  - openssh-server: SSH daemon for remote access"
    echo "  - openssh-client: SSH client for outbound connections"
    echo "  - openssh-sftp-server: Secure file transfer protocol"
    echo ""
    echo -e "${YELLOW}Security Controls Satisfied:${NC}"
    echo "  - SRG-OS-000423-GPOS-00187: Protect confidentiality/integrity"
    echo "  - SRG-OS-000425-GPOS-00189: Secure transmission preparation"
    echo "  - SRG-OS-000426-GPOS-00190: Secure reception"
    echo "  - NIST SP 800-53: SC-8, SC-8(2)"
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
        echo -e "${RED}OpenSSH server is not installed${NC}"
        echo ""
        echo -e "${YELLOW}Remediation Required:${NC}"
        echo "  Run the remediation script to install SSH:"
        echo "    sudo ./SSH_Fix.sh"
        echo ""
        echo "  Or manually install with:"
        echo "    sudo apt update"
        echo "    sudo apt install -y ssh"
        echo "    sudo systemctl enable --now ssh"
    else
        echo -e "${GREEN}[RESULT] System is COMPLIANT with STIG ${STIG_ID}${NC}"
        echo -e "${GREEN}OpenSSH server is installed${NC}"
        echo ""
        echo -e "${CYAN}Additional Recommendations:${NC}"
        echo "  - Ensure SSH service is enabled: sudo systemctl enable ssh"
        echo "  - Ensure SSH service is running: sudo systemctl start ssh"
        echo "  - Review SSH configuration: /etc/ssh/sshd_config"
        echo "  - Configure SSH hardening per additional STIGs"
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

# Perform package checks
check_ssh_packages
check_result=$?

# Additional checks if SSH is installed
if [ $check_result -eq 0 ]; then
    check_ssh_service
    check_ssh_port
    check_ssh_config
fi

# Print security information
print_security_info

# Print summary
print_summary

# Exit with appropriate code
exit $check_result
