#!/bin/bash

#########################################################################
# Ubuntu 24.04 LTS STIG Remediation Script
# STIG ID: UBTU-24-100800
# Rule: Install SSH
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
TITLE="Install SSH on Ubuntu 24.04 LTS"
SEVERITY="CAT I"

# Result tracking
INSTALLATION_SUCCESS=false
SERVICE_ENABLED=false
SERVICE_STARTED=false

# Parse command line arguments
FORCE=false
COMPLIANCE_REPORT=""
ENABLE_SERVICE=true
START_SERVICE=true

while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--force)
            FORCE=true
            shift
            ;;
        -r|--report)
            COMPLIANCE_REPORT="$2"
            shift 2
            ;;
        --no-enable)
            ENABLE_SERVICE=false
            shift
            ;;
        --no-start)
            START_SERVICE=false
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -f, --force          Skip confirmation prompts"
            echo "  --no-enable          Do not enable SSH service on boot"
            echo "  --no-start           Do not start SSH service immediately"
            echo "  -h, --help           Display this help message"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

#########################################################################
# Functions
#########################################################################

print_header() {
    echo -e "${CYAN}"
    echo "============================================"
    echo "STIG ${STIG_ID} Remediation Script"
    echo "Install OpenSSH Server"
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


check_current_status() {
    print_info "Checking current SSH installation status..."
    echo ""
    
    # Check if openssh-server is already installed
    if dpkg -l 2>/dev/null | grep -q "^ii.*openssh-server"; then
        local version=$(dpkg -l | grep "^ii.*openssh-server" | awk '{print $3}')
        print_success "openssh-server is already installed (version ${version})"
        echo ""
        
        if [ "$FORCE" = false ]; then
            read -p "SSH is already installed. Continue anyway? (y/N): " response
            if [[ ! "$response" =~ ^[Yy]$ ]]; then
                print_info "Remediation cancelled by user"
                exit 0
            fi
        fi
        INSTALLATION_SUCCESS=true
        return 0
    else
        print_info "openssh-server is not installed - installation required"
        echo ""
        return 1
    fi
}

update_package_cache() {
    print_info "Updating package cache..."
    
    if apt update 2>&1 | tee /tmp/apt_update_$$.log; then
        print_success "Package cache updated successfully"
    else
        print_error "Failed to update package cache"
        cat /tmp/apt_update_$$.log
        rm -f /tmp/apt_update_$$.log
        return 1
    fi
    
    rm -f /tmp/apt_update_$$.log
    echo ""
    return 0
}

install_ssh() {
    print_info "Installing SSH (openssh-server)..."
    echo ""
    
    # Install the ssh meta-package (includes openssh-server, openssh-client, openssh-sftp-server)
    print_info "Running: apt install -y ssh"
    
    if apt install -y ssh 2>&1 | tee /tmp/apt_install_$$.log; then
        print_success "SSH package installed successfully"
        INSTALLATION_SUCCESS=true
        
        # Verify installation
        if dpkg -l 2>/dev/null | grep -q "^ii.*openssh-server"; then
            local version=$(dpkg -l | grep "^ii.*openssh-server" | awk '{print $3}')
            print_success "Verified: openssh-server version ${version} is installed"
        fi
    else
        print_error "Failed to install SSH package"
        cat /tmp/apt_install_$$.log
        rm -f /tmp/apt_install_$$.log
        return 1
    fi
    
    rm -f /tmp/apt_install_$$.log
    echo ""
    return 0
}

configure_ssh_service() {
    if [ "$INSTALLATION_SUCCESS" = false ]; then
        print_warning "Skipping service configuration (installation failed)"
        return 1
    fi
    
    # Enable SSH service
    if [ "$ENABLE_SERVICE" = true ]; then
        print_info "Enabling SSH service to start on boot..."
        
        if systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null; then
            print_success "SSH service enabled"
            SERVICE_ENABLED=true
        else
            print_error "Failed to enable SSH service"
            return 1
        fi
        echo ""
    fi
    
    # Start SSH service
    if [ "$START_SERVICE" = true ]; then
        print_info "Starting SSH service..."
        
        if systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null; then
            print_success "SSH service started"
            SERVICE_STARTED=true
            
            # Wait a moment for service to fully start
            sleep 2
            
            # Check if service is running
            if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
                print_success "SSH service is running"
            else
                print_warning "SSH service may not be running properly"
            fi
        else
            print_error "Failed to start SSH service"
            return 1
        fi
        echo ""
    fi
    
    return 0
}

verify_ssh_installation() {
    print_info "Verifying SSH installation and configuration..."
    echo ""
    
    local verification_passed=true
    
    # Check package installation
    if dpkg -l 2>/dev/null | grep -q "^ii.*openssh-server"; then
        print_success "openssh-server package is installed"
    else
        print_error "openssh-server package is NOT installed"
        verification_passed=false
    fi
    
    # Check service status
    if systemctl list-unit-files 2>/dev/null | grep -q "ssh.service\|sshd.service"; then
        print_success "SSH service is registered with systemd"
        
        # Check if enabled
        if systemctl is-enabled ssh 2>/dev/null || systemctl is-enabled sshd 2>/dev/null; then
            print_success "SSH service is enabled for automatic start"
        else
            print_warning "SSH service is not enabled (will not start on boot)"
        fi
        
        # Check if running
        if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
            print_success "SSH service is running"
        else
            print_warning "SSH service is not currently running"
        fi
    else
        print_error "SSH service not found in systemd"
        verification_passed=false
    fi
    
    # Check configuration file
    if [ -f /etc/ssh/sshd_config ]; then
        print_success "SSH configuration file exists (/etc/ssh/sshd_config)"
    else
        print_error "SSH configuration file not found"
        verification_passed=false
    fi
    
    # Check host keys
    if ls /etc/ssh/ssh_host_*_key &>/dev/null; then
        local key_count=$(ls /etc/ssh/ssh_host_*_key 2>/dev/null | wc -l)
        print_success "SSH host keys present (${key_count} keys)"
    else
        print_warning "SSH host keys not found (may be generated on first start)"
    fi
    
    # Check listening port
    if command -v ss &> /dev/null; then
        if ss -tlnp 2>/dev/null | grep -q sshd; then
            local port=$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | grep -oP ':\K[0-9]+$' | head -1)
            print_success "SSH is listening on port ${port}"
        else
            print_warning "SSH is not listening on any ports"
        fi
    fi
    
    echo ""
    
    if [ "$verification_passed" = true ]; then
        return 0
    else
        return 1
    fi
}

display_connection_info() {
    echo -e "${CYAN}"
    echo "============================================"
    echo "SSH CONNECTION INFORMATION"
    echo "============================================"
    echo -e "${NC}"
    
    local hostname=$(hostname)
    local ip_addresses=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$')
    
    echo "Hostname: ${hostname}"
    echo ""
    echo "IP Addresses:"
    echo "${ip_addresses}" | while IFS= read -r ip; do
        echo "  - ${ip}"
    done
    echo ""
    echo "To connect to this system via SSH:"
    echo "  ssh username@${hostname}"
    
    if [ -n "${ip_addresses}" ]; then
        local first_ip=$(echo "${ip_addresses}" | head -1)
        echo "  ssh username@${first_ip}"
    fi
    echo ""
    echo -e "${YELLOW}Security Reminder:${NC}"
    echo "  - Use strong authentication (keys preferred over passwords)"
    echo "  - Review and harden SSH configuration per additional STIGs"
    echo "  - Monitor SSH access logs: /var/log/auth.log"
    echo "  - Consider changing default SSH port (22) if required"
    echo ""
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

# Load compliance report if provided
load_compliance_report

# Information message
echo -e "${CYAN}STIG REQUIREMENT${NC}"
echo "================"
echo "Ubuntu 24.04 LTS must have SSH installed to provide secure,"
echo "encrypted remote access that protects confidentiality and"
echo "integrity of transmitted information."
echo ""
echo -e "${YELLOW}What This Script Will Do:${NC}"
echo "  1. Update package cache"
echo "  2. Install openssh-server package (via 'ssh' meta-package)"
echo "  3. Enable SSH service to start on boot"
echo "  4. Start SSH service immediately"
echo "  5. Verify installation and configuration"
echo ""
echo -e "${CYAN}Security Benefits:${NC}"
echo "  - Encrypted remote access (replaces insecure telnet)"
echo "  - Secure file transfer (SFTP/SCP)"
echo "  - Authentication protection"
echo "  - Meets NIST SP 800-53 SC-8 requirements"
echo ""

if [ "$FORCE" = false ]; then
    read -p "Do you want to continue? (y/N): " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        print_info "Remediation cancelled by user"
        exit 0
    fi
    echo ""
fi

# Check current status
check_current_status
already_installed=$?

# Update package cache
if ! update_package_cache; then
    print_error "Cannot proceed without updating package cache"
    exit 1
fi

# Install SSH if not already installed
if [ $already_installed -ne 0 ]; then
    if ! install_ssh; then
        print_error "SSH installation failed"
        exit 1
    fi
fi

# Configure SSH service
configure_ssh_service

# Verify installation
if verify_ssh_installation; then
    VERIFICATION_SUCCESS=true
else
    VERIFICATION_SUCCESS=false
fi

# Display connection information
if [ "$VERIFICATION_SUCCESS" = true ]; then
    display_connection_info
fi

# Print summary
echo -e "${CYAN}"
echo "============================================"
echo "REMEDIATION SUMMARY"
echo "============================================"
echo -e "${NC}"
echo "SSH Installation: $([ "$INSTALLATION_SUCCESS" = true ] && echo "Success" || echo "Failed")"
echo "Service Enabled: $([ "$SERVICE_ENABLED" = true ] && echo "Yes" || echo "No")"
echo "Service Started: $([ "$SERVICE_STARTED" = true ] && echo "Yes" || echo "No")"
echo ""

if [ "$VERIFICATION_SUCCESS" = true ] && [ "$INSTALLATION_SUCCESS" = true ]; then
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}REMEDIATION SUCCESSFUL${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}System should now be compliant with STIG ${STIG_ID}${NC}"
    echo -e "${GREEN}OpenSSH server is installed and configured${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo "  1. Verify compliance with check script:"
    echo "     ./SSH_Check.sh"
    echo "  2. Review SSH configuration:"
    echo "     sudo nano /etc/ssh/sshd_config"
    echo "  3. Harden SSH per additional STIG requirements"
    echo "  4. Test SSH connectivity:"
    echo "     ssh localhost"
    echo "  5. Configure firewall if needed:"
    echo "     sudo ufw allow ssh"
    exit_code=0
else
    echo -e "${RED}============================================${NC}"
    echo -e "${RED}REMEDIATION INCOMPLETE${NC}"
    echo -e "${RED}============================================${NC}"
    echo -e "${RED}Some steps may have failed${NC}"
    echo ""
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo "  1. Check system logs: sudo journalctl -xe"
    echo "  2. Verify package installation: dpkg -l | grep openssh"
    echo "  3. Check service status: sudo systemctl status ssh"
    echo "  4. Test SSH manually: sudo sshd -t"
    echo "  5. Review errors above and retry"
    exit_code=1
fi

exit $exit_code
