#!/bin/bash

#############################################################################
# STIG Remediation Script
# STIG ID: UBTU-24-100040
# Rule ID: SV-270648r1066433
# Severity: CAT I
# Title: Remove RSH server package from Ubuntu 24.04 LTS
#############################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# STIG Information
STIG_ID="UBTU-24-100040"
RULE_ID="SV-270648r1066433"
SEVERITY="CAT I"
TITLE="Ubuntu 24.04 LTS must not have the rsh-server package installed"

# Package names to remove
RSH_PACKAGES=("rsh-server" "rsh-redone-server" "rsh-client" "rsh-redone-client")

# Flags
FORCE=false
BACKUP=false
VERIFY=false

#############################################################################
# Functions
#############################################################################

print_header() {
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}         STIG Remediation - ${STIG_ID}${NC}"
    echo -e "${MAGENTA}         Remove RSH Server Package${NC}"
    echo -e "${MAGENTA}         Severity: ${SEVERITY} (CRITICAL)${NC}"
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
    -f, --force     Skip confirmation prompts
    -b, --backup    Backup package list before removal
    -v, --verify    Verify configuration after remediation
    -h, --help      Display this help message

Examples:
    $0                    # Interactive remediation
    $0 --force           # Automatic remediation
    $0 --force --backup --verify  # Full automated remediation
    
EOF
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}ERROR: This script must be run as root or with sudo${NC}"
        echo "Please run: sudo $0"
        exit 1
    fi
}

check_current_status() {
    echo -e "${CYAN}Checking current system status...${NC}"
    echo ""
    
    local found=false
    local installed_packages=()
    
    for package in "${RSH_PACKAGES[@]}"; do
        if dpkg -l 2>/dev/null | grep -qw "^ii.*${package}"; then
            found=true
            installed_packages+=("${package}")
            VERSION=$(dpkg -l | grep "^ii.*${package}" | awk '{print $3}')
            echo -e "${YELLOW}  Found: ${package} (${VERSION})${NC}"
        fi
    done
    
    echo ""
    
    if [ "${found}" = false ]; then
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}         SYSTEM IS ALREADY COMPLIANT${NC}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "${GREEN}✓ No RSH server packages are installed${NC}"
        echo -e "${GREEN}✓ No remediation is required${NC}"
        echo ""
        return 1
    fi
    
    echo -e "${RED}NON-COMPLIANT CONFIGURATION DETECTED${NC}"
    echo ""
    echo -e "${RED}Current Risk Level: CRITICAL (CAT I)${NC}"
    echo "  ✗ RSH server packages are installed"
    echo "  ✗ Insecure remote shell service available"
    echo "  ✗ Clear-text credentials can be transmitted"
    echo "  ✗ Does NOT meet NIST SP 800-53 CM-7 requirements"
    echo ""
    
    echo -e "${YELLOW}Packages to be removed:${NC}"
    for pkg in "${installed_packages[@]}"; do
        echo "  • ${pkg}"
    done
    echo ""
    
    return 0
}

backup_package_list() {
    if [ "${BACKUP}" = true ]; then
        local backup_file="rsh_packages_backup_$(date +%Y%m%d_%H%M%S).txt"
        
        echo -e "${CYAN}Creating package list backup...${NC}"
        
        dpkg -l | grep -E "(rsh-|rlogin|rexec)" > "${backup_file}" 2>/dev/null
        
        if [ -f "${backup_file}" ]; then
            echo -e "${GREEN}  ✓ Backup created: ${backup_file}${NC}"
            return 0
        else
            echo -e "${YELLOW}  ! No RSH packages found to backup${NC}"
            return 1
        fi
        echo ""
    fi
}

stop_rsh_services() {
    echo -e "${CYAN}Stopping RSH services...${NC}"
    echo ""
    
    # Stop systemd services
    RSH_SYSTEMD_SERVICES=("rsh.socket" "rlogin.socket" "rexec.socket" "rshd.service")
    for service in "${RSH_SYSTEMD_SERVICES[@]}"; do
        if systemctl is-active --quiet "${service}" 2>/dev/null; then
            echo "  Stopping ${service}..."
            systemctl stop "${service}" 2>/dev/null
            systemctl disable "${service}" 2>/dev/null
        fi
    done
    
    # Kill any running RSH daemon processes
    RSH_PROCESSES=("rshd" "in.rshd" "rlogind" "in.rlogind" "rexecd" "in.rexecd")
    for process in "${RSH_PROCESSES[@]}"; do
        if pgrep -x "${process}" > /dev/null 2>&1; then
            echo "  Terminating ${process} processes..."
            pkill -9 "${process}" 2>/dev/null
        fi
    done
    
    echo -e "${GREEN}  ✓ RSH services stopped${NC}"
    echo ""
}

remove_rsh_packages() {
    echo -e "${CYAN}Removing RSH packages...${NC}"
    echo ""
    
    local removed_count=0
    local failed_count=0
    
    for package in "${RSH_PACKAGES[@]}"; do
        if dpkg -l 2>/dev/null | grep -qw "^ii.*${package}"; then
            echo "  Removing ${package}..."
            
            if apt-get remove --purge -y "${package}" > /dev/null 2>&1; then
                echo -e "${GREEN}    ✓ ${package} removed successfully${NC}"
                ((removed_count++))
            else
                echo -e "${RED}    ✗ Failed to remove ${package}${NC}"
                ((failed_count++))
            fi
        fi
    done
    
    echo ""
    
    if [ ${removed_count} -gt 0 ]; then
        echo -e "${GREEN}  ✓ ${removed_count} package(s) removed${NC}"
    fi
    
    if [ ${failed_count} -gt 0 ]; then
        echo -e "${RED}  ✗ ${failed_count} package(s) failed to remove${NC}"
        return 1
    fi
    
    # Clean up
    echo "  Running apt autoremove..."
    apt-get autoremove -y > /dev/null 2>&1
    
    echo -e "${GREEN}  ✓ Cleanup completed${NC}"
    echo ""
    
    return 0
}

remove_config_files() {
    echo -e "${CYAN}Removing RSH configuration files...${NC}"
    echo ""
    
    local configs_removed=false
    
    # Remove inetd/xinetd configurations
    if [ -f /etc/inetd.conf ]; then
        if grep -qE "(shell|login|exec)" /etc/inetd.conf 2>/dev/null; then
            echo "  Removing RSH entries from /etc/inetd.conf..."
            sed -i.bak '/\(shell\|login\|exec\).*stream.*tcp/d' /etc/inetd.conf
            echo -e "${GREEN}    ✓ Entries removed from inetd.conf${NC}"
            configs_removed=true
        fi
    fi
    
    # Remove xinetd RSH configurations
    if [ -d /etc/xinetd.d ]; then
        RSH_XINETD_FILES=("rsh" "rlogin" "rexec")
        for file in "${RSH_XINETD_FILES[@]}"; do
            if [ -f "/etc/xinetd.d/${file}" ]; then
                echo "  Removing /etc/xinetd.d/${file}..."
                rm -f "/etc/xinetd.d/${file}"
                echo -e "${GREEN}    ✓ xinetd ${file} config removed${NC}"
                configs_removed=true
            fi
        done
    fi
    
    # Remove .rhosts files (security risk)
    echo "  Checking for .rhosts files..."
    if find /home -name ".rhosts" 2>/dev/null | grep -q .; then
        echo -e "${YELLOW}  ! Found .rhosts files (security risk)${NC}"
        read -p "  Remove all .rhosts files? (yes/no): " remove_rhosts
        if [ "${remove_rhosts}" = "yes" ]; then
            find /home -name ".rhosts" -exec rm -f {} \; 2>/dev/null
            find /root -name ".rhosts" -exec rm -f {} \; 2>/dev/null
            echo -e "${GREEN}    ✓ .rhosts files removed${NC}"
            configs_removed=true
        fi
    fi
    
    if [ "${configs_removed}" = false ]; then
        echo -e "${GREEN}  ✓ No configuration files to remove${NC}"
    fi
    
    echo ""
}

verify_remediation() {
    if [ "${VERIFY}" = false ]; then
        return 0
    fi
    
    echo -e "${CYAN}Verifying remediation...${NC}"
    echo ""
    
    local verification_passed=true
    
    # Check if packages are removed
    for package in "${RSH_PACKAGES[@]}"; do
        if dpkg -l 2>/dev/null | grep -qw "^ii.*${package}"; then
            echo -e "${RED}  ✗ ${package} is still installed${NC}"
            verification_passed=false
        fi
    done
    
    # Check for running processes
    RSH_PROCESSES=("rshd" "in.rshd" "rlogind" "in.rlogind" "rexecd" "in.rexecd")
    for process in "${RSH_PROCESSES[@]}"; do
        if pgrep -x "${process}" > /dev/null 2>&1; then
            echo -e "${RED}  ✗ ${process} is still running${NC}"
            verification_passed=false
        fi
    done
    
    # Check for listening ports
    RSH_PORTS=(512 513 514)
    for port in "${RSH_PORTS[@]}"; do
        if command -v ss > /dev/null 2>&1; then
            if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
                echo -e "${RED}  ✗ Port ${port} is still listening${NC}"
                verification_passed=false
            fi
        fi
    done
    
    if [ "${verification_passed}" = true ]; then
        echo -e "${GREEN}  ✓ Verification PASSED${NC}"
        echo -e "${GREEN}  ✓ All RSH packages removed${NC}"
        echo -e "${GREEN}  ✓ No RSH services running${NC}"
        echo -e "${GREEN}  ✓ No RSH ports listening${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}  ✗ Verification FAILED${NC}"
        echo -e "${RED}  Some issues remain${NC}"
        echo ""
        return 1
    fi
}

print_success() {
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}         REMEDIATION COMPLETED SUCCESSFULLY${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${GREEN}Configuration Applied:${NC}"
    echo "  ✓ RSH server packages have been removed"
    echo "  ✓ RSH services have been stopped and disabled"
    echo "  ✓ Configuration files have been cleaned"
    echo "  ✓ System is now compliant with STIG ${STIG_ID}"
    echo ""
    
    echo -e "${GREEN}Security Improvements:${NC}"
    echo "  ✓ Insecure remote shell services eliminated"
    echo "  ✓ Clear-text credential transmission prevented"
    echo "  ✓ Attack surface reduced"
    echo "  ✓ Nonessential capabilities removed"
    echo "  ✓ Complies with NIST SP 800-53 CM-7"
    echo "  ✓ Meeting CAT I security requirement"
    echo ""
    
    echo -e "${CYAN}Recommended Next Steps:${NC}"
    echo "  1. Use SSH for secure remote access:"
    echo "     sudo apt install openssh-server"
    echo ""
    echo "  2. Configure SSH for security:"
    echo "     • Disable root login"
    echo "     • Use key-based authentication"
    echo "     • Change default SSH port (optional)"
    echo ""
    echo "  3. Document this remediation action"
    echo ""
    echo "  4. Run compliance check to verify:"
    echo "     ./RSH_Check.sh"
    echo ""
    
    echo -e "${YELLOW}SSH Installation (if needed):${NC}"
    echo "  sudo apt update"
    echo "  sudo apt install openssh-server"
    echo "  sudo systemctl enable ssh"
    echo "  sudo systemctl start ssh"
    echo ""
}


#############################################################################
# Main Execution
#############################################################################

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--force)
            FORCE=true
            shift
            ;;
        -b|--backup)
            BACKUP=true
            shift
            ;;
        -v|--verify)
            VERIFY=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

# Clear screen
clear

# Display header
print_header

# Check for root privileges
check_root

# Check current status
if ! check_current_status; then
    exit 0
fi

# Confirmation prompt
if [ "${FORCE}" = false ]; then
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}              REMEDIATION CONFIRMATION${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "This script will:"
    echo "  • Stop all RSH services"
    echo "  • Remove all RSH server packages"
    echo "  • Clean RSH configuration files"
    echo "  • Remove .rhosts files (if confirmed)"
    echo "  • Improve system security posture"
    echo ""
    echo "Impact:"
    echo "  • RSH will no longer be available"
    echo "  • Use SSH for secure remote access instead"
    echo "  • No system restart required"
    echo ""
    read -p "Do you want to proceed with remediation? (yes/no): " confirmation
    
    if [ "${confirmation}" != "yes" ]; then
        echo ""
        echo -e "${YELLOW}Remediation cancelled by user${NC}"
        exit 0
    fi
    echo ""
fi

# Create backup if requested
backup_package_list

# Stop RSH services
stop_rsh_services

# Remove packages
if ! remove_rsh_packages; then
    echo -e "${RED}Package removal encountered errors${NC}"
    echo "Please check the output above and try manual removal if needed"
    exit 1
fi

# Remove config files
remove_config_files

# Verify remediation
verify_remediation
verification_result=$?

# Display results
if [ ${verification_result} -eq 0 ] || [ "${VERIFY}" = false ]; then
    print_success
    exit 0
else
    echo -e "${RED}Remediation completed but verification failed${NC}"
    echo "Please run the check script to identify remaining issues"
    exit 1
fi
