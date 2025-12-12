#!/bin/bash

#############################################################################
# STIG Compliance Check Script
# STIG ID: UBTU-24-100040
# Rule ID: SV-270648r1066433
# Severity: CAT I
# Title: Ubuntu 24.04 LTS must not have the rsh-server package installed
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

# Package names to check
RSH_PACKAGES=("rsh-server" "rsh-redone-server" "rsh-client" "rsh-redone-client")

# Initialize results
COMPLIANT=true
FINDINGS=()
INSTALLED_PACKAGES=()

#############################################################################
# Functions
#############################################################################

print_header() {
    echo -e "${MAGENTA}---------------------------------------------------------------${NC}"
    echo -e "${MAGENTA}         STIG Compliance Check - ${STIG_ID}${NC}"
    echo -e "${MAGENTA}         RSH Server Package Installation Check${NC}"
    echo -e "${MAGENTA}         Severity: ${SEVERITY} (CRITICAL)${NC}"
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
    echo -e "${CYAN}Purpose:${NC}"
    echo "  • Prevent installation of nonessential capabilities"
    echo "  • Reduce attack surface by removing unnecessary services"
    echo "  • Eliminate insecure remote shell services"
    echo "  • Support mission-essential operations only"
    echo ""
}

check_os_version() {
    echo -e "${CYAN}Checking Operating System Version...${NC}"
    
    if [ ! -f /etc/os-release ]; then
        echo -e "${RED}  ? Cannot determine OS version${NC}"
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
        echo -e "${GREEN}  ? Ubuntu 24.04 LTS detected${NC}"
    fi
    echo ""
}

check_rsh_packages() {
    echo -e "${CYAN}Checking for RSH server package installation...${NC}"
    echo ""
    
    for package in "${RSH_PACKAGES[@]}"; do
        # Check if package is installed using dpkg
        if dpkg -l 2>/dev/null | grep -qw "^ii.*${package}"; then
            COMPLIANT=false
            INSTALLED_PACKAGES+=("${package}")
            
            # Get package version and description
            VERSION=$(dpkg -l | grep "^ii.*${package}" | awk '{print $3}')
            DESCRIPTION=$(dpkg -l | grep "^ii.*${package}" | awk '{$1=$2=$3=""; print $0}' | sed 's/^[ \t]*//')
            
            echo -e "${RED}  ? FOUND: ${package}${NC}"
            echo "    Version: ${VERSION}"
            echo "    Description: ${DESCRIPTION}"
            FINDINGS+=("Package ${package} version ${VERSION} is installed")
        else
            echo -e "${GREEN}  ? NOT INSTALLED: ${package}${NC}"
        fi
    done
    
    echo ""
}

check_rsh_services() {
    echo -e "${CYAN}Checking for running RSH services...${NC}"
    echo ""
    
    local services_found=false
    
    # Check for rsh daemon processes
    RSH_PROCESSES=("rshd" "in.rshd" "rlogind" "in.rlogind" "rexecd" "in.rexecd")
    
    for process in "${RSH_PROCESSES[@]}"; do
        if pgrep -x "${process}" > /dev/null 2>&1; then
            services_found=true
            echo -e "${RED}  ? WARNING: ${process} process is running${NC}"
            FINDINGS+=("${process} daemon process detected running")
            
            # Show process details
            ps aux | grep "[${process:0:1}]${process:1}" | while read -r line; do
                echo -e "    ${YELLOW}Process: ${line}${NC}"
            done
        fi
    done
    
    if [ "${services_found}" = false ]; then
        echo -e "${GREEN}  ? No RSH daemon processes running${NC}"
    fi
    
    echo ""
}

check_rsh_listening_ports() {
    echo -e "${CYAN}Checking for RSH listening ports...${NC}"
    echo ""
    
    # RSH related ports
    # 514/TCP - rsh/rshd
    # 513/TCP - rlogin
    # 512/TCP - rexec
    
    local ports_found=false
    RSH_PORTS=(512 513 514)
    
    for port in "${RSH_PORTS[@]}"; do
        local port_name=""
        case ${port} in
            512) port_name="rexec" ;;
            513) port_name="rlogin" ;;
            514) port_name="rsh" ;;
        esac
        
        if command -v ss > /dev/null 2>&1; then
            if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
                ports_found=true
                echo -e "${RED}  ? WARNING: Port ${port}/TCP (${port_name}) is listening${NC}"
                FINDINGS+=("RSH port ${port}/TCP (${port_name}) is listening")
                ss -tlnp 2>/dev/null | grep ":${port} " | while read -r line; do
                    echo -e "    ${YELLOW}${line}${NC}"
                done
            fi
        elif command -v netstat > /dev/null 2>&1; then
            if netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
                ports_found=true
                echo -e "${RED}  ? WARNING: Port ${port}/TCP (${port_name}) is listening${NC}"
                FINDINGS+=("RSH port ${port}/TCP (${port_name}) is listening")
                netstat -tlnp 2>/dev/null | grep ":${port} " | while read -r line; do
                    echo -e "    ${YELLOW}${line}${NC}"
                done
            fi
        fi
    done
    
    if [ "${ports_found}" = false ]; then
        echo -e "${GREEN}  ? No RSH ports (512, 513, 514) are listening${NC}"
    fi
    
    echo ""
}

check_inetd_xinetd() {
    echo -e "${CYAN}Checking inetd/xinetd RSH configuration...${NC}"
    echo ""
    
    local configs_found=false
    
    # Check /etc/inetd.conf
    if [ -f /etc/inetd.conf ]; then
        RSH_SERVICES=("shell" "login" "exec")
        for service in "${RSH_SERVICES[@]}"; do
            if grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -qw "${service}"; then
                configs_found=true
                echo -e "${RED}  ? RSH service '${service}' enabled in /etc/inetd.conf${NC}"
                FINDINGS+=("RSH service ${service} configured in /etc/inetd.conf")
                grep -v "^#" /etc/inetd.conf | grep -w "${service}" | while read -r line; do
                    echo -e "    ${YELLOW}${line}${NC}"
                done
            fi
        done
    fi
    
    # Check xinetd
    if [ -d /etc/xinetd.d ]; then
        RSH_XINETD_FILES=("rsh" "rlogin" "rexec")
        for file in "${RSH_XINETD_FILES[@]}"; do
            if [ -f "/etc/xinetd.d/${file}" ]; then
                configs_found=true
                echo -e "${RED}  ? RSH service configuration found: /etc/xinetd.d/${file}${NC}"
                FINDINGS+=("RSH service configured in xinetd: ${file}")
            fi
        done
    fi
    
    if [ "${configs_found}" = false ]; then
        echo -e "${GREEN}  ? No RSH services in inetd/xinetd configuration${NC}"
    fi
    
    echo ""
}

check_systemd_services() {
    echo -e "${CYAN}Checking systemd RSH services...${NC}"
    echo ""
    
    local systemd_found=false
    RSH_SYSTEMD_SERVICES=("rsh.socket" "rlogin.socket" "rexec.socket" "rshd.service")
    
    for service in "${RSH_SYSTEMD_SERVICES[@]}"; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${service}"; then
            systemd_found=true
            local status=$(systemctl is-enabled "${service}" 2>/dev/null || echo "disabled")
            local active=$(systemctl is-active "${service}" 2>/dev/null || echo "inactive")
            
            if [ "${status}" = "enabled" ] || [ "${active}" = "active" ]; then
                echo -e "${RED}  ? ${service}: ${status} / ${active}${NC}"
                FINDINGS+=("systemd service ${service} is ${status}")
            else
                echo -e "${YELLOW}  ! ${service}: present but ${status}${NC}"
            fi
        fi
    done
    
    if [ "${systemd_found}" = false ]; then
        echo -e "${GREEN}  ? No RSH systemd services found${NC}"
    fi
    
    echo ""
}

check_security_implications() {
    echo -e "${CYAN}Security Analysis:${NC}"
    echo ""
    
    if [ "${COMPLIANT}" = false ]; then
        echo -e "${RED}RSH Security Vulnerabilities:${NC}"
        echo "  • Transmits credentials in clear text"
        echo "  • No encryption of data in transit"
        echo "  • Subject to man-in-the-middle attacks"
        echo "  • Credential sniffing/eavesdropping"
        echo "  • Session hijacking vulnerabilities"
        echo "  • No modern authentication mechanisms"
        echo "  • Deprecated and obsolete protocol"
        echo ""
        echo -e "${YELLOW}Secure Alternatives:${NC}"
        echo "  • SSH (Secure Shell) - Recommended"
        echo "  • VPN for remote access"
        echo "  • Encrypted tunneling solutions"
        echo ""
    else
        echo -e "${GREEN}Security Posture:${NC}"
        echo "  ? Insecure RSH services not installed"
        echo "  ? Reduced attack surface"
        echo "  ? Mission-essential capabilities only"
        echo "  ? Meets security baseline requirements"
        echo ""
    fi
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
        echo "  ? No RSH server packages are installed"
        echo "  ? No insecure remote shell services present"
        echo "  ? System provides only mission-essential capabilities"
        echo "  ? Complies with NIST SP 800-53 CM-7"
        echo "  ? Meeting CAT I security requirement"
        echo ""
        echo -e "${CYAN}Recommendation:${NC}"
        echo "  • Continue to ensure RSH packages remain uninstalled"
        echo "  • Use SSH for secure remote access"
        echo "  • Regularly audit installed packages"
        echo "  • Monitor for unauthorized service installations"
        echo ""
        
    else
        echo -e "${RED}? STATUS: NON-COMPLIANT${NC}"
        echo ""
        echo -e "${RED}CRITICAL SECURITY ISSUE DETECTED:${NC}"
        echo "  ? RSH server package(s) are installed"
        echo "  ? Insecure remote shell service available"
        echo "  ? Clear-text credential transmission possible"
        echo "  ? Unnecessary capabilities present on system"
        echo "  ? Does NOT meet NIST SP 800-53 requirements"
        echo ""
        
        echo -e "${RED}Installed Packages:${NC}"
        for pkg in "${INSTALLED_PACKAGES[@]}"; do
            echo "  • ${pkg}"
        done
        echo ""
        
        if [ ${#FINDINGS[@]} -gt 0 ]; then
            echo -e "${YELLOW}Findings:${NC}"
            for finding in "${FINDINGS[@]}"; do
                echo "  • ${finding}"
            done
            echo ""
        fi
        
        echo -e "${YELLOW}Security Impact:${NC}"
        echo "  • Unencrypted transmission of authentication credentials"
        echo "  • Potential for credential theft via network sniffing"
        echo "  • Man-in-the-middle attack vulnerability"
        echo "  • Session hijacking risk"
        echo "  • Interception of sensitive data"
        echo "  • Non-essential capability increases attack surface"
        echo "  • Non-compliance with security standards"
        echo ""
        
        echo -e "${YELLOW}IMMEDIATE ACTION REQUIRED:${NC}"
        echo "  1. Run remediation script:"
        echo "     sudo ./RSH_Fix.sh"
        echo ""
        echo "  2. Or manually remove:"
        echo "     sudo apt remove rsh-server rsh-client"
        echo ""
        echo "  3. Use SSH instead of RSH for remote access:"
        echo "     sudo apt install openssh-server"
        echo ""
        echo "  4. Document the finding and remediation"
        echo ""
    fi
}

#############################################################################
# Main Execution
#############################################################################

# Check if running on Ubuntu 24.04
check_os_version

# Display header
print_header
print_info

# Perform checks
check_rsh_packages
check_rsh_services
check_rsh_listening_ports
check_inetd_xinetd
check_systemd_services
check_security_implications

# Display results
print_results

# Exit with appropriate code
if [ "${COMPLIANT}" = true ]; then
    exit 0
else
    exit 1
fi
