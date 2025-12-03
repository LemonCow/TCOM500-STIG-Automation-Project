# STIG Automation Project

This project aims to automate the hardening of Windows 11 and Ubuntu 24.04 LTS systems using STIGs (Security Technical Implementation Guides) provided by the Department of Defense (DoD). The overall goal is to build a framework capable of performing automated configuration, compliance verification, and cross-platform security standardization, ensuring both systems meet DoD-level security baselines.


## Objectives Statement

The objective of this project is to develop a cross-platform security automation framework that:

- Installs and configures Windows 11 and Ubuntu 24.04 LTS systems on dedicated hardware (an old laptop and a Raspberry Pi 5, respectively).  
- Applies at least five Department of Defense (DoD) STIGs to each system to achieve baseline hardening.  
- Automates both STIG application and compliance verification using PowerShell and Bash scripts.  
- Generates structured compliance reports summarizing conforming and non-conforming configurations.  


## Materials & Software

### **Hardware**
- An old laptop capable of running the latest version of Windows 11  
- A Raspberry Pi 5 running Ubuntu 24.04 LTS

### **Software**
- PowerShell scripting for Windows STIG compliance and automation  
- Bash scripting for Ubuntu STIG compliance and automation  
- Python (Flask) for a lightweight compliance server to display results

## Final Project Goals
- Goal 1: Implement at least 5 STIG compliance requirements on a Windows 11 system
- Goal 2: Implement at least 5 STIG compliance requirements on a Ubuntu 24.04 LTS system via a Raspberry Pi
- Goal 3: Create automated compliance checking tools that validate STIG application
- Goal 4: Create automated hardening scripts that apply STIGs without manual intervention
