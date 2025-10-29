# STIG Automation Project

This project aims to automate the hardening of Windows 11 and Ubuntu 24.04 LTS systems using STIGs (Security Technical Implementation Guides) provided by the Department of Defense (DoD).  
It focuses on compliance verification, automated configuration, and cross-platform security standardization.

---

## Objectives Statement

The objective of this project is to develop a cross-platform security automation framework that:

- Installs and configures Windows 11 and Ubuntu 24.04 LTS systems on dedicated hardware (an old laptop and a Raspberry Pi 5, respectively).  
- Applies at least five Department of Defense (DoD) STIGs to each system to achieve baseline hardening.  
- Automates both STIG application and compliance verification using PowerShell and Bash scripts.  
- Generates structured compliance reports summarizing conforming and non-conforming configurations.  
- Transmits these reports to a centralized compliance server that stores, aggregates, and displays system-level security posture across platforms.

---

## Materials & Software

### **Hardware**
- An old laptop capable of running the latest version of Windows 11  
- A Raspberry Pi 5 running Ubuntu 24.04 LTS

### **Software**
- PowerShell scripting for Windows STIG automation  
- Bash scripting for Ubuntu STIG automation  
- Python (Flask) for a lightweight compliance server implementation  
