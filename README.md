# STIG Automation Project
This project aims to automate the hardening of Windows 11 and Ubuntu 24.04 LTS systems using STIGs (Security Technical Implementation Guides) provided by the DOD (Department of Defense). It focuses on compliance verification, automated configuration, and cross-platform security standardization.
**Objectives Statement**
The objective of this project is to develop a cross-platform security automation framework that:
- Install and configure Windows 11 and Ubuntu 24.04 LTS systems on dedicated hardware (an old laptop and a Raspberry Pi 5, respectively)
- Applies at least 5 Department of Defense (DoD) Security Technical Implementation Guides (STIGs) to each system to achieve baseline hardening,
- Automates both STIG application and compliance verification using PowerShell and Bash scripts.
- Generates structured compliance reports summarizing conforming and non-conforming configurations
- Transmits these reports to a centralized compliance server that stores, aggregates, and displays system-level security posture across platforms
**Materials**
  - An old Laptop capable of running the latest version of Windows 11
  - A Raspberry 5 running Ubuntu 24.04 LTS
  **Software**
  - Powershell scripting
  - Bash scripting
  - Python for a lightweight compliance server, implemented using Flask
