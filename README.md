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

## Final Project Goals
- Goal 1: Implement at least 5 STIG compliance requirements on a Windows 11 system
- Goal 2: Implement at least 5 STIG compliance requirements on a Ubuntu 24.04 LTS system via a Raspberry Pi
- Goal 3: Create automated compliance checking tools that validate STIG application
- Goal 4: Create automated hardening scripts that apply STIGs
- Goal 5: Output the results in a readable format for the end user

## Project Requirements

**High Level Block Diagram**

<img width="398" height="626" alt="Block Diagram" src="https://github.com/user-attachments/assets/b66a01e6-206f-4987-81fc-d3afa9734c3b" />

**Project Architecture Flow**

<img width="264" height="653" alt="Architecture Flow" src="https://github.com/user-attachments/assets/9f6c19d2-2d26-4ed7-bf07-fa64dc7c3b56" />

**Below are 2 screenshots of all of the Requirements, Verification, and Validation Methods used to complete this Project**

<img width="1670" height="876" alt="Screenshot 2025-12-12 143750" src="https://github.com/user-attachments/assets/db0f8fab-7ccb-488d-8324-303ffac30b50" />

<img width="1582" height="688" alt="Screenshot 2025-12-12 143949" src="https://github.com/user-attachments/assets/65ff2f6b-ea33-4b49-b2c8-9c28f4fb1589" />

## Instructions

**Windows**

1. Install the windows folder into your Downloads Folder
2. Open up powershell as an Administrator
3. Type out this command to get to the appropriate folder: C:\Users\Philip Isaacs\Downloads\windows\scripts
4. For every STIG you wish to check and implement type the appropriate Check and Fix files in this format: .\\[filename].ps1
5. Follow the instructions outputted by the code as appropriate
6. The results/report will display within Powershell

**Linux**
1. Install all the .sh files your Downloads folder
2. Open up the Terminal
3. Open up the zip file and navigate to the ubuntu file via this command: cd Downloads/TCOM500-STIG-Automation-Project-main/ubuntu/scripts
4. Copy and paste this command in the directory: chmod +x SSH_Unattend_Check.sh SSH_Unattend_Fix.sh SSH_Check.sh SSH_Fix.sh Telnet_Check.sh Telnet_Fix.sh Remote_x_Check.sh Remote_x_Fix.sh RSH_Check.sh RSH_Fix.sh
5. For every STIG you wish to check and implement type the appropriate Check and Fix files in this format:
  - For Check files: .\\[filename].sh
  - For Fix files: sudo .\\[filename].sh
7. Follow the instructions outputted by the code as appropriate
8. The results/report will display within the Terminal

## Extra Notes

For research on which STIG's to use and which to disgard, I consulted this website developed by the Department of Defense: https://www.cyber.mil/stigs/.

Here it provided me with a program called STIG Viewer where you can download and view any STIG requirements from any OS you can think of, from Windows to Linux, and even MAC STIG's. 

STIG's are classified in classes and designated a number ranging from 1 to 3 called CATs. 1 is a vunlerability that can be the most critical and 3 being the least critical for a system's vulnerability. This project covers five CAT 1 vulnerabilites for both systems. 

Below is a screenshot of STIG Viewer:

<img width="1010" height="757" alt="Screenshot 2025-12-12 151854" src="https://github.com/user-attachments/assets/2f4b5715-6011-4e62-9250-4a76ab19178b" />


