<#
.SYNOPSIS
    Remediates STIG WN11-CC-000180 - Disables Autoplay for non-volume devices.

.DESCRIPTION
    Configures the registry to disable Autoplay for non-volume devices (such as MTP devices)
    to achieve compliance with STIG WN11-CC-000180.
    
    STIG ID: WN11-CC-000180
    Severity: CAT I
    
.PARAMETER Force
    Skip confirmation prompts and force remediation.

.PARAMETER CreateBackup
    Creates a backup of the current registry value before modification.

.EXAMPLE
    .\Remediate-STIG-WN11-CC-000180.ps1
    
.EXAMPLE
    .\Remediate-STIG-WN11-CC-000180.ps1 -Force

.EXAMPLE
    .\Remediate-STIG-WN11-CC-000180.ps1 -Force -CreateBackup

.NOTES
    Requires Administrator privileges.
    
    Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer
    Value Name: NoAutoplayfornonVolume
    Value Data: 1 (REG_DWORD)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateBackup
)

# STIG Information
$STIG_ID = "WN11-CC-000180"
$STIG_Title = "Autoplay must be turned off for non-volume devices"
$Severity = "CAT I"

# Registry configuration
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer"
$RegValueName = "NoAutoplayfornonVolume"
$RequiredValue = 1
$RequiredType = "DWord"

# Require Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Red
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "STIG Remediation Script" -ForegroundColor Cyan
Write-Host "STIG ID: $STIG_ID" -ForegroundColor Cyan
Write-Host "Title: $STIG_Title" -ForegroundColor Cyan
Write-Host "Severity: $Severity" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "This script will configure the following:" -ForegroundColor Yellow
Write-Host "  Registry Path: $RegPath" -ForegroundColor Gray
Write-Host "  Value Name: $RegValueName" -ForegroundColor Gray
Write-Host "  Value Type: REG_DWORD" -ForegroundColor Gray
Write-Host "  Value Data: $RequiredValue" -ForegroundColor Gray
Write-Host ""
Write-Host "Effect: Disables Autoplay for non-volume devices (MTP devices, etc.)" -ForegroundColor Yellow
Write-Host ""

# Check current configuration
Write-Host "Checking current configuration..." -ForegroundColor Yellow

$currentValue = $null
$currentType = $null
$pathExists = Test-Path -Path $RegPath

if ($pathExists) {
    try {
        $regItem = Get-ItemProperty -Path $RegPath -Name $RegValueName -ErrorAction SilentlyContinue
        if ($regItem) {
            $currentValue = $regItem.$RegValueName
            $currentType = (Get-Item -Path $RegPath).GetValueKind($RegValueName)
            Write-Host "  Current Value: $currentValue ($currentType)" -ForegroundColor Gray
        }
        else {
            Write-Host "  Current Value: Not configured" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  Current Value: Not configured" -ForegroundColor Gray
    }
}
else {
    Write-Host "  Registry path does not exist" -ForegroundColor Gray
}

Write-Host ""

# Check if already compliant
if ($pathExists -and $currentValue -eq $RequiredValue -and $currentType -eq $RequiredType) {
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "ALREADY COMPLIANT" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "The system is already configured correctly." -ForegroundColor Green
    Write-Host "No changes are needed." -ForegroundColor Green
    Write-Host ""
    exit 0
}

# Confirmation prompt
if (-not $Force) {
    Write-Host "Do you want to proceed with remediation? (yes/no): " -ForegroundColor Yellow -NoNewline
    $confirmation = Read-Host
    
    if ($confirmation -ne "yes") {
        Write-Host ""
        Write-Host "Remediation cancelled by user." -ForegroundColor Yellow
        exit 0
    }
    Write-Host ""
}

# Backup current configuration if requested
$backupPath = $null
if ($CreateBackup -and $pathExists) {
    Write-Host "Creating backup of current registry configuration..." -ForegroundColor Yellow
    
    $backupPath = "$env:TEMP\STIG_Backup_$STIG_ID`_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
    
    try {
        # Export registry key
        $exportPath = $RegPath -replace 'HKLM:\\', 'HKEY_LOCAL_MACHINE\'
        $regExportCmd = "reg export `"$exportPath`" `"$backupPath`" /y"
        
        $exportResult = cmd /c $regExportCmd 2>&1
        
        if (Test-Path $backupPath) {
            Write-Host "  [OK] Backup created: $backupPath" -ForegroundColor Green
        }
        else {
            Write-Host "  [WARN] Backup file not created, but continuing with remediation" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  [WARN] Could not create backup: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "        Continuing with remediation..." -ForegroundColor Yellow
    }
    
    Write-Host ""
}

# Perform remediation
Write-Host "Applying remediation..." -ForegroundColor Yellow

$remediationSuccess = $false
$remediationError = $null

try {
    # Create registry path if it doesn't exist - build path step by step
    if (-not $pathExists) {
        Write-Host "  Creating registry path..." -ForegroundColor Yellow
        
        # Build the path step by step to ensure all parent keys exist
        $pathParts = $RegPath.Replace('HKLM:\', '').Split('\')
        $currentPath = 'HKLM:'
        
        foreach ($part in $pathParts) {
            $currentPath = Join-Path -Path $currentPath -ChildPath $part
            if (-not (Test-Path -Path $currentPath)) {
                Write-Host "    Creating: $currentPath" -ForegroundColor Gray
                New-Item -Path $currentPath -Force -ErrorAction Stop | Out-Null
            }
        }
        
        # Verify the full path was created
        if (Test-Path -Path $RegPath) {
            Write-Host "  [OK] Registry path created successfully" -ForegroundColor Green
        }
        else {
            throw "Failed to create registry path: $RegPath"
        }
    }
    
    # Set registry value using New-ItemProperty (which creates or updates)
    Write-Host "  Setting registry value..." -ForegroundColor Yellow
    
    # Remove existing value if it exists with wrong type
    if ($pathExists -and $null -ne $currentValue -and $currentType -ne $RequiredType) {
        Write-Host "    Removing existing value (wrong type)..." -ForegroundColor Gray
        Remove-ItemProperty -Path $RegPath -Name $RegValueName -Force -ErrorAction SilentlyContinue
    }
    
    # Use New-ItemProperty with -Force to create or update
    $null = New-ItemProperty -Path $RegPath `
                             -Name $RegValueName `
                             -Value $RequiredValue `
                             -PropertyType $RequiredType `
                             -Force `
                             -ErrorAction Stop
    
    # Give the registry a moment to sync
    Start-Sleep -Milliseconds 500
    
    # Verify the change
    Write-Host "  Verifying configuration..." -ForegroundColor Yellow
    
    $verifyItem = Get-ItemProperty -Path $RegPath -Name $RegValueName -ErrorAction Stop
    $verifyValue = $verifyItem.$RegValueName
    $verifyType = (Get-Item -Path $RegPath).GetValueKind($RegValueName)
    
    Write-Host "    Verified Value: $verifyValue" -ForegroundColor Gray
    Write-Host "    Verified Type: $verifyType" -ForegroundColor Gray
    
    if ($verifyValue -eq $RequiredValue -and $verifyType -eq $RequiredType) {
        $remediationSuccess = $true
        Write-Host "  [OK] Registry value configured and verified successfully" -ForegroundColor Green
    }
    else {
        $remediationError = "Verification failed. Expected: Value=$RequiredValue Type=$RequiredType, Got: Value=$verifyValue Type=$verifyType"
        Write-Host "  [FAIL] Verification failed" -ForegroundColor Red
        Write-Host "    Expected: Value=$RequiredValue, Type=$RequiredType" -ForegroundColor Red
        Write-Host "    Got: Value=$verifyValue, Type=$verifyType" -ForegroundColor Red
    }
}
catch {
    $remediationError = $_.Exception.Message
    Write-Host "  [ERROR] Failed to configure registry: $remediationError" -ForegroundColor Red
    Write-Host "    Error Details: $($_.Exception.GetType().FullName)" -ForegroundColor Red
    
    # Additional diagnostics
    Write-Host ""
    Write-Host "  Diagnostics:" -ForegroundColor Yellow
    Write-Host "    Path exists: $(Test-Path -Path $RegPath)" -ForegroundColor Gray
    
    if (Test-Path -Path $RegPath) {
        try {
            $acl = Get-Acl -Path $RegPath
            Write-Host "    Current user has permissions: $($acl.Access.Count) ACEs" -ForegroundColor Gray
        }
        catch {
            Write-Host "    Could not read permissions" -ForegroundColor Gray
        }
    }
}

Write-Host ""

# Display Results
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "REMEDIATION RESULTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($remediationSuccess) {
    Write-Host "STATUS: SUCCESSFUL" -ForegroundColor Green
    Write-Host ""
    Write-Host "Configuration Applied:" -ForegroundColor Green
    Write-Host "  Registry Path: $RegPath" -ForegroundColor Green
    Write-Host "  Value Name: $RegValueName" -ForegroundColor Green
    Write-Host "  Value Type: REG_DWORD" -ForegroundColor Green
    Write-Host "  Value Data: $RequiredValue" -ForegroundColor Green
    Write-Host ""
    Write-Host "Security Improvement:" -ForegroundColor Green
    Write-Host "  - Autoplay is now disabled for non-volume devices" -ForegroundColor Green
    Write-Host "  - MTP devices and similar will not auto-execute content" -ForegroundColor Green
    Write-Host "  - Protection against malicious code execution via Autoplay" -ForegroundColor Green
    Write-Host ""
    Write-Host "Note: This setting takes effect immediately for new device connections." -ForegroundColor Cyan
    Write-Host "      No system restart is required." -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Verification Command:" -ForegroundColor Cyan
    Write-Host "  Get-ItemProperty -Path '$RegPath' -Name '$RegValueName'" -ForegroundColor Gray
    Write-Host ""
    
    # Create remediation report
    $remediationReport = [PSCustomObject]@{
        STIG_ID = $STIG_ID
        Title = $STIG_Title
        Severity = $Severity
        Status = "Remediated"
        RegistryPath = $RegPath
        ValueName = $RegValueName
        ConfiguredValue = $RequiredValue
        ConfiguredType = $RequiredType
        PreviousValue = if ($null -ne $currentValue) { $currentValue } else { "Not configured" }
        PreviousType = if ($null -ne $currentType) { $currentType } else { "N/A" }
        BackupLocation = if ($CreateBackup -and (Test-Path $backupPath)) { $backupPath } else { "No backup created" }
        RemediationDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        RemediatedBy = $env:USERNAME
        Hostname = $env:COMPUTERNAME
    }
    
    # Save report to file
    $reportPath = "$env:TEMP\STIG_Remediation_$STIG_ID`_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $remediationReport | ConvertTo-Json | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Host "Remediation report saved to: $reportPath" -ForegroundColor Cyan
    Write-Host ""
    
    exit 0
}
else {
    Write-Host "STATUS: FAILED" -ForegroundColor Red
    Write-Host ""
    Write-Host "Remediation could not be completed." -ForegroundColor Red
    Write-Host "Error: $remediationError" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting Steps:" -ForegroundColor Yellow
    Write-Host "  1. Verify you are running PowerShell as Administrator" -ForegroundColor Yellow
    Write-Host "  2. Check if Group Policy is overriding this setting" -ForegroundColor Yellow
    Write-Host "  3. Verify registry permissions on: $RegPath" -ForegroundColor Yellow
    Write-Host "  4. Review any error messages above" -ForegroundColor Yellow
    Write-Host "  5. Try running: gpupdate /force" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Manual Remediation (Registry):" -ForegroundColor Yellow
    Write-Host "  reg add `"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer`" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Manual Remediation (Group Policy):" -ForegroundColor Yellow
    Write-Host "  1. Open Group Policy Editor (gpedit.msc)" -ForegroundColor Yellow
    Write-Host "  2. Navigate to: Computer Configuration >> Administrative Templates >>" -ForegroundColor Yellow
    Write-Host "     Windows Components >> AutoPlay Policies" -ForegroundColor Yellow
    Write-Host "  3. Enable: 'Disallow Autoplay for non-volume devices'" -ForegroundColor Yellow
    Write-Host ""
    
    exit 1
}