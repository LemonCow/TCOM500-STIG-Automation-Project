<#
.SYNOPSIS
    Remediates STIG WN11-CC-000185 - Prevents autorun commands from executing.

.DESCRIPTION
    Configures the registry to prevent autorun commands from executing
    to achieve compliance with STIG WN11-CC-000185.
    
    STIG ID: WN11-CC-000185
    Severity: CAT I
    
.PARAMETER Force
    Skip confirmation prompts and force remediation.

.PARAMETER CreateBackup
    Creates a backup of the current registry value before modification.

.PARAMETER ConfigureRelatedSettings
    Also configure related AutoRun security settings (recommended).

.EXAMPLE
    .\Remediate-STIG-WN11-CC-000185.ps1
    
.EXAMPLE
    .\Remediate-STIG-WN11-CC-000185.ps1 -Force

.EXAMPLE
    .\Remediate-STIG-WN11-CC-000185.ps1 -Force -CreateBackup -ConfigureRelatedSettings

.NOTES
    Requires Administrator privileges.
    
    Registry Path: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
    Value Name: NoAutorun
    Value Data: 1 (REG_DWORD)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateBackup,
    
    [Parameter(Mandatory=$false)]
    [switch]$ConfigureRelatedSettings
)

# STIG Information
$STIG_ID = "WN11-CC-000185"
$STIG_Title = "The default autorun behavior must be configured to prevent autorun commands"
$Severity = "CAT I"

# Registry configuration
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$RegValueName = "NoAutorun"
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
Write-Host "Effect: Prevents autorun commands from executing" -ForegroundColor Yellow
Write-Host "        (equivalent to Group Policy: 'Do not execute any autorun commands')" -ForegroundColor Yellow
Write-Host ""

if ($ConfigureRelatedSettings) {
    Write-Host "Additional Settings (with -ConfigureRelatedSettings):" -ForegroundColor Yellow
    Write-Host "  - NoDriveTypeAutoRun: 0xFF (disable AutoRun on all drive types)" -ForegroundColor Gray
    Write-Host "  - Enhanced AutoRun protection" -ForegroundColor Gray
    Write-Host ""
}

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
    if (-not $ConfigureRelatedSettings) {
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "ALREADY COMPLIANT" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "The system is already configured correctly." -ForegroundColor Green
        Write-Host "NoAutorun is set to prevent autorun commands." -ForegroundColor Green
        Write-Host ""
        Write-Host "Tip: Use -ConfigureRelatedSettings for enhanced AutoRun protection." -ForegroundColor Cyan
        Write-Host ""
        exit 0
    }
    else {
        Write-Host "Primary setting is compliant. Checking related settings..." -ForegroundColor Green
        Write-Host ""
    }
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
if ($CreateBackup -and $pathExists) {
    Write-Host "Creating backup of current registry configuration..." -ForegroundColor Yellow
    
    $backupPath = "$env:TEMP\STIG_Backup_$STIG_ID_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
    
    try {
        # Export registry key
        $exportPath = $RegPath -replace 'HKLM:\\', 'HKEY_LOCAL_MACHINE\'
        $regExportCmd = "reg export `"$exportPath`" `"$backupPath`" /y"
        
        $exportResult = Invoke-Expression $regExportCmd 2>&1
        
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
$appliedSettings = @()

try {
    # Create registry path if it doesn't exist
    if (-not $pathExists) {
        Write-Host "  Creating registry path..." -ForegroundColor Yellow
        New-Item -Path $RegPath -Force | Out-Null
        Write-Host "  [OK] Registry path created" -ForegroundColor Green
    }
    
    # Set primary registry value
    Write-Host "  Setting NoAutorun registry value..." -ForegroundColor Yellow
    
    Set-ItemProperty -Path $RegPath -Name $RegValueName -Value $RequiredValue -Type $RequiredType -Force -ErrorAction Stop
    
    # Verify the change
    $verifyValue = Get-ItemProperty -Path $RegPath -Name $RegValueName -ErrorAction Stop
    $verifyType = (Get-Item -Path $RegPath).GetValueKind($RegValueName)
    
    if ($verifyValue.$RegValueName -eq $RequiredValue -and $verifyType -eq $RequiredType) {
        Write-Host "  [OK] NoAutorun configured successfully" -ForegroundColor Green
        $appliedSettings += "NoAutorun = $RequiredValue"
        $remediationSuccess = $true
    }
    else {
        $remediationError = "Verification failed. Value was set but does not match expected configuration."
        Write-Host "  [FAIL] Verification failed" -ForegroundColor Red
    }
    
    # Configure related settings if requested
    if ($ConfigureRelatedSettings -and $remediationSuccess) {
        Write-Host ""
        Write-Host "  Configuring related AutoRun settings..." -ForegroundColor Yellow
        
        # Set NoDriveTypeAutoRun to disable AutoRun on all drive types
        # 0xFF = 255 = all bits set = all drive types disabled
        try {
            Set-ItemProperty -Path $RegPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force -ErrorAction Stop
            Write-Host "  [OK] NoDriveTypeAutoRun set to 0xFF (all drive types)" -ForegroundColor Green
            $appliedSettings += "NoDriveTypeAutoRun = 255 (0xFF)"
        }
        catch {
            Write-Host "  [WARN] Could not set NoDriveTypeAutoRun: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        # Disable CDRom AutoRun (legacy setting)
        try {
            $cdromPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CDRom"
            if (Test-Path $cdromPath) {
                Set-ItemProperty -Path $cdromPath -Name "AutoRun" -Value 0 -Type DWord -Force -ErrorAction Stop
                Write-Host "  [OK] CDRom AutoRun disabled" -ForegroundColor Green
                $appliedSettings += "CDRom AutoRun = 0 (disabled)"
            }
        }
        catch {
            Write-Host "  [WARN] Could not set CDRom AutoRun: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}
catch {
    $remediationError = $_.Exception.Message
    Write-Host "  [ERROR] Failed to configure registry: $remediationError" -ForegroundColor Red
    $remediationSuccess = $false
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
    foreach ($setting in $appliedSettings) {
        Write-Host "  $setting" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "Registry Location:" -ForegroundColor Green
    Write-Host "  Path: $RegPath" -ForegroundColor Green
    Write-Host "  Primary Value: $RegValueName = $RequiredValue" -ForegroundColor Green
    Write-Host ""
    Write-Host "Security Improvement:" -ForegroundColor Green
    Write-Host "  - Autorun commands will NOT execute automatically" -ForegroundColor Green
    Write-Host "  - AutoRun.inf files will be ignored" -ForegroundColor Green
    Write-Host "  - Protection against malicious AutoRun exploitation" -ForegroundColor Green
    Write-Host "  - Reduced attack surface for removable media threats" -ForegroundColor Green
    
    if ($ConfigureRelatedSettings) {
        Write-Host "  - Enhanced protection: AutoRun disabled on all drive types" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "Important Notes:" -ForegroundColor Cyan
    Write-Host "  - This setting takes effect immediately for new media insertions" -ForegroundColor Cyan
    Write-Host "  - No system restart is required" -ForegroundColor Cyan
    Write-Host "  - Users can still manually browse and run files from removable media" -ForegroundColor Cyan
    Write-Host "  - AutoPlay prompts may still appear, but commands won't auto-execute" -ForegroundColor Cyan
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
        AppliedSettings = $appliedSettings -join "; "
        RelatedSettingsConfigured = $ConfigureRelatedSettings
        BackupLocation = if ($CreateBackup -and (Test-Path $backupPath)) { $backupPath } else { "No backup created" }
        RemediationDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    Write-Output $remediationReport
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
    Write-Host "  5. Check for conflicting security software" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Manual Remediation:" -ForegroundColor Yellow
    Write-Host "  1. Open Group Policy Editor (gpedit.msc)" -ForegroundColor Yellow
    Write-Host "  2. Navigate to: Computer Configuration >> Administrative Templates >>" -ForegroundColor Yellow
    Write-Host "     Windows Components >> AutoPlay Policies" -ForegroundColor Yellow
    Write-Host "  3. Open: 'Set the default behavior for AutoRun'" -ForegroundColor Yellow
    Write-Host "  4. Select: Enabled" -ForegroundColor Yellow
    Write-Host "  5. Choose: 'Do not execute any autorun commands'" -ForegroundColor Yellow
    Write-Host "  6. Click: OK" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Alternative (Registry Editor):" -ForegroundColor Yellow
    Write-Host "  1. Open Registry Editor (regedit.exe)" -ForegroundColor Yellow
    Write-Host "  2. Navigate to: $RegPath" -ForegroundColor Yellow
    Write-Host "  3. Create/Modify DWORD: $RegValueName" -ForegroundColor Yellow
    Write-Host "  4. Set value to: $RequiredValue" -ForegroundColor Yellow
    Write-Host ""
    
    exit 1
}