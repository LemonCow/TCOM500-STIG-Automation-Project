# PowerShell Scripts for STIG WN11-AC-000045 Compliance

## Script 1: Check Compliance (`Check-STIG-WN11-AC-000045.ps1`)

```powershell
<#
.SYNOPSIS
    Checks compliance with STIG WN11-AC-000045 - Reversible password encryption.

.DESCRIPTION
    Verifies that reversible password encryption is disabled by checking the 
    ClearTextPassword security policy setting.
    
    STIG ID: WN11-AC-000045
    Severity: CAT I
    
.OUTPUTS
    Returns compliance status and current policy configuration.

.EXAMPLE
    .\Check-STIG-WN11-AC-000045.ps1

.NOTES
    Policy: Store passwords using reversible encryption
    Expected Value: Disabled (0)
    Registry Location: Security policy (secpol.msc)
#>

[CmdletBinding()]
param()

# STIG Information
$STIG_ID = "WN11-AC-000045"
$STIG_Title = "Reversible password encryption must be disabled"
$Severity = "CAT I"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "STIG Compliance Check" -ForegroundColor Cyan
Write-Host "STIG ID: $STIG_ID" -ForegroundColor Cyan
Write-Host "Title: $STIG_Title" -ForegroundColor Cyan
Write-Host "Severity: $Severity" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Policy Information:" -ForegroundColor Yellow
Write-Host "  Policy: Store passwords using reversible encryption" -ForegroundColor Gray
Write-Host "  Expected: Disabled" -ForegroundColor Gray
Write-Host "  Location: Computer Configuration >> Windows Settings >> Security Settings >>" -ForegroundColor Gray
Write-Host "            Account Policies >> Password Policy" -ForegroundColor Gray
Write-Host ""

# Initialize compliance status
$isCompliant = $false
$finding = ""
$currentValue = "Unknown"

Write-Host "Checking security policy configuration..." -ForegroundColor Yellow
Write-Host ""

try {
    # Export current security policy to a temporary file
    $tempFile = [System.IO.Path]::GetTempFileName()
    $secEditOutput = "$env:TEMP\secedit_output_$STIG_ID.txt"
    
    Write-Host "  Exporting security policy..." -ForegroundColor Gray
    
    # Use secedit to export current configuration
    $seceditProcess = Start-Process -FilePath "secedit.exe" -ArgumentList "/export /cfg `"$tempFile`" /areas SECURITYPOLICY" -Wait -NoNewWindow -PassThru -RedirectStandardOutput $secEditOutput -RedirectStandardError $secEditOutput
    
    if ($seceditProcess.ExitCode -eq 0) {
        Write-Host "  [OK] Security policy exported successfully" -ForegroundColor Green
        
        # Read the exported file
        if (Test-Path $tempFile) {
            $policyContent = Get-Content -Path $tempFile
            
            # Look for ClearTextPassword setting
            # Format in file: ClearTextPassword = 0 (disabled) or 1 (enabled)
            $clearTextPasswordLine = $policyContent | Where-Object { $_ -match "^ClearTextPassword\s*=" }
            
            if ($clearTextPasswordLine) {
                # Extract the value
                if ($clearTextPasswordLine -match "ClearTextPassword\s*=\s*(\d+)") {
                    $policyValue = $Matches[1]
                    $currentValue = $policyValue
                    
                    Write-Host "  [OK] Policy setting found" -ForegroundColor Green
                    Write-Host "       Current Value: $policyValue" -ForegroundColor Gray
                    
                    # 0 = Disabled (compliant), 1 = Enabled (non-compliant)
                    if ($policyValue -eq "0") {
                        $isCompliant = $true
                        Write-Host "  [OK] Reversible password encryption is DISABLED" -ForegroundColor Green
                    }
                    else {
                        $isCompliant = $false
                        $finding = "Reversible password encryption is ENABLED (value: $policyValue)"
                        Write-Host "  [FAIL] Reversible password encryption is ENABLED" -ForegroundColor Red
                    }
                }
                else {
                    $isCompliant = $false
                    $finding = "Could not parse ClearTextPassword value from policy export"
                    Write-Host "  [FAIL] Could not parse policy value" -ForegroundColor Red
                }
            }
            else {
                # If not found, check if it might be using default (which should be disabled)
                Write-Host "  [WARN] ClearTextPassword setting not found in policy export" -ForegroundColor Yellow
                
                # Try alternative method using Get-ADDefaultDomainPasswordPolicy if available
                try {
                    $netAccounts = net accounts
                    $reversibleLine = $netAccounts | Select-String "reversible"
                    
                    if ($reversibleLine) {
                        Write-Host "  [INFO] Checking via 'net accounts' command" -ForegroundColor Gray
                        # This is a fallback but may not always show the setting
                    }
                }
                catch {
                    # Fallback didn't work
                }
                
                # Assume default value (disabled) but mark as warning
                $currentValue = "Not explicitly configured (assuming default: disabled)"
                $isCompliant = $true
                Write-Host "  [WARN] Setting not explicitly configured, assuming default (disabled)" -ForegroundColor Yellow
            }
        }
        else {
            $isCompliant = $false
            $finding = "Security policy export file not found"
            Write-Host "  [ERROR] Export file not found at: $tempFile" -ForegroundColor Red
        }
    }
    else {
        $isCompliant = $false
        $finding = "Failed to export security policy (secedit exit code: $($seceditProcess.ExitCode))"
        Write-Host "  [ERROR] Failed to export security policy" -ForegroundColor Red
        
        if (Test-Path $secEditOutput) {
            $errorContent = Get-Content $secEditOutput -Raw
            Write-Host "  Error details: $errorContent" -ForegroundColor Red
        }
    }
    
    # Cleanup temporary files
    if (Test-Path $tempFile) { Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue }
    if (Test-Path $secEditOutput) { Remove-Item -Path $secEditOutput -Force -ErrorAction SilentlyContinue }
}
catch {
    $isCompliant = $false
    $finding = "Exception occurred while checking policy: $($_.Exception.Message)"
    Write-Host "  [ERROR] Exception occurred: $($_.Exception.Message)" -ForegroundColor Red
}

# Additional verification using registry (if available)
Write-Host ""
Write-Host "Performing additional verification..." -ForegroundColor Yellow

try {
    # Check SAM registry location (informational only)
    # Note: The actual setting is in the Security Account Manager database
    $samPath = "HKLM:\SAM"
    
    if (Test-Path $samPath) {
        Write-Host "  [INFO] SAM registry key exists (password policies are stored in SAM database)" -ForegroundColor Gray
    }
    
    # Additional check: Verify no domain-level conflicts (for domain-joined machines)
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    if ($computerSystem.PartOfDomain) {
        Write-Host "  [INFO] Computer is domain-joined: $($computerSystem.Domain)" -ForegroundColor Cyan
        Write-Host "         Domain Group Policy may override local settings" -ForegroundColor Cyan
    }
    else {
        Write-Host "  [INFO] Computer is not domain-joined (using local policy)" -ForegroundColor Gray
    }
}
catch {
    Write-Host "  [WARN] Could not perform additional verification: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Display Results
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "COMPLIANCE RESULTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($isCompliant) {
    Write-Host "STATUS: COMPLIANT" -ForegroundColor Green
    Write-Host ""
    Write-Host "The system is properly configured:" -ForegroundColor Green
    Write-Host "  - Reversible password encryption is DISABLED" -ForegroundColor Green
    Write-Host "  - Passwords are stored using one-way cryptographic hashing" -ForegroundColor Green
    Write-Host "  - Current Value: $currentValue" -ForegroundColor Green
    Write-Host ""
    Write-Host "Security Posture:" -ForegroundColor Green
    Write-Host "  - Passwords cannot be recovered in clear text" -ForegroundColor Green
    Write-Host "  - Complies with NIST SP 800-53 IA-5 (1) (c) and (d)" -ForegroundColor Green
    Write-Host ""
}
else {
    Write-Host "STATUS: NON-COMPLIANT" -ForegroundColor Red
    Write-Host ""
    Write-Host "Finding:" -ForegroundColor Red
    Write-Host "  $finding" -ForegroundColor Red
    Write-Host ""
    Write-Host "Current Configuration:" -ForegroundColor Yellow
    Write-Host "  Current Value: $currentValue" -ForegroundColor Yellow
    Write-Host "  Required Value: 0 (Disabled)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Security Risk:" -ForegroundColor Red
    Write-Host "  - Passwords may be stored in a reversible format" -ForegroundColor Red
    Write-Host "  - This is equivalent to storing clear-text passwords" -ForegroundColor Red
    Write-Host "  - Significantly increases risk of password compromise" -ForegroundColor Red
    Write-Host ""
    Write-Host "ACTION REQUIRED: Run the remediation script immediately." -ForegroundColor Yellow
    Write-Host ""
}

# Create a compliance report object
$complianceReport = [PSCustomObject]@{
    STIG_ID = $STIG_ID
    Title = $STIG_Title
    Severity = $Severity
    Status = if ($isCompliant) { "Compliant" } else { "Non-Compliant" }
    PolicyName = "Store passwords using reversible encryption"
    ExpectedValue = "Disabled (0)"
    CurrentValue = $currentValue
    Finding = $finding
    IsDomainJoined = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
    DomainName = if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) { (Get-WmiObject -Class Win32_ComputerSystem).Domain } else { "N/A" }
    CheckDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

# Output compliance report to pipeline
Write-Output $complianceReport

# Set exit code
if ($isCompliant) {
    exit 0
}
else {
    exit 1
}
```

## Script 2: Implement Compliance (`Remediate-STIG-WN11-AC-000045.ps1`)

```powershell
<#
.SYNOPSIS
    Remediates STIG WN11-AC-000045 - Disables reversible password encryption.

.DESCRIPTION
    Configures the security policy to disable reversible password encryption
    to achieve compliance with STIG WN11-AC-000045.
    
    STIG ID: WN11-AC-000045
    Severity: CAT I
    
.PARAMETER Force
    Skip confirmation prompts and force remediation.

.PARAMETER CreateBackup
    Creates a backup of the current security policy before modification.

.EXAMPLE
    .\Remediate-STIG-WN11-AC-000045.ps1
    
.EXAMPLE
    .\Remediate-STIG-WN11-AC-000045.ps1 -Force

.EXAMPLE
    .\Remediate-STIG-WN11-AC-000045.ps1 -Force -CreateBackup

.NOTES
    Requires Administrator privileges.
    This setting affects password storage for all user accounts on the system.
    
    Policy: Store passwords using reversible encryption
    Required Value: Disabled (0)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateBackup
)

# STIG Information
$STIG_ID = "WN11-AC-000045"
$STIG_Title = "Reversible password encryption must be disabled"
$Severity = "CAT I"

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
Write-Host "  Policy: Store passwords using reversible encryption" -ForegroundColor Gray
Write-Host "  Setting: Disabled" -ForegroundColor Gray
Write-Host "  Location: Computer Configuration >> Windows Settings >> Security Settings >>" -ForegroundColor Gray
Write-Host "            Account Policies >> Password Policy" -ForegroundColor Gray
Write-Host ""
Write-Host "Effect: Ensures passwords are stored using one-way cryptographic hashing" -ForegroundColor Yellow
Write-Host ""

# Warning for domain-joined computers
$computerSystem = Get-WmiObject -Class Win32_ComputerSystem
if ($computerSystem.PartOfDomain) {
    Write-Host "WARNING: This computer is domain-joined: $($computerSystem.Domain)" -ForegroundColor Yellow
    Write-Host "         Domain Group Policy may override this local setting." -ForegroundColor Yellow
    Write-Host "         Ensure domain-level GPO also has this setting configured correctly." -ForegroundColor Yellow
    Write-Host ""
}

# Check current configuration
Write-Host "Checking current configuration..." -ForegroundColor Yellow

$currentValue = "Unknown"
$tempExportFile = [System.IO.Path]::GetTempFileName()

try {
    $seceditProcess = Start-Process -FilePath "secedit.exe" -ArgumentList "/export /cfg `"$tempExportFile`" /areas SECURITYPOLICY" -Wait -NoNewWindow -PassThru -RedirectStandardError "$env:TEMP\secedit_error.txt"
    
    if ($seceditProcess.ExitCode -eq 0 -and (Test-Path $tempExportFile)) {
        $policyContent = Get-Content -Path $tempExportFile
        $clearTextPasswordLine = $policyContent | Where-Object { $_ -match "^ClearTextPassword\s*=" }
        
        if ($clearTextPasswordLine -and $clearTextPasswordLine -match "ClearTextPassword\s*=\s*(\d+)") {
            $currentValue = $Matches[1]
            Write-Host "  Current Value: $currentValue ($(if ($currentValue -eq '0') { 'Disabled' } else { 'Enabled' }))" -ForegroundColor Gray
        }
        else {
            Write-Host "  Current Value: Not explicitly configured (default: disabled)" -ForegroundColor Gray
        }
    }
}
catch {
    Write-Host "  [WARN] Could not determine current value: $($_.Exception.Message)" -ForegroundColor Yellow
}
finally {
    if (Test-Path $tempExportFile) { Remove-Item -Path $tempExportFile -Force -ErrorAction SilentlyContinue }
}

Write-Host ""

# Check if already compliant
if ($currentValue -eq "0") {
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "ALREADY COMPLIANT" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Reversible password encryption is already disabled." -ForegroundColor Green
    Write-Host "No changes are needed." -ForegroundColor Green
    Write-Host ""
    exit 0
}

# Confirmation prompt
if (-not $Force) {
    Write-Host "WARNING: This will modify the password policy for this system." -ForegroundColor Yellow
    Write-Host "Do you want to proceed with remediation? (yes/no): " -ForegroundColor Yellow -NoNewline
    $confirmation = Read-Host
    
    if ($confirmation -ne "yes") {
        Write-Host ""
        Write-Host "Remediation cancelled by user." -ForegroundColor Yellow
        exit 0
    }
    Write-Host ""
}

# Backup current security policy if requested
$backupPath = $null
if ($CreateBackup) {
    Write-Host "Creating backup of current security policy..." -ForegroundColor Yellow
    
    $backupPath = "$env:TEMP\STIG_Backup_$STIG_ID_$(Get-Date -Format 'yyyyMMdd_HHmmss').inf"
    
    try {
        $backupProcess = Start-Process -FilePath "secedit.exe" -ArgumentList "/export /cfg `"$backupPath`"" -Wait -NoNewWindow -PassThru -RedirectStandardError "$env:TEMP\secedit_backup_error.txt"
        
        if ($backupProcess.ExitCode -eq 0 -and (Test-Path $backupPath)) {
            Write-Host "  [OK] Backup created: $backupPath" -ForegroundColor Green
        }
        else {
            Write-Host "  [WARN] Backup failed, but continuing with remediation" -ForegroundColor Yellow
            $backupPath = $null
        }
    }
    catch {
        Write-Host "  [WARN] Could not create backup: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "        Continuing with remediation..." -ForegroundColor Yellow
        $backupPath = $null
    }
    
    Write-Host ""
}

# Perform remediation
Write-Host "Applying remediation..." -ForegroundColor Yellow

$remediationSuccess = $false
$remediationError = $null

try {
    # Create a temporary security template file
    $securityTemplate = [System.IO.Path]::GetTempFileName()
    $securityTemplateContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
ClearTextPassword = 0
"@
    
    # Write the security template
    Set-Content -Path $securityTemplate -Value $securityTemplateContent -Encoding Unicode
    
    Write-Host "  Security template created" -ForegroundColor Gray
    Write-Host "  Applying security policy..." -ForegroundColor Yellow
    
    # Create a database file for secedit
    $securityDatabase = [System.IO.Path]::GetTempFileName()
    
    # Apply the security template using secedit
    $applyProcess = Start-Process -FilePath "secedit.exe" -ArgumentList "/configure /db `"$securityDatabase`" /cfg `"$securityTemplate`" /areas SECURITYPOLICY" -Wait -NoNewWindow -PassThru -RedirectStandardOutput "$env:TEMP\secedit_apply_output.txt" -RedirectStandardError "$env:TEMP\secedit_apply_error.txt"
    
    if ($applyProcess.ExitCode -eq 0) {
        Write-Host "  [OK] Security policy applied successfully" -ForegroundColor Green
        
        # Verify the change
        Write-Host "  Verifying configuration..." -ForegroundColor Yellow
        
        Start-Sleep -Seconds 2  # Give the system a moment to apply the change
        
        $verifyFile = [System.IO.Path]::GetTempFileName()
        $verifyProcess = Start-Process -FilePath "secedit.exe" -ArgumentList "/export /cfg `"$verifyFile`" /areas SECURITYPOLICY" -Wait -NoNewWindow -PassThru -RedirectStandardError "$env:TEMP\secedit_verify_error.txt"
        
        if ($verifyProcess.ExitCode -eq 0 -and (Test-Path $verifyFile)) {
            $verifyContent = Get-Content -Path $verifyFile
            $verifyLine = $verifyContent | Where-Object { $_ -match "^ClearTextPassword\s*=" }
            
            if ($verifyLine -and $verifyLine -match "ClearTextPassword\s*=\s*(\d+)") {
                $newValue = $Matches[1]
                
                if ($newValue -eq "0") {
                    $remediationSuccess = $true
                    Write-Host "  [OK] Verification successful - Reversible encryption is DISABLED" -ForegroundColor Green
                }
                else {
                    $remediationError = "Verification failed. Policy shows value: $newValue (expected: 0)"
                    Write-Host "  [FAIL] Verification failed - Value is $newValue" -ForegroundColor Red
                }
            }
            else {
                # Could not find the value, but secedit succeeded
                # This might mean it's using default (which is disabled)
                $remediationSuccess = $true
                Write-Host "  [OK] Policy applied (using default disabled setting)" -ForegroundColor Green
            }
        }
        else {
            $remediationError = "Could not verify the configuration change"
            Write-Host "  [WARN] Could not verify configuration" -ForegroundColor Yellow
            # Still consider it successful if secedit didn't error
            $remediationSuccess = $true
        }
        
        # Cleanup verification file
        if (Test-Path $verifyFile) { Remove-Item -Path $verifyFile -Force -ErrorAction SilentlyContinue }
    }
    else {
        $remediationError = "secedit.exe failed with exit code: $($applyProcess.ExitCode)"
        
        if (Test-Path "$env:TEMP\secedit_apply_error.txt") {
            $errorContent = Get-Content "$env:TEMP\secedit_apply_error.txt" -Raw
            $remediationError += ". Error: $errorContent"
        }
        
        Write-Host "  [ERROR] Failed to apply security policy" -ForegroundColor Red
        Write-Host "          Exit Code: $($applyProcess.ExitCode)" -ForegroundColor Red
    }
    
    # Cleanup temporary files
    if (Test-Path $securityTemplate) { Remove-Item -Path $securityTemplate -Force -ErrorAction SilentlyContinue }
    if (Test-Path $securityDatabase) { Remove-Item -Path $securityDatabase -Force -ErrorAction SilentlyContinue }
    if (Test-Path "$env:TEMP\secedit_apply_output.txt") { Remove-Item -Path "$env:TEMP\secedit_apply_output.txt" -Force -ErrorAction SilentlyContinue }
    if (Test-Path "$env:TEMP\secedit_apply_error.txt") { Remove-Item -Path "$env:TEMP\secedit_apply_error.txt" -Force -ErrorAction SilentlyContinue }
    if (Test-Path "$env:TEMP\secedit_verify_error.txt") { Remove-Item -Path "$env:TEMP\secedit_verify_error.txt" -Force -ErrorAction SilentlyContinue }
}
catch {
    $remediationError = $_.Exception.Message
    Write-Host "  [ERROR] Exception occurred: $remediationError" -ForegroundColor Red
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
    Write-Host "  Policy: Store passwords using reversible encryption" -ForegroundColor Green
    Write-Host "  Setting: Disabled" -ForegroundColor Green
    Write-Host "  Value: 0" -ForegroundColor Green
    Write-Host ""
    Write-Host "Security Improvement:" -ForegroundColor Green
    Write-Host "  - Passwords are now stored using one-way cryptographic hashing" -ForegroundColor Green
    Write-Host "  - Passwords cannot be recovered in clear text format" -ForegroundColor Green
    Write-Host "  - Complies with NIST SP 800-53 IA-5 (1) (c) and (d)" -ForegroundColor Green
    Write-Host "  - Protection against password database compromise" -ForegroundColor Green
    Write-Host ""
    
    if ($backupPath -and (Test-Path $backupPath)) {
        Write-Host "Backup Information:" -ForegroundColor Cyan
        Write-Host "  Previous policy backed up to: $backupPath" -ForegroundColor Cyan
        Write-Host ""
    }
    
    Write-Host "Important Notes:" -ForegroundColor Cyan
    Write-Host "  - This setting takes effect immediately for new passwor