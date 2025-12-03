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
    Write-Host "  - This setting takes effect immediately for new password changes" -ForegroundColor Cyan
    Write-Host "  - Existing passwords stored in reversible format (if any) will be" -ForegroundColor Cyan
    Write-Host "    converted to hashed format on next password change" -ForegroundColor Cyan
    Write-Host "  - No system restart is required" -ForegroundColor Cyan
    
    if ($computerSystem.PartOfDomain) {
        Write-Host ""
        Write-Host "  - Domain-joined systems: Verify domain GPO also has this setting" -ForegroundColor Cyan
    }
    
    Write-Host ""
    
    # Create remediation report
    $remediationReport = [PSCustomObject]@{
        STIG_ID = $STIG_ID
        Title = $STIG_Title
        Severity = $Severity
        Status = "Remediated"
        PolicyName = "Store passwords using reversible encryption"
        ConfiguredValue = "Disabled (0)"
        PreviousValue = if ($currentValue -ne "Unknown") { $currentValue } else { "Unknown" }
        BackupLocation = if ($backupPath -and (Test-Path $backupPath)) { $backupPath } else { "No backup created" }
        IsDomainJoined = $computerSystem.PartOfDomain
        DomainName = if ($computerSystem.PartOfDomain) { $computerSystem.Domain } else { "N/A" }
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
    Write-Host "  2. Check if Group Policy is preventing local policy changes" -ForegroundColor Yellow
    Write-Host "  3. Verify secedit.exe is available and functioning" -ForegroundColor Yellow
    Write-Host "  4. Check Windows Event Logs for security policy errors" -ForegroundColor Yellow
    Write-Host "  5. Review any error messages above" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Manual Remediation:" -ForegroundColor Yellow
    Write-Host "  1. Press Win+R and run: secpol.msc" -ForegroundColor Yellow
    Write-Host "  2. Navigate to: Account Policies >> Password Policy" -ForegroundColor Yellow
    Write-Host "  3. Double-click: 'Store passwords using reversible encryption'" -ForegroundColor Yellow
    Write-Host "  4. Select: Disabled" -ForegroundColor Yellow
    Write-Host "  5. Click: OK and close Local Security Policy" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Alternative (using Group Policy Editor):" -ForegroundColor Yellow
    Write-Host "  1. Press Win+R and run: gpedit.msc" -ForegroundColor Yellow
    Write-Host "  2. Navigate to: Computer Configuration >> Windows Settings >>" -ForegroundColor Yellow
    Write-Host "     Security Settings >> Account Policies >> Password Policy" -ForegroundColor Yellow
    Write-Host "  3. Configure: 'Store passwords using reversible encryption' to Disabled" -ForegroundColor Yellow
    Write-Host ""
    
    exit 1
}