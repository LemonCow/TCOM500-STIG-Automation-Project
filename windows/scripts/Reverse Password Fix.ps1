<#
.SYNOPSIS
    Remediates STIG WN11-AC-000045 - Disables reversible password encryption

.DESCRIPTION
    Configures the security policy to disable "Store passwords using reversible encryption"
    to achieve compliance with STIG WN11-AC-000045. This is a CAT I (Critical) finding
    that must be remediated immediately.

    STIG ID: WN11-AC-000045
    Rule ID: SV-253305r1051046
    Severity: CAT I

.PARAMETER Force
    Skip confirmation prompts and force remediation

.PARAMETER Backup
    Create a backup of the current security policy before modification

.PARAMETER Verify
    Verify the configuration after applying changes

.PARAMETER Silent
    Suppress all output except errors

.NOTES
    Requires Administrator privileges
    Version: 2.0
    Benchmark Date: 2025-07-02

.EXAMPLE
    .\Remediate-STIG-WN11-AC-000045.ps1

.EXAMPLE
    .\Remediate-STIG-WN11-AC-000045.ps1 -Force -Backup

.EXAMPLE
    .\Remediate-STIG-WN11-AC-000045.ps1 -Force -Verify -Backup

.EXAMPLE
    .\Remediate-STIG-WN11-AC-000045.ps1 -Silent
#>

#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$Backup,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verify,
    
    [Parameter(Mandatory=$false)]
    [switch]$Silent
)

# Script configuration
$script:STIG_ID = "WN11-AC-000045"
$script:RULE_ID = "SV-253305r1051046"
$script:SEVERITY = "CAT I"
$script:TITLE = "Reversible password encryption must be disabled"

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Type = "Info"
    )
    
    if ($Silent -and $Type -ne "Error") { return }
    
    $color = switch ($Type) {
        "Success" { "Green" }
        "Error" { "Red" }
        "Warning" { "Yellow" }
        "Info" { "Cyan" }
        "Header" { "Magenta" }
        default { "White" }
    }
    
    Write-Host $Message -ForegroundColor $color
}

function Get-CurrentPolicyValue {
    <#
    .SYNOPSIS
        Gets the current ClearTextPassword policy value
    #>
    
    $tempFile = [System.IO.Path]::GetTempFileName()
    $secFile = "$tempFile.txt"
    
    try {
        secedit /export /cfg $secFile /quiet | Out-Null
        
        if (-not (Test-Path $secFile)) {
            throw "Failed to export security policy"
        }
        
        $content = Get-Content -Path $secFile -Encoding Unicode -ErrorAction Stop
        $line = $content | Where-Object { $_ -match '^ClearTextPassword\s*=\s*(\d+)' }
        
        if ($line -match '^ClearTextPassword\s*=\s*(\d+)') {
            return @{
                Value = [int]$Matches[1]
                Found = $true
                Setting = if ([int]$Matches[1] -eq 0) { "Disabled" } else { "Enabled" }
            }
        }
        
        return @{
            Value = 0
            Found = $false
            Setting = "Not Configured (Default: Disabled)"
        }
    }
    catch {
        throw "Error reading security policy: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path $secFile) {
            Remove-Item $secFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function Backup-SecurityPolicy {
    <#
    .SYNOPSIS
        Creates a backup of the current security policy
    #>
    param(
        [string]$BackupPath
    )
    
    try {
        Write-ColorOutput "Creating security policy backup..." "Info"
        
        $backupResult = secedit /export /cfg $BackupPath /quiet
        
        if ($LASTEXITCODE -eq 0 -and (Test-Path $BackupPath)) {
            Write-ColorOutput "  ? Backup created successfully" "Success"
            Write-ColorOutput "    Location: $BackupPath" "Info"
            return $true
        }
        else {
            Write-ColorOutput "  ? Backup creation failed" "Warning"
            return $false
        }
    }
    catch {
        Write-ColorOutput "  ? Backup error: $($_.Exception.Message)" "Warning"
        return $false
    }
}

function Set-ReversibleEncryptionDisabled {
    <#
    .SYNOPSIS
        Applies security template to disable reversible password encryption
    #>
    
    $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
    $templateFile = "$env:TEMP\ReversiblePasswordFix_$timestamp.inf"
    $dbFile = "$env:TEMP\secedit_$timestamp.sdb"
    $logFile = "$env:TEMP\secedit_$timestamp.log"
    
    try {
        Write-ColorOutput "`nApplying security configuration..." "Info"
        
        # Create security template
        $templateContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
ClearTextPassword = 0
"@
        
        # Write template to file
        $templateContent | Out-File -FilePath $templateFile -Encoding Unicode -Force
        Write-ColorOutput "  ? Security template created" "Success"
        
        # Apply the template
        Write-ColorOutput "  Configuring security policy..." "Info"
        $configResult = secedit /configure /db $dbFile /cfg $templateFile /log $logFile /quiet
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "  ? Security policy configured successfully" "Success"
            
            # Force policy refresh
            Write-ColorOutput "  Refreshing Group Policy..." "Info"
            gpupdate /target:computer /force /wait:0 | Out-Null
            
            return @{
                Success = $true
                Message = "Reversible password encryption has been disabled"
                ExitCode = 0
            }
        }
        else {
            # Check log file for details
            $errorDetails = if (Test-Path $logFile) {
                Get-Content $logFile -Tail 10 | Out-String
            } else {
                "No log file available"
            }
            
            return @{
                Success = $false
                Message = "secedit configuration failed with exit code: $LASTEXITCODE"
                Details = $errorDetails
                ExitCode = $LASTEXITCODE
            }
        }
    }
    catch {
        return @{
            Success = $false
            Message = "Exception during remediation: $($_.Exception.Message)"
            Details = $_.Exception.ToString()
            ExitCode = 1
        }
    }
    finally {
        # Cleanup temporary files
        $filesToClean = @($templateFile, $dbFile, $logFile)
        foreach ($file in $filesToClean) {
            if (Test-Path $file) {
                Remove-Item $file -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Test-Compliance {
    <#
    .SYNOPSIS
        Verifies that the policy is correctly configured
    #>
    
    Write-ColorOutput "`nVerifying configuration..." "Info"
    
    Start-Sleep -Seconds 2  # Give system time to apply changes
    
    try {
        $currentPolicy = Get-CurrentPolicyValue
        
        if ($currentPolicy.Value -eq 0) {
            Write-ColorOutput "  ? Verification PASSED" "Success"
            Write-ColorOutput "    ClearTextPassword = 0 (Disabled)" "Success"
            return $true
        }
        else {
            Write-ColorOutput "  ? Verification FAILED" "Error"
            Write-ColorOutput "    ClearTextPassword = $($currentPolicy.Value)" "Error"
            Write-ColorOutput "    Expected: 0 (Disabled)" "Error"
            return $false
        }
    }
    catch {
        Write-ColorOutput "  ? Verification error: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Show-PostRemediationGuidance {
    <#
    .SYNOPSIS
        Displays important post-remediation information
    #>
    
    Write-Host ""
    Write-ColorOutput "-----------------------------------------------------------" "Header"
    Write-ColorOutput "         POST-REMEDIATION ACTIONS REQUIRED                  " "Header"
    Write-ColorOutput "-----------------------------------------------------------" "Header"
    Write-Host ""
    
    Write-ColorOutput "IMPORTANT: Password Conversion Process" "Warning"
    Write-Host ""
    Write-Host "1. Existing Passwords in Reversible Format:"
    Write-Host "   • Will NOT be automatically converted to hashed format"
    Write-Host "   • Will convert when users change their passwords"
    Write-Host "   • Remain vulnerable until converted"
    Write-Host ""
    
    Write-ColorOutput "2. Recommended Actions:" "Warning"
    Write-Host "   ? Force password reset for all user accounts"
    Write-Host "   ? Review security logs for potential password compromise"
    Write-Host "   ? Document this remediation and actions taken"
    Write-Host "   ? Notify security team of the finding and remediation"
    Write-Host "   ? Monitor for any authentication issues"
    Write-Host ""
    
    Write-ColorOutput "3. Force Password Reset Options:" "Info"
    Write-Host ""
    Write-Host "   Local Users (PowerShell):"
    Write-Host "   Get-LocalUser | Where-Object {`$_.Enabled -eq `$true} | Set-LocalUser -PasswordNeverExpires `$false"
    Write-Host ""
    Write-Host "   Active Directory Users (PowerShell):"
    Write-Host "   Get-ADUser -Filter * | Set-ADUser -ChangePasswordAtLogon `$true"
    Write-Host ""
    
    Write-ColorOutput "4. Verification Steps:" "Info"
    Write-Host "   ? Run compliance check script again"
    Write-Host "   ? Verify no authentication issues"
    Write-Host "   ? Test user login after password change"
    Write-Host "   ? Review Group Policy application"
    Write-Host ""
    
    Write-ColorOutput "5. Documentation:" "Info"
    Write-Host "   ? Record finding date and severity"
    Write-Host "   ? Document remediation date and method"
    Write-Host "   ? Note any user accounts that had passwords reset"
    Write-Host "   ? Update security compliance records"
    Write-Host ""
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Display header
if (-not $Silent) {
    Clear-Host
    Write-Host ""
    Write-ColorOutput "+---------------------------------------------------------------+" "Header"
    Write-ColorOutput "¦         STIG Remediation Script - WN11-AC-000045             ¦" "Header"
    Write-ColorOutput "¦       Disable Reversible Password Encryption                 ¦" "Header"
    Write-ColorOutput "¦                 Severity: CAT I (Critical)                    ¦" "Header"
    Write-ColorOutput "+---------------------------------------------------------------+" "Header"
    Write-Host ""
    
    Write-Host "STIG Information:"
    Write-Host "  STIG ID:   $script:STIG_ID"
    Write-Host "  Rule ID:   $script:RULE_ID"
    Write-Host "  Title:     $script:TITLE"
    Write-Host "  Severity:  $script:SEVERITY"
    Write-Host ""
}

# Initialize result object
$remediationResult = @{
    STIGID = $script:STIG_ID
    RuleID = $script:RULE_ID
    Title = $script:TITLE
    Severity = $script:SEVERITY
    Status = "Not Started"
    Success = $false
    PreRemediationValue = $null
    PostRemediationValue = $null
    BackupCreated = $false
    BackupLocation = $null
    VerificationPassed = $false
    RemediationDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    RemediatedBy = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Messages = @()
}

# Check if running as Administrator
try {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-ColorOutput "ERROR: This script must be run as Administrator" "Error"
        Write-ColorOutput "Please right-click PowerShell and select 'Run as Administrator'" "Error"
        exit 1
    }
}
catch {
    Write-ColorOutput "ERROR: Could not verify Administrator privileges" "Error"
    exit 1
}

# Check for domain membership
try {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $isDomainJoined = $computerSystem.PartOfDomain
    $domainName = if ($isDomainJoined) { $computerSystem.Domain } else { "N/A" }
    
    if ($isDomainJoined -and -not $Silent) {
        Write-ColorOutput "? DOMAIN-JOINED SYSTEM DETECTED" "Warning"
        Write-Host "  Domain: $domainName"
        Write-Host "  Note: Domain Group Policy may override local policy settings"
        Write-Host "  Ensure domain-level GPO also disables reversible encryption"
        Write-Host ""
    }
    
    $remediationResult.IsDomainJoined = $isDomainJoined
    $remediationResult.DomainName = $domainName
}
catch {
    $remediationResult.IsDomainJoined = $false
    $remediationResult.DomainName = "Unknown"
}

# Get current policy value
Write-ColorOutput "Checking current configuration..." "Info"

try {
    $currentPolicy = Get-CurrentPolicyValue
    $remediationResult.PreRemediationValue = $currentPolicy.Value
    
    Write-Host "  Current Setting: $($currentPolicy.Setting)"
    Write-Host "  Current Value:   $($currentPolicy.Value)"
    Write-Host "  Required Value:  0 (Disabled)"
    Write-Host ""
    
    # Check if already compliant
    if ($currentPolicy.Value -eq 0) {
        Write-ColorOutput "+---------------------------------------------------------------+" "Success"
        Write-ColorOutput "¦              SYSTEM IS ALREADY COMPLIANT                      ¦" "Success"
        Write-ColorOutput "+---------------------------------------------------------------+" "Success"
        Write-Host ""
        Write-ColorOutput "? Reversible password encryption is already disabled" "Success"
        Write-ColorOutput "? No remediation is required" "Success"
        Write-Host ""
        
        $remediationResult.Status = "Already Compliant"
        $remediationResult.Success = $true
        $remediationResult.VerificationPassed = $true
        $remediationResult.Messages += "System was already compliant - no changes made"
        
        # Output result object
        $remediationResult | ConvertTo-Json -Depth 5 | Out-Null
        exit 0
    }
    
    # System is non-compliant - show risk
    Write-ColorOutput "? NON-COMPLIANT CONFIGURATION DETECTED" "Error"
    Write-Host ""
    Write-ColorOutput "Current Risk Level: CRITICAL (CAT I)" "Error"
    Write-Host "  ? Reversible password encryption is ENABLED"
    Write-Host "  ? Passwords stored in reversible format (equivalent to clear text)"
    Write-Host "  ? High risk of password compromise"
    Write-Host "  ? Does NOT meet NIST SP 800-53 requirements"
    Write-Host ""
    
}
catch {
    Write-ColorOutput "ERROR: Could not read current policy configuration" "Error"
    Write-ColorOutput "Details: $($_.Exception.Message)" "Error"
    $remediationResult.Status = "Error"
    $remediationResult.Messages += "Failed to read current configuration: $($_.Exception.Message)"
    exit 1
}

# Confirmation prompt (unless -Force is specified)
if (-not $Force -and -not $Silent) {
    Write-ColorOutput "-----------------------------------------------------------" "Warning"
    Write-ColorOutput "              REMEDIATION CONFIRMATION                      " "Warning"
    Write-ColorOutput "-----------------------------------------------------------" "Warning"
    Write-Host ""
    Write-Host "This script will:"
    Write-Host "  • Disable reversible password encryption"
    Write-Host "  • Set ClearTextPassword = 0 in security policy"
    Write-Host "  • Apply changes immediately (no restart required)"
    Write-Host ""
    Write-Host "Impact:"
    Write-Host "  • Existing passwords in reversible format will convert on next password change"
    Write-Host "  • No impact on normal password operations"
    Write-Host "  • Improves security posture significantly"
    Write-Host ""
    
    $confirmation = Read-Host "Do you want to proceed with remediation? (yes/no)"
    
    if ($confirmation -ne "yes") {
        Write-ColorOutput "`nRemediation cancelled by user" "Warning"
        $remediationResult.Status = "Cancelled"
        $remediationResult.Messages += "Remediation cancelled by user"
        exit 0
    }
    Write-Host ""
}

# Create backup if requested
if ($Backup) {
    $backupPath = "$env:TEMP\SecPol_Backup_$script:STIG_ID`_$(Get-Date -Format 'yyyyMMddHHmmss').inf"
    
    if (Backup-SecurityPolicy -BackupPath $backupPath) {
        $remediationResult.BackupCreated = $true
        $remediationResult.BackupLocation = $backupPath
        $remediationResult.Messages += "Backup created at: $backupPath"
    }
    else {
        Write-ColorOutput "`n? Backup creation failed, but continuing with remediation..." "Warning"
        $remediationResult.BackupCreated = $false
        $remediationResult.Messages += "Backup creation failed but remediation continued"
    }
    Write-Host ""
}

# Apply remediation
Write-ColorOutput "-----------------------------------------------------------" "Info"
Write-ColorOutput "           APPLYING REMEDIATION                             " "Info"
Write-ColorOutput "-----------------------------------------------------------" "Info"

$applyResult = Set-ReversibleEncryptionDisabled

if ($applyResult.Success) {
    Write-Host ""
    Write-ColorOutput "? Remediation applied successfully" "Success"
    $remediationResult.Status = "Remediated"
    $remediationResult.Success = $true
    $remediationResult.Messages += $applyResult.Message
    
    # Verify if requested
    if ($Verify) {
        $verificationPassed = Test-Compliance
        $remediationResult.VerificationPassed = $verificationPassed
        
        if ($verificationPassed) {
            $currentPolicyAfter = Get-CurrentPolicyValue
            $remediationResult.PostRemediationValue = $currentPolicyAfter.Value
            $remediationResult.Messages += "Verification passed: Policy correctly configured"
        }
        else {
            $remediationResult.Messages += "Verification failed: Policy may not be applied correctly"
            Write-ColorOutput "`n? Consider running gpupdate /force manually" "Warning"
        }
    }
    else {
        # Get post-remediation value even without explicit verify
        try {
            $currentPolicyAfter = Get-CurrentPolicyValue
            $remediationResult.PostRemediationValue = $currentPolicyAfter.Value
        }
        catch {
            $remediationResult.PostRemediationValue = "Unknown"
        }
    }
    
    # Display success message
    Write-Host ""
    Write-ColorOutput "+---------------------------------------------------------------+" "Success"
    Write-ColorOutput "¦         REMEDIATION COMPLETED SUCCESSFULLY                    ¦" "Success"
    Write-ColorOutput "+---------------------------------------------------------------+" "Success"
    Write-Host ""
    
    Write-ColorOutput "Configuration Applied:" "Success"
    Write-Host "  ? Reversible password encryption is now DISABLED"
    Write-Host "  ? ClearTextPassword = 0"
    Write-Host "  ? Passwords will be stored using one-way cryptographic hashing"
    Write-Host "  ? Compliant with NIST SP 800-53 IA-5(1)(c) and IA-5(1)(d)"
    Write-Host ""
    
    Write-ColorOutput "Security Improvements:" "Success"
    Write-Host "  ? Passwords cannot be recovered in clear text"
    Write-Host "  ? Uses approved salted key derivation function (PBKDF2)"
    Write-Host "  ? Protection against password database compromise"
    Write-Host "  ? Meets CAT I security requirement"
    Write-Host ""
    
    if (-not $Silent) {
        Show-PostRemediationGuidance
    }
      
    exit 0
}
else {
    # Remediation failed
    Write-Host ""
    Write-ColorOutput "? REMEDIATION FAILED" "Error"
    Write-ColorOutput "Error: $($applyResult.Message)" "Error"
    
    if ($applyResult.Details) {
        Write-Host ""
        Write-ColorOutput "Error Details:" "Error"
        Write-Host $applyResult.Details
    }
    
    $remediationResult.Status = "Failed"
    $remediationResult.Success = $false
    $remediationResult.Messages += "Remediation failed: $($applyResult.Message)"
    
    Write-Host ""
    Write-ColorOutput "-----------------------------------------------------------" "Warning"
    Write-ColorOutput "         MANUAL REMEDIATION REQUIRED                        " "Warning"
    Write-ColorOutput "-----------------------------------------------------------" "Warning"
    Write-Host ""
    
    Write-ColorOutput "Troubleshooting Steps:" "Warning"
    Write-Host "  1. Verify you are running as Administrator"
    Write-Host "  2. Check if Group Policy is preventing local changes"
    Write-Host "  3. Ensure secedit.exe is available and functioning"
    Write-Host "  4. Review Windows Event Logs for security policy errors"
    Write-Host "  5. Check for third-party security software blocking changes"
    Write-Host ""
    
    Write-ColorOutput "Manual Remediation Options:" "Info"
    Write-Host ""
    Write-Host "METHOD 1: Local Security Policy (secpol.msc)"
    Write-Host "  1. Press Win+R and type: secpol.msc"
    Write-Host "  2. Navigate to: Account Policies >> Password Policy"
    Write-Host "  3. Double-click: 'Store passwords using reversible encryption'"
    Write-Host "  4. Select: Disabled"
    Write-Host "  5. Click: OK"
    Write-Host ""
    Write-Host "METHOD 2: Group Policy Editor (gpedit.msc)"
    Write-Host "  1. Press Win+R and type: gpedit.msc"
    Write-Host "  2. Navigate to: Computer Configuration >> Windows Settings >>"
    Write-Host "     Security Settings >> Account Policies >> Password Policy"
    Write-Host "  3. Configure: 'Store passwords using reversible encryption' to Disabled"
    Write-Host "  4. Run: gpupdate /force"
    Write-Host ""
    Write-Host "METHOD 3: Command Line (secedit)"
    Write-Host "  1. Create file: C:\\temp\\fix.inf with content:"
    Write-Host "     [Unicode]"
    Write-Host "     Unicode=yes"
    Write-Host "     [System Access]"
    Write-Host "     ClearTextPassword = 0"
    Write-Host "  2. Run: secedit /configure /db secedit.sdb /cfg C:\\temp\\fix.inf"
    Write-Host ""
    
    exit 1
}