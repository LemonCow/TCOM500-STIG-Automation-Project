<#
.SYNOPSIS
    Checks compliance with STIG WN11-CC-000185 - Autorun commands prevention.

.DESCRIPTION
    Verifies that autorun commands are prevented from executing by checking
    the NoAutorun registry value.
    
    STIG ID: WN11-CC-000185
    Severity: CAT I
    
.OUTPUTS
    Returns compliance status and registry value details.

.EXAMPLE
    .\Check-STIG-WN11-CC-000185.ps1

.NOTES
    Registry Path: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
    Value Name: NoAutorun
    Expected Value: 1 (REG_DWORD)
#>

[CmdletBinding()]
param()

# STIG Information
$STIG_ID = "WN11-CC-000185"
$STIG_Title = "The default autorun behavior must be configured to prevent autorun commands"
$Severity = "CAT I"

# Registry configuration
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$RegValueName = "NoAutorun"
$ExpectedValue = 1
$ExpectedType = "DWord"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "STIG Compliance Check" -ForegroundColor Cyan
Write-Host "STIG ID: $STIG_ID" -ForegroundColor Cyan
Write-Host "Title: $STIG_Title" -ForegroundColor Cyan
Write-Host "Severity: $Severity" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Registry Settings:" -ForegroundColor Yellow
Write-Host "  Path: $RegPath" -ForegroundColor Gray
Write-Host "  Value Name: $RegValueName" -ForegroundColor Gray
Write-Host "  Expected Value: $ExpectedValue (REG_DWORD)" -ForegroundColor Gray
Write-Host "  Group Policy: Set the default behavior for AutoRun" -ForegroundColor Gray
Write-Host "  Required Setting: Do not execute any autorun commands" -ForegroundColor Gray
Write-Host ""

# Initialize compliance status
$isCompliant = $false
$finding = ""

Write-Host "Checking registry configuration..." -ForegroundColor Yellow
Write-Host ""

try {
    # Check if registry path exists
    if (-not (Test-Path -Path $RegPath)) {
        $isCompliant = $false
        $finding = "Registry path does not exist: $RegPath"
        Write-Host "  [FAIL] Registry path does not exist" -ForegroundColor Red
        Write-Host "         Path: $RegPath" -ForegroundColor Red
    }
    else {
        Write-Host "  [OK] Registry path exists" -ForegroundColor Green
        
        # Check if registry value exists
        $regValue = Get-ItemProperty -Path $RegPath -Name $RegValueName -ErrorAction SilentlyContinue
        
        if ($null -eq $regValue) {
            $isCompliant = $false
            $finding = "Registry value '$RegValueName' does not exist"
            Write-Host "  [FAIL] Registry value does not exist" -ForegroundColor Red
            Write-Host "         Value Name: $RegValueName" -ForegroundColor Red
        }
        else {
            $currentValue = $regValue.$RegValueName
            $valueType = (Get-Item -Path $RegPath).GetValueKind($RegValueName)
            
            Write-Host "  [OK] Registry value exists" -ForegroundColor Green
            Write-Host "       Current Value: $currentValue" -ForegroundColor Gray
            Write-Host "       Value Type: $valueType" -ForegroundColor Gray
            
            # Check if value type is correct
            if ($valueType -ne $ExpectedType) {
                $isCompliant = $false
                $finding = "Registry value type is incorrect. Expected: $ExpectedType, Found: $valueType"
                Write-Host "  [FAIL] Incorrect value type" -ForegroundColor Red
                Write-Host "         Expected: $ExpectedType" -ForegroundColor Red
                Write-Host "         Found: $valueType" -ForegroundColor Red
            }
            # Check if value is correct
            elseif ($currentValue -ne $ExpectedValue) {
                $isCompliant = $false
                $finding = "Registry value is incorrect. Expected: $ExpectedValue, Found: $currentValue"
                Write-Host "  [FAIL] Incorrect value" -ForegroundColor Red
                Write-Host "         Expected: $ExpectedValue" -ForegroundColor Red
                Write-Host "         Found: $currentValue" -ForegroundColor Red
            }
            else {
                $isCompliant = $true
                Write-Host "  [OK] Registry value is correctly configured" -ForegroundColor Green
            }
        }
    }
}
catch {
    $isCompliant = $false
    $finding = "Error checking registry: $($_.Exception.Message)"
    Write-Host "  [ERROR] Exception occurred while checking registry" -ForegroundColor Red
    Write-Host "          $($_.Exception.Message)" -ForegroundColor Red
}

# Additional verification - check related AutoRun settings
Write-Host ""
Write-Host "Checking related AutoRun settings..." -ForegroundColor Yellow

$relatedSettings = @()

# Check NoDriveTypeAutoRun (complementary setting)
try {
    $noDriveTypeAutoRunValue = Get-ItemProperty -Path $RegPath -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    if ($noDriveTypeAutoRunValue) {
        $noDriveTypeValue = $noDriveTypeAutoRunValue.NoDriveTypeAutoRun
        Write-Host "  [INFO] NoDriveTypeAutoRun: $noDriveTypeValue (0xFF = all drives disabled)" -ForegroundColor Cyan
        $relatedSettings += "NoDriveTypeAutoRun = $noDriveTypeValue"
    }
    else {
        Write-Host "  [INFO] NoDriveTypeAutoRun: Not configured" -ForegroundColor Gray
    }
}
catch {
    Write-Host "  [INFO] NoDriveTypeAutoRun: Could not check" -ForegroundColor Gray
}

# Check AutoRun value (legacy)
try {
    $autoRunValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CDRom" -Name "AutoRun" -ErrorAction SilentlyContinue
    if ($autoRunValue) {
        $autoRunVal = $autoRunValue.AutoRun
        Write-Host "  [INFO] CDRom AutoRun: $autoRunVal (0 = disabled, 1 = enabled)" -ForegroundColor Cyan
        $relatedSettings += "CDRom AutoRun = $autoRunVal"
    }
}
catch {
    Write-Host "  [INFO] CDRom AutoRun: Could not check" -ForegroundColor Gray
}

# Additional check: Group Policy inheritance
Write-Host ""
Write-Host "Additional Information:" -ForegroundColor Yellow

if ($isCompliant) {
    Write-Host "  Group Policy: 'Set the default behavior for AutoRun' is properly configured" -ForegroundColor Green
    Write-Host "  Effect: Autorun commands will NOT execute" -ForegroundColor Green
    Write-Host "  Protection: Prevents malicious code execution via AutoRun" -ForegroundColor Green
}
else {
    Write-Host "  Group Policy: 'Set the default behavior for AutoRun' is NOT properly configured" -ForegroundColor Red
    Write-Host "  Risk: Autorun commands may execute when media is inserted" -ForegroundColor Red
    Write-Host "  Threat: Malicious code could be introduced to the system" -ForegroundColor Red
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
    Write-Host "  - Autorun commands are prevented from executing" -ForegroundColor Green
    Write-Host "  - Registry value '$RegValueName' is set to $ExpectedValue" -ForegroundColor Green
    Write-Host "  - Protection against malicious AutoRun exploitation is active" -ForegroundColor Green
    Write-Host ""
    
    if ($relatedSettings.Count -gt 0) {
        Write-Host "Related Settings:" -ForegroundColor Cyan
        foreach ($setting in $relatedSettings) {
            Write-Host "  $setting" -ForegroundColor Cyan
        }
        Write-Host ""
    }
}
else {
    Write-Host "STATUS: NON-COMPLIANT" -ForegroundColor Red
    Write-Host ""
    Write-Host "Finding:" -ForegroundColor Red
    Write-Host "  $finding" -ForegroundColor Red
    Write-Host ""
    Write-Host "Required Configuration:" -ForegroundColor Yellow
    Write-Host "  Registry Path: $RegPath" -ForegroundColor Yellow
    Write-Host "  Value Name: $RegValueName" -ForegroundColor Yellow
    Write-Host "  Value Type: REG_DWORD" -ForegroundColor Yellow
    Write-Host "  Value Data: $ExpectedValue" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Security Risk:" -ForegroundColor Red
    Write-Host "  - Autorun commands may execute automatically when media is inserted" -ForegroundColor Red
    Write-Host "  - Malicious code could be introduced via removable media" -ForegroundColor Red
    Write-Host "  - AutoRun.inf files could execute unauthorized commands" -ForegroundColor Red
    Write-Host "  - System vulnerable to AutoRun-based attacks" -ForegroundColor Red
    Write-Host ""
    Write-Host "ACTION REQUIRED: Run the remediation script to configure this setting." -ForegroundColor Yellow
    Write-Host ""
}

# Create a compliance report object
$complianceReport = [PSCustomObject]@{
    STIG_ID = $STIG_ID
    Title = $STIG_Title
    Severity = $Severity
    Status = if ($isCompliant) { "Compliant" } else { "Non-Compliant" }
    RegistryPath = $RegPath
    ValueName = $RegValueName
    ExpectedValue = $ExpectedValue
    ExpectedType = $ExpectedType
    CurrentValue = if ($regValue) { $regValue.$RegValueName } else { "N/A" }
    CurrentType = if ($regValue) { (Get-Item -Path $RegPath -ErrorAction SilentlyContinue).GetValueKind($RegValueName) } else { "N/A" }
    Finding = $finding
    RelatedSettings = $relatedSettings -join "; "
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