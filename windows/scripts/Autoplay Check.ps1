<#
.SYNOPSIS
    Checks compliance with STIG WN11-CC-000180 - Autoplay for non-volume devices.

.DESCRIPTION
    Verifies that Autoplay is disabled for non-volume devices (such as MTP devices)
    by checking the NoAutoplayfornonVolume registry value.
    
    STIG ID: WN11-CC-000180
    Severity: CAT I
    
.OUTPUTS
    Returns compliance status and registry value details.

.EXAMPLE
    .\Check-STIG-WN11-CC-000180.ps1

.NOTES
    Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer
    Value Name: NoAutoplayfornonVolume
    Expected Value: 1 (REG_DWORD)
#>

[CmdletBinding()]
param()

# STIG Information
$STIG_ID = "WN11-CC-000180"
$STIG_Title = "Autoplay must be turned off for non-volume devices"
$Severity = "CAT I"

# Registry configuration
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
$RegValueName = "NoAutoplayfornonVolume"
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

# Additional check: Verify Group Policy setting interpretation
Write-Host ""
Write-Host "Additional Information:" -ForegroundColor Yellow

if ($isCompliant) {
    Write-Host "  Group Policy: 'Disallow Autoplay for non-volume devices' is ENABLED" -ForegroundColor Green
    Write-Host "  Effect: Autoplay is disabled for non-volume devices (MTP devices, etc.)" -ForegroundColor Green
}
else {
    Write-Host "  Group Policy: 'Disallow Autoplay for non-volume devices' is NOT properly configured" -ForegroundColor Red
    Write-Host "  Risk: Autoplay may execute on non-volume devices, potentially introducing malicious code" -ForegroundColor Red
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
    Write-Host "  - Autoplay for non-volume devices is disabled" -ForegroundColor Green
    Write-Host "  - Registry value '$RegValueName' is set to $ExpectedValue" -ForegroundColor Green
    Write-Host ""
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