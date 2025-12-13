<#
.SYNOPSIS
    Checks compliance with STIG WN11-AC-000045 - Reversible password encryption must be disabled

.DESCRIPTION
    Verifies that "Store passwords using reversible encryption" is disabled in the
    password policy. This setting should NEVER be enabled as it's equivalent to
    storing passwords in clear text.

    STIG ID: WN11-AC-000045
    Severity: CAT I

.NOTES
    Requires Administrator privileges
    Version: 1.0
    Benchmark Date: 2025-07-02

.EXAMPLE
    .\Reverse Password Check.ps1

.EXAMPLE
    .\Reverse Password Check.ps1 -Remediate
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Remediate
)

function Test-ReversiblePasswordCompliance {
    [CmdletBinding()]
    param(
        [bool]$DoRemediate
    )

    $result = @{
        STIGID = "WN11-AC-000045"
        Title = "Reversible password encryption must be disabled"
        Severity = "CAT I"
        Status = "Not_Reviewed"
        Finding = $false
        Details = @()
        PolicyValue = $null
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        RemediationAttempted = $DoRemediate
    }

    Write-Host "`n============================================" -ForegroundColor Cyan
    Write-Host "STIG Compliance Check: WN11-AC-000045" -ForegroundColor Cyan
    Write-Host "Reversible Password Encryption" -ForegroundColor Cyan
    Write-Host "Severity: CAT I" -ForegroundColor Cyan
    Write-Host "============================================`n" -ForegroundColor Cyan

    try {
        # Export security policy to temp file
        $tempFile = [System.IO.Path]::GetTempFileName()
        $secFile = "$tempFile.txt"
        secedit /export /cfg $secFile /quiet | Out-Null

        if (-not (Test-Path $secFile)) { throw "Failed to export security policy." }

        $content = Get-Content -Path $secFile -ErrorAction Stop
        $line = $content | Where-Object { $_ -match '^ClearTextPassword\s*=\s*(\d+)' }

        if ($line -match '^ClearTextPassword\s*=\s*(\d+)') {
            $value = [int]$Matches[1]
            $result.PolicyValue = $value

            if ($value -eq 0) {
                $result.Status = "NotAFinding"
                $result.Finding = $false
                $result.Details += "Reversible password encryption is DISABLED (compliant)."
                Write-Host "[RESULT] System is COMPLIANT (Reversible encryption = Disabled)" -ForegroundColor Green
            } else {
                $result.Status = "Open"
                $result.Finding = $true
                $result.Details += "Reversible password encryption is ENABLED (non-compliant)."
                Write-Host "[FINDING] System is NOT COMPLIANT (Reversible encryption = Enabled)" -ForegroundColor Red

                if ($DoRemediate) {
                    Write-Host "`nAttempting remediation..." -ForegroundColor Yellow
                    try {
                        # Apply correct security template via secedit
                        $templateContent = @"
[Unicode]
Unicode=yes
[System Access]
ClearTextPassword = 0
"@
                        $templateFile = "$env:TEMP\ReversiblePasswordFix.inf"
                        $templateContent | Out-File -FilePath $templateFile -Encoding Unicode
                        secedit /configure /db secedit.sdb /cfg $templateFile /quiet /overwrite | Out-Null
                        Write-Host "Reversible password encryption disabled successfully." -ForegroundColor Green
                        $result.Details += "Remediation applied: Reversible encryption disabled."
                        $result.Status = "Fixed"
                        $result.Finding = $false
                    } catch {
                        Write-Host "[ERROR] Failed to remediate: $($_.Exception.Message)" -ForegroundColor Red
                        $result.Details += "Remediation failed: $($_.Exception.Message)"
                        $result.Status = "Error"
                    } finally {
                        if (Test-Path $templateFile) { Remove-Item $templateFile -Force }
                    }
                }
            }
        } else {
            $result.Status = "Open"
            $result.Finding = $true
            $result.PolicyValue = "Not Found"
            $result.Details += "Reversible encryption setting not found in security policy."
            Write-Host "[WARNING] Setting not found in security policy." -ForegroundColor Yellow
        }

    } catch {
        $result.Status = "Error"
        $result.Finding = $true
        $result.Details += "Error during compliance check: $($_.Exception.Message)"
        Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        if (Test-Path $secFile) { Remove-Item $secFile -Force }
    }

    Write-Host "`n============================================`n" -ForegroundColor Cyan
    return $result
}

# Main execution
$complianceResult = Test-ReversiblePasswordCompliance -DoRemediate $Remediate.IsPresent

# Output summary
Write-Host "COMPLIANCE REPORT" -ForegroundColor Cyan
Write-Host "=================" -ForegroundColor Cyan
Write-Host "STIG ID: $($complianceResult.STIGID)"
Write-Host "Severity: $($complianceResult.Severity)"
Write-Host "Status: $($complianceResult.Status)"
Write-Host "Finding: $($complianceResult.Finding)"
Write-Host "Policy Value: $($complianceResult.PolicyValue)"
Write-Host "Remediation Attempted: $($complianceResult.RemediationAttempted)"
Write-Host "Timestamp: $($complianceResult.Timestamp)`n"

Write-Host "Details:" -ForegroundColor Cyan
foreach ($detail in $complianceResult.Details) {
    $color = if ($detail -match "non-compliant|ERROR|WARNING") { "Red" } else { "Green" }
    Write-Host "  - $detail" -ForegroundColor $color
}

