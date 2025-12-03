<#
.SYNOPSIS
    Checks compliance with STIG WN11-00-000100 - IIS must not be installed on workstation.

.DESCRIPTION
    Verifies that Internet Information Services (IIS) and IIS Hostable Web Core 
    are not installed on Windows 11 workstation.
    
    STIG ID: WN11-00-000100
    Severity: CAT I
    
.OUTPUTS
    Returns compliance status and details of any IIS components found.

.EXAMPLE
    .\Check-STIG-WN11-00-000100.ps1
#>

[CmdletBinding()]
param()

# STIG Information
$STIG_ID = "WN11-00-000100"
$STIG_Title = "Internet Information System (IIS) or its subcomponents must not be installed on a workstation"
$Severity = "CAT I"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "STIG Compliance Check" -ForegroundColor Cyan
Write-Host "STIG ID: $STIG_ID" -ForegroundColor Cyan
Write-Host "Title: $STIG_Title" -ForegroundColor Cyan
Write-Host "Severity: $Severity" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Initialize compliance status
$isCompliant = $true
$findings = @()

# Check for IIS Windows Features
$iisFeatures = @(
    "IIS-WebServerRole",
    "IIS-WebServer",
    "IIS-CommonHttpFeatures",
    "IIS-HttpErrors",
    "IIS-HttpRedirect",
    "IIS-ApplicationDevelopment",
    "IIS-NetFxExtensibility",
    "IIS-NetFxExtensibility45",
    "IIS-HealthAndDiagnostics",
    "IIS-HttpLogging",
    "IIS-LoggingLibraries",
    "IIS-RequestMonitor",
    "IIS-HttpTracing",
    "IIS-Security",
    "IIS-URLAuthorization",
    "IIS-RequestFiltering",
    "IIS-IPSecurity",
    "IIS-Performance",
    "IIS-HttpCompressionDynamic",
    "IIS-WebServerManagementTools",
    "IIS-ManagementScriptingTools",
    "IIS-IIS6ManagementCompatibility",
    "IIS-Metabase",
    "IIS-HostableWebCore",
    "IIS-StaticContent",
    "IIS-DefaultDocument",
    "IIS-DirectoryBrowsing",
    "IIS-WebDAV",
    "IIS-WebSockets",
    "IIS-ApplicationInit",
    "IIS-ASPNET",
    "IIS-ASPNET45",
    "IIS-ASP",
    "IIS-CGI",
    "IIS-ISAPIExtensions",
    "IIS-ISAPIFilter",
    "IIS-ServerSideIncludes",
    "IIS-CustomLogging",
    "IIS-BasicAuthentication",
    "IIS-HttpCompressionStatic",
    "IIS-ManagementConsole",
    "IIS-ManagementService",
    "IIS-WMICompatibility",
    "IIS-LegacyScripts",
    "IIS-LegacySnapIn",
    "IIS-FTPServer",
    "IIS-FTPSvc",
    "IIS-FTPExtensibility"
)

Write-Host "Checking for IIS Windows Features..." -ForegroundColor Yellow

foreach ($feature in $iisFeatures) {
    try {
        $featureState = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
        
        if ($featureState -and $featureState.State -eq "Enabled") {
            $isCompliant = $false
            $findings += "Feature '$feature' is ENABLED"
            Write-Host "  [FAIL] $feature is ENABLED" -ForegroundColor Red
        }
    }
    catch {
        # Feature doesn't exist on this system, which is fine
        continue
    }
}

# Check using DISM as alternative method
Write-Host ""
Write-Host "Performing additional DISM check..." -ForegroundColor Yellow

try {
    $dismFeatures = dism /online /get-features /format:table | Select-String "IIS-"
    
    if ($dismFeatures) {
        foreach ($line in $dismFeatures) {
            if ($line -match "Enabled") {
                $featureName = ($line -split '\|')[0].Trim()
                if ($featureName -match "IIS-") {
                    if ($findings -notcontains "Feature '$featureName' is ENABLED") {
                        $isCompliant = $false
                        $findings += "Feature '$featureName' is ENABLED (DISM)"
                        Write-Host "  [FAIL] $featureName is ENABLED (detected via DISM)" -ForegroundColor Red
                    }
                }
            }
        }
    }
}
catch {
    Write-Host "  [WARN] Could not perform DISM check: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Check for IIS service
Write-Host ""
Write-Host "Checking for IIS services..." -ForegroundColor Yellow

$iisServices = @("W3SVC", "WAS", "IISADMIN")

foreach ($service in $iisServices) {
    try {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        
        if ($svc) {
            $isCompliant = $false
            $findings += "Service '$service' exists (Status: $($svc.Status))"
            Write-Host "  [FAIL] Service '$service' exists - Status: $($svc.Status)" -ForegroundColor Red
        }
    }
    catch {
        # Service doesn't exist, which is what we want
        continue
    }
}

# Display Results
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "COMPLIANCE RESULTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($isCompliant) {
    Write-Host ""
    Write-Host "STATUS: COMPLIANT" -ForegroundColor Green
    Write-Host "No IIS components or services were found on this system." -ForegroundColor Green
    Write-Host ""
    exit 0
}
else {
    Write-Host ""
    Write-Host "STATUS: NON-COMPLIANT" -ForegroundColor Red
    Write-Host ""
    Write-Host "The following IIS components were found:" -ForegroundColor Red
    foreach ($finding in $findings) {
        Write-Host "  - $finding" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "ACTION REQUIRED: Run the remediation script to remove IIS components." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}