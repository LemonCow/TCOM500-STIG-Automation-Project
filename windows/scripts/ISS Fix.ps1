<#
.SYNOPSIS
    Remediates STIG WN11-00-000100 - Removes IIS from workstation.

.DESCRIPTION
    Uninstalls Internet Information Services (IIS) and IIS Hostable Web Core 
    from Windows 11 workstation to achieve compliance with STIG WN11-00-000100.
    
    STIG ID: WN11-00-000100
    Severity: CAT I
    
.PARAMETER Force
    Skip confirmation prompts and force removal of IIS components.

.PARAMETER CreateBackup
    Creates a backup of IIS configuration before removal (if IIS is installed).

.EXAMPLE
    .\Remediate-STIG-WN11-00-000100.ps1
    
.EXAMPLE
    .\Remediate-STIG-WN11-00-000100.ps1 -Force

.EXAMPLE
    .\Remediate-STIG-WN11-00-000100.ps1 -Force -CreateBackup

.NOTES
    Requires Administrator privileges.
    A system restart may be required after removal.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateBackup
)

# STIG Information
$STIG_ID = "WN11-00-000100"
$STIG_Title = "Internet Information System (IIS) or its subcomponents must not be installed on a workstation"
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

# Warning message
Write-Host "WARNING: This script will remove IIS and all its components from this system." -ForegroundColor Yellow
Write-Host "This action may affect applications that depend on IIS." -ForegroundColor Yellow
Write-Host ""

if (-not $Force) {
    $confirmation = Read-Host "Do you want to continue? (yes/no)"
    if ($confirmation -ne "yes") {
        Write-Host "Remediation cancelled by user." -ForegroundColor Yellow
        exit 0
    }
}

# Initialize tracking
$removedFeatures = @()
$failedRemovals = @()
$stoppedServices = @()

# Backup IIS configuration if requested
if ($CreateBackup) {
    Write-Host "Creating backup of IIS configuration..." -ForegroundColor Yellow
    
    $backupPath = "$env:TEMP\IIS_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    
    try {
        New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
        
        # Backup applicationHost.config if it exists
        $configPath = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"
        if (Test-Path $configPath) {
            Copy-Item -Path $configPath -Destination "$backupPath\applicationHost.config" -Force
            Write-Host "  [OK] Configuration backed up to: $backupPath" -ForegroundColor Green
        }
        
        # Backup web.config files from wwwroot if they exist
        $wwwrootPath = "$env:SystemDrive\inetpub\wwwroot"
        if (Test-Path $wwwrootPath) {
            Copy-Item -Path $wwwrootPath -Destination "$backupPath\wwwroot" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Host "  [WARN] Could not create backup: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-Host ""
}

# Stop IIS services first
Write-Host "Stopping IIS services..." -ForegroundColor Yellow

$iisServices = @("W3SVC", "WAS", "IISADMIN", "FTPSVC")

foreach ($serviceName in $iisServices) {
    try {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        
        if ($service) {
            if ($service.Status -eq "Running") {
                Stop-Service -Name $serviceName -Force -ErrorAction Stop
                $stoppedServices += $serviceName
                Write-Host "  [OK] Stopped service: $serviceName" -ForegroundColor Green
            }
            else {
                Write-Host "  [INFO] Service $serviceName is already stopped" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "  [WARN] Could not stop service $serviceName : $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ""

# Get all IIS features
Write-Host "Identifying IIS features to remove..." -ForegroundColor Yellow

$allIISFeatures = @()

try {
    $installedFeatures = Get-WindowsOptionalFeature -Online | Where-Object { 
        $_.FeatureName -like "IIS-*" -and $_.State -eq "Enabled" 
    }
    
    foreach ($feature in $installedFeatures) {
        $allIISFeatures += $feature.FeatureName
    }
    
    if ($allIISFeatures.Count -gt 0) {
        Write-Host "  Found $($allIISFeatures.Count) IIS feature(s) to remove" -ForegroundColor Yellow
    }
    else {
        Write-Host "  No enabled IIS features found" -ForegroundColor Green
    }
}
catch {
    Write-Host "  [ERROR] Could not enumerate features: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""

# Remove IIS features
if ($allIISFeatures.Count -gt 0) {
    Write-Host "Removing IIS features..." -ForegroundColor Yellow
    Write-Host "This may take several minutes..." -ForegroundColor Yellow
    Write-Host ""
    
    # Remove features in reverse dependency order (remove child features first)
    # Core features should be removed last
    $priorityOrder = @(
        "IIS-FTPExtensibility",
        "IIS-FTPSvc",
        "IIS-FTPServer",
        "IIS-LegacySnapIn",
        "IIS-LegacyScripts",
        "IIS-WMICompatibility",
        "IIS-ManagementService",
        "IIS-ManagementConsole",
        "IIS-ManagementScriptingTools",
        "IIS-WebServerManagementTools",
        "IIS-IIS6ManagementCompatibility",
        "IIS-Metabase"
    )
    
    # Sort features: priority items first, then everything else
    $sortedFeatures = @()
    foreach ($priority in $priorityOrder) {
        if ($allIISFeatures -contains $priority) {
            $sortedFeatures += $priority
        }
    }
    foreach ($feature in $allIISFeatures) {
        if ($sortedFeatures -notcontains $feature) {
            $sortedFeatures += $feature
        }
    }
    
    foreach ($featureName in $sortedFeatures) {
        try {
            Write-Host "  Removing: $featureName..." -ForegroundColor Yellow -NoNewline
            
            $result = Disable-WindowsOptionalFeature -Online -FeatureName $featureName -NoRestart -ErrorAction Stop
            
            if ($result.RestartNeeded) {
                $script:restartNeeded = $true
            }
            
            $removedFeatures += $featureName
            Write-Host " [OK]" -ForegroundColor Green
        }
        catch {
            $failedRemovals += "$featureName : $($_.Exception.Message)"
            Write-Host " [FAILED]" -ForegroundColor Red
            Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    Write-Host ""
}

# Additional cleanup - remove IIS directories if they exist and are empty
Write-Host "Performing additional cleanup..." -ForegroundColor Yellow

$iisDirectories = @(
    "$env:SystemDrive\inetpub\logs\LogFiles",
    "$env:SystemDrive\inetpub\logs",
    "$env:SystemDrive\inetpub\temp",
    "$env:SystemDrive\inetpub\wwwroot",
    "$env:SystemDrive\inetpub"
)

foreach ($dir in $iisDirectories) {
    if (Test-Path $dir) {
        try {
            $items = Get-ChildItem -Path $dir -Force -ErrorAction SilentlyContinue
            if ($items.Count -eq 0) {
                Remove-Item -Path $dir -Force -Recurse -ErrorAction Stop
                Write-Host "  [OK] Removed empty directory: $dir" -ForegroundColor Green
            }
            else {
                Write-Host "  [INFO] Directory not empty, skipping: $dir" -ForegroundColor Gray
            }
        }
        catch {
            Write-Host "  [WARN] Could not remove directory $dir : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

Write-Host ""

# Display Results
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "REMEDIATION RESULTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($removedFeatures.Count -gt 0) {
    Write-Host "Successfully removed $($removedFeatures.Count) IIS feature(s):" -ForegroundColor Green
    foreach ($feature in $removedFeatures) {
        Write-Host "  - $feature" -ForegroundColor Green
    }
    Write-Host ""
}

if ($stoppedServices.Count -gt 0) {
    Write-Host "Stopped $($stoppedServices.Count) IIS service(s):" -ForegroundColor Green
    foreach ($service in $stoppedServices) {
        Write-Host "  - $service" -ForegroundColor Green
    }
    Write-Host ""
}

if ($failedRemovals.Count -gt 0) {
    Write-Host "Failed to remove $($failedRemovals.Count) feature(s):" -ForegroundColor Red
    foreach ($failure in $failedRemovals) {
        Write-Host "  - $failure" -ForegroundColor Red
    }
    Write-Host ""
}

if ($script:restartNeeded) {
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "RESTART REQUIRED" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "A system restart is required to complete the removal of IIS components." -ForegroundColor Yellow
    Write-Host ""
    
    if ($Force) {
        $restart = Read-Host "Restart now? (yes/no)"
        if ($restart -eq "yes") {
            Write-Host "Restarting system in 10 seconds..." -ForegroundColor Yellow
            shutdown /r /t 10 /c "System restart required to complete STIG remediation WN11-00-000100"
        }
    }
    else {
        Write-Host "Please restart your system to complete the remediation." -ForegroundColor Yellow
    }
}
else {
    Write-Host "Remediation completed successfully." -ForegroundColor Green
    Write-Host "No restart is required." -ForegroundColor Green
}

Write-Host ""

if ($removedFeatures.Count -gt 0 -or $allIISFeatures.Count -eq 0) {
    exit 0
}
else {
    exit 1
}