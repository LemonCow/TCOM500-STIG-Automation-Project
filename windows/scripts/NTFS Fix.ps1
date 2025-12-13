<#
.SYNOPSIS
    Remediates STIG WN11-00-000050 - Converts volumes to NTFS.

.DESCRIPTION
    Converts non-NTFS volumes to NTFS file system to achieve compliance with 
    STIG WN11-00-000050. This script provides information and guidance for conversion.
    
    STIG ID: WN11-00-000050
    Severity: CAT I
    
.PARAMETER DriveLetter
    The drive letter to convert (e.g., "D"). If not specified, will display options.

.PARAMETER Force
    Skip confirmation prompts (USE WITH EXTREME CAUTION).

.PARAMETER QuickFormat
    Use quick format for conversion (faster but less thorough).

.EXAMPLE
    .\Remediate-STIG-WN11-00-000050.ps1
    
.EXAMPLE
    .\Remediate-STIG-WN11-00-000050.ps1 -DriveLetter D

.NOTES
    WARNING: Converting file systems can result in DATA LOSS.
    ALWAYS backup data before attempting conversion.
    
    This script uses the CONVERT.EXE utility for FAT/FAT32 to NTFS conversion.
    For other file systems, a format operation is required which WILL DELETE ALL DATA.
    
    Requires Administrator privileges.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [ValidatePattern('^[A-Za-z]$')]
    [string]$DriveLetter,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$QuickFormat
)

# STIG Information
$STIG_ID = "WN11-00-000050"
$STIG_Title = "Local volumes must be formatted using NTFS"
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

Write-Host "WARNING: FILE SYSTEM CONVERSION IS A CRITICAL OPERATION" -ForegroundColor Red -BackgroundColor Black
Write-Host "========================================" -ForegroundColor Red
Write-Host "This script assists with converting volumes to NTFS." -ForegroundColor Yellow
Write-Host ""
Write-Host "IMPORTANT:" -ForegroundColor Yellow
Write-Host "  - ALWAYS backup your data before conversion" -ForegroundColor Yellow
Write-Host "  - FAT/FAT32 can be converted without data loss (using CONVERT.EXE)" -ForegroundColor Yellow
Write-Host "  - Other file systems require formatting (DATA WILL BE DELETED)" -ForegroundColor Yellow
Write-Host "  - Ensure adequate free space for conversion" -ForegroundColor Yellow
Write-Host "  - Close all applications accessing the drive" -ForegroundColor Yellow
Write-Host ""

# Scan for non-NTFS volumes
Write-Host "Scanning for non-NTFS volumes..." -ForegroundColor Cyan
Write-Host ""

$nonNTFSVolumes = @()

try {
    $volumes = Get-Volume | Where-Object { 
        $null -ne $_.DriveLetter -and 
        $_.FileSystem -ne "NTFS" -and 
        $_.DriveType -eq "Fixed"
    }
    
    foreach ($volume in $volumes) {
        $driveLetter = $volume.DriveLetter
        $partition = Get-Partition -DriveLetter $driveLetter -ErrorAction SilentlyContinue
        
        # Exclude system partitions
        if ($partition) {
            $isRecovery = ($partition.Type -eq "Recovery")
            $isEFI = ($partition.Type -eq "System") -or ($partition.Type -like "*EFI*")
            
            if (-not $isRecovery -and -not $isEFI) {
                $nonNTFSVolumes += [PSCustomObject]@{
                    DriveLetter = $driveLetter
                    Label = if ($volume.FileSystemLabel) { $volume.FileSystemLabel } else { "(No Label)" }
                    FileSystem = $volume.FileSystem
                    SizeGB = [math]::Round($volume.Size / 1GB, 2)
                    FreeGB = [math]::Round($volume.SizeRemaining / 1GB, 2)
                    CanConvert = ($volume.FileSystem -in @("FAT", "FAT32"))
                    RequiresFormat = ($volume.FileSystem -notin @("FAT", "FAT32", "NTFS"))
                }
            }
        }
    }
}
catch {
    Write-Host "ERROR: Failed to scan volumes: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if ($nonNTFSVolumes.Count -eq 0) {
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "NO ACTION REQUIRED" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "All local volumes are already formatted with NTFS." -ForegroundColor Green
    Write-Host "The system is compliant with STIG $STIG_ID." -ForegroundColor Green
    Write-Host ""
    exit 0
}

# Display non-NTFS volumes
Write-Host "Non-NTFS Volumes Found:" -ForegroundColor Yellow
Write-Host ""

$volumeTable = $nonNTFSVolumes | Format-Table -Property `
    @{Label="Drive"; Expression={"$($_.DriveLetter):"}},
    @{Label="Label"; Expression={$_.Label}},
    @{Label="File System"; Expression={$_.FileSystem}},
    @{Label="Size (GB)"; Expression={$_.SizeGB}},
    @{Label="Free (GB)"; Expression={$_.FreeGB}},
    @{Label="Conversion Method"; Expression={
        if ($_.CanConvert) { "CONVERT (No data loss)" }
        elseif ($_.RequiresFormat) { "FORMAT (DATA LOSS!)" }
        else { "Unknown" }
    }} -AutoSize | Out-String

Write-Host $volumeTable

# If no drive letter specified, prompt user
if (-not $DriveLetter) {
    Write-Host ""
    Write-Host "Please specify which drive to convert using the -DriveLetter parameter." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Example: .\Remediate-STIG-WN11-00-000050.ps1 -DriveLetter D" -ForegroundColor Cyan
    Write-Host ""
    
    if ($nonNTFSVolumes.Count -eq 1) {
        $singleDrive = $nonNTFSVolumes[0].DriveLetter
        Write-Host "Only one non-NTFS drive found: ${singleDrive}:" -ForegroundColor Cyan
        
        if (-not $Force) {
            $response = Read-Host "Convert drive ${singleDrive}: to NTFS? (yes/no)"
            if ($response -eq "yes") {
                $DriveLetter = $singleDrive
            }
            else {
                Write-Host "Operation cancelled." -ForegroundColor Yellow
                exit 0
            }
        }
    }
    else {
        exit 0
    }
}

# Validate the specified drive letter
$DriveLetter = $DriveLetter.ToUpper()
$targetVolume = $nonNTFSVolumes | Where-Object { $_.DriveLetter -eq $DriveLetter }

if (-not $targetVolume) {
    Write-Host "ERROR: Drive ${DriveLetter}: is either already NTFS, not found, or excluded from conversion." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CONVERSION DETAILS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Drive Letter: ${DriveLetter}:" -ForegroundColor White
Write-Host "  Volume Label: $($targetVolume.Label)" -ForegroundColor White
Write-Host "  Current File System: $($targetVolume.FileSystem)" -ForegroundColor White
Write-Host "  Size: $($targetVolume.SizeGB) GB" -ForegroundColor White
Write-Host "  Free Space: $($targetVolume.FreeGB) GB" -ForegroundColor White
Write-Host ""

# Determine conversion method
if ($targetVolume.CanConvert) {
    Write-Host "  Conversion Method: CONVERT.EXE (preserves data)" -ForegroundColor Green
    Write-Host "  Data Loss Risk: LOW (but backup recommended)" -ForegroundColor Green
    $conversionMethod = "CONVERT"
}
elseif ($targetVolume.RequiresFormat) {
    Write-Host "  Conversion Method: FORMAT (DELETES ALL DATA)" -ForegroundColor Red
    Write-Host "  Data Loss Risk: CERTAIN - ALL DATA WILL BE LOST" -ForegroundColor Red
    $conversionMethod = "FORMAT"
}
else {
    Write-Host "  ERROR: Cannot determine conversion method for file system: $($targetVolume.FileSystem)" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Final confirmation
if (-not $Force) {
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "FINAL CONFIRMATION REQUIRED" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""
    
    if ($conversionMethod -eq "FORMAT") {
        Write-Host "WARNING: This operation will FORMAT drive ${DriveLetter}: and DELETE ALL DATA!" -ForegroundColor Red -BackgroundColor Black
        Write-Host ""
        Write-Host "Have you backed up all data on this drive? (yes/no): " -ForegroundColor Yellow -NoNewline
        $backupConfirm = Read-Host
        
        if ($backupConfirm -ne "yes") {
            Write-Host ""
            Write-Host "Operation cancelled. Please backup your data first." -ForegroundColor Yellow
            exit 0
        }
        
        Write-Host ""
        Write-Host "Type 'DELETE ALL DATA' to confirm formatting: " -ForegroundColor Red -NoNewline
        $deleteConfirm = Read-Host
        
        if ($deleteConfirm -ne "DELETE ALL DATA") {
            Write-Host ""
            Write-Host "Confirmation failed. Operation cancelled." -ForegroundColor Yellow
            exit 0
        }
    }
    else {
        Write-Host "Have you backed up your data? (yes/no): " -ForegroundColor Yellow -NoNewline
        $backupConfirm = Read-Host
        
        if ($backupConfirm -ne "yes") {
            Write-Host ""
            Write-Host "Operation cancelled. Please backup your data first." -ForegroundColor Yellow
            exit 0
        }
        
        Write-Host ""
        Write-Host "Proceed with conversion of drive ${DriveLetter}: to NTFS? (yes/no): " -ForegroundColor Yellow -NoNewline
        $proceedConfirm = Read-Host
        
        if ($proceedConfirm -ne "yes") {
            Write-Host ""
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            exit 0
        }
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "STARTING CONVERSION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$conversionSuccess = $false
$conversionError = $null

try {
    if ($conversionMethod -eq "CONVERT") {
        Write-Host "Converting drive ${DriveLetter}: from $($targetVolume.FileSystem) to NTFS..." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Note: The drive may need to be dismounted. Conversion may complete on next restart." -ForegroundColor Cyan
        Write-Host ""
        
        # Build convert command
        $convertArgs = "${DriveLetter}: /FS:NTFS /V"
        
        Write-Host "Executing: CONVERT.EXE $convertArgs" -ForegroundColor Gray
        Write-Host ""
        
        # Execute convert command
        $convertProcess = Start-Process -FilePath "CONVERT.EXE" -ArgumentList $convertArgs -Wait -NoNewWindow -PassThru
        
        if ($convertProcess.ExitCode -eq 0) {
            Write-Host ""
            Write-Host "[OK] Conversion completed successfully" -ForegroundColor Green
            $conversionSuccess = $true
        }
        elseif ($convertProcess.ExitCode -eq 2) {
            Write-Host ""
            Write-Host "[INFO] Conversion scheduled for next restart" -ForegroundColor Cyan
            Write-Host "       Please restart the system to complete conversion" -ForegroundColor Cyan
            $conversionSuccess = $true
        }
        else {
            $conversionError = "CONVERT.EXE exited with code: $($convertProcess.ExitCode)"
            Write-Host ""
            Write-Host "[ERROR] Conversion failed" -ForegroundColor Red
        }
    }
    elseif ($conversionMethod -eq "FORMAT") {
        Write-Host "Formatting drive ${DriveLetter}: with NTFS file system..." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "WARNING: ALL DATA ON THIS DRIVE WILL BE DELETED!" -ForegroundColor Red
        Write-Host ""
        
        Start-Sleep -Seconds 3
        
        # Format the volume
        $formatParams = @{
            DriveLetter = $DriveLetter
            FileSystem = "NTFS"
            Confirm = $false
            Force = $true
        }
        
        if ($QuickFormat) {
            $formatParams.Add("Quick", $true)
            Write-Host "Using quick format..." -ForegroundColor Gray
        }
        else {
            Write-Host "Using full format (this may take a while)..." -ForegroundColor Gray
        }
        
        if ($targetVolume.Label -ne "(No Label)") {
            $formatParams.Add("NewFileSystemLabel", $targetVolume.Label)
        }
        
        Write-Host ""
        Format-Volume @formatParams | Out-Null
        
        # Verify the format
        Start-Sleep -Seconds 2
        $verifyVolume = Get-Volume -DriveLetter $DriveLetter
        
        if ($verifyVolume.FileSystem -eq "NTFS") {
            Write-Host ""
            Write-Host "[OK] Format completed successfully" -ForegroundColor Green
            $conversionSuccess = $true
        }
        else {
            $conversionError = "Volume still shows file system as: $($verifyVolume.FileSystem)"
            Write-Host ""
            Write-Host "[ERROR] Format verification failed" -ForegroundColor Red
        }
    }
}
catch {
    $conversionError = $_.Exception.Message
    Write-Host ""
    Write-Host "[ERROR] Exception occurred: $conversionError" -ForegroundColor Red
}

Write-Host ""

# Display Results
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "REMEDIATION RESULTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($conversionSuccess) {
    Write-Host "STATUS: SUCCESSFUL" -ForegroundColor Green
    Write-Host ""
    Write-Host "Drive ${DriveLetter}: has been converted to NTFS" -ForegroundColor Green
    Write-Host ""
    
    # Verify current state
    try {
        $verifyVolume = Get-Volume -DriveLetter $DriveLetter
        
        Write-Host "Current Configuration:" -ForegroundColor Green
        Write-Host "  Drive Letter: ${DriveLetter}:" -ForegroundColor Green
        Write-Host "  File System: $($verifyVolume.FileSystem)" -ForegroundColor Green
        Write-Host "  Health Status: $($verifyVolume.HealthStatus)" -ForegroundColor Green
        Write-Host ""
    }
    catch {
        Write-Host "  Could not verify current state, but conversion appeared successful" -ForegroundColor Yellow
        Write-Host ""
    }
    
    Write-Host "Security Benefits:" -ForegroundColor Green
    Write-Host "  - File and folder level permissions (ACLs) are now supported" -ForegroundColor Green
    Write-Host "  - File system auditing is now available" -ForegroundColor Green
    Write-Host "  - Encryption (EFS/BitLocker) is now supported" -ForegroundColor Green
    Write-Host "  - Advanced security features are now enabled" -ForegroundColor Green
    Write-Host "  - Compliant with NIST SP 800-53 AC-3" -ForegroundColor Green
    Write-Host ""
    
    if ($conversionMethod -eq "CONVERT") {
        Write-Host "Next Steps:" -ForegroundColor Cyan
        Write-Host "  - Verify all files are accessible" -ForegroundColor Cyan
        Write-Host "  - Check application functionality" -ForegroundColor Cyan
        Write-Host "  - If conversion was scheduled for restart, reboot the system" -ForegroundColor Cyan
        Write-Host ""
    }
    
    # Check if there are more non-NTFS volumes
    $remainingNonNTFS = $nonNTFSVolumes | Where-Object { $_.DriveLetter -ne $DriveLetter }
    
    if ($remainingNonNTFS.Count -gt 0) {
        Write-Host "Remaining Non-NTFS Volumes:" -ForegroundColor Yellow
        foreach ($vol in $remainingNonNTFS) {
            Write-Host "  $($vol.DriveLetter): [$($vol.FileSystem)]" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "Run this script again to convert additional volumes." -ForegroundColor Yellow
        Write-Host ""
    }
    else {
        Write-Host "All local volumes are now using NTFS." -ForegroundColor Green
        Write-Host "System is compliant with STIG $STIG_ID." -ForegroundColor Green
        Write-Host ""
    }
    
    # Create remediation report
    $remediationReport = [PSCustomObject]@{
        STIG_ID = $STIG_ID
        Title = $STIG_Title
        Severity = $Severity
        Status = "Remediated"
        DriveLetter = "${DriveLetter}:"
        PreviousFileSystem = $targetVolume.FileSystem
        NewFileSystem = "NTFS"
        ConversionMethod = $conversionMethod
        RemediationDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    Write-Output $remediationReport
    exit 0
}
else {
    Write-Host "STATUS: FAILED" -ForegroundColor Red
    Write-Host ""
    Write-Host "Conversion of drive ${DriveLetter}: could not be completed." -ForegroundColor Red
    Write-Host "Error: $conversionError" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting Steps:" -ForegroundColor Yellow
    Write-Host "  1. Ensure you are running PowerShell as Administrator" -ForegroundColor Yellow
    Write-Host "  2. Close all applications accessing the drive" -ForegroundColor Yellow
    Write-Host "  3. Check for file locks using Resource Monitor" -ForegroundColor Yellow
    Write-Host "  4. Verify adequate free space on the drive" -ForegroundColor Yellow
    Write-Host "  5. Check the drive for errors using CHKDSK" -ForegroundColor Yellow
    Write-Host "  6. Review Windows Event Logs for disk errors" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Manual Conversion (FAT/FAT32 to NTFS):" -ForegroundColor Yellow
    Write-Host "  1. Open Command Prompt as Administrator" -ForegroundColor Yellow
    Write-Host "  2. Run: CONVERT ${DriveLetter}: /FS:NTFS" -ForegroundColor Yellow
    Write-Host "  3. Follow the prompts" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Manual Formatting (Other File Systems):" -ForegroundColor Yellow
    Write-Host "  1. Backup ALL data from the drive" -ForegroundColor Yellow
    Write-Host "  2. Open Disk Management (diskmgmt.msc)" -ForegroundColor Yellow
    Write-Host "  3. Right-click the volume" -ForegroundColor Yellow
    Write-Host "  4. Select 'Format...'" -ForegroundColor Yellow
    Write-Host "  5. Choose 'NTFS' as the file system" -ForegroundColor Yellow
    Write-Host "  6. Complete the format" -ForegroundColor Yellow
    Write-Host ""
    
    exit 1
}