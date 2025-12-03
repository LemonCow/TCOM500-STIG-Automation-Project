<#
.SYNOPSIS
    Checks compliance with STIG WN11-00-000050 - NTFS file system requirement.

.DESCRIPTION
    Verifies that all local volumes with drive letters are formatted using NTFS.
    System partitions (Recovery, EFI System Partition) are excluded from the check.
    
    STIG ID: WN11-00-000050
    Severity: CAT I
    
.OUTPUTS
    Returns compliance status and details of any non-NTFS volumes.

.EXAMPLE
    .\Check-STIG-WN11-00-000050.ps1

.NOTES
    Excluded from check:
    - Recovery partitions
    - EFI System Partition
    - Volumes without drive letters
#>

[CmdletBinding()]
param()

# STIG Information
$STIG_ID = "WN11-00-000050"
$STIG_Title = "Local volumes must be formatted using NTFS"
$Severity = "CAT I"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "STIG Compliance Check" -ForegroundColor Cyan
Write-Host "STIG ID: $STIG_ID" -ForegroundColor Cyan
Write-Host "Title: $STIG_Title" -ForegroundColor Cyan
Write-Host "Severity: $Severity" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Requirement:" -ForegroundColor Yellow
Write-Host "  All local volumes with drive letters must use NTFS" -ForegroundColor Gray
Write-Host "  Exceptions: Recovery partitions, EFI System Partition" -ForegroundColor Gray
Write-Host ""

# Initialize compliance tracking
$isCompliant = $true
$nonCompliantVolumes = @()
$compliantVolumes = @()
$excludedVolumes = @()
$allVolumeDetails = @()

Write-Host "Scanning local volumes..." -ForegroundColor Yellow
Write-Host ""

try {
    # Get all volumes
    $volumes = Get-Volume | Where-Object { $null -ne $_.DriveLetter }
    
    if ($volumes.Count -eq 0) {
        Write-Host "  [WARN] No volumes with drive letters found" -ForegroundColor Yellow
        Write-Host ""
    }
    else {
        Write-Host "  Found $($volumes.Count) volume(s) with drive letters" -ForegroundColor Gray
        Write-Host ""
        
        foreach ($volume in $volumes) {
            $driveLetter = $volume.DriveLetter
            $fileSystem = $volume.FileSystem
            $label = if ($volume.FileSystemLabel) { $volume.FileSystemLabel } else { "(No Label)" }
            $sizeGB = [math]::Round($volume.Size / 1GB, 2)
            $driveType = $volume.DriveType
            
            # Get additional partition information
            $partition = Get-Partition -DriveLetter $driveLetter -ErrorAction SilentlyContinue
            $isSystemPartition = $false
            $isRecoveryPartition = $false
            $isEFIPartition = $false
            $partitionType = "Unknown"
            
            if ($partition) {
                $partitionType = $partition.Type
                $isSystemPartition = $partition.IsSystem
                $isRecoveryPartition = ($partitionType -eq "Recovery")
                $isEFIPartition = ($partitionType -eq "System") -or ($partitionType -like "*EFI*")
            }
            
            # Create volume detail object
            $volumeDetail = [PSCustomObject]@{
                DriveLetter = "${driveLetter}:"
                Label = $label
                FileSystem = $fileSystem
                SizeGB = $sizeGB
                DriveType = $driveType
                PartitionType = $partitionType
                IsSystem = $isSystemPartition
                IsRecovery = $isRecoveryPartition
                IsEFI = $isEFIPartition
                Status = ""
            }
            
            # Determine if this volume should be excluded
            $shouldExclude = $false
            $excludeReason = ""
            
            if ($isRecoveryPartition) {
                $shouldExclude = $true
                $excludeReason = "Recovery partition"
            }
            elseif ($isEFIPartition) {
                $shouldExclude = $true
                $excludeReason = "EFI System Partition"
            }
            elseif ($driveType -ne "Fixed") {
                # Only check fixed drives, not removable/network/etc
                $shouldExclude = $true
                $excludeReason = "Not a fixed drive (Type: $driveType)"
            }
            
            # Check compliance
            if ($shouldExclude) {
                $volumeDetail.Status = "Excluded - $excludeReason"
                $excludedVolumes += $volumeDetail
                
                Write-Host "  Drive $driveLetter`: " -ForegroundColor Gray -NoNewline
                Write-Host "$label " -ForegroundColor Gray -NoNewline
                Write-Host "[$fileSystem, $sizeGB GB]" -ForegroundColor Gray
                Write-Host "    Status: EXCLUDED - $excludeReason" -ForegroundColor Cyan
            }
            elseif ($fileSystem -eq "NTFS") {
                $volumeDetail.Status = "Compliant"
                $compliantVolumes += $volumeDetail
                
                Write-Host "  Drive $driveLetter`: " -ForegroundColor Green -NoNewline
                Write-Host "$label " -ForegroundColor Green -NoNewline
                Write-Host "[$fileSystem, $sizeGB GB]" -ForegroundColor Green
                Write-Host "    Status: COMPLIANT - NTFS" -ForegroundColor Green
            }
            else {
                $volumeDetail.Status = "Non-Compliant"
                $nonCompliantVolumes += $volumeDetail
                $isCompliant = $false
                
                Write-Host "  Drive $driveLetter`: " -ForegroundColor Red -NoNewline
                Write-Host "$label " -ForegroundColor Red -NoNewline
                Write-Host "[$fileSystem, $sizeGB GB]" -ForegroundColor Red
                Write-Host "    Status: NON-COMPLIANT - File system is $fileSystem (must be NTFS)" -ForegroundColor Red
            }
            
            $allVolumeDetails += $volumeDetail
            Write-Host ""
        }
    }
}
catch {
    Write-Host "  [ERROR] Exception occurred while scanning volumes: $($_.Exception.Message)" -ForegroundColor Red
    $isCompliant = $false
}

# Additional checks using WMI for comprehensive coverage
Write-Host "Performing additional verification using WMI..." -ForegroundColor Yellow

try {
    $logicalDisks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" # DriveType 3 = Local Disk
    
    foreach ($disk in $logicalDisks) {
        $driveLetter = $disk.DeviceID -replace ":", ""
        $existingVolume = $allVolumeDetails | Where-Object { $_.DriveLetter -eq $disk.DeviceID }
        
        if (-not $existingVolume) {
            Write-Host "  [INFO] Additional drive found via WMI: $($disk.DeviceID)" -ForegroundColor Cyan
            
            $wmiFileSystem = $disk.FileSystem
            $wmiLabel = if ($disk.VolumeName) { $disk.VolumeName } else { "(No Label)" }
            $wmiSizeGB = [math]::Round($disk.Size / 1GB, 2)
            
            Write-Host "        Label: $wmiLabel, FileSystem: $wmiFileSystem, Size: $wmiSizeGB GB" -ForegroundColor Cyan
            
            if ($wmiFileSystem -ne "NTFS") {
                $isCompliant = $false
                Write-Host "        [FAIL] Non-NTFS file system detected" -ForegroundColor Red
                
                $nonCompliantVolumes += [PSCustomObject]@{
                    DriveLetter = $disk.DeviceID
                    Label = $wmiLabel
                    FileSystem = $wmiFileSystem
                    SizeGB = $wmiSizeGB
                    DriveType = "Fixed"
                    Status = "Non-Compliant (WMI)"
                }
            }
        }
    }
}
catch {
    Write-Host "  [WARN] Could not perform WMI check: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""

# Display Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "VOLUME SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($compliantVolumes.Count -gt 0) {
    Write-Host "Compliant Volumes ($($compliantVolumes.Count)):" -ForegroundColor Green
    foreach ($vol in $compliantVolumes) {
        Write-Host "  $($vol.DriveLetter) - $($vol.Label) [$($vol.FileSystem), $($vol.SizeGB) GB]" -ForegroundColor Green
    }
    Write-Host ""
}

if ($excludedVolumes.Count -gt 0) {
    Write-Host "Excluded Volumes ($($excludedVolumes.Count)):" -ForegroundColor Cyan
    foreach ($vol in $excludedVolumes) {
        Write-Host "  $($vol.DriveLetter) - $($vol.Label) [$($vol.FileSystem), $($vol.SizeGB) GB]" -ForegroundColor Cyan
        Write-Host "    Reason: $($vol.Status)" -ForegroundColor Gray
    }
    Write-Host ""
}

if ($nonCompliantVolumes.Count -gt 0) {
    Write-Host "Non-Compliant Volumes ($($nonCompliantVolumes.Count)):" -ForegroundColor Red
    foreach ($vol in $nonCompliantVolumes) {
        Write-Host "  $($vol.DriveLetter) - $($vol.Label) [$($vol.FileSystem), $($vol.SizeGB) GB]" -ForegroundColor Red
        Write-Host "    Issue: File system is $($vol.FileSystem), must be NTFS" -ForegroundColor Red
    }
    Write-Host ""
}

# Display Results
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "COMPLIANCE RESULTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($isCompliant) {
    Write-Host "STATUS: COMPLIANT" -ForegroundColor Green
    Write-Host ""
    Write-Host "All local volumes with drive letters are formatted using NTFS." -ForegroundColor Green
    Write-Host ""
    Write-Host "Security Benefits:" -ForegroundColor Green
    Write-Host "  - File and folder level permissions (ACLs) are supported" -ForegroundColor Green
    Write-Host "  - File system auditing is available" -ForegroundColor Green
    Write-Host "  - Encryption (EFS/BitLocker) is supported" -ForegroundColor Green
    Write-Host "  - Advanced security features are enabled" -ForegroundColor Green
    Write-Host ""
}
else {
    Write-Host "STATUS: NON-COMPLIANT" -ForegroundColor Red
    Write-Host ""
    Write-Host "Finding:" -ForegroundColor Red
    Write-Host "  One or more local volumes are not formatted using NTFS" -ForegroundColor Red
    Write-Host ""
    Write-Host "Non-Compliant Volumes:" -ForegroundColor Red
    foreach ($vol in $nonCompliantVolumes) {
        Write-Host "  - $($vol.DriveLetter) [$($vol.FileSystem)]" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "Security Risk:" -ForegroundColor Yellow
    Write-Host "  - Cannot set file and folder level permissions" -ForegroundColor Yellow
    Write-Host "  - File system auditing not available" -ForegroundColor Yellow
    Write-Host "  - Reduced access control capabilities" -ForegroundColor Yellow
    Write-Host "  - Does not meet NIST SP 800-53 AC-3 requirements" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "WARNING: Converting file systems requires data backup!" -ForegroundColor Red
    Write-Host "         Review the remediation script carefully before use." -ForegroundColor Red
    Write-Host ""
}

# Create a compliance report object
$complianceReport = [PSCustomObject]@{
    STIG_ID = $STIG_ID
    Title = $STIG_Title
    Severity = $Severity
    Status = if ($isCompliant) { "Compliant" } else { "Non-Compliant" }
    TotalVolumes = $allVolumeDetails.Count
    CompliantVolumes = $compliantVolumes.Count
    NonCompliantVolumes = $nonCompliantVolumes.Count
    ExcludedVolumes = $excludedVolumes.Count
    NonCompliantDetails = $nonCompliantVolumes
    CompliantDetails = $compliantVolumes
    ExcludedDetails = $excludedVolumes
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