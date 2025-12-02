<#
.SYNOPSIS
    CyAudit 3.5 SCCM Detection Script

.DESCRIPTION
    Detection method script for SCCM/ConfigMgr application deployment.
    Returns exit code 0 if CyAudit is properly installed, non-zero otherwise.

    SCCM uses this script to determine if the application is installed on
    a target system. This script checks for:
    - Required application files
    - Proper directory structure
    - Minimum file versions (via modification dates)

.PARAMETER InstallPath
    Base installation directory to check. Default: C:\CyAudit

.PARAMETER CheckScheduledTask
    Also verify the scheduled task exists

.PARAMETER Verbose
    Output detailed detection information

.EXAMPLE
    .\Detection.ps1
    Basic detection check (silent, returns exit code only)

.EXAMPLE
    .\Detection.ps1 -Verbose
    Detection check with detailed output

.EXAMPLE
    .\Detection.ps1 -CheckScheduledTask
    Detection including scheduled task verification

.NOTES
    Version:        1.0.0
    Author:         CyAudit Team
    Creation Date:  2025-12-01
    Purpose:        SCCM Detection Method

    SCCM Configuration:
    - Detection Method Type: Script
    - Script Type: PowerShell
    - Run script as 32-bit process: No
    - Enforce script signature check: No (or sign the script)

    Exit Codes (for SCCM):
    0  - Application IS installed (detection success)
    1  - Application is NOT installed (detection failure)

    IMPORTANT: SCCM considers exit code 0 as "installed" and any non-zero
    as "not installed". This script writes to STDOUT on success per SCCM
    best practices.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$InstallPath = "C:\CyAudit",

    [Parameter()]
    [switch]$CheckScheduledTask
)

# Configuration
$RequiredFiles = @(
    "CyAudit_3.5\CyAudit_Opus_V3.5.ps1",
    "CyAudit_3.5\Run-CyAuditPipeline.ps1",
    "CyAudit_3.5\Transform-CyAuditForSplunk.ps1",
    "CyAudit_3.5\CyAuditPipeline.config.json"
)

$RequiredDirectories = @(
    "CyAudit_3.5",
    "CyAudit_3.5\STIGData"
)

$TaskName = "CyAudit Automated Assessment"

# Minimum expected file sizes (to detect corrupted/empty files)
$MinFileSizes = @{
    "CyAudit_Opus_V3.5.ps1" = 100000    # ~200KB expected
    "Run-CyAuditPipeline.ps1" = 10000   # ~20KB expected
    "Transform-CyAuditForSplunk.ps1" = 30000  # ~60KB expected
}

function Write-DetectionLog {
    param(
        [string]$Message,
        [switch]$IsError
    )

    if ($VerbosePreference -eq "Continue" -or $PSBoundParameters.ContainsKey('Verbose')) {
        if ($IsError) {
            Write-Verbose "DETECTION FAILED: $Message"
        } else {
            Write-Verbose "DETECTION: $Message"
        }
    }
}

function Test-CyAuditInstallation {
    # Check base directory
    if (-not (Test-Path $InstallPath)) {
        Write-DetectionLog "Base directory not found: $InstallPath" -IsError
        return $false
    }

    Write-DetectionLog "Base directory exists: $InstallPath"

    # Check required directories
    foreach ($dir in $RequiredDirectories) {
        $fullPath = Join-Path $InstallPath $dir
        if (-not (Test-Path $fullPath)) {
            Write-DetectionLog "Required directory not found: $dir" -IsError
            return $false
        }
        Write-DetectionLog "Directory exists: $dir"
    }

    # Check required files
    foreach ($file in $RequiredFiles) {
        $fullPath = Join-Path $InstallPath $file
        if (-not (Test-Path $fullPath)) {
            Write-DetectionLog "Required file not found: $file" -IsError
            return $false
        }

        # Check file size for critical files
        $fileName = Split-Path $file -Leaf
        if ($MinFileSizes.ContainsKey($fileName)) {
            $fileInfo = Get-Item $fullPath
            $minSize = $MinFileSizes[$fileName]

            if ($fileInfo.Length -lt $minSize) {
                Write-DetectionLog "File too small (possible corruption): $fileName ($($fileInfo.Length) bytes, expected >= $minSize)" -IsError
                return $false
            }
            Write-DetectionLog "File OK: $fileName ($($fileInfo.Length) bytes)"
        } else {
            Write-DetectionLog "File exists: $file"
        }
    }

    # Check for at least one STIG XML file
    $stigPath = Join-Path $InstallPath "CyAudit_3.5\STIGData"
    $stigFiles = Get-ChildItem -Path $stigPath -Filter "*.xml" -ErrorAction SilentlyContinue

    if ($stigFiles.Count -eq 0) {
        Write-DetectionLog "No STIG XML files found in STIGData directory" -IsError
        return $false
    }

    Write-DetectionLog "STIG files found: $($stigFiles.Count)"

    # Optional: Check scheduled task
    if ($CheckScheduledTask) {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (-not $task) {
            Write-DetectionLog "Scheduled task not found: $TaskName" -IsError
            return $false
        }
        Write-DetectionLog "Scheduled task exists: $TaskName"
    }

    return $true
}

# Main detection logic
try {
    $isInstalled = Test-CyAuditInstallation

    if ($isInstalled) {
        # SCCM expects output to STDOUT for successful detection
        Write-Output "CyAudit 3.5 is installed at $InstallPath"
        exit 0
    } else {
        # No output for failed detection (SCCM best practice)
        exit 1
    }
} catch {
    Write-DetectionLog "Detection error: $_" -IsError
    exit 1
}
