<#
.SYNOPSIS
    CyAudit 3.5 Enterprise Uninstallation Script

.DESCRIPTION
    Removes CyAudit 3.5 security assessment framework from the system.
    Handles:
    - Scheduled task removal
    - Application file removal
    - Optional: Assessment data preservation or removal
    - Optional: Log file preservation or removal

.PARAMETER InstallPath
    Base installation directory. Default: C:\CyAudit

.PARAMETER KeepData
    Preserve assessment data and logs (removes only application files)

.PARAMETER KeepLogs
    Preserve log files only

.PARAMETER Force
    Skip confirmation prompts (for silent uninstallation)

.EXAMPLE
    .\Uninstall-CyAudit.ps1
    Interactive uninstallation with confirmation

.EXAMPLE
    .\Uninstall-CyAudit.ps1 -Force
    Silent uninstallation (SCCM deployment)

.EXAMPLE
    .\Uninstall-CyAudit.ps1 -KeepData
    Remove application but preserve assessment data and logs

.EXAMPLE
    .\Uninstall-CyAudit.ps1 -InstallPath "D:\Security\CyAudit" -Force
    Silent removal from custom path

.NOTES
    Version:        1.0.0
    Author:         CyAudit Team
    Creation Date:  2025-12-01
    Purpose:        SCCM/Enterprise Uninstallation

    Requirements:
    - PowerShell 5.1 or later
    - Administrator privileges

    Exit Codes:
    0 - Success
    1 - Not running as administrator
    2 - User cancelled
    3 - Failed to remove scheduled task
    4 - Failed to remove files
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$InstallPath = "C:\CyAudit",

    [Parameter()]
    [switch]$KeepData,

    [Parameter()]
    [switch]$KeepLogs,

    [Parameter()]
    [switch]$Force
)

# Script configuration
$ErrorActionPreference = "Stop"
$ScriptVersion = "1.0.0"
$TaskName = "CyAudit Automated Assessment"

# Logging function
function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
        "WARN"    { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default   { Write-Host $logMessage }
    }
}

# Banner
function Show-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  CyAudit 3.5 Enterprise Uninstallation" -ForegroundColor Cyan
    Write-Host "  Version: $ScriptVersion" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

# Check if CyAudit is installed
function Test-CyAuditInstalled {
    $appPath = Join-Path $InstallPath "CyAudit_3.5"
    return (Test-Path $appPath)
}

# Remove scheduled task
function Remove-CyAuditScheduledTask {
    Write-Log "Checking for scheduled task: $TaskName"

    try {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

        if ($task) {
            Write-Log "Removing scheduled task..."

            # Stop the task if running
            if ($task.State -eq "Running") {
                Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }

            # Unregister the task
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Log "Scheduled task removed" -Level SUCCESS
        } else {
            Write-Log "Scheduled task not found (may not have been created)"
        }

        return $true
    } catch {
        Write-Log "Failed to remove scheduled task: $_" -Level ERROR
        return $false
    }
}

# Remove application files
function Remove-ApplicationFiles {
    Write-Log "Removing application files..."

    $appPath = Join-Path $InstallPath "CyAudit_3.5"

    if (Test-Path $appPath) {
        try {
            Remove-Item -Path $appPath -Recurse -Force
            Write-Log "Application files removed" -Level SUCCESS
        } catch {
            Write-Log "Failed to remove application files: $_" -Level ERROR
            return $false
        }
    } else {
        Write-Log "Application directory not found: $appPath" -Level WARN
    }

    return $true
}

# Remove data directories
function Remove-DataDirectories {
    if ($KeepData) {
        Write-Log "Preserving assessment data (as requested)"
        return $true
    }

    Write-Log "Removing assessment data..."

    $assessmentsPath = Join-Path $InstallPath "Assessments"
    $splunkReadyPath = Join-Path $InstallPath "SplunkReady"

    try {
        if (Test-Path $assessmentsPath) {
            $assessmentCount = (Get-ChildItem -Path $assessmentsPath -Directory -ErrorAction SilentlyContinue).Count
            if ($assessmentCount -gt 0) {
                Write-Log "Removing $assessmentCount assessment(s)..."
            }
            Remove-Item -Path $assessmentsPath -Recurse -Force
            Write-Log "Assessments directory removed"
        }

        if (Test-Path $splunkReadyPath) {
            Remove-Item -Path $splunkReadyPath -Recurse -Force
            Write-Log "SplunkReady directory removed"
        }

        return $true
    } catch {
        Write-Log "Failed to remove data directories: $_" -Level ERROR
        return $false
    }
}

# Remove log files
function Remove-LogFiles {
    if ($KeepLogs -or $KeepData) {
        Write-Log "Preserving log files (as requested)"
        return $true
    }

    Write-Log "Removing log files..."

    $logsPath = Join-Path $InstallPath "Logs"

    try {
        if (Test-Path $logsPath) {
            Remove-Item -Path $logsPath -Recurse -Force
            Write-Log "Logs directory removed"
        }

        return $true
    } catch {
        Write-Log "Failed to remove log files: $_" -Level ERROR
        return $false
    }
}

# Remove base directory if empty
function Remove-BaseDirectory {
    Write-Log "Checking base directory..."

    try {
        # Check if directory exists and is empty
        if (Test-Path $InstallPath) {
            $remainingItems = Get-ChildItem -Path $InstallPath -Force -ErrorAction SilentlyContinue

            if ($remainingItems.Count -eq 0) {
                Remove-Item -Path $InstallPath -Force
                Write-Log "Base directory removed (was empty)" -Level SUCCESS
            } else {
                Write-Log "Base directory not removed - contains preserved data:"
                foreach ($item in $remainingItems) {
                    Write-Log "  - $($item.Name)"
                }
            }
        }

        return $true
    } catch {
        Write-Log "Failed to remove base directory: $_" -Level WARN
        return $true  # Non-critical
    }
}

# Confirmation prompt
function Get-UserConfirmation {
    if ($Force) {
        return $true
    }

    Write-Host ""
    Write-Host "This will remove CyAudit 3.5 from: $InstallPath" -ForegroundColor Yellow

    if (-not $KeepData) {
        Write-Host "WARNING: All assessment data will be deleted!" -ForegroundColor Red
    } else {
        Write-Host "Assessment data will be preserved." -ForegroundColor Green
    }

    Write-Host ""

    $response = Read-Host "Are you sure you want to continue? (Y/N)"
    return ($response -eq "Y" -or $response -eq "y")
}

# Main uninstallation routine
function Start-Uninstallation {
    Show-Banner

    # Check if installed
    if (-not (Test-CyAuditInstalled)) {
        Write-Log "CyAudit does not appear to be installed at: $InstallPath" -Level WARN
        Write-Log "Checking for scheduled task anyway..."

        # Still try to remove scheduled task
        Remove-CyAuditScheduledTask | Out-Null

        Write-Log "Uninstallation complete (nothing to remove)" -Level SUCCESS
        exit 0
    }

    Write-Log "Found CyAudit installation at: $InstallPath"

    # Get confirmation
    if (-not (Get-UserConfirmation)) {
        Write-Log "Uninstallation cancelled by user" -Level WARN
        exit 2
    }

    Write-Log ""
    Write-Log "Starting uninstallation..."

    # Step 1: Remove scheduled task
    if (-not (Remove-CyAuditScheduledTask)) {
        Write-Log "Warning: Could not remove scheduled task. Continuing..." -Level WARN
    }

    # Step 2: Remove application files
    if (-not (Remove-ApplicationFiles)) {
        Write-Log "Uninstallation failed: Could not remove application files" -Level ERROR
        exit 4
    }

    # Step 3: Remove data directories
    if (-not (Remove-DataDirectories)) {
        Write-Log "Warning: Could not remove all data directories" -Level WARN
    }

    # Step 4: Remove log files
    if (-not (Remove-LogFiles)) {
        Write-Log "Warning: Could not remove log files" -Level WARN
    }

    # Step 5: Remove base directory if empty
    Remove-BaseDirectory | Out-Null

    Write-Log ""
    Write-Log "============================================================" -Level SUCCESS
    Write-Log "  CyAudit 3.5 uninstalled successfully!" -Level SUCCESS
    Write-Log "============================================================" -Level SUCCESS
    Write-Log ""

    if ($KeepData -or $KeepLogs) {
        Write-Log "Preserved data location: $InstallPath"
    }

    exit 0
}

# Run uninstallation
Start-Uninstallation
