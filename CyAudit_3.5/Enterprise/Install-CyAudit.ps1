<#
.SYNOPSIS
    CyAudit 3.5 Enterprise Deployment Script

.DESCRIPTION
    Installs CyAudit 3.5 security assessment framework for enterprise deployment
    via SCCM or manual execution. Handles:
    - Directory structure creation
    - File deployment and unblocking
    - PowerSTIG module installation
    - Optional scheduled task creation

.PARAMETER InstallPath
    Base installation directory. Default: C:\CyAudit

.PARAMETER CreateScheduledTask
    Create a weekly scheduled task for automated assessments

.PARAMETER TaskSchedule
    Schedule for the task: Daily, Weekly, or Monthly. Default: Weekly

.PARAMETER TaskTime
    Time to run the scheduled task. Default: 02:00

.PARAMETER TaskDay
    Day of week for Weekly schedule. Default: Sunday

.PARAMETER SkipPowerSTIG
    Skip PowerSTIG module installation (for offline environments)

.PARAMETER ConfigFile
    Path to custom configuration file to deploy

.EXAMPLE
    .\Install-CyAudit.ps1
    Basic installation to C:\CyAudit

.EXAMPLE
    .\Install-CyAudit.ps1 -CreateScheduledTask
    Install with weekly scheduled task (Sunday 2am)

.EXAMPLE
    .\Install-CyAudit.ps1 -InstallPath "D:\Security\CyAudit" -CreateScheduledTask -TaskTime "03:00"
    Custom install path with scheduled task at 3am

.EXAMPLE
    .\Install-CyAudit.ps1 -SkipPowerSTIG
    Install without attempting PowerSTIG installation (offline environment)

.NOTES
    Version:        1.0.0
    Author:         CyAudit Team
    Creation Date:  2025-12-01
    Purpose:        SCCM/Enterprise Deployment

    Requirements:
    - PowerShell 5.1 or later
    - Administrator privileges
    - Network access for PowerSTIG installation (unless -SkipPowerSTIG)

    Exit Codes:
    0 - Success
    1 - Not running as administrator
    2 - Failed to create directory structure
    3 - Failed to copy files
    4 - Failed to unblock files
    5 - Failed to install PowerSTIG
    6 - Failed to create scheduled task
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$InstallPath = "C:\CyAudit",

    [Parameter()]
    [switch]$CreateScheduledTask,

    [Parameter()]
    [ValidateSet("Daily", "Weekly", "Monthly")]
    [string]$TaskSchedule = "Weekly",

    [Parameter()]
    [ValidatePattern("^\d{2}:\d{2}$")]
    [string]$TaskTime = "02:00",

    [Parameter()]
    [ValidateSet("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")]
    [string]$TaskDay = "Sunday",

    [Parameter()]
    [switch]$SkipPowerSTIG,

    [Parameter()]
    [string]$ConfigFile
)

# Script configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Constants
$ScriptVersion = "1.0.0"
$TaskName = "CyAudit Automated Assessment"
$SourcePath = $PSScriptRoot

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

    # Also write to log file if Logs directory exists
    $logDir = Join-Path $InstallPath "Logs"
    if (Test-Path $logDir) {
        $logFile = Join-Path $logDir "Install_$(Get-Date -Format 'yyyyMMdd').log"
        Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
    }
}

# Banner
function Show-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  CyAudit 3.5 Enterprise Deployment" -ForegroundColor Cyan
    Write-Host "  Version: $ScriptVersion" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

# Verify administrator privileges (redundant with #Requires but provides better error message)
function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Create directory structure
function New-DirectoryStructure {
    Write-Log "Creating directory structure at: $InstallPath"

    $directories = @(
        $InstallPath,
        (Join-Path $InstallPath "Logs"),
        (Join-Path $InstallPath "Assessments"),
        (Join-Path $InstallPath "SplunkReady"),
        (Join-Path $InstallPath "CyAudit_3.5")
    )

    foreach ($dir in $directories) {
        try {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                Write-Log "Created: $dir"
            } else {
                Write-Log "Exists: $dir"
            }
        } catch {
            Write-Log "Failed to create directory: $dir - $_" -Level ERROR
            return $false
        }
    }

    return $true
}

# Copy application files
function Copy-ApplicationFiles {
    Write-Log "Copying application files..."

    $sourceAppPath = Join-Path $SourcePath "CyAudit_3.5"
    $destAppPath = Join-Path $InstallPath "CyAudit_3.5"

    # Check if source exists
    if (-not (Test-Path $sourceAppPath)) {
        Write-Log "Source application path not found: $sourceAppPath" -Level ERROR
        Write-Log "Attempting to copy from script root directory..." -Level WARN
        $sourceAppPath = $SourcePath
    }

    # Files to copy (PowerShell scripts only - excludes Python report generator)
    $filesToCopy = @(
        "CyAudit_Opus_V3.5.ps1",
        "Run-CyAuditPipeline.ps1",
        "Transform-CyAuditForSplunk.ps1",
        "Test-SplunkTransformation.ps1",
        "Upload-ToSplunkCloud.ps1",
        "CyAuditPipeline.config.json"
    )

    foreach ($file in $filesToCopy) {
        $sourceFile = Join-Path $sourceAppPath $file
        $destFile = Join-Path $destAppPath $file

        if (Test-Path $sourceFile) {
            try {
                Copy-Item -Path $sourceFile -Destination $destFile -Force
                Write-Log "Copied: $file"
            } catch {
                Write-Log "Failed to copy: $file - $_" -Level ERROR
                return $false
            }
        } else {
            Write-Log "Source file not found: $sourceFile" -Level WARN
        }
    }

    # Copy STIGData directory
    $sourceStigPath = Join-Path $sourceAppPath "STIGData"
    $destStigPath = Join-Path $destAppPath "STIGData"

    if (Test-Path $sourceStigPath) {
        try {
            if (-not (Test-Path $destStigPath)) {
                New-Item -Path $destStigPath -ItemType Directory -Force | Out-Null
            }
            Copy-Item -Path "$sourceStigPath\*" -Destination $destStigPath -Recurse -Force
            Write-Log "Copied STIGData directory"
        } catch {
            Write-Log "Failed to copy STIGData: $_" -Level ERROR
            return $false
        }
    } else {
        Write-Log "STIGData directory not found at: $sourceStigPath" -Level WARN
    }

    # Copy splunk_configs directory (optional)
    $sourceSplunkPath = Join-Path $sourceAppPath "splunk_configs"
    $destSplunkPath = Join-Path $destAppPath "splunk_configs"

    if (Test-Path $sourceSplunkPath) {
        try {
            if (-not (Test-Path $destSplunkPath)) {
                New-Item -Path $destSplunkPath -ItemType Directory -Force | Out-Null
            }
            Copy-Item -Path "$sourceSplunkPath\*" -Destination $destSplunkPath -Recurse -Force
            Write-Log "Copied splunk_configs directory"
        } catch {
            Write-Log "Failed to copy splunk_configs: $_" -Level WARN
        }
    }

    # Copy custom config if specified
    if ($ConfigFile -and (Test-Path $ConfigFile)) {
        try {
            $destConfig = Join-Path $destAppPath "CyAuditPipeline.config.json"
            Copy-Item -Path $ConfigFile -Destination $destConfig -Force
            Write-Log "Copied custom configuration file"
        } catch {
            Write-Log "Failed to copy custom config: $_" -Level WARN
        }
    }

    return $true
}

# Unblock all files (remove Zone.Identifier)
function Unblock-AllFiles {
    Write-Log "Unblocking files (removing Zone.Identifier)..."

    try {
        $files = Get-ChildItem -Path $InstallPath -Recurse -File
        $unblockedCount = 0

        foreach ($file in $files) {
            try {
                Unblock-File -Path $file.FullName -ErrorAction SilentlyContinue
                $unblockedCount++
            } catch {
                # Silently continue - file may not have Zone.Identifier
            }
        }

        Write-Log "Processed $unblockedCount files" -Level SUCCESS
        return $true
    } catch {
        Write-Log "Failed to unblock files: $_" -Level ERROR
        return $false
    }
}

# Install PowerSTIG module
function Install-PowerSTIGModule {
    if ($SkipPowerSTIG) {
        Write-Log "Skipping PowerSTIG installation (as requested)" -Level WARN
        return $true
    }

    Write-Log "Checking PowerSTIG module..."

    # Check if already installed
    $existingModule = Get-Module -ListAvailable -Name PowerSTIG -ErrorAction SilentlyContinue
    if ($existingModule) {
        Write-Log "PowerSTIG module already installed (version: $($existingModule.Version))" -Level SUCCESS
        return $true
    }

    Write-Log "Installing PowerSTIG module..."

    try {
        # Ensure NuGet provider is available
        $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
        if (-not $nuget -or $nuget.Version -lt [version]"2.8.5.201") {
            Write-Log "Installing NuGet package provider..."
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
        }

        # Set PSGallery as trusted (temporarily)
        $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        $originalInstallationPolicy = $psGallery.InstallationPolicy

        if ($psGallery.InstallationPolicy -ne "Trusted") {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }

        # Install PowerSTIG
        Install-Module -Name PowerSTIG -Force -AllowClobber -Scope AllUsers -SkipPublisherCheck

        # Restore original trust setting
        if ($originalInstallationPolicy -ne "Trusted") {
            Set-PSRepository -Name PSGallery -InstallationPolicy $originalInstallationPolicy
        }

        Write-Log "PowerSTIG module installed successfully" -Level SUCCESS
        return $true
    } catch {
        Write-Log "Failed to install PowerSTIG: $_" -Level ERROR
        Write-Log "You may need to install PowerSTIG manually or ensure network connectivity to PowerShell Gallery" -Level WARN
        return $false
    }
}

# Create scheduled task
function New-CyAuditScheduledTask {
    if (-not $CreateScheduledTask) {
        Write-Log "Skipping scheduled task creation (not requested)"
        return $true
    }

    Write-Log "Creating scheduled task: $TaskName"

    try {
        # Remove existing task if present
        $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Write-Log "Removing existing scheduled task..."
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }

        # Script path
        $scriptPath = Join-Path $InstallPath "CyAudit_3.5\Run-CyAuditPipeline.ps1"

        # Create action
        $actionArgs = "-ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"$scriptPath`""
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $actionArgs

        # Create trigger based on schedule type
        switch ($TaskSchedule) {
            "Daily" {
                $trigger = New-ScheduledTaskTrigger -Daily -At $TaskTime
            }
            "Weekly" {
                $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $TaskDay -At $TaskTime
            }
            "Monthly" {
                $trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek $TaskDay -At $TaskTime
            }
        }

        # Create principal (run as SYSTEM with highest privileges)
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        # Create settings
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -ExecutionTimeLimit (New-TimeSpan -Hours 4) `
            -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 10) `
            -MultipleInstances IgnoreNew

        # Register the task
        Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Description "CyAudit 3.5 automated security assessment. Runs $TaskSchedule at $TaskTime." `
            -Force | Out-Null

        Write-Log "Scheduled task created successfully" -Level SUCCESS
        Write-Log "  Schedule: $TaskSchedule at $TaskTime" -Level INFO
        Write-Log "  Run as: NT AUTHORITY\SYSTEM" -Level INFO

        return $true
    } catch {
        Write-Log "Failed to create scheduled task: $_" -Level ERROR
        return $false
    }
}

# Verify installation
function Test-Installation {
    Write-Log "Verifying installation..."

    $requiredFiles = @(
        (Join-Path $InstallPath "CyAudit_3.5\CyAudit_Opus_V3.5.ps1"),
        (Join-Path $InstallPath "CyAudit_3.5\Run-CyAuditPipeline.ps1"),
        (Join-Path $InstallPath "CyAudit_3.5\Transform-CyAuditForSplunk.ps1"),
        (Join-Path $InstallPath "CyAudit_3.5\CyAuditPipeline.config.json")
    )

    $missingFiles = @()
    foreach ($file in $requiredFiles) {
        if (-not (Test-Path $file)) {
            $missingFiles += $file
        }
    }

    if ($missingFiles.Count -gt 0) {
        Write-Log "Missing required files:" -Level WARN
        foreach ($file in $missingFiles) {
            Write-Log "  - $file" -Level WARN
        }
        return $false
    }

    # Verify STIG data
    $stigPath = Join-Path $InstallPath "CyAudit_3.5\STIGData"
    if (Test-Path $stigPath) {
        $stigFiles = Get-ChildItem -Path $stigPath -Filter "*.xml" -ErrorAction SilentlyContinue
        Write-Log "STIG files found: $($stigFiles.Count)"
    } else {
        Write-Log "STIGData directory not found" -Level WARN
    }

    # Verify scheduled task if created
    if ($CreateScheduledTask) {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Write-Log "Scheduled task verified: $TaskName" -Level SUCCESS
        } else {
            Write-Log "Scheduled task not found: $TaskName" -Level WARN
        }
    }

    return $true
}

# Main installation routine
function Start-Installation {
    Show-Banner

    Write-Log "Starting CyAudit 3.5 installation..."
    Write-Log "Install path: $InstallPath"
    Write-Log "Source path: $SourcePath"

    # Step 1: Create directory structure
    if (-not (New-DirectoryStructure)) {
        Write-Log "Installation failed: Could not create directory structure" -Level ERROR
        exit 2
    }

    # Step 2: Copy application files
    if (-not (Copy-ApplicationFiles)) {
        Write-Log "Installation failed: Could not copy application files" -Level ERROR
        exit 3
    }

    # Step 3: Unblock files
    if (-not (Unblock-AllFiles)) {
        Write-Log "Installation failed: Could not unblock files" -Level ERROR
        exit 4
    }

    # Step 4: Install PowerSTIG
    if (-not (Install-PowerSTIGModule)) {
        if (-not $SkipPowerSTIG) {
            Write-Log "PowerSTIG installation failed. CyAudit may not function correctly without it." -Level WARN
            Write-Log "You can install it manually: Install-Module -Name PowerSTIG -Force -Scope AllUsers" -Level WARN
            # Don't exit - continue with warning
        }
    }

    # Step 5: Create scheduled task
    if (-not (New-CyAuditScheduledTask)) {
        Write-Log "Installation failed: Could not create scheduled task" -Level ERROR
        exit 6
    }

    # Step 6: Verify installation
    if (Test-Installation) {
        Write-Log ""
        Write-Log "============================================================" -Level SUCCESS
        Write-Log "  CyAudit 3.5 installed successfully!" -Level SUCCESS
        Write-Log "============================================================" -Level SUCCESS
        Write-Log ""
        Write-Log "Installation directory: $InstallPath"
        Write-Log ""
        Write-Log "Next steps:"
        Write-Log "  1. Edit configuration: $InstallPath\CyAudit_3.5\CyAuditPipeline.config.json"
        Write-Log "  2. Update ClientName and other settings as needed"
        if ($CreateScheduledTask) {
            Write-Log "  3. Scheduled task '$TaskName' is configured"
            Write-Log "     To run manually: powershell -ExecutionPolicy Bypass -File `"$InstallPath\CyAudit_3.5\Run-CyAuditPipeline.ps1`""
        } else {
            Write-Log "  3. To run manually:"
            Write-Log "     powershell -ExecutionPolicy Bypass -File `"$InstallPath\CyAudit_3.5\Run-CyAuditPipeline.ps1`""
        }
        Write-Log ""
        exit 0
    } else {
        Write-Log "Installation completed with warnings. Please verify manually." -Level WARN
        exit 0
    }
}

# Run installation
Start-Installation
