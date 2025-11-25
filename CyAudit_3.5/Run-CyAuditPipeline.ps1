#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Automated CyAudit assessment and Splunk transformation pipeline

.DESCRIPTION
    This script orchestrates the complete CyAudit workflow:
    1. Runs CyAudit_Opus_V3.5.ps1 security assessment
    2. Automatically transforms output for Splunk ingestion
    3. Optionally validates transformed data
    4. Manages retention and cleanup of old assessments
    5. Logs all operations for auditing

    Designed for scheduled task execution with comprehensive error handling
    and alerting capabilities.

.PARAMETER ConfigFile
    Path to configuration JSON file (default: .\CyAuditPipeline.config.json)

.PARAMETER ComputerName
    Computer name to audit (overrides config file, defaults to localhost)

.PARAMETER SkipValidation
    Skip validation of transformed Splunk data

.PARAMETER Force
    Bypass confirmation prompts

.EXAMPLE
    .\Run-CyAuditPipeline.ps1

    Runs with default configuration file

.EXAMPLE
    .\Run-CyAuditPipeline.ps1 -ConfigFile "C:\CyAudit\custom.config.json" -ComputerName "SERVER01"

    Runs with custom config and specific computer name

.EXAMPLE
    .\Run-CyAuditPipeline.ps1 -SkipValidation -Force

    Runs without validation and skips confirmations

.NOTES
    Version: 1.0.0
    Author: CyAudit Splunk Integration
    Created: 2025-11-12

    Prerequisites:
    - PowerShell 5.1 or later
    - Administrator privileges
    - CyAudit_Opus_V3.5.ps1 in same directory
    - Transform-CyAuditForSplunk.ps1 in same directory
    - Configuration file (CyAuditPipeline.config.json)

    Exit Codes:
    0 = Success
    1 = Configuration error
    2 = CyAudit execution failed
    3 = Transformation failed
    4 = Validation failed
    5 = Cleanup failed
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = (Join-Path $PSScriptRoot "CyAuditPipeline.config.json"),

    [Parameter(Mandatory=$false)]
    [string]$ComputerName,

    [Parameter(Mandatory=$false)]
    [switch]$SkipValidation,

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

#region Script Variables

$ScriptVersion = "1.0.0"
$StartTime = Get-Date
$ScriptDir = $PSScriptRoot
$LogTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"

#endregion

#region Helper Functions

function Write-PipelineLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "DEBUG")]
        [string]$Level = "INFO",
        [switch]$NoConsole
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] $Message"

    # Write to console with color
    if (-not $NoConsole) {
        $color = switch ($Level) {
            "SUCCESS" { "Green" }
            "WARNING" { "Yellow" }
            "ERROR"   { "Red" }
            "DEBUG"   { "Gray" }
            default   { "White" }
        }
        Write-Host $logMessage -ForegroundColor $color
    }

    # Write to log file
    if ($script:LogFilePath) {
        $logMessage | Out-File -FilePath $script:LogFilePath -Append -Encoding UTF8
    }
}

function Test-Prerequisites {
    Write-PipelineLog "Validating prerequisites..." -Level INFO

    $errors = @()

    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $errors += "PowerShell 5.1 or later required (current: $($PSVersionTable.PSVersion))"
    }

    # Check administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $errors += "Script must be run with Administrator privileges"
    }

    # Check required scripts exist
    $requiredScripts = @(
        "CyAudit_Opus_V3.5.ps1",
        "Transform-CyAuditForSplunk.ps1"
    )

    foreach ($script in $requiredScripts) {
        $scriptPath = Join-Path $ScriptDir $script
        if (-not (Test-Path $scriptPath)) {
            $errors += "Required script not found: $scriptPath"
        }
    }

    if (-not $SkipValidation) {
        $validationScript = Join-Path $ScriptDir "Test-SplunkTransformation.ps1"
        if (-not (Test-Path $validationScript)) {
            Write-PipelineLog "Validation script not found, will skip validation" -Level WARNING
        }
    }

    if ($errors.Count -gt 0) {
        foreach ($error in $errors) {
            Write-PipelineLog $error -Level ERROR
        }
        return $false
    }

    Write-PipelineLog "Prerequisites validated successfully" -Level SUCCESS
    return $true
}

function Send-AlertEmail {
    param(
        [string]$Subject,
        [string]$Body,
        [string]$Priority = "Normal"
    )

    if (-not $script:Config.EmailAlerts.Enabled) {
        return
    }

    try {
        $mailParams = @{
            To = $script:Config.EmailAlerts.To
            From = $script:Config.EmailAlerts.From
            Subject = "CyAudit Pipeline: $Subject"
            Body = $Body
            SmtpServer = $script:Config.EmailAlerts.SmtpServer
            Priority = $Priority
        }

        if ($script:Config.EmailAlerts.Port) {
            $mailParams['Port'] = $script:Config.EmailAlerts.Port
        }

        if ($script:Config.EmailAlerts.UseSsl) {
            $mailParams['UseSsl'] = $true
        }

        if ($script:Config.EmailAlerts.Credential) {
            $securePassword = ConvertTo-SecureString $script:Config.EmailAlerts.Credential.Password -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential ($script:Config.EmailAlerts.Credential.Username, $securePassword)
            $mailParams['Credential'] = $credential
        }

        Send-MailMessage @mailParams -ErrorAction Stop
        Write-PipelineLog "Alert email sent successfully" -Level SUCCESS
    }
    catch {
        Write-PipelineLog "Failed to send alert email: $($_.Exception.Message)" -Level WARNING
    }
}

function Invoke-Cleanup {
    param([int]$RetentionDays)

    if ($RetentionDays -le 0) {
        Write-PipelineLog "Cleanup disabled (RetentionDays = 0)" -Level DEBUG
        return $true
    }

    Write-PipelineLog "Starting cleanup of assessments older than $RetentionDays days..." -Level INFO

    try {
        $cutoffDate = (Get-Date).AddDays(-$RetentionDays)

        # Cleanup assessment directories
        if (Test-Path $script:Config.OutputBasePath) {
            $oldDirs = Get-ChildItem -Path $script:Config.OutputBasePath -Directory |
                Where-Object { $_.LastWriteTime -lt $cutoffDate }

            foreach ($dir in $oldDirs) {
                Write-PipelineLog "Removing old assessment: $($dir.Name)" -Level DEBUG
                Remove-Item -Path $dir.FullName -Recurse -Force -ErrorAction Stop
            }

            Write-PipelineLog "Cleaned up $($oldDirs.Count) old assessment(s)" -Level SUCCESS
        }

        # Cleanup old transformed files
        if (Test-Path $script:Config.SplunkReadyPath) {
            $oldFiles = Get-ChildItem -Path $script:Config.SplunkReadyPath -File |
                Where-Object { $_.LastWriteTime -lt $cutoffDate }

            foreach ($file in $oldFiles) {
                Write-PipelineLog "Removing old transformed file: $($file.Name)" -Level DEBUG
                Remove-Item -Path $file.FullName -Force -ErrorAction Stop
            }

            Write-PipelineLog "Cleaned up $($oldFiles.Count) old transformed file(s)" -Level SUCCESS
        }

        # Cleanup old logs
        if (Test-Path $script:Config.LogPath) {
            $oldLogs = Get-ChildItem -Path $script:Config.LogPath -Filter "*.log" |
                Where-Object { $_.LastWriteTime -lt $cutoffDate }

            foreach ($log in $oldLogs) {
                Write-PipelineLog "Removing old log: $($log.Name)" -Level DEBUG
                Remove-Item -Path $log.FullName -Force -ErrorAction Stop
            }

            Write-PipelineLog "Cleaned up $($oldLogs.Count) old log file(s)" -Level SUCCESS
        }

        return $true
    }
    catch {
        Write-PipelineLog "Cleanup failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

#endregion

#region Main Execution

try {
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host " CyAudit Automated Pipeline v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host ""

    #region Load Configuration

    Write-PipelineLog "Loading configuration from: $ConfigFile" -Level INFO

    if (-not (Test-Path $ConfigFile)) {
        Write-PipelineLog "Configuration file not found: $ConfigFile" -Level ERROR
        Write-PipelineLog "Please create configuration file or specify -ConfigFile parameter" -Level ERROR
        exit 1
    }

    try {
        $script:Config = Get-Content -Path $ConfigFile -Raw | ConvertFrom-Json
        Write-PipelineLog "Configuration loaded successfully" -Level SUCCESS
    }
    catch {
        Write-PipelineLog "Failed to parse configuration file: $($_.Exception.Message)" -Level ERROR
        exit 1
    }

    # Resolve relative paths to the script directory so all outputs live alongside CyAudit artifacts
    $pathsToResolve = @('OutputBasePath', 'SplunkReadyPath', 'LogPath')
    foreach ($key in $pathsToResolve) {
        $value = $script:Config.$key
        if ($value -and -not [System.IO.Path]::IsPathRooted($value)) {
            $resolved = Join-Path $ScriptDir $value
            $script:Config.$key = $resolved
            Write-PipelineLog "Resolved $key to $resolved" -Level DEBUG
        }
    }

    # Ensure CyAudit output path defaults to OutputBasePath (also resolve if relative)
    if (-not $script:Config.CyAuditOptions) {
        $script:Config | Add-Member -MemberType NoteProperty -Name CyAuditOptions -Value @{}
    }
    if (-not $script:Config.CyAuditOptions.OutputPath) {
        $script:Config.CyAuditOptions.OutputPath = $script:Config.OutputBasePath
    } elseif (-not [System.IO.Path]::IsPathRooted($script:Config.CyAuditOptions.OutputPath)) {
        $script:Config.CyAuditOptions.OutputPath = Join-Path $ScriptDir $script:Config.CyAuditOptions.OutputPath
    }

    # Override computer name if specified
    if ($ComputerName) {
        $script:Config.ComputerName = $ComputerName
    }
    elseif (-not $script:Config.ComputerName) {
        $script:Config.ComputerName = $env:COMPUTERNAME
    }

    # Create directories if they don't exist
    foreach ($path in @($script:Config.OutputBasePath, $script:Config.SplunkReadyPath, $script:Config.LogPath)) {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -ItemType Directory -Force | Out-Null
            Write-PipelineLog "Created directory: $path" -Level DEBUG
        }
    }

    # Set up logging
    $script:LogFilePath = Join-Path $script:Config.LogPath "CyAuditPipeline_$LogTimestamp.log"
    Write-PipelineLog "Pipeline started at $StartTime" -Level INFO
    Write-PipelineLog "Computer Name: $($script:Config.ComputerName)" -Level INFO
    Write-PipelineLog "Client Name: $($script:Config.ClientName)" -Level INFO
    Write-PipelineLog "Log File: $script:LogFilePath" -Level INFO

    #endregion

    #region Validate Prerequisites

    if (-not (Test-Prerequisites)) {
        Write-PipelineLog "Prerequisite validation failed" -Level ERROR
        Send-AlertEmail -Subject "Pipeline Failed - Prerequisites" -Body "Prerequisite validation failed. Check log: $script:LogFilePath" -Priority "High"
        exit 1
    }

    #endregion

    #region Run CyAudit Assessment

    Write-Host ""
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Phase 1: CyAudit Security Assessment" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""

    $cyauditScript = Join-Path $ScriptDir "CyAudit_Opus_V3.5.ps1"
    Write-PipelineLog "Running CyAudit assessment..." -Level INFO
    Write-PipelineLog "Script: $cyauditScript" -Level DEBUG

    # Build CyAudit parameters
    $cyauditParams = @{
        ComputerName = $script:Config.ComputerName
        ClientName = $script:Config.ClientName
    }

    # Determine where CyAudit will output - track this so pipeline can find it
    # CyAudit defaults to current directory ($PWD) unless OutputPath is specified
    if ($script:Config.CyAuditOptions -and $script:Config.CyAuditOptions.OutputPath) {
        $cyauditParams['OutputPath'] = $script:Config.CyAuditOptions.OutputPath
        $script:ActualOutputPath = $script:Config.CyAuditOptions.OutputPath
    } else {
        # Let CyAudit use its default (current directory)
        # Track where that is so we can find the output later
        $script:ActualOutputPath = $PWD.Path
    }

    if ($script:Config.CyAuditOptions) {
        if ($script:Config.CyAuditOptions.IncludeHTML -eq $false) {
            $cyauditParams['NoHTML'] = $true
        }
    }

    try {
        # Execute CyAudit
        $cyauditOutput = & $cyauditScript @cyauditParams 2>&1

        if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
            throw "CyAudit exited with code: $LASTEXITCODE"
        }

        Write-PipelineLog "CyAudit assessment completed successfully" -Level SUCCESS

        # Find the output directory (most recent directory in ActualOutputPath)
        # ActualOutputPath is either CyAuditOptions.OutputPath if set, or $PWD (current directory)
        $assessmentDir = Get-ChildItem -Path $script:ActualOutputPath -Directory |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1

        if (-not $assessmentDir) {
            throw "Could not locate CyAudit output directory in $($script:ActualOutputPath)"
        }

        $script:AssessmentPath = $assessmentDir.FullName
        Write-PipelineLog "Assessment output: $script:AssessmentPath" -Level INFO
    }
    catch {
        Write-PipelineLog "CyAudit assessment failed: $($_.Exception.Message)" -Level ERROR
        Write-PipelineLog "Output: $cyauditOutput" -Level DEBUG
        Send-AlertEmail -Subject "Pipeline Failed - CyAudit Assessment" -Body "CyAudit assessment failed: $($_.Exception.Message)`n`nLog: $script:LogFilePath" -Priority "High"
        exit 2
    }

    #endregion

    #region Transform for Splunk

    Write-Host ""
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Phase 2: Splunk Transformation" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""

    $transformScript = Join-Path $ScriptDir "Transform-CyAuditForSplunk.ps1"
    Write-PipelineLog "Running Splunk transformation..." -Level INFO
    Write-PipelineLog "Script: $transformScript" -Level DEBUG

    try {
        $transformParams = @{
            InputPath = $script:AssessmentPath
            OutputPath = $script:Config.SplunkReadyPath
            IncludeAuxiliaryFiles = $true
            Force = $true
        }

        if ($VerbosePreference -eq 'Continue') {
            $transformParams['Verbose'] = $true
        }

        & $transformScript @transformParams

        if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
            throw "Transform script exited with code: $LASTEXITCODE"
        }

        Write-PipelineLog "Transformation completed successfully" -Level SUCCESS

        # Count transformed files
        $transformedFiles = Get-ChildItem -Path $script:Config.SplunkReadyPath -Filter "*.json" -File
        Write-PipelineLog "Generated $($transformedFiles.Count) Splunk-ready files" -Level INFO
    }
    catch {
        Write-PipelineLog "Transformation failed: $($_.Exception.Message)" -Level ERROR
        Send-AlertEmail -Subject "Pipeline Failed - Transformation" -Body "Transformation failed: $($_.Exception.Message)`n`nLog: $script:LogFilePath" -Priority "High"
        exit 3
    }

    #endregion

    #region Validate Output

    if (-not $SkipValidation -and $script:Config.ValidateOutput) {
        Write-Host ""
        Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
        Write-Host " Phase 3: Validation" -ForegroundColor Cyan
        Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
        Write-Host ""

        $validationScript = Join-Path $ScriptDir "Test-SplunkTransformation.ps1"

        if (Test-Path $validationScript) {
            Write-PipelineLog "Running validation..." -Level INFO

            try {
                & $validationScript -Path $script:Config.SplunkReadyPath

                if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
                    throw "Validation failed with exit code: $LASTEXITCODE"
                }

                Write-PipelineLog "Validation passed" -Level SUCCESS
            }
            catch {
                Write-PipelineLog "Validation failed: $($_.Exception.Message)" -Level ERROR

                if ($script:Config.FailOnValidationError) {
                    Send-AlertEmail -Subject "Pipeline Failed - Validation" -Body "Validation failed: $($_.Exception.Message)`n`nLog: $script:LogFilePath" -Priority "High"
                    exit 4
                }
                else {
                    Write-PipelineLog "Continuing despite validation failure (FailOnValidationError = false)" -Level WARNING
                }
            }
        }
        else {
            Write-PipelineLog "Validation script not found, skipping validation" -Level WARNING
        }
    }
    else {
        Write-PipelineLog "Validation skipped" -Level INFO
    }

    #endregion

    #region Cleanup

    if ($script:Config.RetentionDays -gt 0) {
        Write-Host ""
        Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
        Write-Host " Phase 4: Cleanup" -ForegroundColor Cyan
        Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
        Write-Host ""

        $cleanupSuccess = Invoke-Cleanup -RetentionDays $script:Config.RetentionDays

        if (-not $cleanupSuccess) {
            Write-PipelineLog "Cleanup encountered errors, but pipeline will continue" -Level WARNING
        }
    }

    #endregion

    #region Summary

    $endTime = Get-Date
    $duration = $endTime - $StartTime

    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Green
    Write-Host " Pipeline Completed Successfully!" -ForegroundColor Green
    Write-Host "===================================================================" -ForegroundColor Green
    Write-Host ""

    Write-PipelineLog "Pipeline completed at $endTime" -Level SUCCESS
    Write-PipelineLog "Total duration: $($duration.ToString('hh\:mm\:ss'))" -Level SUCCESS
    Write-PipelineLog "Assessment: $script:AssessmentPath" -Level INFO
    Write-PipelineLog "Transformed files: $($script:Config.SplunkReadyPath)" -Level INFO
    Write-PipelineLog "Log file: $script:LogFilePath" -Level INFO

    # Send success notification if configured
    if ($script:Config.EmailAlerts.Enabled -and $script:Config.EmailAlerts.SendOnSuccess) {
        $body = @"
CyAudit pipeline completed successfully.

Computer: $($script:Config.ComputerName)
Duration: $($duration.ToString('hh\:mm\:ss'))
Assessment: $script:AssessmentPath
Transformed Files: $($transformedFiles.Count)
Log: $script:LogFilePath

The transformed data is ready for Splunk ingestion via Universal Forwarder.
"@
        Send-AlertEmail -Subject "Pipeline Completed Successfully" -Body $body
    }

    Write-Host ""
    Write-PipelineLog "Next: Universal Forwarder will automatically forward new files to Splunk Cloud" -Level INFO
    Write-Host ""

    exit 0

    #endregion
}
catch {
    $endTime = Get-Date
    $duration = $endTime - $StartTime

    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Red
    Write-Host " Pipeline Failed!" -ForegroundColor Red
    Write-Host "===================================================================" -ForegroundColor Red
    Write-Host ""

    Write-PipelineLog "Pipeline failed with unhandled exception: $($_.Exception.Message)" -Level ERROR
    Write-PipelineLog "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR
    Write-PipelineLog "Duration before failure: $($duration.ToString('hh\:mm\:ss'))" -Level ERROR

    # Send failure notification
    $body = @"
CyAudit pipeline failed with unhandled exception.

Computer: $($script:Config.ComputerName)
Error: $($_.Exception.Message)
Duration: $($duration.ToString('hh\:mm\:ss'))
Log: $script:LogFilePath

Please review the log file for details.
"@
    Send-AlertEmail -Subject "Pipeline Failed - Unhandled Exception" -Body $body -Priority "High"

    exit 99
}

#endregion
