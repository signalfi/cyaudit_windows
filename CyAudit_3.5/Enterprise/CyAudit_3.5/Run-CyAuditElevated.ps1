#Requires -Version 5.1
<#
.SYNOPSIS
    Elevated launcher for CyAudit - triggers UAC and runs assessment with admin privileges

.DESCRIPTION
    This launcher script triggers a UAC elevation prompt and then runs the
    Run-CyAuditPipeline.ps1 script (or .exe) with administrator privileges.

    Required because Run-CyAuditPipeline.ps1 contains #requires -RunAsAdministrator

.NOTES
    Version: 1.4
    The elevated PowerShell window closes automatically when the script completes.
    Compatible with both .ps1 and PS2EXE compiled .exe versions.
#>

# Get script directory - works for both .ps1 and PS2EXE compiled .exe
if ($PSScriptRoot) {
    $ScriptDir = $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    # Fallback for PS2EXE compiled executables
    $ScriptDir = Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
}

# Look for .exe first (protected build), then .ps1 (standard build)
$TargetExe = Join-Path $ScriptDir "Run-CyAuditPipeline.exe"
$TargetScript = Join-Path $ScriptDir "Run-CyAuditPipeline.ps1"

if (Test-Path $TargetExe) {
    $TargetToRun = $TargetExe
    $IsExe = $true
} else {
    $TargetToRun = $TargetScript
    $IsExe = $false
}

# Verify target exists
if (-not (Test-Path $TargetToRun)) {
    Write-Error "Target not found: $TargetToRun"
    exit 1
}

# Launch elevated - different approach for .exe vs .ps1
if ($IsExe) {
    # For compiled EXE, run it directly with elevation
    Start-Process -FilePath $TargetToRun -Verb RunAs -WorkingDirectory $ScriptDir
} else {
    # For .ps1, launch PowerShell with the script
    Start-Process powershell -ArgumentList @(
        "-NoProfile"
        "-ExecutionPolicy", "Bypass"
        "-Command"
        "Set-Location '$ScriptDir'; & '$TargetToRun'"
    ) -Verb RunAs -WorkingDirectory $ScriptDir
}
