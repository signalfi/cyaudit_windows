#Requires -Version 5.1
<#
.SYNOPSIS
    Compiles CyAudit PowerShell scripts to EXE using PS2EXE

.DESCRIPTION
    Run this script on a Windows machine to compile all CyAudit scripts to EXE.
    The compiled executables will be output to the Build/ folder.

    After running, copy the Build/ folder back to your Mac and run:
    ./build.sh --protected

.NOTES
    Version: 1.0
    Requires: Windows PowerShell 5.1+, Internet connection (first run)
#>

param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  CyAudit PS2EXE Build Script" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Determine paths
$ScriptDir = $PSScriptRoot
$SourceDir = Join-Path $ScriptDir "Scripts"
$OutputDir = Join-Path $ScriptDir "Build"

# Verify source directory exists
if (-not (Test-Path $SourceDir)) {
    Write-Host "[ERROR] Scripts directory not found: $SourceDir" -ForegroundColor Red
    Write-Host ""
    Write-Host "Make sure you copied the entire WindowsBuild folder from your Mac." -ForegroundColor Yellow
    exit 1
}

# Step 1: Install PS2EXE if not present
Write-Host "[1/4] Checking PS2EXE module..." -ForegroundColor Yellow
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host "      Installing PS2EXE module (requires internet)..." -ForegroundColor Gray
    try {
        Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber
        Write-Host "      PS2EXE installed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to install PS2EXE: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Try running manually:" -ForegroundColor Yellow
        Write-Host "  Install-Module -Name ps2exe -Scope CurrentUser -Force" -ForegroundColor White
        exit 1
    }
}
Import-Module ps2exe -Force
Write-Host "      PS2EXE module ready" -ForegroundColor Green

# Step 2: Create output directory
Write-Host "[2/4] Preparing output directory..." -ForegroundColor Yellow
if (Test-Path $OutputDir) {
    if ($Force) {
        Remove-Item -Path $OutputDir -Recurse -Force
    }
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
Write-Host "      Output: $OutputDir" -ForegroundColor Green

# Step 3: Create modified scripts for EXE compilation
Write-Host "[3/4] Creating modified scripts for EXE compilation..." -ForegroundColor Yellow

# Scripts that need .ps1 -> .exe reference changes
$ScriptsToModify = @{
    "Run-CyAuditPipeline.ps1" = @(
        @{ Find = 'CyAudit_Opus_V3.5.ps1'; Replace = 'CyAudit_Opus_V3.5.exe' }
        @{ Find = 'Transform-CyAuditForSplunk.ps1'; Replace = 'Transform-CyAuditForSplunk.exe' }
        @{ Find = 'Test-SplunkTransformation.ps1'; Replace = 'Test-SplunkTransformation.exe' }
    )
    "Run-CyAuditElevated.ps1" = @(
        @{ Find = 'Run-CyAuditPipeline.ps1'; Replace = 'Run-CyAuditPipeline.exe' }
    )
}

# Create temp directory for modified scripts
$TempDir = Join-Path $OutputDir "_temp"
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

foreach ($scriptName in $ScriptsToModify.Keys) {
    $sourcePath = Join-Path $SourceDir $scriptName
    $tempPath = Join-Path $TempDir $scriptName

    if (Test-Path $sourcePath) {
        $content = Get-Content -Path $sourcePath -Raw
        foreach ($replacement in $ScriptsToModify[$scriptName]) {
            $content = $content -replace [regex]::Escape($replacement.Find), $replacement.Replace
        }
        $content | Set-Content -Path $tempPath -Encoding UTF8
        Write-Host "      Modified: $scriptName" -ForegroundColor Gray
    } else {
        Write-Host "      SKIP: $scriptName (not found in Scripts/)" -ForegroundColor Yellow
    }
}

# Copy unmodified scripts to temp
$UnmodifiedScripts = @(
    "CyAudit_Opus_V3.5.ps1"
    "Transform-CyAuditForSplunk.ps1"
    "Test-SplunkTransformation.ps1"
    "Upload-ToSplunkCloud.ps1"
)

foreach ($scriptName in $UnmodifiedScripts) {
    $sourcePath = Join-Path $SourceDir $scriptName
    $tempPath = Join-Path $TempDir $scriptName
    if (Test-Path $sourcePath) {
        Copy-Item -Path $sourcePath -Destination $tempPath -Force
        Write-Host "      Copied: $scriptName" -ForegroundColor Gray
    }
}

# Step 4: Compile all scripts to EXE
Write-Host "[4/4] Compiling scripts to EXE..." -ForegroundColor Yellow

$ScriptsToCompile = @(
    @{
        Name = "Run-CyAuditPipeline.ps1"
        RequireAdmin = $true
        Description = "CyAudit Automated Assessment Pipeline"
    }
    @{
        Name = "Run-CyAuditElevated.ps1"
        RequireAdmin = $false  # This one triggers elevation itself
        Description = "CyAudit Elevated Launcher"
    }
    @{
        Name = "CyAudit_Opus_V3.5.ps1"
        RequireAdmin = $true
        Description = "CyAudit Security Assessment Engine"
    }
    @{
        Name = "Transform-CyAuditForSplunk.ps1"
        RequireAdmin = $false
        Description = "CyAudit Splunk Transformation"
    }
    @{
        Name = "Test-SplunkTransformation.ps1"
        RequireAdmin = $false
        Description = "CyAudit Splunk Validation"
    }
    @{
        Name = "Upload-ToSplunkCloud.ps1"
        RequireAdmin = $false
        Description = "CyAudit Splunk Upload"
    }
)

$successCount = 0
$failCount = 0

foreach ($script in $ScriptsToCompile) {
    $scriptPath = Join-Path $TempDir $script.Name
    $exeName = $script.Name -replace '\.ps1$', '.exe'
    $exePath = Join-Path $OutputDir $exeName

    if (-not (Test-Path $scriptPath)) {
        Write-Host "      SKIP: $($script.Name) (not found)" -ForegroundColor Yellow
        continue
    }

    try {
        $ps2exeParams = @{
            InputFile = $scriptPath
            OutputFile = $exePath
            NoConsole = $true              # v2.9: Suppress console for performance
            NoOutput = $true               # v2.10: Suppress Write-Host popups
            NoError = $true                # v2.10: Suppress error popups
            x64 = $true                    # v2.9: 64-bit compilation
            Version = "3.5.0.0"
            Company = "Cymantis"
            Product = "CyAudit"
            Description = $script.Description
            Copyright = "Cymantis 2025"
            Trademark = "CyAudit"
        }

        if ($script.RequireAdmin) {
            $ps2exeParams.RequireAdmin = $true
        }

        Invoke-PS2EXE @ps2exeParams -ErrorAction Stop | Out-Null

        if (Test-Path $exePath) {
            $size = [math]::Round((Get-Item $exePath).Length / 1KB, 1)
            Write-Host "      OK: $exeName ($size KB)" -ForegroundColor Green
            $successCount++
        } else {
            Write-Host "      FAIL: $exeName (output not created)" -ForegroundColor Red
            $failCount++
        }
    }
    catch {
        Write-Host "      FAIL: $exeName - $($_.Exception.Message)" -ForegroundColor Red
        $failCount++
    }
}

# Cleanup temp directory
Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue

# Summary
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Build Complete" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Success: $successCount" -ForegroundColor Green
Write-Host "  Failed:  $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Output:  $OutputDir" -ForegroundColor Gray
Write-Host ""

if ($failCount -gt 0) {
    Write-Host "[WARNING] Some compilations failed. Check errors above." -ForegroundColor Yellow
    exit 1
}

Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Copy the 'Build' folder back to your Mac" -ForegroundColor White
Write-Host "  2. Place it in: Enterprise/CyAudit_3.5/Build/" -ForegroundColor White
Write-Host "  3. Run: ./build.sh --protected" -ForegroundColor White
Write-Host ""
