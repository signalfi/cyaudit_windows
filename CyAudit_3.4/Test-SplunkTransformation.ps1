#Requires -Version 5.1

<#
.SYNOPSIS
    Validates CyAudit transformed data for Splunk ingestion

.DESCRIPTION
    This script validates that transformed NDJSON files are properly formatted
    and ready for Splunk Cloud ingestion. Validates:
    - JSON syntax
    - Encoding (UTF-8)
    - Required fields presence
    - Timestamp format
    - File structure
    - Event counts

.PARAMETER Path
    Path to SplunkReady directory containing transformed JSON files

.PARAMETER ShowSampleEvents
    Display sample events from each file

.PARAMETER GenerateSampleQueries
    Generate sample Splunk search queries

.EXAMPLE
    .\Test-SplunkTransformation.ps1 -Path ".\SplunkReady"

.EXAMPLE
    .\Test-SplunkTransformation.ps1 -Path ".\SplunkReady" -ShowSampleEvents -GenerateSampleQueries -Verbose

.NOTES
    Version: 1.0
    Author: CyAudit Splunk Integration
    Created: 2025-11-12
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$Path,

    [switch]$ShowSampleEvents,

    [switch]$GenerateSampleQueries
)

# Script version
$ScriptVersion = "1.0.0"

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " CyAudit Splunk Transformation Validation v$ScriptVersion" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

#region Helper Functions

function Write-ValidationLog {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error", "Test")]
        [string]$Level = "Info"
    )

    $color = switch ($Level) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Test" { "Cyan" }
        default { "White" }
    }

    $prefix = switch ($Level) {
        "Success" { "[✓]" }
        "Warning" { "[!]" }
        "Error" { "[✗]" }
        "Test" { "[?]" }
        default { "[•]" }
    }

    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Test-JsonSyntax {
    param([string]$FilePath)

    $errors = @()
    $lineNumber = 0

    try {
        $lines = Get-Content -Path $FilePath -Encoding UTF8

        foreach ($line in $lines) {
            $lineNumber++

            if ([string]::IsNullOrWhiteSpace($line)) {
                $errors += "Line $lineNumber`: Empty line (should not exist in NDJSON)"
                continue
            }

            try {
                $null = $line | ConvertFrom-Json -ErrorAction Stop
            } catch {
                $errors += "Line $lineNumber`: Invalid JSON - $($_.Exception.Message)"
            }
        }

        return @{
            Valid = ($errors.Count -eq 0)
            Errors = $errors
            LineCount = $lineNumber
        }

    } catch {
        return @{
            Valid = $false
            Errors = @("Failed to read file: $($_.Exception.Message)")
            LineCount = 0
        }
    }
}

function Test-RequiredFields {
    param([string]$FilePath)

    $requiredFields = @('@timestamp', 'sourcetype', 'computer_name', 'audit_date', 'event_type')
    $missingFields = @()

    try {
        $firstLine = Get-Content -Path $FilePath -Encoding UTF8 -TotalCount 1

        if ($firstLine) {
            $event = $firstLine | ConvertFrom-Json

            foreach ($field in $requiredFields) {
                if (-not ($event.PSObject.Properties.Name -contains $field)) {
                    $missingFields += $field
                }
            }
        }

        return @{
            Valid = ($missingFields.Count -eq 0)
            MissingFields = $missingFields
        }

    } catch {
        return @{
            Valid = $false
            MissingFields = @("Error reading file: $($_.Exception.Message)")
        }
    }
}

function Test-TimestampFormat {
    param([string]$FilePath)

    $invalidTimestamps = @()

    try {
        $lines = Get-Content -Path $FilePath -Encoding UTF8 -TotalCount 10

        $lineNumber = 0
        foreach ($line in $lines) {
            $lineNumber++

            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            # Check timestamp in raw JSON before ConvertFrom-Json parses it
            if ($line -match '"@timestamp"\s*:\s*"([^"]+)"') {
                $timestampValue = $matches[1]

                # Check if timestamp is ISO 8601 format
                if ($timestampValue -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$') {
                    $invalidTimestamps += "Line $lineNumber`: Invalid timestamp format: $timestampValue"
                }
            }
        }

        return @{
            Valid = ($invalidTimestamps.Count -eq 0)
            InvalidTimestamps = $invalidTimestamps
        }

    } catch {
        return @{
            Valid = $false
            InvalidTimestamps = @("Error validating timestamps: $($_.Exception.Message)")
        }
    }
}

function Test-Encoding {
    param([string]$FilePath)

    try {
        # Read first few bytes to check for BOM
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)

        if ($bytes.Length -ge 3) {
            # Check for UTF-8 BOM (EF BB BF) - acceptable
            $hasUTF8BOM = ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)

            # Check for UTF-16 LE BOM (FF FE) - not acceptable
            $hasUTF16LEBOM = ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE)

            # Check for UTF-16 BE BOM (FE FF) - not acceptable
            $hasUTF16BEBOM = ($bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF)

            if ($hasUTF16LEBOM -or $hasUTF16BEBOM) {
                return @{
                    Valid = $false
                    Encoding = "UTF-16 (INVALID - must be UTF-8)"
                }
            }

            # UTF-8 with or without BOM is acceptable
            return @{
                Valid = $true
                Encoding = if ($hasUTF8BOM) { "UTF-8 with BOM" } else { "UTF-8" }
            }
        }

        return @{
            Valid = $true
            Encoding = "UTF-8 (assumed)"
        }

    } catch {
        return @{
            Valid = $false
            Encoding = "Unknown - Error: $($_.Exception.Message)"
        }
    }
}

function Get-FileStats {
    param([string]$FilePath)

    try {
        $lines = Get-Content -Path $FilePath -Encoding UTF8
        $file = Get-Item $FilePath

        $firstEvent = $null
        $sourcetype = "Unknown"
        $computerName = "Unknown"

        if ($lines.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($lines[0])) {
            $firstEvent = $lines[0] | ConvertFrom-Json
            $sourcetype = $firstEvent.sourcetype
            $computerName = $firstEvent.computer_name
        }

        return @{
            FileName = $file.Name
            EventCount = $lines.Count
            FileSizeKB = [Math]::Round($file.Length / 1KB, 2)
            Sourcetype = $sourcetype
            ComputerName = $computerName
            FirstEvent = $firstEvent
        }

    } catch {
        return @{
            FileName = (Get-Item $FilePath).Name
            EventCount = 0
            FileSizeKB = 0
            Sourcetype = "Error"
            ComputerName = "Error"
            FirstEvent = $null
        }
    }
}

#endregion

#region Main Validation

try {
    Write-ValidationLog "Validation Path: $Path" -Level Info
    Write-Host ""

    # Get all JSON files
    $jsonFiles = Get-ChildItem -Path $Path -Filter "*.json" -File | Sort-Object Name

    if ($jsonFiles.Count -eq 0) {
        Write-ValidationLog "No JSON files found in $Path" -Level Error
        exit 1
    }

    Write-ValidationLog "Found $($jsonFiles.Count) files to validate" -Level Info
    Write-Host ""

    Write-Host "───────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host " Running Validation Tests" -ForegroundColor Cyan
    Write-Host "───────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""

    # Initialize counters
    $totalFiles = $jsonFiles.Count
    $filesProcessed = 0
    $filesPassed = 0
    $filesFailed = 0
    $totalEvents = 0
    $totalSizeKB = 0
    $allStats = @()

    # Validate each file
    foreach ($file in $jsonFiles) {
        $filesProcessed++

        Write-Host "[$filesProcessed/$totalFiles] Validating: $($file.Name)" -ForegroundColor Yellow
        Write-Host ""

        $testsPassed = 0
        $testsFailed = 0

        # Test 1: JSON Syntax
        Write-ValidationLog "  Test 1: JSON Syntax..." -Level Test
        $jsonTest = Test-JsonSyntax -FilePath $file.FullName

        if ($jsonTest.Valid) {
            Write-ValidationLog "    ✓ All $($jsonTest.LineCount) events have valid JSON syntax" -Level Success
            $testsPassed++
        } else {
            Write-ValidationLog "    ✗ JSON syntax errors found:" -Level Error
            foreach ($jsonError in $jsonTest.Errors | Select-Object -First 5) {
                Write-ValidationLog "      - $jsonError" -Level Error
            }
            if ($jsonTest.Errors.Count -gt 5) {
                Write-ValidationLog "      ... and $($jsonTest.Errors.Count - 5) more errors" -Level Error
            }
            $testsFailed++
        }

        # Test 2: Encoding
        Write-ValidationLog "  Test 2: File Encoding..." -Level Test
        $encodingTest = Test-Encoding -FilePath $file.FullName

        if ($encodingTest.Valid) {
            Write-ValidationLog "    ✓ Encoding: $($encodingTest.Encoding)" -Level Success
            $testsPassed++
        } else {
            Write-ValidationLog "    ✗ Invalid encoding: $($encodingTest.Encoding)" -Level Error
            $testsFailed++
        }

        # Test 3: Required Fields
        Write-ValidationLog "  Test 3: Required Fields..." -Level Test
        $fieldsTest = Test-RequiredFields -FilePath $file.FullName

        if ($fieldsTest.Valid) {
            Write-ValidationLog "    ✓ All required fields present" -Level Success
            $testsPassed++
        } else {
            Write-ValidationLog "    ✗ Missing required fields:" -Level Error
            foreach ($field in $fieldsTest.MissingFields) {
                Write-ValidationLog "      - $field" -Level Error
            }
            $testsFailed++
        }

        # Test 4: Timestamp Format
        Write-ValidationLog "  Test 4: Timestamp Format..." -Level Test
        $timestampTest = Test-TimestampFormat -FilePath $file.FullName

        if ($timestampTest.Valid) {
            Write-ValidationLog "    ✓ Timestamps are ISO 8601 compliant" -Level Success
            $testsPassed++
        } else {
            Write-ValidationLog "    ✗ Invalid timestamp formats:" -Level Error
            foreach ($invalidTs in $timestampTest.InvalidTimestamps | Select-Object -First 3) {
                Write-ValidationLog "      - $invalidTs" -Level Error
            }
            $testsFailed++
        }

        # Get file stats
        $stats = Get-FileStats -FilePath $file.FullName
        $allStats += $stats
        $totalEvents += $stats.EventCount
        $totalSizeKB += $stats.FileSizeKB

        Write-Host ""
        Write-ValidationLog "  File Statistics:" -Level Info
        Write-ValidationLog "    Events: $($stats.EventCount)" -Level Info
        Write-ValidationLog "    Size: $($stats.FileSizeKB) KB" -Level Info
        Write-ValidationLog "    Sourcetype: $($stats.Sourcetype)" -Level Info
        Write-ValidationLog "    Computer: $($stats.ComputerName)" -Level Info

        # Show sample event if requested
        if ($ShowSampleEvents -and $stats.FirstEvent) {
            Write-Host ""
            Write-ValidationLog "  Sample Event (first):" -Level Info
            Write-Host ($stats.FirstEvent | ConvertTo-Json -Depth 3) -ForegroundColor Gray
        }

        Write-Host ""

        # Summary for this file
        if ($testsFailed -eq 0) {
            Write-ValidationLog "  ✓ ALL TESTS PASSED ($testsPassed/$testsPassed)" -Level Success
            $filesPassed++
        } else {
            Write-ValidationLog "  ✗ SOME TESTS FAILED ($testsPassed passed, $testsFailed failed)" -Level Error
            $filesFailed++
        }

        Write-Host ""
        Write-Host "───────────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host ""
    }

    # Generate overall summary
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor $(if ($filesFailed -eq 0) { "Green" } else { "Yellow" })
    Write-Host " Validation Summary" -ForegroundColor $(if ($filesFailed -eq 0) { "Green" } else { "Yellow" })
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor $(if ($filesFailed -eq 0) { "Green" } else { "Yellow" })
    Write-Host ""

    Write-ValidationLog "Files Validated: $totalFiles" -Level Info
    Write-ValidationLog "Files Passed: $filesPassed" -Level $(if ($filesPassed -eq $totalFiles) { "Success" } else { "Warning" })
    Write-ValidationLog "Files Failed: $filesFailed" -Level $(if ($filesFailed -gt 0) { "Error" } else { "Success" })
    Write-ValidationLog "Total Events: $totalEvents" -Level Info
    Write-ValidationLog "Total Size: $([Math]::Round($totalSizeKB / 1024, 2)) MB" -Level Info

    Write-Host ""

    # Show breakdown by sourcetype
    Write-ValidationLog "Events by Sourcetype:" -Level Info
    $allStats | Group-Object -Property Sourcetype | Sort-Object Count -Descending | ForEach-Object {
        Write-ValidationLog "  $($_.Name): $($_.Group | Measure-Object -Property EventCount -Sum | Select-Object -ExpandProperty Sum) events" -Level Info
    }

    Write-Host ""

    # Generate sample queries if requested
    if ($GenerateSampleQueries) {
        Write-Host "───────────────────────────────────────────────────────────────" -ForegroundColor Cyan
        Write-Host " Sample Splunk Queries" -ForegroundColor Cyan
        Write-Host "───────────────────────────────────────────────────────────────" -ForegroundColor Cyan
        Write-Host ""

        $computerName = $allStats[0].ComputerName

        Write-Host "# Count all events by sourcetype" -ForegroundColor Green
        Write-Host "index=cyaudit | stats count by sourcetype" -ForegroundColor White
        Write-Host ""

        Write-Host "# View STIG compliance summary" -ForegroundColor Green
        Write-Host "index=cyaudit sourcetype=cyaudit:stig_* | stats count by compliance_status, compliance_framework" -ForegroundColor White
        Write-Host ""

        Write-Host "# List non-compliant STIG checks" -ForegroundColor Green
        Write-Host "index=cyaudit sourcetype=cyaudit:stig_* compliance_status=fail | table STIG_ID, Description, Status" -ForegroundColor White
        Write-Host ""

        Write-Host "# View user accounts" -ForegroundColor Green
        Write-Host "index=cyaudit sourcetype=cyaudit:users | table UserName, AccountDisabled, PasswordRequired, LastLogon" -ForegroundColor White
        Write-Host ""

        Write-Host "# View running services" -ForegroundColor Green
        Write-Host "index=cyaudit sourcetype=cyaudit:services service_status=running | stats count by ServiceName, StartMode" -ForegroundColor White
        Write-Host ""

        Write-Host "# Missing critical patches" -ForegroundColor Green
        Write-Host "index=cyaudit sourcetype=cyaudit:missinghotfixes | table KBNum, Description, Rating" -ForegroundColor White
        Write-Host ""

        Write-Host "# System inventory" -ForegroundColor Green
        Write-Host "index=cyaudit sourcetype=cyaudit:systeminfo | table computer_name, Caption, Version, Domain, DomainRole" -ForegroundColor White
        Write-Host ""

        Write-Host "# Compliance rate by computer" -ForegroundColor Green
        Write-Host "index=cyaudit sourcetype=cyaudit:executive_summary | table computer_name, OverallComplianceRate, CompliantChecks, NonCompliantChecks" -ForegroundColor White
        Write-Host ""
    }

    # Final result
    Write-Host ""
    if ($filesFailed -eq 0) {
        Write-ValidationLog "✓ All files passed validation! Data is ready for Splunk." -Level Success
        Write-Host ""
        Write-ValidationLog "Next step: Upload to Splunk Cloud using Upload-ToSplunkCloud.ps1" -Level Info
        exit 0
    } else {
        Write-ValidationLog "✗ Validation completed with errors. Please review and fix issues." -Level Error
        exit 1
    }

} catch {
    Write-ValidationLog "FATAL ERROR: $($_.Exception.Message)" -Level Error
    Write-ValidationLog "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    exit 1
}

#endregion
