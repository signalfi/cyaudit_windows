#Requires -Version 5.1

<#
.SYNOPSIS
    Upload CyAudit transformed data to Splunk Cloud via HTTP Event Collector (HEC)

.DESCRIPTION
    This script uploads Splunk-ready NDJSON files to Splunk Cloud using the
    HTTP Event Collector (HEC) API. Features include:
    - Batch processing with configurable batch size
    - Progress tracking and reporting
    - Retry logic for failed uploads
    - SSL/TLS support
    - Detailed logging

.PARAMETER Path
    Path to SplunkReady directory containing transformed JSON files

.PARAMETER HecToken
    Splunk HEC authentication token (from Splunk Cloud UI)

.PARAMETER HecUrl
    Splunk HEC endpoint URL (e.g., https://inputs.splunkcloud.com:8088)

.PARAMETER Index
    Splunk index name (default: cyaudit)

.PARAMETER BatchSize
    Number of events to send per HTTP request (default: 100)

.PARAMETER MaxRetries
    Maximum number of retry attempts for failed uploads (default: 3)

.PARAMETER Verbose
    Enable detailed logging

.EXAMPLE
    .\Upload-ToSplunkCloud.ps1 `
        -Path ".\SplunkReady" `
        -HecToken "12345678-1234-1234-1234-123456789012" `
        -HecUrl "https://inputs.splunkcloud.com:8088"

.EXAMPLE
    .\Upload-ToSplunkCloud.ps1 `
        -Path ".\SplunkReady" `
        -HecToken "12345678-1234-1234-1234-123456789012" `
        -HecUrl "https://inputs.splunkcloud.com:8088" `
        -Index "cyaudit" `
        -BatchSize 50 `
        -Verbose

.NOTES
    Version: 1.0
    Author: CyAudit Splunk Integration
    Created: 2025-11-12

    Prerequisites:
    1. HEC token created in Splunk Cloud (Settings > Data Inputs > HTTP Event Collector)
    2. Cyaudit index created in Splunk Cloud
    3. Transformed data in NDJSON format (from Transform-CyAuditForSplunk.ps1)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$Path,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$HecToken,

    [Parameter(Mandatory=$true)]
    [ValidatePattern('^https?://')]
    [string]$HecUrl,

    [Parameter(Mandatory=$false)]
    [string]$Index = "cyaudit",

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 1000)]
    [int]$BatchSize = 100,

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 10)]
    [int]$MaxRetries = 3
)

# Script version
$ScriptVersion = "1.0.0"
$UploadStartTime = Get-Date

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " CyAudit to Splunk Cloud Upload via HEC v$ScriptVersion" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

#region Helper Functions

function Write-UploadLog {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Level = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        default { "White" }
    }

    $prefix = switch ($Level) {
        "Success" { "[OK]" }
        "Warning" { "[!]" }
        "Error" { "[X]" }
        default { "[*]" }
    }

    Write-Host "$timestamp $prefix $Message" -ForegroundColor $color
}

function Send-HECBatch {
    <#
    .SYNOPSIS
        Sends a batch of events to Splunk HEC
    #>
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Events,

        [Parameter(Mandatory=$true)]
        [string]$HecToken,

        [Parameter(Mandatory=$true)]
        [string]$HecUrl,

        [Parameter(Mandatory=$true)]
        [string]$Index,

        [Parameter(Mandatory=$false)]
        [int]$RetryCount = 0,

        [Parameter(Mandatory=$false)]
        [int]$MaxRetries = 3
    )

    # Build HEC endpoint URL
    $hecEndpoint = "$HecUrl/services/collector/event"

    # Build headers
    $headers = @{
        "Authorization" = "Splunk $HecToken"
        "Content-Type" = "application/json"
    }

    try {
        # Convert events to HEC format (one JSON object per line)
        $hecPayload = ""
        foreach ($event in $Events) {
            # Parse the event JSON
            $eventObj = $event | ConvertFrom-Json

            # Build HEC event wrapper
            $hecEvent = @{
                "event" = $eventObj
                "index" = $Index
            }

            # Extract sourcetype if present
            if ($eventObj.sourcetype) {
                $hecEvent["sourcetype"] = $eventObj.sourcetype
            }

            # Extract timestamp if present
            if ($eventObj.'@timestamp') {
                # Convert ISO 8601 to epoch time (HEC format)
                try {
                    $dt = [DateTime]::Parse($eventObj.'@timestamp')
                    $epoch = [Math]::Floor((New-TimeSpan -Start (Get-Date "1970-01-01") -End $dt).TotalSeconds)
                    $hecEvent["time"] = $epoch
                } catch {
                    # If timestamp parsing fails, let Splunk use ingestion time
                    Write-Verbose "Failed to parse timestamp for event, using ingestion time"
                }
            }

            # Convert to JSON and append (NDJSON format for HEC)
            $hecPayload += ($hecEvent | ConvertTo-Json -Compress -Depth 10) + "`n"
        }

        # Send to HEC
        $response = Invoke-RestMethod -Uri $hecEndpoint `
                                      -Method Post `
                                      -Headers $headers `
                                      -Body $hecPayload `
                                      -ContentType "application/json" `
                                      -ErrorAction Stop

        # Check response
        if ($response.code -eq 0) {
            return @{
                Success = $true
                EventsSent = $Events.Count
                Response = $response
            }
        } else {
            Write-UploadLog "HEC returned error code $($response.code): $($response.text)" -Level Warning
            return @{
                Success = $false
                EventsSent = 0
                Error = $response.text
            }
        }

    } catch {
        $errorMessage = $_.Exception.Message

        # Check if this is a retryable error
        $retryable = $errorMessage -match "(timeout|connection|503|504)" -or $RetryCount -lt $MaxRetries

        if ($retryable -and $RetryCount -lt $MaxRetries) {
            $nextRetry = $RetryCount + 1
            $waitTime = [Math]::Pow(2, $nextRetry)  # Exponential backoff

            Write-UploadLog "Upload failed (attempt $($RetryCount + 1)/$MaxRetries): $errorMessage" -Level Warning
            Write-UploadLog "Retrying in $waitTime seconds..." -Level Warning

            Start-Sleep -Seconds $waitTime

            # Retry
            return Send-HECBatch -Events $Events `
                                 -HecToken $HecToken `
                                 -HecUrl $HecUrl `
                                 -Index $Index `
                                 -RetryCount $nextRetry `
                                 -MaxRetries $MaxRetries
        } else {
            Write-UploadLog "Upload failed after $($RetryCount + 1) attempts: $errorMessage" -Level Error
            return @{
                Success = $false
                EventsSent = 0
                Error = $errorMessage
            }
        }
    }
}

function Test-HECConnection {
    <#
    .SYNOPSIS
        Tests connectivity to Splunk HEC endpoint
    #>
    param(
        [string]$HecToken,
        [string]$HecUrl
    )

    Write-UploadLog "Testing HEC connection to $HecUrl..."

    try {
        # Build test endpoint URL (health check)
        $healthEndpoint = "$HecUrl/services/collector/health"

        # Test connection
        $headers = @{
            "Authorization" = "Splunk $HecToken"
        }

        $response = Invoke-RestMethod -Uri $healthEndpoint `
                                      -Method Get `
                                      -Headers $headers `
                                      -TimeoutSec 10 `
                                      -ErrorAction Stop

        Write-UploadLog "HEC connection successful!" -Level Success
        return $true

    } catch {
        Write-UploadLog "HEC connection failed: $($_.Exception.Message)" -Level Error
        Write-UploadLog "Please verify:" -Level Error
        Write-UploadLog "  - HEC endpoint URL is correct" -Level Error
        Write-UploadLog "  - HEC token is valid" -Level Error
        Write-UploadLog "  - HEC is enabled in Splunk Cloud" -Level Error
        Write-UploadLog "  - Network connectivity to Splunk Cloud" -Level Error
        return $false
    }
}

#endregion

#region Main Execution

try {
    Write-UploadLog "Upload Configuration:"
    Write-UploadLog "  Source Path: $Path"
    Write-UploadLog "  HEC Endpoint: $HecUrl"
    Write-UploadLog "  Target Index: $Index"
    Write-UploadLog "  Batch Size: $BatchSize events"
    Write-Host ""

    # Test HEC connection first
    if (-not (Test-HECConnection -HecToken $HecToken -HecUrl $HecUrl)) {
        Write-UploadLog "Upload aborted due to connection test failure" -Level Error
        exit 1
    }

    Write-Host ""
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Processing Files" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan

    # Get all JSON files
    $jsonFiles = Get-ChildItem -Path $Path -Filter "*.json" -File | Sort-Object Name

    if ($jsonFiles.Count -eq 0) {
        Write-UploadLog "No JSON files found in $Path" -Level Warning
        exit 0
    }

    Write-UploadLog "Found $($jsonFiles.Count) files to upload"
    Write-Host ""

    # Initialize counters
    $totalEvents = 0
    $totalEventsSent = 0
    $totalFiles = $jsonFiles.Count
    $filesProcessed = 0
    $filesSucceeded = 0
    $filesFailed = 0

    # Process each file
    foreach ($file in $jsonFiles) {
        $filesProcessed++

        Write-UploadLog "[$filesProcessed/$totalFiles] Processing: $($file.Name)"

        try {
            # Read file (UTF-8 NDJSON format)
            $lines = Get-Content -Path $file.FullName -Encoding UTF8

            if ($lines.Count -eq 0) {
                Write-UploadLog "  File is empty, skipping" -Level Warning
                continue
            }

            $totalEvents += $lines.Count
            Write-Verbose "  Events in file: $($lines.Count)"

            # Split into batches
            $batches = @()
            for ($i = 0; $i -lt $lines.Count; $i += $BatchSize) {
                $end = [Math]::Min($i + $BatchSize, $lines.Count)
                $batch = $lines[$i..($end-1)]
                $batches += ,$batch
            }

            Write-Verbose "  Split into $($batches.Count) batches"

            # Upload each batch
            $fileEventsSent = 0
            foreach ($batch in $batches) {
                $result = Send-HECBatch -Events $batch `
                                        -HecToken $HecToken `
                                        -HecUrl $HecUrl `
                                        -Index $Index `
                                        -MaxRetries $MaxRetries

                if ($result.Success) {
                    $fileEventsSent += $result.EventsSent
                } else {
                    Write-UploadLog "  Batch upload failed: $($result.Error)" -Level Error
                }
            }

            $totalEventsSent += $fileEventsSent

            if ($fileEventsSent -eq $lines.Count) {
                Write-UploadLog "  [OK] Uploaded $fileEventsSent events" -Level Success
                $filesSucceeded++
            } else {
                Write-UploadLog "  ! Uploaded $fileEventsSent / $($lines.Count) events" -Level Warning
                $filesFailed++
            }

        } catch {
            Write-UploadLog "  Failed to process file: $($_.Exception.Message)" -Level Error
            $filesFailed++
        }

        Write-Host ""
    }

    # Calculate upload duration
    $uploadDuration = (Get-Date) - $UploadStartTime
    $eventsPerSecond = if ($uploadDuration.TotalSeconds -gt 0) {
        [Math]::Round($totalEventsSent / $uploadDuration.TotalSeconds, 2)
    } else {
        0
    }

    # Generate summary
    Write-Host "===================================================================" -ForegroundColor Green
    Write-Host " Upload Complete!" -ForegroundColor Green
    Write-Host "===================================================================" -ForegroundColor Green
    Write-Host ""

    Write-UploadLog "Summary:" -Level Success
    Write-UploadLog "  Files Processed: $filesProcessed" -Level Success
    Write-UploadLog "  Files Succeeded: $filesSucceeded" -Level Success
    Write-UploadLog "  Files Failed: $filesFailed" -Level $(if ($filesFailed -gt 0) { "Warning" } else { "Success" })
    Write-UploadLog "  Total Events Sent: $totalEventsSent / $totalEvents" -Level Success
    Write-UploadLog "  Upload Duration: $($uploadDuration.ToString('hh\:mm\:ss'))" -Level Success
    Write-UploadLog "  Average Speed: $eventsPerSecond events/second" -Level Success

    Write-Host ""
    Write-UploadLog "Next Steps:" -Level Info
    Write-UploadLog "  1. Log into Splunk Cloud" -Level Info
    Write-UploadLog "  2. Run search: index=$Index | stats count by sourcetype" -Level Info
    Write-UploadLog "  3. Verify data in Splunk Search & Reporting app" -Level Info
    Write-Host ""

    # Exit with appropriate code
    if ($filesFailed -gt 0) {
        Write-UploadLog "Upload completed with errors" -Level Warning
        exit 1
    } else {
        exit 0
    }

} catch {
    Write-UploadLog "FATAL ERROR: $($_.Exception.Message)" -Level Error
    Write-UploadLog "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    exit 1
}

#endregion
