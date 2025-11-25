#Requires -Version 5.1

<#
.SYNOPSIS
    Transform CyAudit Opus v3.5 output for Splunk Cloud ingestion

.DESCRIPTION
    This script transforms CyAudit's 52 output files into Splunk-optimized
    newline-delimited JSON (NDJSON) format with:
    - UTF-16 LE → UTF-8 encoding conversion
    - Timestamp normalization to ISO 8601
    - Nested JSON flattening
    - Multi-value field expansion
    - Numeric code translation
    - PowerSTIG XML → JSON conversion
    - Metadata enrichment

.PARAMETER InputPath
    Path to CyAudit output directory (e.g., "HOSTNAME-20251111_160412")

.PARAMETER OutputPath
    Path where transformed Splunk-ready files will be saved (default: ./SplunkReady)

.PARAMETER IncludeAuxiliaryFiles
    Include transformation of auxiliary text files (gpresult.txt, DetailedAuditSettings.txt)

.PARAMETER Verbose
    Enable detailed logging

.EXAMPLE
    .\Transform-CyAuditForSplunk.ps1 -InputPath ".\JDBC08-20251111_160412" -OutputPath ".\SplunkReady"

.EXAMPLE
    .\Transform-CyAuditForSplunk.ps1 -InputPath ".\SERVER01-20251111_160412" -IncludeAuxiliaryFiles -Verbose

.NOTES
    Version: 1.0
    Author: CyAudit Splunk Integration
    Created: 2025-11-12
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$InputPath,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\SplunkReady",

    [switch]$IncludeAuxiliaryFiles,

    [switch]$Force
)

# Script version
$ScriptVersion = "1.0.0"
$TransformDate = Get-Date

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " CyAudit to Splunk Cloud Transformation Pipeline v$ScriptVersion" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

#region Helper Functions

function Write-TransformLog {
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

function ConvertTo-ISO8601 {
    <#
    .SYNOPSIS
        Converts various datetime formats to ISO 8601
    #>
    param(
        [Parameter(ValueFromPipeline)]
        $InputValue
    )

    process {
        if ($null -eq $InputValue -or $InputValue -eq "") {
            return $null
        }

        try {
            # Handle .NET JSON date format: /Date(epochms)/
            if ($InputValue -is [string] -and $InputValue -match '/Date\((\d+)\)/') {
                $epochMs = [long]$matches[1]
                $dateTime = [DateTimeOffset]::FromUnixTimeMilliseconds($epochMs)
                return $dateTime.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", [System.Globalization.CultureInfo]::InvariantCulture)
            }

            # Handle standard datetime objects
            if ($InputValue -is [DateTime]) {
                return $InputValue.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", [System.Globalization.CultureInfo]::InvariantCulture)
            }

            # Handle string datetime
            if ($InputValue -is [string]) {
                # Try parsing as datetime
                $parsedDate = [DateTime]::MinValue
                if ([DateTime]::TryParse($InputValue, [ref]$parsedDate)) {
                    return $parsedDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", [System.Globalization.CultureInfo]::InvariantCulture)
                }
            }

            # If all else fails, return as-is
            return $InputValue

        } catch {
            Write-Verbose "Failed to convert datetime: $InputValue"
            return $InputValue
        }
    }
}

function Expand-RegistryType {
    <#
    .SYNOPSIS
        Translates numeric registry type codes to readable names
    #>
    param([int]$Type)

    $typeMap = @{
        0 = "None"
        1 = "String"
        2 = "ExpandString"
        3 = "Binary"
        4 = "DWord"
        7 = "MultiString"
        11 = "QWord"
    }

    if ($typeMap.ContainsKey($Type)) {
        return $typeMap[$Type]
    }
    return "Unknown"
}

function Expand-FileSystemRights {
    <#
    .SYNOPSIS
        Translates FileSystemRights bitmask to array of permission names
    #>
    param([int]$Rights)

    $permissions = @()

    # Common combinations
    if ($Rights -eq 2032127) { return @("FullControl") }
    if ($Rights -eq 1179817) { return @("Modify") }
    if ($Rights -eq 1179785) { return @("ReadAndExecute") }
    if ($Rights -eq 131241) { return @("Read") }
    if ($Rights -eq 278) { return @("Write") }

    # Bitwise flags
    if ($Rights -band 1) { $permissions += "ReadData" }
    if ($Rights -band 2) { $permissions += "WriteData" }
    if ($Rights -band 4) { $permissions += "AppendData" }
    if ($Rights -band 8) { $permissions += "ReadExtendedAttributes" }
    if ($Rights -band 16) { $permissions += "WriteExtendedAttributes" }
    if ($Rights -band 32) { $permissions += "ExecuteFile" }
    if ($Rights -band 64) { $permissions += "DeleteSubdirectoriesAndFiles" }
    if ($Rights -band 128) { $permissions += "ReadAttributes" }
    if ($Rights -band 256) { $permissions += "WriteAttributes" }
    if ($Rights -band 65536) { $permissions += "Delete" }
    if ($Rights -band 131072) { $permissions += "ReadPermissions" }
    if ($Rights -band 262144) { $permissions += "ChangePermissions" }
    if ($Rights -band 524288) { $permissions += "TakeOwnership" }

    if ($permissions.Count -eq 0) {
        $permissions += "Unknown_$Rights"
    }

    return $permissions
}

function Expand-AccessControlType {
    <#
    .SYNOPSIS
        Translates AccessControlType numeric code
    #>
    param($AccessControlType)

    if ($AccessControlType -eq 0 -or $AccessControlType -eq "0") {
        return "Allow"
    } elseif ($AccessControlType -eq 1 -or $AccessControlType -eq "1") {
        return "Deny"
    } else {
        return $AccessControlType
    }
}

function Read-UTF16Json {
    <#
    .SYNOPSIS
        Reads UTF-16 LE encoded JSON file and returns PowerShell objects
    #>
    param(
        [string]$FilePath
    )

    try {
        # Read file as UTF-16 LE (with BOM: 0xFF 0xFE)
        $content = Get-Content -Path $FilePath -Encoding Unicode -Raw

        # Parse JSON
        $objects = $content | ConvertFrom-Json

        return $objects

    } catch {
        Write-TransformLog "Failed to read UTF-16 JSON: $FilePath - $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Write-SplunkNDJson {
    <#
    .SYNOPSIS
        Writes PowerShell objects as UTF-8 newline-delimited JSON
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSObject[]]$Objects,

        [Parameter(Mandatory=$true)]
        [string]$OutputFile,

        [string]$Context,

        [int]$ProgressInterval = 200,

        [switch]$UseSimpleSerializer
    )

    # Derive a friendly context label for logging
    $contextLabel = if ($Context) { $Context } else { Split-Path -Path $OutputFile -Leaf }
    $total = $Objects.Count
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $streamWriter = $null

    try {
        # Ensure output directory exists (default to current directory if none specified)
        $outputDir = Split-Path -Parent $OutputFile
        if (-not $outputDir) { $outputDir = "." }
        [System.IO.Directory]::CreateDirectory($outputDir) | Out-Null

        Write-TransformLog "  NDJSON write start ($contextLabel): $total events -> $OutputFile" -Level Info

        # Build NDJSON lines in memory to avoid any StreamWriter close/flush stalls
        $encoding = New-Object System.Text.UTF8Encoding($false) # no BOM

        if ($total -eq 0) {
            [System.IO.File]::WriteAllText($OutputFile, "", $encoding)
            $stopwatch.Stop()
            Write-TransformLog "  NDJSON write complete ($contextLabel): 0 events in 0s" -Level Success
            return $true
        }

        $lines = New-Object System.Collections.Generic.List[string] $total
        # For smaller datasets, lower the progress interval so we still get a heartbeat
        $interval = if ($total -le 200) { 25 } else { [Math]::Max(50, $ProgressInterval) }

        function Escape-JsonString {
            param([string]$s)
            if ($null -eq $s) { return "" }
            $s = $s.Replace('\', '\\').Replace('"', '\"').Replace("`b", '\b').Replace("`f", '\f').Replace("`n", '\n').Replace("`r", '\r').Replace("`t", '\t')
            return $s
        }

        function Serialize-SimpleJson {
            param($obj)
            $sb = [System.Text.StringBuilder]::new()
            $sb.Append('{') | Out-Null
            $first = $true
            foreach ($prop in $obj.PSObject.Properties) {
                if (-not $first) { $sb.Append(',') | Out-Null } else { $first = $false }
                $name = Escape-JsonString $prop.Name
                $value = $prop.Value

                $sb.Append('"').Append($name).Append('":') | Out-Null
                if ($null -eq $value) {
                    $sb.Append('null') | Out-Null
                } elseif ($value -is [bool]) {
                    $sb.Append($(if ($value) { 'true' } else { 'false' })) | Out-Null
                } elseif ($value -is [int] -or $value -is [long] -or $value -is [double] -or $value -is [decimal]) {
                    $sb.Append(([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $value))) | Out-Null
                } else {
                    $sb.Append('"').Append((Escape-JsonString ([string]$value))).Append('"') | Out-Null
                }
            }
            $sb.Append('}') | Out-Null
            return $sb.ToString()
        }

        $count = 0
        foreach ($obj in $Objects) {
            $count++

            # Convert to JSON (compact, no indentation) with per-record guardrails
            try {
                if ($UseSimpleSerializer) {
                    $jsonLine = Serialize-SimpleJson -obj $obj
                } else {
                    $jsonLine = $obj | ConvertTo-Json -Compress -Depth 10 -ErrorAction Stop
                }
            } catch {
                Write-TransformLog "    Serialization error at item $count of $total ($contextLabel): $($_.Exception.Message)" -Level Error
                $fallback = @{
                    serialization_error = $($_.Exception.Message)
                    raw_object = $obj | Out-String
                }
                $jsonLine = $fallback | ConvertTo-Json -Compress -Depth 5
            }

            $lines.Add($jsonLine)

            # Progress indicator
            if ($count % $interval -eq 0 -or $count -eq $total) {
                Write-TransformLog "    Serialized $count / $total ($contextLabel)" -Level Info
            }
        }

        Write-TransformLog "  Writing NDJSON file ($contextLabel)..." -Level Info
        [System.IO.File]::WriteAllLines($OutputFile, $lines, $encoding)

        $stopwatch.Stop()
        $duration = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
        Write-TransformLog "  NDJSON write complete ($contextLabel): $total events in ${duration}s" -Level Success
        return $true

    } catch {
        $stopwatch.Stop()
        Write-TransformLog "Failed to write NDJSON ($contextLabel): $($_.Exception.Message)" -Level Error
        return $false
    } finally {
        # Ensure StreamWriter is always disposed
        if ($streamWriter) {
            try {
                $streamWriter.Dispose()
            } catch {
                # Ignore disposal errors
            }
        }
    }
}

function Get-ComputerNameFromPath {
    <#
    .SYNOPSIS
        Extracts computer name from CyAudit output directory path
    #>
    param([string]$Path)

    # Extract from directory name pattern: HOSTNAME-YYYYMMDD_HHMMSS
    $dirName = Split-Path -Leaf $Path
    if ($dirName -match '^(.+?)-\d{8}_\d{6}$') {
        return $matches[1]
    }

    # Fallback: look for files with hostname prefix
    $sampleFile = Get-ChildItem -Path $Path -Filter "*SystemInfo.json" -File | Select-Object -First 1
    if ($sampleFile) {
        if ($sampleFile.BaseName -match '^(.+?)SystemInfo$') {
            return $matches[1]
        }
    }

    return "Unknown"
}

function Get-AuditDateFromPath {
    <#
    .SYNOPSIS
        Extracts audit date from CyAudit output directory path or files
    #>
    param([string]$Path)

    # Extract from directory name pattern: HOSTNAME-YYYYMMDD_HHMMSS or "YYYY-MM-DD HH.MM.SS"
    $dirName = Split-Path -Leaf $Path

    # Try pattern: HOSTNAME-YYYY-MM-DD HH.MM.SS
    if ($dirName -match '\-(\d{4})-(\d{2})-(\d{2}) (\d{2})\.(\d{2})\.(\d{2})$') {
        $year = $matches[1]
        $month = $matches[2]
        $day = $matches[3]
        $hour = $matches[4]
        $minute = $matches[5]
        $second = $matches[6]

        $dateTime = Get-Date -Year $year -Month $month -Day $day -Hour $hour -Minute $minute -Second $second
        return $dateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", [System.Globalization.CultureInfo]::InvariantCulture)
    }

    # Try pattern: HOSTNAME-YYYYMMDD_HHMMSS
    if ($dirName -match '\-(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})$') {
        $year = $matches[1]
        $month = $matches[2]
        $day = $matches[3]
        $hour = $matches[4]
        $minute = $matches[5]
        $second = $matches[6]

        $dateTime = Get-Date -Year $year -Month $month -Day $day -Hour $hour -Minute $minute -Second $second
        return $dateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", [System.Globalization.CultureInfo]::InvariantCulture)
    }

    # Fallback to current time
    return $TransformDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", [System.Globalization.CultureInfo]::InvariantCulture)
}

#endregion

#region Main Transformation Functions

function Transform-SystemInfo {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming System Information..."

    $filePath = Join-Path $InputPath "$($ComputerName)SystemInfo.json"
    if (-not (Test-Path $filePath)) {
        Write-TransformLog "SystemInfo.json not found, skipping" -Level Warning
        return $null
    }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    # Transform each object
    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:systeminfo'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'system_info'
            'ComputerName' = $item.ComputerName
            'Caption' = $item.Caption
            'ServicePack' = $item.ServicePack
            'Version' = $item.Version
            'RunDate' = ConvertTo-ISO8601 $item.RunDate
            'IPAddresses' = if ($item.IPAddresses) { $item.IPAddresses -split '; ' } else { @() }
            'Domain' = $item.Domain
            'DomainRole' = $item.DomainRole
            'CurrentUser' = $item.CurrentUser
        }
        $transformed += $obj
    }

    return $transformed
}

function Transform-Users {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Users..."

    $filePath = Join-Path $InputPath "$($ComputerName)Users.json"
    if (-not (Test-Path $filePath)) {
        Write-TransformLog "Users.json not found, skipping" -Level Warning
        return $null
    }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:users'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'user_account'
            'UserName' = $item.UserName
            'FullName' = $item.FullName
            'Description' = $item.Description
            'AccountType' = $item.AccountType
            'SID' = $item.SID
            'PasswordLastSet' = ConvertTo-ISO8601 $item.PasswordLastSet
            'Domain' = $item.Domain
            'PasswordChangeableDate' = ConvertTo-ISO8601 $item.PasswordChangeableDate
            'PasswordExpires' = ConvertTo-ISO8601 $item.PasswordExpires
            'PasswordRequired' = $item.PasswordRequired
            'AccountDisabled' = $item.AccountDisabled
            'AccountLocked' = $item.AccountLocked
            'LastLogon' = ConvertTo-ISO8601 $item.LastLogon
            'AccountExpires' = ConvertTo-ISO8601 $item.AccountExpires
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) user accounts" -Level Success
    return $transformed
}

function Transform-Groups {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Groups..."

    $filePath = Join-Path $InputPath "$($ComputerName)Groups.json"
    if (-not (Test-Path $filePath)) {
        Write-TransformLog "Groups.json not found, skipping" -Level Warning
        return $null
    }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:groups'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'group_membership'
            'Name' = $item.Name
            'SID' = $item.SID
            'Caption' = $item.Caption
            'Description' = $item.Description
            'Domain' = $item.Domain
            'Members' = if ($item.Members) { $item.Members -split '; ' } else { @() }
            'member_count' = if ($item.Members) { ($item.Members -split '; ').Count } else { 0 }
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) groups" -Level Success
    return $transformed
}

function Transform-PasswordPolicies {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Password Policies..."

    $filePath = Join-Path $InputPath "$($ComputerName)PasswordPolicies.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:passwordpolicies'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'security_policy'
            'Policy' = $item.Policy
            'Value' = $item.Value
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) password policies" -Level Success
    return $transformed
}

function Transform-AuditPolicies {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Audit Policies..."

    $filePath = Join-Path $InputPath "$($ComputerName)AuditPolicies.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:auditpolicies'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'security_policy'
            'Policy' = $item.Policy
            'Setting' = $item.Setting
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) audit policies" -Level Success
    return $transformed
}

function Transform-UserRights {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming User Rights..."

    $filePath = Join-Path $InputPath "$($ComputerName)UserRights.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:userrights'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'security_policy'
            'Right' = $item.Right
            'Assignees' = if ($item.Assignees) { $item.Assignees -split '; ' } else { @() }
            'assignee_count' = if ($item.Assignees) { ($item.Assignees -split '; ').Count } else { 0 }
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) user rights" -Level Success
    return $transformed
}

function Transform-RegistryValues {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Registry Values..."

    $filePath = Join-Path $InputPath "$($ComputerName)RegistryValues.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:registry'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'registry_value'
            'RegistryKey' = $item.RegistryKey
            'ValueName' = $item.ValueName
            'Data' = $item.Data
            'Type' = $item.Type
            'TypeName' = Expand-RegistryType -Type $item.Type
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) registry values" -Level Success
    return $transformed
}

function Transform-STIGRegistryCompliance {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming STIG Registry Compliance..."

    $filePath = Join-Path $InputPath "$($ComputerName)_STIG_Registry_Compliance.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = ConvertTo-ISO8601 $item.Timestamp
            'sourcetype' = 'cyaudit:stig_registry'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'stig_compliance'
            'compliance_framework' = 'DISA_STIG_V33_Registry'
            'STIG_ID' = $item.STIG_ID
            'Category' = $item.Category
            'Description' = $item.Description
            'Status' = $item.Status
            'compliance_status' = switch ($item.Status) {
                "Compliant" { "pass" }
                "Not Compliant" { "fail" }
                default { "review" }
            }
            'Finding' = $item.Finding
            'Expected' = $item.Expected
            'Actual' = $item.Actual
            'Source' = $item.Source
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) STIG registry checks" -Level Success
    return $transformed
}

function Transform-Services {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Services (may take a moment for large datasets)..."

    $filePath = Join-Path $InputPath "$($ComputerName)Services.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:services'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'service_configuration'
            'ServiceName' = $item.ServiceName
            'ServiceState' = $item.ServiceState
            'Caption' = $item.Caption
            'Description' = $item.Description
            'CanInteractWithDesktop' = $item.CanInteractWithDesktop
            'DisplayName' = $item.DisplayName
            'ErrorControl' = $item.ErrorControl
            'ExecutablePathName' = $item.ExecutablePathName
            'ServiceStarted' = $item.ServiceStarted
            'StartMode' = $item.StartMode
            'AccountName' = $item.AccountName
            'service_status' = if ($item.ServiceStarted -eq $true) { "running" } else { "stopped" }
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) services" -Level Success
    return $transformed
}

function Transform-WindowsFeatures {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Windows Features..."

    $filePath = Join-Path $InputPath "$($ComputerName)WindowsFeatures.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:features'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'windows_feature'
            'FeatureName' = $item.FeatureName
            'DisplayName' = $item.DisplayName
            'InstallState' = $item.InstallState
            'Required' = $item.Required
            'Compliant' = $item.Compliant
            'feature_status' = switch ($item.InstallState) {
                2 { "installed" }
                0 { "not_installed" }
                1 { "pending" }
                default { "unknown" }
            }
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) Windows features" -Level Success
    return $transformed
}

function Transform-FilePermissions {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming File Permissions..."

    $filePath = Join-Path $InputPath "$($ComputerName)FilePermissions.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        # Flatten nested IdentityReference if present
        $identity = if ($item.IdentityReference -is [PSCustomObject] -and $item.IdentityReference.Value) {
            $item.IdentityReference.Value
        } else {
            $item.IdentityReference
        }

        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:filepermissions'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'file_permission'
            'FilePath' = $item.FilePath
            'IdentityReference' = $identity
            'FileSystemRights' = $item.FileSystemRights
            'FileSystemRightsNames' = Expand-FileSystemRights -Rights $item.FileSystemRights
            'AccessControlType' = Expand-AccessControlType -AccessControlType $item.AccessControlType
            'IsInherited' = $item.IsInherited
            'InheritanceFlags' = $item.InheritanceFlags
            'PropagationFlags' = $item.PropagationFlags
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) file permissions" -Level Success
    return $transformed
}

function Transform-DirectoryPermissions {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Directory Permissions..."

    $filePath = Join-Path $InputPath "$($ComputerName)DirectoryPermissions.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        # Flatten nested IdentityReference
        $identity = if ($item.IdentityReference -is [PSCustomObject] -and $item.IdentityReference.Value) {
            $item.IdentityReference.Value
        } else {
            $item.IdentityReference
        }

        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:dirpermissions'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'directory_permission'
            'DirectoryPath' = $item.DirectoryPath
            'IdentityReference' = $identity
            'FileSystemRights' = $item.FileSystemRights
            'FileSystemRightsNames' = Expand-FileSystemRights -Rights $item.FileSystemRights
            'AccessControlType' = Expand-AccessControlType -AccessControlType $item.AccessControlType
            'IsInherited' = $item.IsInherited
            'InheritanceFlags' = $item.InheritanceFlags
            'PropagationFlags' = $item.PropagationFlags
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) directory permissions" -Level Success
    return $transformed
}

function Transform-Drives {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Drives..."

    $filePath = Join-Path $InputPath "$($ComputerName)Drives.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:drives'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'storage_info'
            'DriveLetter' = $item.DriveLetter
            'TotalSize' = $item.TotalSize
            'FreeSpace' = $item.FreeSpace
            'UsedSpace' = $item.UsedSpace
            'PercentFree' = $item.PercentFree
            'VolumeName' = $item.VolumeName
            'Path' = $item.Path
            'DriveType' = $item.DriveType
            'SerialNo' = $item.SerialNo
            'FileSystem' = $item.FileSystem
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) drives" -Level Success
    return $transformed
}

function Transform-HotFixes {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming HotFixes..."

    $filePath = Join-Path $InputPath "$($ComputerName)HotFixes.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:hotfixes'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'patch_installed'
            'Description' = $item.Description
            'HotFixID' = $item.HotFixID
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) hotfixes" -Level Success
    return $transformed
}

function Transform-MissingHotfixes {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Missing HotFixes..."

    $filePath = Join-Path $InputPath "$($ComputerName)MissingHotfixes.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:missinghotfixes'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'patch_missing'
            'severity' = 'critical'
            'KBNum' = $item.KBNum
            'Rating' = $item.Rating
            'Description' = $item.Description
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) missing hotfixes" -Level Success
    return $transformed
}

function Transform-LogSettings {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Log Settings..."

    $filePath = Join-Path $InputPath "$($ComputerName)LogSettings.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:logsettings'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'eventlog_configuration'
            'LogName' = $item.LogName
            'MaximumSizeKB' = $item.MaximumSizeKB
            'OverflowAction' = $item.OverflowAction
            'MinimumRetentionDays' = $item.MinimumRetentionDays
            'EnableRaisingEvents' = $item.EnableRaisingEvents
            'LogFilePath' = $item.LogFilePath
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) log settings" -Level Success
    return $transformed
}

function Transform-Shares {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Shares..."

    $filePath = Join-Path $InputPath "$($ComputerName)Shares.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:shares'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'network_share'
            'Name' = $item.Name
            'Path' = $item.Path
            'Caption' = $item.Caption
            'Type' = $item.Type
            'Permissions' = $item.Permissions
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) shares" -Level Success
    return $transformed
}

function Transform-STIGComplianceSummary {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming STIG Compliance Summary (V3.3)..."

    $filePath = Join-Path $InputPath "$($ComputerName)_STIG_Compliance_Summary_V3.3.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = ConvertTo-ISO8601 $item.Timestamp
            'sourcetype' = 'cyaudit:stig_summary_v33'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'stig_compliance'
            'compliance_framework' = 'DISA_STIG_V33'
            'STIG_ID' = $item.STIG_ID
            'Category' = $item.Category
            'Description' = $item.Description
            'Status' = $item.Status
            'compliance_status' = switch ($item.Status) {
                "Compliant" { "pass" }
                "Not Compliant" { "fail" }
                default { "review" }
            }
            'Finding' = $item.Finding
            'Expected' = $item.Expected
            'Actual' = $item.Actual
            'Source' = $item.Source
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed $($transformed.Count) V3.3 STIG checks" -Level Success
    return $transformed
}

function Transform-PowerSTIGFindings {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming PowerSTIG Findings..."

    $filePath = Join-Path $InputPath "$($ComputerName)_PowerSTIG_Findings.csv"
    if (-not (Test-Path $filePath)) {
        Write-TransformLog "PowerSTIG_Findings.csv not found, skipping" -Level Warning
        return $null
    }

    try {
        $data = Import-Csv -Path $filePath -Encoding UTF8

        $transformed = @()
        foreach ($item in $data) {
            $obj = [PSCustomObject]@{
                '@timestamp' = $AuditDate
                'sourcetype' = 'cyaudit:stig_powerstig'
                'computer_name' = $ComputerName
                'audit_date' = $AuditDate
                'event_type' = 'stig_compliance'
                'compliance_framework' = 'PowerSTIG'
                'STIG_ID' = $item.STIG_ID
                'ResourceType' = $item.ResourceType
                'ResourceId' = $item.ResourceId
                'Status' = $item.Status
                'InDesiredState' = [bool]::Parse($item.InDesiredState)
                'compliance_status' = if ($item.InDesiredState -eq 'True') { "pass" } else { "fail" }
                'ConfigurationName' = $item.ConfigurationName
                'Source' = $item.Source
                'EvaluationMethod' = $item.EvaluationMethod
            }
            $transformed += $obj
        }

        Write-TransformLog "  Transformed $($transformed.Count) PowerSTIG findings" -Level Success
        return $transformed

    } catch {
        Write-TransformLog "Failed to transform PowerSTIG findings: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Transform-STIGComparison {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming STIG Comparison..."

    $filePath = Join-Path $InputPath "$($ComputerName)_STIG_Comparison.csv"
    if (-not (Test-Path $filePath)) {
        Write-TransformLog "STIG_Comparison.csv not found, skipping" -Level Warning
        return $null
    }

    try {
        $data = Import-Csv -Path $filePath -Encoding UTF8

        $transformed = @()
        foreach ($item in $data) {
            $obj = [PSCustomObject]@{
                '@timestamp' = $AuditDate
                'sourcetype' = 'cyaudit:stig_comparison'
                'computer_name' = $ComputerName
                'audit_date' = $AuditDate
                'event_type' = 'stig_comparison'
                'compliance_framework' = 'STIG_Comparison'
                'STIG_ID' = $item.STIG_ID
                'V33_Status' = $item.V33_Status
                'PowerSTIG_Status' = $item.PowerSTIG_Status
                'Comparison' = $item.Comparison
                'Category' = $item.Category
                'Description' = $item.Description
            }
            $transformed += $obj
        }

        Write-TransformLog "  Transformed $($transformed.Count) comparison records" -Level Success
        return $transformed

    } catch {
        Write-TransformLog "Failed to transform STIG comparison: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Transform-STIGMergedResults {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming STIG Merged Results..."

    $filePath = Join-Path $InputPath "$($ComputerName)_STIG_Merged_Results.csv"
    if (-not (Test-Path $filePath)) {
        Write-TransformLog "STIG_Merged_Results.csv not found, skipping" -Level Warning
        return $null
    }

    try {
        $data = Import-Csv -Path $filePath -Encoding UTF8

        $transformed = @()
        foreach ($item in $data) {
            $obj = [PSCustomObject]@{
                '@timestamp' = ConvertTo-ISO8601 $item.Timestamp
                'sourcetype' = 'cyaudit:stig_merged'
                'computer_name' = $ComputerName
                'audit_date' = $AuditDate
                'event_type' = 'stig_compliance'
                'compliance_framework' = 'STIG_Merged'
                'STIG_ID' = $item.STIG_ID
                'Category' = $item.Category
                'Description' = $item.Description
                'Status' = $item.Status
                'compliance_status' = switch ($item.Status) {
                    "Compliant" { "pass" }
                    "Not Compliant" { "fail" }
                    "Pass" { "pass" }
                    "Fail" { "fail" }
                    default { "review" }
                }
                'Finding' = $item.Finding
                'Expected' = $item.Expected
                'Actual' = $item.Actual
                'Source' = $item.Source
                'EvaluationMethod' = $item.EvaluationMethod
            }
            $transformed += $obj
        }

        Write-TransformLog "  Transformed $($transformed.Count) merged STIG results" -Level Success
        return $transformed

    } catch {
        Write-TransformLog "Failed to transform merged STIG results: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Transform-EnhancedSummary {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Enhanced Summary..."

    $filePath = Join-Path $InputPath "$($ComputerName)_Enhanced_Summary.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = ConvertTo-ISO8601 $item.AuditDate
            'sourcetype' = 'cyaudit:enhanced_summary'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'audit_summary'
            'ComputerName' = $item.ComputerName
            'AuditDate' = ConvertTo-ISO8601 $item.AuditDate
            'V33_TotalChecks' = $item.V33_TotalChecks
            'PowerSTIG_TotalChecks' = $item.PowerSTIG_TotalChecks
            'PowerSTIG_Compliant' = $item.PowerSTIG_Compliant
            'PowerSTIG_NonCompliant' = $item.PowerSTIG_NonCompliant
            'OverlappingChecks' = $item.OverlappingChecks
            'BothCompliant' = $item.BothCompliant
            'BothNonCompliant' = $item.BothNonCompliant
            'Conflicts' = $item.Conflicts
            'PowerSTIGDuration' = $item.PowerSTIGDuration
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed enhanced summary" -Level Success
    return $transformed
}

function Transform-ExecutiveSummary {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Executive Summary (V3.3)..."

    $filePath = Join-Path $InputPath "$($ComputerName)_Executive_Summary_V3.3.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = ConvertTo-ISO8601 $item.AuditDate
            'sourcetype' = 'cyaudit:executive_summary'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'audit_summary'
            'ComputerName' = $item.ComputerName
            'WindowsVersion' = $item.WindowsVersion
            'WindowsType' = $item.WindowsType
            'ServerRole' = $item.ServerRole
            'AuditDate' = ConvertTo-ISO8601 $item.AuditDate
            'ScriptVersion' = $item.ScriptVersion
            'TotalChecks' = $item.TotalChecks
            'CompliantChecks' = $item.CompliantChecks
            'NonCompliantChecks' = $item.NonCompliantChecks
            'ReviewRequiredChecks' = $item.ReviewRequiredChecks
            'OverallComplianceRate' = $item.OverallComplianceRate
            'RegistryChecks' = $item.RegistryChecks
            'RegistryCompliantChecks' = $item.RegistryCompliantChecks
            'RegistryComplianceRate' = $item.RegistryComplianceRate
            'V33_Enhancement' = $item.V33_Enhancement
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed executive summary" -Level Success
    return $transformed
}

function Transform-ErrorLog {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Error Log..."

    $filePath = Join-Path $InputPath "ErrorLog.txt"
    if (-not (Test-Path $filePath)) { return $null }

    try {
        # ErrorLog.txt is written with Add-Content (default encoding), not UTF-8
        # Read without forcing encoding to avoid corruption
        $lines = Get-Content -Path $filePath

        $transformed = @()
        foreach ($line in $lines) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            # Parse line format: "YYYY-MM-DD HH:MM:SS - Message"
            if ($line -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (.+)$') {
                $timestamp = $matches[1]
                $message = $matches[2]

                $obj = [PSCustomObject]@{
                    '@timestamp' = ConvertTo-ISO8601 $timestamp
                    'sourcetype' = 'cyaudit:errorlog'
                    'computer_name' = $ComputerName
                    'audit_date' = $AuditDate
                    'event_type' = 'audit_execution'
                    'log_level' = if ($message -match '^ERROR:') { "error" } elseif ($message -match '^WARNING:') { "warning" } else { "info" }
                    'message' = $message
                }
                $transformed += $obj
            } else {
                # Line doesn't match expected format, include as-is
                $obj = [PSCustomObject]@{
                    '@timestamp' = $AuditDate
                    'sourcetype' = 'cyaudit:errorlog'
                    'computer_name' = $ComputerName
                    'audit_date' = $AuditDate
                    'event_type' = 'audit_execution'
                    'log_level' = "info"
                    'message' = $line
                }
                $transformed += $obj
            }
        }

        Write-TransformLog "  Transformed $($transformed.Count) log entries" -Level Success
        return $transformed

    } catch {
        Write-TransformLog "Failed to transform error log: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Transform-WindowsVersionInfo {
    param([string]$InputPath, [string]$ComputerName, [string]$AuditDate)

    Write-TransformLog "Transforming Windows Version Info..."

    $filePath = Join-Path $InputPath "$($ComputerName)WindowsVersionInfo.json"
    if (-not (Test-Path $filePath)) { return $null }

    $data = Read-UTF16Json -FilePath $filePath
    if (-not $data) { return $null }

    $transformed = @()
    foreach ($item in $data) {
        $obj = [PSCustomObject]@{
            '@timestamp' = $AuditDate
            'sourcetype' = 'cyaudit:versioninfo'
            'computer_name' = $ComputerName
            'audit_date' = $AuditDate
            'event_type' = 'system_info'
            'ProductName' = $item.ProductName
            'ReleaseId' = $item.ReleaseId
            'CurrentBuild' = $item.CurrentBuild
            'UBR' = $item.UBR
            'ComputerName' = $item.ComputerName
        }
        $transformed += $obj
    }

    Write-TransformLog "  Transformed Windows version info" -Level Success
    return $transformed
}

#endregion

#region Main Execution

try {
    Write-Host ""
    Write-TransformLog "Starting transformation pipeline..."
    Write-TransformLog "Input Path: $InputPath"
    Write-TransformLog "Output Path: $OutputPath"
    Write-Host ""

    # Extract metadata from input path
    $computerName = Get-ComputerNameFromPath -Path $InputPath
    $auditDate = Get-AuditDateFromPath -Path $InputPath

    Write-TransformLog "Detected Computer Name: $computerName" -Level Info
    Write-TransformLog "Detected Audit Date: $auditDate" -Level Info
    Write-Host ""

    # Create output directory
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-TransformLog "Created output directory: $OutputPath" -Level Success
    } elseif (-not $Force) {
        Write-TransformLog "Output directory already exists. Use -Force to overwrite." -Level Warning
        $response = Read-Host "Continue and overwrite existing files? (Y/N)"
        if ($response -ne 'Y' -and $response -ne 'y') {
            Write-TransformLog "Transformation cancelled by user." -Level Warning
            exit 0
        }
    }

    Write-Host ""
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Phase 1: Core System Data" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan

    # Transform System Information
    $data = Transform-SystemInfo -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_systeminfo.json")
    }

    $data = Transform-WindowsVersionInfo -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_versioninfo.json")
    }

    Write-Host ""
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Phase 2: Identity and Access Management" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan

    # Transform Users and Groups
    $data = Transform-Users -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_users.json")
    }

    $data = Transform-Groups -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_groups.json")
    }

    Write-Host ""
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Phase 3: Security Policies" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan

    # Transform Security Policies
    $data = Transform-PasswordPolicies -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_passwordpolicies.json")
    }

    $data = Transform-AuditPolicies -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_auditpolicies.json")
    }

    $data = Transform-UserRights -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_userrights.json")
    }

    Write-Host ""
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Phase 4: Registry and Configuration" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan

    # Transform Registry
    $data = Transform-RegistryValues -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_registry.json")
    }

    $data = Transform-STIGRegistryCompliance -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_stig_registry.json")
    }

    Write-Host ""
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Phase 5: Services and Features" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan

    # Transform Services and Features
    $data = Transform-Services -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_services.json")
    }

    $data = Transform-WindowsFeatures -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_features.json")
    }

    Write-Host ""
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Phase 6: File System Permissions" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan

    # Transform Permissions
    $data = Transform-FilePermissions -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_filepermissions.json")
    }

    $data = Transform-DirectoryPermissions -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_dirpermissions.json")
    }

    Write-Host ""
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Phase 7: Storage and Patching" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan

    # Transform Storage and Patching
    $data = Transform-Drives -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_drives.json")
    }

    $data = Transform-HotFixes -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_hotfixes.json")
    }

    $data = Transform-MissingHotfixes -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_missinghotfixes.json")
    }

    Write-Host ""
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Phase 8: Event Logs and Network" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan

    # Transform Event Logs
    $data = Transform-LogSettings -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_logsettings.json")
    }

    # Transform Network
    $data = Transform-Shares -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_shares.json")
    }

    Write-Host ""
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Phase 9: STIG Compliance Results" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan

    # Transform STIG Compliance
    $data = Transform-STIGComplianceSummary -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_stig_summary_v33.json")
    }

    $data = Transform-PowerSTIGFindings -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_stig_powerstig.json")
    }

    $data = Transform-STIGComparison -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_stig_comparison.json")
    }

    $data = Transform-STIGMergedResults -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_stig_merged.json")
    }

    Write-Host ""
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Phase 10: Summary Reports" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan

    # Transform Summaries
    $data = Transform-EnhancedSummary -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_enhanced_summary.json")
    }

    $data = Transform-ExecutiveSummary -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $null = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_executive_summary.json")
    }

    # Transform Error Log
    $data = Transform-ErrorLog -InputPath $InputPath -ComputerName $computerName -AuditDate $auditDate
    if ($data) {
        $errorLogWritten = Write-SplunkNDJson -Objects $data -OutputFile (Join-Path $OutputPath "cyaudit_errorlog.json") -Context "Error Log" -ProgressInterval 5 -UseSimpleSerializer
        if (-not $errorLogWritten) {
            throw "Failed to write error log NDJSON"
        }
    }

    # Generate transformation summary
    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Green
    Write-Host " Transformation Complete!" -ForegroundColor Green
    Write-Host "===================================================================" -ForegroundColor Green
    Write-Host ""

    $outputFiles = Get-ChildItem -Path $OutputPath -Filter "*.json" -File
    $totalSize = ($outputFiles | Measure-Object -Property Length -Sum).Sum
    $totalSizeMB = [math]::Round($totalSize / 1MB, 2)

    Write-TransformLog "Output Location: $OutputPath" -Level Success
    Write-TransformLog "Files Generated: $($outputFiles.Count)" -Level Success
    Write-TransformLog "Total Size: $totalSizeMB MB" -Level Success
    Write-Host ""
    Write-TransformLog "Next Steps:" -Level Info
    Write-TransformLog "  1. Review generated files in: $OutputPath" -Level Info
    Write-TransformLog "  2. Run Test-SplunkTransformation.ps1 to validate" -Level Info
    Write-TransformLog "  3. Upload to Splunk Cloud using Upload-ToSplunkCloud.ps1" -Level Info
    Write-Host ""

} catch {
    Write-TransformLog "FATAL ERROR: $($_.Exception.Message)" -Level Error
    Write-TransformLog "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    exit 1
}

#endregion
