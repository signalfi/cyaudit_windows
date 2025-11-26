# CyAudit to Splunk Cloud Integration Guide

**Version:** 1.1
**Date:** 2025-11-25
**Target Platform:** Splunk Cloud

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Quick Start](#quick-start)
5. [Detailed Setup](#detailed-setup)
6. [Usage Workflow](#usage-workflow)
7. [Splunk Configuration](#splunk-configuration)
8. [Troubleshooting](#troubleshooting)
9. [Advanced Topics](#advanced-topics)
10. [Sample Searches](#sample-searches)
11. [Appendix](#appendix)

---

## Overview

This integration transforms CyAudit Opus v3.5 security assessment output into Splunk Cloud-optimized newline-delimited JSON (NDJSON) format for efficient ingestion and analysis.

### Key Features

✅ **UTF-8 Encoding** - Converts UTF-16 LE to UTF-8 for Splunk native support
✅ **ISO 8601 Timestamps** - Normalizes all datetime fields
✅ **Search-Time Extraction** - 60-70% smaller index size, flexible schema
✅ **20+ Sourcetypes** - Dedicated sourcetypes for different data schemas
✅ **Universal Forwarder Integration** - Automated file monitoring and forwarding (recommended)
✅ **HEC Upload Option** - Alternative manual upload via HTTP Event Collector
✅ **Comprehensive Validation** - Built-in testing and quality assurance
✅ **CIM Compliance** - Common Information Model compatible field mappings

### Benefits

- **Cost Reduction**: 60-70% smaller index size vs. index-time extraction
- **Flexibility**: Schema changes don't require reindexing
- **Performance**: Optimized for weekly/monthly batch ingestion
- **Compliance**: STIG compliance tracking and reporting
- **Visibility**: Unified security posture across all systems

---

## Architecture

### Data Flow (Universal Forwarder - Recommended)

```
┌─────────────────────────────────────────────────────────────────┐
│ Step 1: CyAudit Assessment                                      │
│ CyAudit_Opus_V3.5.ps1 → 52 files (CSV/JSON/XML/TXT)           │
│ - UTF-16 LE encoded                                             │
│ - Multiple timestamp formats                                     │
│ - Nested structures                                              │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│ Step 2: Transformation                                           │
│ Transform-CyAuditForSplunk.ps1 → 25 NDJSON files               │
│ - UTF-8 encoding                                                 │
│ - ISO 8601 timestamps                                            │
│ - Flattened structures                                           │
│ - Metadata enrichment                                            │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│ Step 3: Validation (Optional)                                    │
│ Test-SplunkTransformation.ps1                                    │
│ - JSON syntax validation                                         │
│ - Encoding verification                                          │
│ - Required fields check                                          │
│ - Timestamp format validation                                    │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│ Step 4: Universal Forwarder Monitors & Forwards                 │
│ Splunk Universal Forwarder (installed on Windows system)        │
│ - Monitors SplunkReady/ directory                                │
│ - Automatically forwards new .json files                         │
│ - No manual intervention required                                │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│ Step 5: Splunk Cloud Ingestion & Analysis                       │
│ - 20+ sourcetypes with search-time extraction                   │
│ - Field aliases and calculated fields                            │
│ - Lookup tables for enrichment                                  │
│ - CIM-compliant data models                                      │
└─────────────────────────────────────────────────────────────────┘
```

**Alternative Method**: For ad-hoc uploads without a forwarder, use `Upload-ToSplunkCloud.ps1` with HEC (see [Alternative: Manual HEC Upload](#alternative-manual-hec-upload))

### File Structure

```
CyAudit/
├── Transform-CyAuditForSplunk.ps1       # Main transformation script
├── Upload-ToSplunkCloud.ps1             # HEC upload script
├── Test-SplunkTransformation.ps1        # Validation script
├── README_Splunk_Integration.md         # This file
│
├── splunk_configs/                       # Splunk configuration files
│   ├── props.conf                        # Sourcetype definitions (20+)
│   ├── inputs.conf                       # HEC configuration
│   ├── transforms.conf                   # Field transformations
│   ├── indexes.conf                      # Index definitions
│   └── lookups/                          # Lookup tables
│       ├── registry_types.csv
│       ├── filesystemrights.csv
│       └── stig_severity.csv
│
└── SplunkReady/                          # Output directory (created by script)
    ├── cyaudit_systeminfo.json
    ├── cyaudit_users.json
    ├── cyaudit_groups.json
    ├── cyaudit_stig_summary_v33.json
    ├── cyaudit_stig_powerstig.json
    ├── cyaudit_stig_registry.json
    ├── cyaudit_executive_summary.json
    └── ... (25 files total)
```

---

## Prerequisites

### System Requirements

- **PowerShell**: Version 5.1 or later (required)
- **Operating System**: Windows 10/11, Windows Server 2016+
- **Disk Space**: ~10 MB per assessment (temporary storage)
- **Network**: HTTPS connectivity to Splunk Cloud (port 9997 for forwarder, or port 8088 for HEC)
- **Splunk Universal Forwarder**: Version 9.x or later (recommended for production use)

### Splunk Cloud Requirements

1. **Splunk Cloud Instance**: Active subscription
2. **Permissions**: Admin or power user role
3. **Index**: `cyaudit` index created (or custom index name)
4. **Forwarder Management**: Ability to configure receiving (port 9997)
   - *Alternative*: HEC token for manual uploads (not required if using forwarder)

### CyAudit Requirements

1. **CyAudit Opus v3.5** installed and configured
2. **Assessment Output**: At least one completed assessment
3. **Output Format**: Standard CyAudit output structure

---

## Quick Start (Universal Forwarder Method)

This is the **recommended** approach for ongoing, automated data collection.

### 1. Install Splunk Universal Forwarder

Download and install the Splunk Universal Forwarder on your Windows system:

```powershell
# Download from Splunk.com or use your organization's installer
# Install to default location: C:\Program Files\SplunkUniversalForwarder
```

### 2. Configure Universal Forwarder

Create `inputs.conf` on the forwarder to monitor the CyAudit output directory:

**File**: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
[monitor://C:\CyAudit\SplunkReady\*.json]
disabled = false
index = cyaudit
sourcetype = cyaudit:auto
recursive = false
whitelist = \.json$
```

Configure forwarder to send data to Splunk Cloud:

**File**: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`

```ini
[tcpout]
defaultGroup = splunk_cloud

[tcpout:splunk_cloud]
server = inputs.splunkcloud.com:9997
# Additional SSL/certificate settings per your Splunk Cloud configuration
```

Restart the forwarder:

```powershell
Restart-Service SplunkForwarder
```

### 3. Run CyAudit Assessment

```powershell
.\CyAudit_Opus_V3.5.ps1 -ClientName "MyCompany" -ComputerName "SERVER01"
```

**Output**: `SERVER01-20251112_153045/` directory with 52 files

### 4. Transform for Splunk

```powershell
.\Transform-CyAuditForSplunk.ps1 `
    -InputPath ".\SERVER01-20251112_153045" `
    -OutputPath "C:\CyAudit\SplunkReady" `
    -IncludeAuxiliaryFiles
```

**Output**: `C:\CyAudit\SplunkReady\` directory with 25 NDJSON files

**Note**: The Universal Forwarder automatically detects and forwards the new JSON files within seconds.

### 5. (Optional) Validate Transformation

```powershell
.\Test-SplunkTransformation.ps1 -Path "C:\CyAudit\SplunkReady"
```

**Expected**: "All files passed validation!" message

### 6. Search in Splunk Cloud

```spl
index=cyaudit | stats count by sourcetype
```

**Done!** Your CyAudit data is now automatically forwarded to Splunk Cloud.

---

### Quick Start (Alternative: Manual HEC Upload)

For one-time uploads or systems without forwarders, see [Alternative: Manual HEC Upload](#alternative-manual-hec-upload) section below.

---

## Detailed Setup

### Step 1: Create Splunk Cloud Index

1. Log into Splunk Cloud
2. Navigate to **Settings** > **Indexes**
3. Click **New Index**
4. Configure index:
   - **Index Name**: `cyaudit`
   - **Max Size**: `10 GB` (adjust for your environment)
   - **Searchable Retention**: `90 days` (or 180/365 for compliance)
   - **Datatype**: `Events`
5. Click **Save**

### Step 2: Install and Configure Universal Forwarder

#### A. Download and Install

1. Download the Splunk Universal Forwarder for Windows from [Splunk.com](https://www.splunk.com/en_us/download/universal-forwarder.html)
2. Run the installer with admin privileges
3. During installation:
   - **Installation Directory**: `C:\Program Files\SplunkUniversalForwarder` (default)
   - **Service Account**: Local System (or domain account with appropriate permissions)
   - **Deployment Server**: (leave blank unless using centralized management)
4. Complete installation

#### B. Configure Receiving (outputs.conf)

Create or edit: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`

```ini
[tcpout]
defaultGroup = splunk_cloud_cyaudit

[tcpout:splunk_cloud_cyaudit]
server = inputs.yourinstance.splunkcloud.com:9997

# For Splunk Cloud, you'll need SSL configuration
[tcpout-server://inputs.yourinstance.splunkcloud.com:9997]
sslCertPath = $SPLUNK_HOME\etc\auth\server.pem
sslRootCAPath = $SPLUNK_HOME\etc\auth\cacert.pem
sslPassword = <encrypted_password>
sslVerifyServerCert = true
```

**Note**: Contact your Splunk Cloud admin for the exact server address and SSL certificate files.

#### C. Configure Monitoring (inputs.conf)

Create or edit: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
# Monitor CyAudit transformed output directory
[monitor://C:\CyAudit\SplunkReady\*.json]
disabled = false
index = cyaudit
sourcetype = cyaudit:auto
recursive = false
whitelist = \.json$
ignoreOlderThan = 14d
# Optional: Clean up after forwarding
#move_policy = sinkhole

# Optional: Monitor transformation errors
[monitor://C:\CyAudit\SplunkReady\*.log]
disabled = false
index = cyaudit
sourcetype = cyaudit:script_log
```

#### D. Restart Forwarder Service

```powershell
Restart-Service SplunkForwarder
```

Verify service is running:

```powershell
Get-Service SplunkForwarder | Select-Object Status, StartType
```

### Step 3: Deploy Splunk Configuration Files

#### Option A: Via Splunk Web UI (Recommended for Splunk Cloud)

1. Navigate to **Settings** > **Knowledge** > **Field Extractions**
2. For each sourcetype in `props.conf`:
   - Click **New Field Extraction**
   - Select **cyaudit** index
   - Select appropriate sourcetype
   - Configure KV_MODE and TIME_FORMAT

#### Option B: Via Configuration Files (Enterprise/Self-Hosted)

1. Copy `splunk_configs/*` to your Splunk instance:
   ```
   $SPLUNK_HOME/etc/apps/cyaudit_app/
   ├── local/
   │   ├── props.conf
   │   ├── inputs.conf
   │   ├── transforms.conf
   │   └── indexes.conf
   └── lookups/
       ├── registry_types.csv
       ├── filesystemrights.csv
       └── stig_severity.csv
   ```

2. Restart Splunk:
   ```bash
   $SPLUNK_HOME/bin/splunk restart
   ```

### Step 4: Upload Lookup Tables

1. Navigate to **Settings** > **Lookups** > **Lookup Table Files**
2. Click **New Lookup Table File**
3. Upload each CSV file from `splunk_configs/lookups/`:
   - `registry_types.csv`
   - `filesystemrights.csv`
   - `stig_severity.csv`
4. Configure lookup definitions in **Lookup Definitions**

---

## Usage Workflow

### Standard Assessment Workflow (with Universal Forwarder)

Once the Universal Forwarder is configured, your ongoing workflow is simplified:

```powershell
# 1. Run assessment (weekly/monthly schedule recommended)
.\CyAudit_Opus_V3.5.ps1 -ClientName "Acme Corp" -ComputerName "WEB-SERVER-01"

# 2. Transform output (writes to monitored directory)
.\Transform-CyAuditForSplunk.ps1 `
    -InputPath ".\WEB-SERVER-01-20251112_153045" `
    -OutputPath "C:\CyAudit\SplunkReady" `
    -Verbose

# 3. (Optional) Validate transformation
.\Test-SplunkTransformation.ps1 `
    -Path "C:\CyAudit\SplunkReady" `
    -ShowSampleEvents `
    -GenerateSampleQueries

# That's it! The Universal Forwarder automatically:
# - Detects new .json files in C:\CyAudit\SplunkReady\
# - Forwards them to Splunk Cloud within seconds
# - No manual upload required

# 4. Verify in Splunk Cloud (wait ~30 seconds for data to appear)
# Search: index=cyaudit computer_name="WEB-SERVER-01" | stats count by sourcetype
```

### Batch Processing Multiple Systems

```powershell
# Assessment list
$systems = @("SERVER01", "SERVER02", "SERVER03", "WEB01", "DB01")

foreach ($system in $systems) {
    # Run assessment
    .\CyAudit_Opus_V3.5.ps1 -ClientName "Acme Corp" -ComputerName $system

    # Find latest output directory
    $latestDir = Get-ChildItem -Directory |
        Where-Object { $_.Name -match "^$system-\d{8}_\d{6}$" } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($latestDir) {
        # Transform
        .\Transform-CyAuditForSplunk.ps1 `
            -InputPath $latestDir.FullName `
            -OutputPath ".\SplunkReady\$system"

        # Upload
        .\Upload-ToSplunkCloud.ps1 `
            -Path ".\SplunkReady\$system" `
            -HecToken $env:SPLUNK_HEC_TOKEN `
            -HecUrl "https://inputs.splunkcloud.com:8088"
    }
}
```

### Automated Schedule (Task Scheduler)

Create a scheduled task to run weekly:

```powershell
# Create scheduled task script: Run-CyAuditAndUpload.ps1
param([string[]]$Systems)

$HEC_TOKEN = $env:SPLUNK_HEC_TOKEN
$HEC_URL = "https://inputs.splunkcloud.com:8088"

foreach ($system in $Systems) {
    try {
        # Assessment
        .\CyAudit_Opus_V3.5.ps1 -ClientName "Weekly Assessment" -ComputerName $system -ErrorAction Stop

        # Transform
        $latestDir = Get-ChildItem -Directory | Where-Object { $_.Name -like "$system-*" } | Sort-Object -Descending | Select-Object -First 1
        .\Transform-CyAuditForSplunk.ps1 -InputPath $latestDir -OutputPath ".\SplunkReady\$system" -ErrorAction Stop

        # Validate
        $validationResult = .\Test-SplunkTransformation.ps1 -Path ".\SplunkReady\$system" -ErrorAction Stop

        if ($LASTEXITCODE -eq 0) {
            # Upload
            .\Upload-ToSplunkCloud.ps1 -Path ".\SplunkReady\$system" -HecToken $HEC_TOKEN -HecUrl $HEC_URL
        }

    } catch {
        Write-Error "Failed processing $system`: $($_.Exception.Message)"
    }
}
```

**Windows Task Scheduler**:
- **Trigger**: Weekly on Sunday at 2:00 AM
- **Action**: `powershell.exe -ExecutionPolicy Bypass -File "C:\CyAudit\Run-CyAuditAndUpload.ps1" -Systems "SERVER01","SERVER02"`
- **Run As**: Service account with admin privileges

---

## Alternative: Manual HEC Upload

If you cannot deploy a Universal Forwarder (e.g., restricted environments, one-time uploads, testing), you can manually upload data using the HTTP Event Collector (HEC) API.

### Prerequisites for HEC Upload

1. **Create HEC Token** in Splunk Cloud:
   - Navigate to **Settings** > **Data Inputs** > **HTTP Event Collector**
   - Click **New Token**
   - Configure token:
     - **Name**: `CyAudit`
     - **Source Type**: `Automatic`
     - **Index**: `cyaudit`
     - **Enable Indexer Acknowledgment**: `Yes` (recommended)
   - Click **Review** then **Submit**
   - **Copy the token value** (format: `12345678-1234-1234-1234-123456789012`)

2. **Verify HEC Endpoint** URL:
   - Format: `https://inputs.yourinstance.splunkcloud.com:8088`
   - Contact your Splunk Cloud admin if unsure

### Upload Workflow

```powershell
# 1. Run CyAudit assessment
.\CyAudit_Opus_V3.5.ps1 -ClientName "Acme Corp" -ComputerName "WEB-SERVER-01"

# 2. Transform output
.\Transform-CyAuditForSplunk.ps1 `
    -InputPath ".\WEB-SERVER-01-20251112_153045" `
    -OutputPath ".\SplunkReady" `
    -IncludeAuxiliaryFiles

# 3. (Optional) Validate transformation
.\Test-SplunkTransformation.ps1 -Path ".\SplunkReady"

# 4. Upload to Splunk Cloud via HEC
.\Upload-ToSplunkCloud.ps1 `
    -Path ".\SplunkReady" `
    -HecToken "12345678-1234-1234-1234-123456789012" `
    -HecUrl "https://inputs.yourinstance.splunkcloud.com:8088" `
    -Index "cyaudit" `
    -BatchSize 100 `
    -Verbose

# 5. Verify upload
# Search in Splunk: index=cyaudit computer_name="WEB-SERVER-01" | stats count by sourcetype
```

### Upload Script Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `-Path` | Directory containing NDJSON files | Yes | - |
| `-HecToken` | Splunk HEC authentication token | Yes | - |
| `-HecUrl` | HEC endpoint URL (e.g., https://inputs.splunkcloud.com:8088) | Yes | - |
| `-Index` | Target Splunk index | No | `cyaudit` |
| `-BatchSize` | Events per HTTP request | No | `100` |
| `-MaxRetries` | Retry attempts for failed uploads | No | `3` |
| `-Verbose` | Enable detailed logging | No | `false` |

### Upload Script Features

- **Batch Processing**: Uploads events in configurable batches (default: 100 events/request)
- **Retry Logic**: Exponential backoff for transient failures (network timeouts, 503 errors)
- **Progress Tracking**: Real-time progress display and statistics
- **Connection Testing**: Pre-flight HEC health check before upload
- **Error Handling**: Detailed error messages and troubleshooting guidance

### Troubleshooting HEC Uploads

**Error: "HEC connection failed"**
- Verify HEC endpoint URL is correct
- Check that HEC is enabled in Splunk Cloud (Settings > Data Inputs > HTTP Event Collector > Global Settings > "All Tokens" = Enabled)
- Confirm network connectivity to port 8088
- Validate HEC token is active and not expired

**Error: "Upload failed: 403 Forbidden"**
- HEC token is invalid or expired
- Index doesn't exist or HEC token doesn't have access
- Generate a new HEC token in Splunk Cloud

**Error: "Upload failed: 400 Bad Request"**
- JSON formatting issue (should not occur after transformation)
- Run `Test-SplunkTransformation.ps1` to validate data

**Slow Upload Performance**
- Increase `-BatchSize` parameter (try 200-500)
- Check network bandwidth to Splunk Cloud
- Consider using Universal Forwarder for better throughput

---

## Splunk Configuration

### Sourcetypes Reference

| Sourcetype | Description | Event Count (typical) |
|------------|-------------|----------------------|
| `cyaudit:systeminfo` | System identification | 1 |
| `cyaudit:versioninfo` | Windows version details | 1 |
| `cyaudit:users` | User accounts | 5-50 |
| `cyaudit:groups` | Group membership | 20-50 |
| `cyaudit:passwordpolicies` | Password policies | 10-20 |
| `cyaudit:auditpolicies` | Audit policies | 9-10 |
| `cyaudit:userrights` | User rights assignments | 30-50 |
| `cyaudit:registry` | Registry values | 100-200 |
| `cyaudit:stig_registry` | STIG registry compliance | 50-60 |
| `cyaudit:services` | Windows services | 100-300 |
| `cyaudit:features` | Windows features | 5-20 |
| `cyaudit:filepermissions` | File ACLs | 50-150 |
| `cyaudit:dirpermissions` | Directory ACLs | 50-100 |
| `cyaudit:drives` | Disk drives | 2-10 |
| `cyaudit:hotfixes` | Installed patches | 5-50 |
| `cyaudit:missinghotfixes` | Missing patches | 0-10 |
| `cyaudit:logsettings` | Event log config | 3-5 |
| `cyaudit:shares` | Network shares | 3-10 |
| `cyaudit:stig_summary_v33` | V3.3 STIG checks | 70-80 |
| `cyaudit:stig_powerstig` | PowerSTIG checks | 200-240 |
| `cyaudit:stig_comparison` | V3.3 vs PowerSTIG | 300-320 |
| `cyaudit:stig_merged` | Merged STIG results | 300-320 |
| `cyaudit:enhanced_summary` | Enhanced summary | 1 |
| `cyaudit:executive_summary` | Executive summary | 1 |
| `cyaudit:errorlog` | Execution log | 50-200 |

### Field Reference

#### Common Fields (All Events)

- `@timestamp` - Event timestamp (ISO 8601)
- `sourcetype` - Splunk sourcetype
- `computer_name` - System hostname
- `audit_date` - Assessment date
- `event_type` - Event classification

#### STIG Compliance Fields

- `STIG_ID` - STIG control ID
- `Category` - CAT I/II/III
- `Description` - Control description
- `Status` / `compliance_status` - pass/fail/review
- `Expected` - Expected value
- `Actual` - Actual value
- `Finding` - Detailed finding

#### Identity Fields

- `UserName` / `user` - Username
- `SID` - Security identifier
- `AccountDisabled` - Boolean
- `AccountLocked` - Boolean
- `PasswordRequired` - Boolean
- `Members` - Array of group members

#### System Fields

- `ServiceName` / `service` - Service name
- `StartMode` - Auto/Manual/Disabled
- `ServiceState` - Running/Stopped
- `RegistryKey` - Registry path
- `ValueName` - Registry value name
- `Type` / `TypeName` - Registry type

---

## Troubleshooting

### Common Issues

#### Issue: "HEC connection test failed"

**Symptoms**:
```
[✗] HEC connection failed: The remote name could not be resolved
```

**Solutions**:
1. Verify HEC URL is correct for your Splunk Cloud instance
2. Check firewall allows HTTPS to ports 443 and 8088
3. Verify HEC token is valid and not expired
4. Test connectivity: `Test-NetConnection inputs.splunkcloud.com -Port 8088`

#### Issue: "Transformation validation failed - JSON syntax errors"

**Symptoms**:
```
[✗] JSON syntax errors found:
  - Line 42: Invalid JSON - Unexpected character
```

**Solutions**:
1. Check input files are from CyAudit v3.5 (not earlier versions)
2. Verify input directory is complete (all 52 files present)
3. Re-run CyAudit assessment if files are corrupted
4. Check for special characters in computer names or descriptions

#### Issue: "UTF-16 encoding detected instead of UTF-8"

**Symptoms**:
```
[✗] Invalid encoding: UTF-16 (INVALID - must be UTF-8)
```

**Solutions**:
1. This indicates transformation script didn't run properly
2. Re-run `Transform-CyAuditForSplunk.ps1`
3. Verify PowerShell version is 5.1+
4. Check output directory permissions

#### Issue: "Events not appearing in Splunk after upload"

**Symptoms**:
- Upload succeeds but `index=cyaudit | stats count` returns 0

**Solutions**:
1. Check index name matches between upload script and search
2. Verify HEC token is assigned to correct index
3. Wait 5-10 minutes for indexing to complete
4. Check Splunk Cloud ingestion queue: Settings > Data Inputs > HTTP Event Collector > View HEC Token Status
5. Review HEC logs in Splunk: `index=_internal sourcetype=splunkd component=HttpInputProcessor`

#### Issue: "Missing required fields in validation"

**Symptoms**:
```
[✗] Missing required fields:
  - @timestamp
  - sourcetype
```

**Solutions**:
1. Update transformation script to latest version
2. Verify input path contains CyAudit output (not other data)
3. Check for file system permissions issues

### Debug Mode

Enable verbose output for detailed troubleshooting:

```powershell
# Transformation with debug info
.\Transform-CyAuditForSplunk.ps1 `
    -InputPath ".\SERVER01-..." `
    -OutputPath ".\SplunkReady" `
    -Verbose `
    -Debug

# Validation with sample events
.\Test-SplunkTransformation.ps1 `
    -Path ".\SplunkReady" `
    -ShowSampleEvents `
    -Verbose

# Upload with detailed logging
.\Upload-ToSplunkCloud.ps1 `
    -Path ".\SplunkReady" `
    -HecToken $token `
    -HecUrl $url `
    -Verbose
```

### Getting Help

1. Review `ErrorLog.txt` in CyAudit output directory
2. Check PowerShell error messages and stack traces
3. Verify all prerequisites are met
4. Test with small sample data first
5. Contact Splunk Cloud support for HEC issues
6. Review Splunk Cloud documentation: https://docs.splunk.com/Documentation/SplunkCloud

---

## Advanced Topics

### Custom Field Extractions

Add custom fields in `props.conf`:

```ini
[cyaudit:users]
EVAL-password_age_days = if(PasswordLastSet, round((now() - strptime(PasswordLastSet, "%Y-%m-%dT%H:%M:%S.%3NZ")) / 86400, 0), null())
EVAL-account_risk_score = case(AccountDisabled="false" AND PasswordRequired="false", 100, AccountDisabled="false" AND PasswordExpires="null", 75, 1=1, 25)
```

### Data Model Acceleration

Create accelerated data model for dashboards:

```
Settings > Data Models > New Data Model
- Name: CyAudit_Compliance
- Root Object: STIG Compliance
  - Constraints: sourcetype=cyaudit:stig_*
  - Fields: STIG_ID, compliance_status, computer_name, audit_date
- Child Object: Non-Compliant
  - Constraints: compliance_status="fail"
```

Enable acceleration:
- Acceleration: Yes
- Summary Range: 90 days
- Cron Schedule: `0 */4 * * *` (every 4 hours)

### Custom Dashboards

Sample dashboard XML:

```xml
<dashboard>
  <label>CyAudit STIG Compliance Overview</label>
  <row>
    <panel>
      <title>Overall Compliance Rate</title>
      <single>
        <search>
          <query>
            index=cyaudit sourcetype=cyaudit:stig_merged earliest=-7d@d latest=now
            | stats count(eval(compliance_status="pass")) as passed count as total
            | eval compliance_rate=round((passed/total)*100, 2)
            | fields compliance_rate
          </query>
        </search>
        <option name="drilldown">none</option>
        <option name="unit">%</option>
      </single>
    </panel>
  </row>

  <row>
    <panel>
      <title>Top 10 Non-Compliant Checks</title>
      <table>
        <search>
          <query>
            index=cyaudit sourcetype=cyaudit:stig_* compliance_status="fail" earliest=-7d@d latest=now
            | stats count by STIG_ID, Description
            | sort -count
            | head 10
          </query>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
```

### Alerting

Create alert for critical compliance failures:

```spl
index=cyaudit sourcetype=cyaudit:stig_* compliance_status="fail" severity="critical"
| stats count by computer_name, STIG_ID, Description
| where count > 0
```

**Alert Actions**:
- Email notification
- Create ServiceNow incident
- Slack webhook
- PagerDuty integration

### Performance Tuning

#### Index Sizing

Calculate required index size:

```
Systems × Assessment Size × Frequency × Retention
Example: 50 systems × 3 MB × 52 weeks × 1.5 buffer = 11.7 GB
```

#### Search Performance

Use `tstats` for fast searches on indexed fields:

```spl
| tstats count WHERE index=cyaudit sourcetype=cyaudit:stig_* BY sourcetype, compliance_status
```

#### Data Retention Tiers

Configure cold storage for long-term retention:

```ini
[cyaudit]
frozenTimePeriodInSecs = 7776000  # 90 days hot/warm
coldToFrozenDir = /opt/splunk/frozen/cyaudit  # Cold storage path
```

---

## Sample Searches

### Security Posture

#### Overall Compliance Dashboard

```spl
index=cyaudit sourcetype=cyaudit:executive_summary
| table computer_name, OverallComplianceRate, CompliantChecks, NonCompliantChecks, audit_date
| rename computer_name as "System", OverallComplianceRate as "Compliance %", CompliantChecks as "Passed", NonCompliantChecks as "Failed"
| sort -"Compliance %"
```

#### STIG Failures by Category

```spl
index=cyaudit sourcetype=cyaudit:stig_merged compliance_status="fail"
| stats count by Category, STIG_ID, Description
| sort -count
```

### User Account Security

#### Accounts with No Password Expiration

```spl
index=cyaudit sourcetype=cyaudit:users PasswordExpires="null" AccountDisabled="false"
| table computer_name, UserName, AccountType, PasswordLastSet, LastLogon
| sort computer_name, UserName
```

#### Dormant Accounts (No Recent Logon)

```spl
index=cyaudit sourcetype=cyaudit:users AccountDisabled="false"
| eval last_logon_epoch = strptime(LastLogon, "%Y-%m-%dT%H:%M:%S.%3NZ")
| eval days_since_logon = round((now() - last_logon_epoch) / 86400, 0)
| where days_since_logon > 35 OR isnull(LastLogon)
| table computer_name, UserName, LastLogon, days_since_logon
| sort -days_since_logon
```

### Service Configuration

#### Services Running as Non-Standard Accounts

```spl
index=cyaudit sourcetype=cyaudit:services service_status="running"
| where NOT match(AccountName, "LocalSystem|NT AUTHORITY")
| stats count by computer_name, ServiceName, AccountName, StartMode
| sort computer_name, ServiceName
```

#### Critical Services Not Running

```spl
index=cyaudit sourcetype=cyaudit:services ServiceName IN ("wuauserv", "BITS", "WinDefend", "EventLog")
| where service_status!="running"
| table computer_name, ServiceName, ServiceState, StartMode
```

### Patch Management

#### Systems Missing Critical Patches

```spl
index=cyaudit sourcetype=cyaudit:missinghotfixes
| stats count by computer_name
| where count > 0
| join type=left computer_name [
    search index=cyaudit sourcetype=cyaudit:missinghotfixes
    | stats values(KBNum) as missing_kbs by computer_name
  ]
| table computer_name, count, missing_kbs
| rename count as "Missing Patch Count", missing_kbs as "KB Numbers"
| sort -"Missing Patch Count"
```

#### Patch Deployment Trend

```spl
index=cyaudit sourcetype=cyaudit:hotfixes
| timechart span=1mon count by computer_name
```

### Registry Compliance

#### Non-Compliant Registry Settings

```spl
index=cyaudit sourcetype=cyaudit:stig_registry compliance_status="fail"
| table computer_name, STIG_ID, Description, Expected, Actual
| sort computer_name, STIG_ID
```

#### Critical Registry Vulnerabilities

```spl
index=cyaudit sourcetype=cyaudit:stig_registry compliance_status="fail"
| lookup stig_severity STIG_ID OUTPUT Severity, Category
| where Severity="High" OR Category="CAT1"
| table computer_name, STIG_ID, Severity, Description, Expected, Actual
```

### File System Security

#### Overly Permissive File Permissions

```spl
index=cyaudit sourcetype=cyaudit:filepermissions
| where match(FileSystemRightsNames, "FullControl|Modify")
  AND match(IdentityReference, "Users|Everyone|Authenticated Users")
| table computer_name, FilePath, IdentityReference, FileSystemRightsNames, AccessControlType
| sort computer_name, FilePath
```

### Trend Analysis

#### Compliance Improvement Over Time

```spl
index=cyaudit sourcetype=cyaudit:executive_summary
| timechart span=1w avg(OverallComplianceRate) by computer_name
```

#### New Non-Compliance Issues

```spl
index=cyaudit sourcetype=cyaudit:stig_merged compliance_status="fail"
| transaction STIG_ID computer_name maxspan=30d
| where eventcount=1
| table computer_name, STIG_ID, Description, _time
| rename _time as "First Detected"
```

---

## Appendix

### A. Transformation Script Details

#### Transformations Applied

1. **Encoding Conversion**
   - Source: UTF-16 LE with BOM (0xFF 0xFE)
   - Target: UTF-8 without BOM
   - Method: `StreamWriter` with UTF8Encoding

2. **Timestamp Normalization**
   - .NET JSON format: `/Date(1728944467444)/` → `2024-10-14T16:07:47.444Z`
   - Standard datetime: `2025-11-11 16:04:12` → `2025-11-11T16:04:12.000Z`
   - ISO 8601: Already compliant, validation only

3. **Nested Structure Flattening**
   - `FilePermissions.IdentityReference.Value` → `FilePermissions.IdentityReference`
   - Preserves data integrity
   - Simplifies Splunk field extraction

4. **Multi-Value Field Expansion**
   - `Groups.Members` (semicolon-delimited string) → Array
   - `IPAddresses` (comma-delimited string) → Array
   - `UserRights.Assignees` (semicolon-delimited) → Array

5. **Numeric Code Translation**
   - Registry types: `1` → `"String"`, `3` → `"DWord"`, `4` → `"QWord"`
   - FileSystemRights: `2032127` → `["FullControl"]`, `1179817` → `["Modify"]`
   - AccessControlType: `0` → `"Allow"`, `1` → `"Deny"`

6. **Metadata Enrichment**
   - `@timestamp`: ISO 8601 timestamp (primary Splunk timestamp field)
   - `sourcetype`: Splunk sourcetype for automatic routing
   - `computer_name`: Extracted from directory/filename
   - `audit_date`: Assessment execution timestamp
   - `event_type`: Event classification for filtering

#### Excluded Files

- **CSV files**: Duplicates of JSON data (smaller size, but less flexible)
- **Binary .sdb file**: 1MB Security Database (not text-parseable)
- **INF files**: Windows Security Template (optional, low value)
- **XML files**: Converted to JSON (PowerSTIG DSC results)

#### Output Size Comparison

| Format | Original | Transformed | Reduction |
|--------|----------|-------------|-----------|
| SystemInfo | 948 bytes (UTF-16) | 580 bytes (UTF-8) | 39% |
| Users | 5.8 KB (UTF-16) | 3.5 KB (UTF-8) | 40% |
| Services | 350 KB (UTF-16) | 210 KB (UTF-8) | 40% |
| **Total** | **~2.1 MB** | **~1.3 MB** | **38%** |

### B. Splunk HEC API Reference

#### HEC Event Format

```json
{
  "time": 1699819200,
  "host": "SERVER01",
  "source": "cyaudit",
  "sourcetype": "cyaudit:users",
  "index": "cyaudit",
  "event": {
    "@timestamp": "2025-11-11T16:04:12.000Z",
    "sourcetype": "cyaudit:users",
    "computer_name": "SERVER01",
    "audit_date": "2025-11-11T16:04:12.000Z",
    "event_type": "user_account",
    "UserName": "Administrator",
    "SID": "S-1-5-21-xxx",
    "AccountDisabled": false
  }
}
```

#### HEC Endpoints

- **Event Submission**: `https://<splunk-cloud-url>:8088/services/collector/event`
- **Batch Event Submission**: `https://<splunk-cloud-url>:8088/services/collector/event` (NDJSON)
- **Raw Event Submission**: `https://<splunk-cloud-url>:8088/services/collector/raw`
- **Health Check**: `https://<splunk-cloud-url>:8088/services/collector/health`
- **ACK Status**: `https://<splunk-cloud-url>:8088/services/collector/ack`

#### Response Codes

- `200 OK`: Success
- `400 Bad Request`: Invalid JSON or missing required fields
- `401 Unauthorized`: Invalid or missing HEC token
- `403 Forbidden`: Token disabled or insufficient permissions
- `503 Service Unavailable`: Splunk indexer queue full (retry)

### C. Storage Estimation Calculator

```
# Variables
$SystemsCount = 50
$AssessmentSizeMB = 3
$FrequencyPerYear = 52  # Weekly
$RetentionDays = 90
$BufferMultiplier = 1.5

# Calculate
$WeeksInRetention = [Math]::Ceiling($RetentionDays / 7)
$TotalSizeMB = $SystemsCount * $AssessmentSizeMB * $WeeksInRetention
$TotalWithBufferMB = $TotalSizeMB * $BufferMultiplier
$TotalGB = [Math]::Ceiling($TotalWithBufferMB / 1024)

Write-Host "Estimated Index Size: $TotalGB GB"
Write-Host "Daily Ingestion: $([Math]::Round(($SystemsCount * $AssessmentSizeMB * 52 / 365), 2)) MB/day"
```

**Example Results**:
- 50 systems, 3 MB each, weekly, 90-day retention = **12 GB**
- 100 systems, 3 MB each, monthly, 180-day retention = **11 GB**
- 10 systems, 5 MB each, daily, 365-day retention = **69 GB**

### D. Security Considerations

1. **HEC Token Management**
   - Store tokens in environment variables or secure vaults
   - Rotate tokens every 90 days
   - Use different tokens for dev/test/prod
   - Never commit tokens to version control

2. **Data Privacy**
   - CyAudit captures usernames, SIDs, and system configuration
   - Consider data masking for sensitive environments
   - Review GDPR/compliance requirements for log retention
   - Implement role-based access control (RBAC) in Splunk

3. **Network Security**
   - Use HTTPS for all HEC communication
   - Restrict HEC access to authorized IP ranges
   - Enable HEC token indexer acknowledgment
   - Monitor failed authentication attempts

4. **Splunk Access Control**
   - Limit index access to security team
   - Create read-only roles for reporting
   - Enable audit logging for Splunk access
   - Implement multi-factor authentication (MFA)

### E. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.1.0 | 2025-11-25 | Fixed filename patterns for STIG/Executive files; added sourcetype routing via `[cyaudit:auto]`; consolidated duplicate props.conf stanzas; now generates 25 files |
| 1.0.0 | 2025-11-12 | Initial release with full HEC integration |

### F. Support & Resources

**Splunk Resources**:
- Splunk Cloud Documentation: https://docs.splunk.com/Documentation/SplunkCloud
- HEC Documentation: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
- Common Information Model: https://docs.splunk.com/Documentation/CIM/latest/User/Overview

**CyAudit Resources**:
- CyAudit Repository: (internal)
- PowerSTIG Documentation: https://github.com/microsoft/PowerSTIG

**Community Support**:
- Splunk Answers: https://community.splunk.com/
- Splunk Slack: https://splunk-usergroups.slack.com/

---

## License

This integration is provided as-is for use with CyAudit Opus v3.5 and Splunk Cloud.

---

**Last Updated**: 2025-11-25
**Maintainer**: CyAudit Team
**Version**: 1.1.0
