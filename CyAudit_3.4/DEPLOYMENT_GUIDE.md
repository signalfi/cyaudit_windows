# CyAudit 3.4 - Complete Deployment and Scheduling Guide

**Version:** 1.0.0
**Date:** 2025-11-12
**Target Audience:** System Administrators, Security Engineers

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Testing](#testing)
7. [Scheduled Task Setup](#scheduled-task-setup)
8. [Universal Forwarder Integration](#universal-forwarder-integration)
9. [Monitoring & Maintenance](#monitoring--maintenance)
10. [Troubleshooting](#troubleshooting)
11. [Advanced Scenarios](#advanced-scenarios)

---

## Overview

This guide provides complete instructions for deploying the CyAudit 3.4 automated security assessment and Splunk integration pipeline. The solution automates:

1. **Security Assessment** - CyAudit Opus v3.4 performs comprehensive Windows security audits
2. **Data Transformation** - Converts audit data to Splunk-optimized NDJSON format
3. **Automatic Forwarding** - Splunk Universal Forwarder sends data to Splunk Cloud
4. **Scheduled Execution** - Windows Task Scheduler runs assessments on defined intervals
5. **Retention Management** - Automatic cleanup of old assessments and logs

### Benefits

✅ **Fully Automated** - Schedule once, runs continuously without intervention
✅ **Production Ready** - Comprehensive error handling, logging, and alerting
✅ **Scalable** - Deploy to multiple systems with consistent configuration
✅ **Monitored** - Email alerts, detailed logs, and Splunk visibility
✅ **Compliant** - STIG compliance tracking with historical trending

---

## Architecture

### Complete Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ Windows Task Scheduler                                           │
│ Triggers: Weekly (Sunday 2:00 AM)                               │
└────────────────────┬────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────────┐
│ Run-CyAuditPipeline.ps1 (Orchestration)                        │
│ - Loads configuration                                            │
│ - Validates prerequisites                                        │
│ - Coordinates all phases                                         │
│ - Handles errors and logging                                     │
└────────────────────┬────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────────┐
│ Phase 1: CyAudit_Opus_V3.4.ps1                                 │
│ - Collects 50+ security data points                             │
│ - Generates 52 output files                                      │
│ - Output: C:\CyAudit\Assessments\COMPUTER-YYYY-MM-DD HH.MM.SS\ │
└────────────────────┬────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────────┐
│ Phase 2: Transform-CyAuditForSplunk.ps1                        │
│ - Converts UTF-16 LE → UTF-8                                    │
│ - Normalizes timestamps to ISO 8601                             │
│ - Creates 22 NDJSON files                                        │
│ - Output: C:\CyAudit\SplunkReady\*.json                        │
└────────────────────┬────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────────┐
│ Phase 3: Test-SplunkTransformation.ps1 (Optional)              │
│ - Validates JSON syntax                                          │
│ - Verifies UTF-8 encoding                                       │
│ - Checks required fields                                         │
│ - Validates timestamp format                                     │
└────────────────────┬────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────────┐
│ Phase 4: Cleanup                                                 │
│ - Deletes assessments older than RetentionDays                  │
│ - Removes old logs                                               │
│ - Frees disk space                                               │
└────────────────────┬────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────────┐
│ Splunk Universal Forwarder                                       │
│ - Monitors: C:\CyAudit\SplunkReady\*.json                      │
│ - Automatically detects new files                                │
│ - Forwards to Splunk Cloud within seconds                        │
└────────────────────┬────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────────┐
│ Splunk Cloud                                                     │
│ - Index: cyaudit                                                 │
│ - 20+ sourcetypes with search-time extraction                   │
│ - CIM-compliant field mappings                                  │
│ - Ready for searches and dashboards                              │
└─────────────────────────────────────────────────────────────────┘
```

### File Structure

```
C:\CyAudit\
├── CyAudit_3.4\                          # Application files (read-only)
│   ├── CyAudit_Opus_V3.4.ps1             # Security assessment engine
│   ├── Transform-CyAuditForSplunk.ps1    # Transformation script
│   ├── Test-SplunkTransformation.ps1     # Validation script
│   ├── Run-CyAuditPipeline.ps1           # Orchestration script (THIS IS THE SCHEDULED TASK)
│   ├── CyAuditPipeline.config.json       # Configuration file
│   ├── DEPLOYMENT_GUIDE.md               # This document
│   ├── README.md                          # Quick reference
│   ├── README_Splunk_Integration.md      # Detailed Splunk documentation
│   └── splunk_configs\                    # Splunk configuration files
│       ├── props.conf
│       ├── inputs.conf
│       ├── transforms.conf
│       ├── indexes.conf
│       └── lookups\
│           ├── registry_types.csv
│           ├── filesystemrights.csv
│           └── stig_severity.csv
│
├── Assessments\                          # Raw assessment output (auto-managed)
│   ├── COMPUTER-2025-11-12 02.00.15\
│   ├── COMPUTER-2025-11-19 02.00.22\
│   └── COMPUTER-2025-11-26 02.00.18\
│
├── SplunkReady\                          # Transformed files (monitored by UF)
│   ├── cyaudit_systeminfo.json
│   ├── cyaudit_users.json
│   ├── cyaudit_groups.json
│   └── ... (22 files per assessment)
│
└── Logs\                                  # Pipeline execution logs
    ├── CyAuditPipeline_20251112_020015.log
    ├── CyAuditPipeline_20251119_020022.log
    └── CyAuditPipeline_20251126_020018.log
```

---

## Prerequisites

### System Requirements

| Component | Requirement |
|-----------|-------------|
| **Operating System** | Windows 10/11, Windows Server 2016+ |
| **PowerShell** | Version 5.1 or later |
| **Privileges** | Local Administrator rights |
| **Disk Space** | 500 MB free (assessments + logs) |
| **Network** | HTTPS to Splunk Cloud (port 9997) |
| **Splunk Universal Forwarder** | Version 9.x or later |

### Splunk Cloud Requirements

1. **Splunk Cloud Instance** - Active subscription with admin access
2. **Index Created** - `cyaudit` index configured (see Splunk setup section)
3. **Forwarder Configured** - Universal Forwarder can connect to your Splunk Cloud instance
4. **Props/Transforms Deployed** - Sourcetype definitions configured (optional, but recommended)

### Service Account Recommendations

For production deployments, create a dedicated service account:

- **Account Type**: Domain or Local account with Administrator privileges
- **Password**: Set to never expire (or use Group Managed Service Account - gMSA)
- **Permissions**:
  - Local Administrator on target system(s)
  - Read/Write access to `C:\CyAudit\` directory
  - "Log on as a batch job" right (for scheduled tasks)
- **Security**: Follow least privilege principle; grant only necessary permissions

---

## Installation

### Step 1: Extract Files

1. Copy the entire `CyAudit_3.4` folder to your target location:
   ```
   Recommended: C:\CyAudit\CyAudit_3.4\
   ```

2. Verify all files extracted successfully:
   ```powershell
   Get-ChildItem -Path "C:\CyAudit\CyAudit_3.4" -Recurse | Measure-Object | Select-Object -ExpandProperty Count
   # Should return: 15+ files
   ```

### Step 2: Create Working Directories

```powershell
# Create directory structure
New-Item -Path "C:\CyAudit\Assessments" -ItemType Directory -Force
New-Item -Path "C:\CyAudit\SplunkReady" -ItemType Directory -Force
New-Item -Path "C:\CyAudit\Logs" -ItemType Directory -Force

# Verify creation
Get-ChildItem -Path "C:\CyAudit" -Directory
```

Expected output:
```
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        11/12/2025  12:00 PM                Assessments
d-----        11/12/2025  12:00 PM                CyAudit_3.4
d-----        11/12/2025  12:00 PM                Logs
d-----        11/12/2025  12:00 PM                SplunkReady
```

### Step 3: Set Execution Policy

```powershell
# Allow script execution (if not already set)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

# Verify
Get-ExecutionPolicy -List
```

### Step 4: Unblock Files

```powershell
# Unblock all PowerShell scripts
Get-ChildItem -Path "C:\CyAudit\CyAudit_3.4" -Filter "*.ps1" -Recurse | Unblock-File
```

---

## Configuration

### Edit Configuration File

1. Open the configuration file:
   ```powershell
   notepad "C:\CyAudit\CyAudit_3.4\CyAuditPipeline.config.json"
   ```

2. Customize the following settings:

#### Basic Configuration

```json
{
  "ClientName": "MyOrganization",
  "ComputerName": "",
  "OutputBasePath": "C:\\CyAudit\\Assessments",
  "SplunkReadyPath": "C:\\CyAudit\\SplunkReady",
  "LogPath": "C:\\CyAudit\\Logs",
  "ValidateOutput": true,
  "FailOnValidationError": false,
  "RetentionDays": 30
}
```

**Configuration Fields Explained:**

| Field | Description | Recommended Value |
|-------|-------------|-------------------|
| `ClientName` | Your organization name | Your company name |
| `ComputerName` | System to audit (blank = localhost) | Leave blank for local system |
| `OutputBasePath` | Where CyAudit stores raw output | `C:\\CyAudit\\Assessments` |
| `SplunkReadyPath` | Where transformed files are written | `C:\\CyAudit\\SplunkReady` |
| `LogPath` | Pipeline execution logs | `C:\\CyAudit\\Logs` |
| `ValidateOutput` | Run validation after transformation | `true` (recommended) |
| `FailOnValidationError` | Stop if validation fails | `false` (continue despite validation errors) |
| `RetentionDays` | Delete old assessments after N days | `30` (adjust per compliance requirements) |

#### Optional: Email Alerts

To enable email notifications on pipeline failures:

```json
{
  "EmailAlerts": {
    "Enabled": true,
    "SendOnSuccess": false,
    "SmtpServer": "smtp.office365.com",
    "Port": 587,
    "UseSsl": true,
    "From": "cyaudit@yourcompany.com",
    "To": "security-team@yourcompany.com",
    "Credential": {
      "Username": "cyaudit@yourcompany.com",
      "Password": "YourAppPassword"
    }
  }
}
```

**Security Note:** For production, consider using:
- Encrypted configuration files
- Windows Credential Manager
- Azure Key Vault or similar secrets management

3. Save the file

---

## Testing

### Test 1: Manual Pipeline Execution

Run the pipeline manually to verify everything works:

```powershell
# Navigate to installation directory
cd "C:\CyAudit\CyAudit_3.4"

# Run pipeline (this will take 5-15 minutes depending on system)
.\Run-CyAuditPipeline.ps1 -Verbose
```

**Expected Output:**
```
═══════════════════════════════════════════════════════════════
 CyAudit Automated Pipeline v1.0.0
═══════════════════════════════════════════════════════════════

2025-11-12 14:30:00 [INFO] Loading configuration from: C:\CyAudit\CyAudit_3.4\CyAuditPipeline.config.json
2025-11-12 14:30:00 [SUCCESS] Configuration loaded successfully
2025-11-12 14:30:00 [INFO] Pipeline started at 11/12/2025 14:30:00
2025-11-12 14:30:00 [INFO] Computer Name: MYCOMPUTER
2025-11-12 14:30:00 [INFO] Client Name: MyOrganization
...
───────────────────────────────────────────────────────────────
 Phase 1: CyAudit Security Assessment
───────────────────────────────────────────────────────────────
...
[CyAudit output...]
...
───────────────────────────────────────────────────────────────
 Phase 2: Splunk Transformation
───────────────────────────────────────────────────────────────
...
[Transformation output...]
...
───────────────────────────────────────────────────────────────
 Phase 3: Validation
───────────────────────────────────────────────────────────────
...
[Validation output...]
...
═══════════════════════════════════════════════════════════════
 Pipeline Completed Successfully!
═══════════════════════════════════════════════════════════════

2025-11-12 14:42:15 [SUCCESS] Pipeline completed at 11/12/2025 14:42:15
2025-11-12 14:42:15 [SUCCESS] Total duration: 00:12:15
```

### Test 2: Verify Output Files

```powershell
# Check assessment was created
Get-ChildItem -Path "C:\CyAudit\Assessments" -Directory | Select-Object Name, LastWriteTime

# Check transformed files were created
Get-ChildItem -Path "C:\CyAudit\SplunkReady" -Filter "*.json" | Measure-Object | Select-Object -ExpandProperty Count
# Should return: 22 files

# Check log was created
Get-ChildItem -Path "C:\CyAudit\Logs" -Filter "*.log" | Select-Object Name, Length, LastWriteTime
```

### Test 3: Review Log File

```powershell
# Open most recent log
$latestLog = Get-ChildItem -Path "C:\CyAudit\Logs" -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
notepad $latestLog.FullName
```

Look for:
- ✅ `[SUCCESS]` messages indicating completion
- ⚠️ `[WARNING]` messages (review but may be acceptable)
- ❌ `[ERROR]` messages (must be resolved)

### Test 4: Validate JSON Files

```powershell
# Manually run validation
cd "C:\CyAudit\CyAudit_3.4"
.\Test-SplunkTransformation.ps1 -Path "C:\CyAudit\SplunkReady" -Verbose
```

Expected result: `All files passed validation!`

---

## Scheduled Task Setup

### Option A: GUI Method (Task Scheduler)

#### Step 1: Open Task Scheduler

1. Press `Win + R`
2. Type `taskschd.msc`
3. Press Enter

#### Step 2: Create New Task

1. In the right pane, click **"Create Task..."** (not "Create Basic Task")
2. Configure General tab:

**General Tab:**
- **Name**: `CyAudit Automated Assessment`
- **Description**: `Runs CyAudit security assessment and transforms data for Splunk Cloud ingestion`
- **Security options**:
  - Select: **"Run whether user is logged on or not"**
  - Check: **"Run with highest privileges"**
  - Select: **"Configure for: Windows 10"** (or your OS version)

#### Step 3: Configure Triggers

Click **"Triggers"** tab, then **"New..."**

**Recommended: Weekly Schedule**
- **Begin the task**: `On a schedule`
- **Settings**: `Weekly`
- **Recur every**: `1 weeks`
- **Days**: Check **Sunday** (or your preferred day)
- **Start**: `2:00:00 AM` (or low-usage time)
- **Enabled**: ✅ Checked

Click **OK**

**Alternative Schedules:**
- **Monthly**: First Sunday of each month at 2:00 AM
- **Daily**: For high-security environments (not recommended - generates significant data)
- **On Demand**: No trigger (run manually via Task Scheduler)

#### Step 4: Configure Actions

Click **"Actions"** tab, then **"New..."**

- **Action**: `Start a program`
- **Program/script**: `powershell.exe`
- **Add arguments**:
  ```
  -ExecutionPolicy Bypass -NoProfile -File "C:\CyAudit\CyAudit_3.4\Run-CyAuditPipeline.ps1"
  ```
- **Start in**: `C:\CyAudit\CyAudit_3.4`

Click **OK**

#### Step 5: Configure Conditions

Click **"Conditions"** tab:

Recommended settings:
- **Power**:
  - ❌ Uncheck: "Start the task only if the computer is on AC power"
  - ❌ Uncheck: "Stop if the computer switches to battery power"
  - ✅ Check: "Wake the computer to run this task" (if applicable)

- **Network**:
  - ✅ Check: "Start only if the following network connection is available"
  - Select: **"Any connection"**

#### Step 6: Configure Settings

Click **"Settings"** tab:

Recommended settings:
- ✅ Check: "Allow task to be run on demand"
- ✅ Check: "Run task as soon as possible after a scheduled start is missed"
- ✅ Check: "If the task fails, restart every": `10 minutes`, Attempt to restart up to: `3 times`
- ❌ Uncheck: "Stop the task if it runs longer than": (let it complete naturally)
- Select: "If the running task does not end when requested, force it to stop"

#### Step 7: Save and Test

1. Click **OK** to save the task
2. Enter credentials for the service account (if prompted)
3. Right-click the task in Task Scheduler Library
4. Click **"Run"** to test immediately
5. Monitor execution:
   - **Last Run Result**: Should show `0x0` (success)
   - **Last Run Time**: Should update
   - Check log files in `C:\CyAudit\Logs\`

---

### Option B: PowerShell Method (Automated Deployment)

For deploying to multiple systems or automation:

```powershell
# Configuration
$TaskName = "CyAudit Automated Assessment"
$TaskDescription = "Runs CyAudit security assessment and transforms data for Splunk Cloud ingestion"
$ScriptPath = "C:\CyAudit\CyAudit_3.4\Run-CyAuditPipeline.ps1"
$WorkingDirectory = "C:\CyAudit\CyAudit_3.4"
$ServiceAccountUser = "DOMAIN\ServiceAccount"  # Change to your service account
$ScheduleTime = "2:00AM"
$ScheduleDay = "Sunday"

# Create scheduled task action
$Action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$ScriptPath`"" `
    -WorkingDirectory $WorkingDirectory

# Create weekly trigger
$Trigger = New-ScheduledTaskTrigger `
    -Weekly `
    -DaysOfWeek $ScheduleDay `
    -At $ScheduleTime

# Create task settings
$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 10)

# Create task principal (run with highest privileges)
$Principal = New-ScheduledTaskPrincipal `
    -UserId $ServiceAccountUser `
    -LogonType Password `
    -RunLevel Highest

# Register the task
Register-ScheduledTask `
    -TaskName $TaskName `
    -Description $TaskDescription `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -Principal $Principal `
    -Force

Write-Host "Scheduled task created successfully!" -ForegroundColor Green
Write-Host "Task Name: $TaskName" -ForegroundColor Cyan
Write-Host "Schedule: Every $ScheduleDay at $ScheduleTime" -ForegroundColor Cyan
```

**To run this script:**
1. Save as `Deploy-CyAuditScheduledTask.ps1`
2. Edit configuration variables at the top
3. Run with Administrator privileges:
   ```powershell
   .\Deploy-CyAuditScheduledTask.ps1
   ```

---

## Universal Forwarder Integration

### Install Splunk Universal Forwarder

1. **Download** from [Splunk.com](https://www.splunk.com/en_us/download/universal-forwarder.html)

2. **Run installer** with Administrator privileges

3. **Configure during installation:**
   - Installation Path: `C:\Program Files\SplunkUniversalForwarder` (default)
   - Admin Username: `admin`
   - Admin Password: (set a strong password)
   - Deployment Server: (leave blank unless using centralized management)

### Configure Forwarder Outputs

Create/edit: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`

```ini
[tcpout]
defaultGroup = splunk_cloud_cyaudit

[tcpout:splunk_cloud_cyaudit]
server = inputs.yourinstance.splunkcloud.com:9997

# SSL configuration for Splunk Cloud
[tcpout-server://inputs.yourinstance.splunkcloud.com:9997]
sslCertPath = $SPLUNK_HOME\etc\auth\server.pem
sslRootCAPath = $SPLUNK_HOME\etc\auth\cacert.pem
sslPassword = changeme
sslVerifyServerCert = true
```

**Note:** Contact your Splunk Cloud administrator for:
- Exact server address
- SSL certificates
- Authentication credentials

### Configure Forwarder Inputs

Copy the provided inputs.conf or create: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
[monitor://C:\CyAudit\SplunkReady\*.json]
disabled = false
index = cyaudit
sourcetype = cyaudit:auto
recursive = false
whitelist = \.json$
ignoreOlderThan = 14d
crcSalt = <SOURCE>
initCrcLength = 1024

# Optional: Monitor pipeline logs
[monitor://C:\CyAudit\Logs\*.log]
disabled = false
index = cyaudit
sourcetype = cyaudit:pipeline_log
```

### Restart Forwarder Service

```powershell
Restart-Service SplunkForwarder
```

### Verify Forwarder is Running

```powershell
Get-Service SplunkForwarder | Select-Object Status, StartType, DisplayName

# Check forwarder is sending data
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server
```

Expected output:
```
Active forwards:
        inputs.yourinstance.splunkcloud.com:9997
```

---

## Monitoring & Maintenance

### Check Pipeline Execution

#### Via Task Scheduler

1. Open Task Scheduler (`taskschd.msc`)
2. Locate: `CyAudit Automated Assessment`
3. Review:
   - **Status**: Should show "Ready" or "Running"
   - **Last Run Time**: Should match schedule
   - **Last Run Result**: `0x0` = Success, other = Error
   - **Next Run Time**: Confirms schedule is active

#### Via PowerShell

```powershell
# Get task status
Get-ScheduledTask -TaskName "CyAudit Automated Assessment" | Select-Object State, LastRunTime, LastTaskResult, NextRunTime

# Get detailed task history
Get-ScheduledTask -TaskName "CyAudit Automated Assessment" | Get-ScheduledTaskInfo

# View recent task runs (Event Viewer)
Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -MaxEvents 50 | Where-Object {$_.Message -like "*CyAudit*"} | Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize
```

### Review Logs

```powershell
# List recent logs
Get-ChildItem -Path "C:\CyAudit\Logs" | Sort-Object LastWriteTime -Descending | Select-Object -First 10

# Open most recent log
$log = Get-ChildItem -Path "C:\CyAudit\Logs" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
notepad $log.FullName

# Search for errors
Get-Content -Path "C:\CyAudit\Logs\*.log" | Select-String -Pattern "\[ERROR\]" -Context 2
```

### Monitor Splunk Ingestion

In Splunk Cloud:

```spl
# Verify data is being received
index=cyaudit | stats count by sourcetype, computer_name | sort -count

# Check most recent assessment
index=cyaudit | stats latest(_time) as last_assessment by computer_name | eval last_assessment=strftime(last_assessment, "%Y-%m-%d %H:%M:%S")

# Count assessments by day
index=cyaudit sourcetype=cyaudit:systeminfo | timechart span=1d count

# Pipeline execution tracking
index=cyaudit sourcetype=cyaudit:pipeline_log | stats count by host, log_level
```

### Disk Space Monitoring

```powershell
# Check disk usage
Get-ChildItem -Path "C:\CyAudit\" -Recurse | Measure-Object -Property Length -Sum | Select-Object @{Name="SizeMB";Expression={[math]::Round($_.Sum / 1MB, 2)}}

# Breakdown by directory
Get-ChildItem -Path "C:\CyAudit\" -Directory | ForEach-Object {
    $size = (Get-ChildItem -Path $_.FullName -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
    [PSCustomObject]@{
        Directory = $_.Name
        SizeMB = [math]::Round($size, 2)
    }
} | Sort-Object SizeMB -Descending
```

### Maintenance Tasks

#### Weekly

- ✅ Review last scheduled task execution (verify 0x0 exit code)
- ✅ Check recent log for warnings/errors
- ✅ Verify data appears in Splunk within expected timeframe

#### Monthly

- ✅ Review disk space usage (ensure retention policy is working)
- ✅ Review Splunk dashboard for STIG compliance trends
- ✅ Validate Universal Forwarder is connected: `Get-Service SplunkForwarder`
- ✅ Update CyAudit scripts if new version available

#### Quarterly

- ✅ Review and adjust `RetentionDays` if needed (compliance requirements)
- ✅ Review scheduled task trigger (adjust timing if conflicts with backups/maintenance windows)
- ✅ Test pipeline manually to ensure no configuration drift
- ✅ Review email alert configuration (test notification delivery)

---

## Troubleshooting

### Pipeline Fails to Run

**Symptom:** Scheduled task shows failed status, no log files created

**Possible Causes & Solutions:**

1. **Execution Policy Issue**
   ```powershell
   Get-ExecutionPolicy -List
   # Should show RemoteSigned or Unrestricted for LocalMachine
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
   ```

2. **Permissions Issue**
   - Verify service account has Administrator privileges
   - Check file/folder permissions on `C:\CyAudit\`
   - Test: Run Task Scheduler task manually with "Run with highest privileges"

3. **Script Path Incorrect**
   - Verify path in Task Scheduler action matches actual file location
   - Check for typos in file paths

4. **Working Directory Not Set**
   - Task Scheduler: Ensure "Start in" field is set to `C:\CyAudit\CyAudit_3.4`

### Configuration File Not Found

**Symptom:** Error message: `Configuration file not found: ...\CyAuditPipeline.config.json`

**Solution:**
```powershell
# Verify file exists
Test-Path "C:\CyAudit\CyAudit_3.4\CyAuditPipeline.config.json"

# If missing, copy from another system or recreate from template in this guide
```

### CyAudit Assessment Fails

**Symptom:** Phase 1 fails with error, pipeline exits with code 2

**Diagnostic Steps:**

1. Run CyAudit manually to see detailed error:
   ```powershell
   cd "C:\CyAudit\CyAudit_3.4"
   .\CyAudit_Opus_V3.4.ps1 -ComputerName "localhost" -ClientName "Test"
   ```

2. Common issues:
   - **Insufficient privileges**: Must run as Administrator
   - **WMI service not running**: Start service: `Start-Service Winmgmt`
   - **Firewall blocking**: Check Windows Firewall settings
   - **PowerShell version**: Must be 5.1+

### Transformation Fails

**Symptom:** Phase 2 fails, pipeline exits with code 3

**Diagnostic Steps:**

1. Check if assessment output exists:
   ```powershell
   Get-ChildItem -Path "C:\CyAudit\Assessments" -Directory | Select-Object -Last 1
   ```

2. Run transformation manually:
   ```powershell
   cd "C:\CyAudit\CyAudit_3.4"
   $latest = Get-ChildItem -Path "C:\CyAudit\Assessments" -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
   .\Transform-CyAuditForSplunk.ps1 -InputPath $latest.FullName -OutputPath "C:\CyAudit\SplunkReady" -Verbose
   ```

3. Common issues:
   - **Corrupted assessment output**: Re-run CyAudit
   - **Disk full**: Check available space on C:\
   - **Permission denied**: Verify service account can write to `SplunkReadyPath`

### Validation Fails

**Symptom:** Phase 3 fails, validation errors reported

**Solutions:**

- If data quality is acceptable but validation fails:
  ```json
  "FailOnValidationError": false
  ```
  This allows pipeline to continue despite validation warnings.

- If data quality is actually bad:
  1. Check source CyAudit output for issues
  2. Check transformation script for errors
  3. Review validation log for specific failures

### Forwarder Not Forwarding Data

**Symptom:** Files appear in `C:\CyAudit\SplunkReady\` but not in Splunk

**Diagnostic Steps:**

1. Verify forwarder service is running:
   ```powershell
   Get-Service SplunkForwarder
   ```

2. Check forwarder internal logs:
   ```
   C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log
   ```

3. Test forwarder connection:
   ```powershell
   & "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server
   ```

4. Common issues:
   - **Network connectivity**: Verify port 9997 is reachable
   - **SSL certificate issue**: Check certificates in outputs.conf
   - **Inputs.conf misconfigured**: Verify monitor path matches `SplunkReadyPath`
   - **Index doesn't exist**: Create `cyaudit` index in Splunk Cloud

### Email Alerts Not Sending

**Symptom:** Pipeline fails but no email received

**Diagnostic Steps:**

1. Verify email configuration:
   ```powershell
   $config = Get-Content "C:\CyAudit\CyAudit_3.4\CyAuditPipeline.config.json" | ConvertFrom-Json
   $config.EmailAlerts
   ```

2. Test SMTP connectivity:
   ```powershell
   Test-NetConnection -ComputerName "smtp.office365.com" -Port 587
   ```

3. Test Send-MailMessage manually:
   ```powershell
   Send-MailMessage -To "test@example.com" -From "cyaudit@example.com" -Subject "Test" -Body "Test" -SmtpServer "smtp.office365.com" -Port 587 -UseSsl
   ```

4. Common issues:
   - **SMTP credentials wrong**: Verify username/password
   - **App password required**: Some providers (Office 365, Gmail) require app-specific passwords
   - **Firewall blocking SMTP**: Check outbound port 587/465/25
   - **TLS version mismatch**: Update to PowerShell 5.1+ for modern TLS support

### Disk Space Full

**Symptom:** Pipeline fails with "insufficient disk space" errors

**Solution:**

1. Reduce retention period:
   ```json
   "RetentionDays": 7
   ```

2. Manually cleanup old files:
   ```powershell
   # Remove assessments older than 7 days
   $cutoff = (Get-Date).AddDays(-7)
   Get-ChildItem -Path "C:\CyAudit\Assessments" -Directory | Where-Object {$_.LastWriteTime -lt $cutoff} | Remove-Item -Recurse -Force

   # Remove old logs
   Get-ChildItem -Path "C:\CyAudit\Logs" -File | Where-Object {$_.LastWriteTime -lt $cutoff} | Remove-Item -Force
   ```

3. Consider moving to larger drive or network storage

---

## Advanced Scenarios

### Multi-System Scanning

To scan multiple systems from a central server:

1. **Create separate configuration files** for each system:
   ```
   C:\CyAudit\CyAudit_3.4\config_server01.json
   C:\CyAudit\CyAudit_3.4\config_server02.json
   ```

2. **Create separate scheduled tasks** for each system:
   ```powershell
   # Task 1: SERVER01 - Runs Sunday at 2:00 AM
   # Action: Run-CyAuditPipeline.ps1 -ConfigFile "config_server01.json" -ComputerName "SERVER01"

   # Task 2: SERVER02 - Runs Sunday at 3:00 AM
   # Action: Run-CyAuditPipeline.ps1 -ConfigFile "config_server02.json" -ComputerName "SERVER02"
   ```

3. **Stagger execution times** to avoid resource contention

### Custom Retention Policies

**Scenario:** Keep STIG compliance data forever, but delete other assessments after 30 days

**Solution:** Modify cleanup logic in `Run-CyAuditPipeline.ps1` or use external script:

```powershell
# Selective cleanup script
$cutoff = (Get-Date).AddDays(-30)

# Delete all old assessments EXCEPT those containing STIG data
Get-ChildItem -Path "C:\CyAudit\Assessments" -Directory | Where-Object {
    $_.LastWriteTime -lt $cutoff -and
    -not (Test-Path (Join-Path $_.FullName "*STIG*.json"))
} | Remove-Item -Recurse -Force
```

### Performance Tuning

For systems with limited resources:

1. **Reduce CyAudit scope**: Edit `CyAudit_Opus_V3.4.ps1` to skip non-essential checks
2. **Disable HTML generation**: Set `"IncludeHTML": false` in config
3. **Skip validation**: Set `"ValidateOutput": false` or use `-SkipValidation` parameter
4. **Increase scheduled task timeout**: Task Scheduler Settings → adjust "Stop the task if it runs longer than"

### Integration with SIEM/Ticketing

To create tickets on STIG compliance failures:

1. **Parse Splunk data** via API
2. **Trigger on** non-compliant findings
3. **Create ticket** in ServiceNow/Jira/etc.

Example Splunk alert query:
```spl
index=cyaudit sourcetype=cyaudit:stig_* compliance_status=fail
| stats count by computer_name, STIG_ID, Description
| where count > 0
```

---

## Summary Checklist

### Initial Setup
- [ ] Extract files to `C:\CyAudit\CyAudit_3.4\`
- [ ] Create working directories (Assessments, SplunkReady, Logs)
- [ ] Edit `CyAuditPipeline.config.json`
- [ ] Test pipeline manually
- [ ] Verify output files created
- [ ] Review log for errors

### Scheduled Task
- [ ] Create scheduled task via GUI or PowerShell
- [ ] Configure trigger (weekly recommended)
- [ ] Set service account with Admin privileges
- [ ] Enable "Run with highest privileges"
- [ ] Test task execution
- [ ] Verify Last Run Result = 0x0

### Universal Forwarder
- [ ] Install Splunk Universal Forwarder
- [ ] Configure outputs.conf (Splunk Cloud connection)
- [ ] Configure inputs.conf (monitor SplunkReadyPath)
- [ ] Restart forwarder service
- [ ] Verify data appears in Splunk Cloud

### Monitoring
- [ ] Schedule weekly review of task execution
- [ ] Set up Splunk dashboard for compliance tracking
- [ ] Configure email alerts for failures
- [ ] Document any customizations made

---

## Support Resources

### Documentation
- **This Guide**: Complete deployment instructions
- **README.md**: Quick reference and overview
- **README_Splunk_Integration.md**: Detailed Splunk configuration and sample searches

### Logs
- **Pipeline Logs**: `C:\CyAudit\Logs\CyAuditPipeline_*.log`
- **Forwarder Logs**: `C:\Program Files\SplunkUniversalForwarder\var\log\splunk\`
- **Windows Event Viewer**: Task Scheduler operational logs

### Contact
- **Splunk Cloud Support**: Contact your Splunk administrator
- **CyAudit Support**: Review GitHub repository or internal documentation

---

**Congratulations!** Your automated CyAudit security assessment pipeline is now fully deployed and operational. The system will continuously monitor your environment and provide up-to-date security posture visibility in Splunk Cloud.
