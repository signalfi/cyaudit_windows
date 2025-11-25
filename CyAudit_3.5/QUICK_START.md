# CyAudit 3.4 - Quick Start Guide

**For Experienced Administrators** | **Estimated Time:** 15 minutes

---

## Prerequisites

✅ Windows 10/11 or Server 2016+
✅ PowerShell 5.1+
✅ Local Administrator privileges
✅ Splunk Universal Forwarder 9.x installed
✅ Splunk Cloud instance with `cyaudit` index created

---

## 1. Installation (2 minutes)

```powershell
# Extract to installation directory
Copy-Item -Path "CyAudit_3.5" -Destination "C:\CyAudit\" -Recurse

# Create working directories
New-Item -Path "C:\CyAudit\Assessments","C:\CyAudit\SplunkReady","C:\CyAudit\Logs" -ItemType Directory -Force

# Unblock scripts
Get-ChildItem -Path "C:\CyAudit\CyAudit_3.5" -Filter "*.ps1" -Recurse | Unblock-File

# Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
```

---

## 2. Configuration (3 minutes)

Edit `C:\CyAudit\CyAudit_3.5\CyAuditPipeline.config.json`:

```json
{
  "ClientName": "YourOrgName",
  "ComputerName": "",
  "OutputBasePath": "C:\\CyAudit\\Assessments",
  "SplunkReadyPath": "C:\\CyAudit\\SplunkReady",
  "LogPath": "C:\\CyAudit\\Logs",
  "ValidateOutput": true,
  "FailOnValidationError": false,
  "RetentionDays": 30,
  "EmailAlerts": {
    "Enabled": false
  }
}
```

---

## 3. Test Execution (10 minutes)

```powershell
cd "C:\CyAudit\CyAudit_3.5"
.\Run-CyAuditPipeline.ps1 -Verbose
```

**Expected:** Pipeline completes successfully, creates 22 JSON files in `C:\CyAudit\SplunkReady\`

---

## 4. Configure Universal Forwarder (5 minutes)

### A. Configure Inputs

Edit: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
[monitor://C:\CyAudit\SplunkReady\*.json]
disabled = false
index = cyaudit
sourcetype = cyaudit:auto
recursive = false
whitelist = \.json$
ignoreOlderThan = 14d
```

### B. Configure Outputs (if not already done)

Edit: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`

```ini
[tcpout]
defaultGroup = splunk_cloud_cyaudit

[tcpout:splunk_cloud_cyaudit]
server = inputs.yourinstance.splunkcloud.com:9997
```

**Note:** Contact Splunk admin for SSL configuration

### C. Restart Forwarder

```powershell
Restart-Service SplunkForwarder
```

---

## 5. Create Scheduled Task (5 minutes)

### Option A: PowerShell (Fastest)

```powershell
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-ExecutionPolicy Bypass -NoProfile -File "C:\CyAudit\CyAudit_3.5\Run-CyAuditPipeline.ps1"' -WorkingDirectory "C:\CyAudit\CyAudit_3.5"
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2:00AM
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "CyAudit Automated Assessment" -Description "Runs CyAudit security assessment and transforms data for Splunk" -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Force

Write-Host "✓ Scheduled task created: Runs every Sunday at 2:00 AM" -ForegroundColor Green
```

### Option B: Task Scheduler GUI

1. Open `taskschd.msc`
2. Create Task → **Name:** `CyAudit Automated Assessment`
3. **General:** Run with highest privileges, Run whether user is logged on or not
4. **Triggers:** Weekly, Sunday, 2:00 AM
5. **Actions:** Start `powershell.exe` with arguments:
   ```
   -ExecutionPolicy Bypass -NoProfile -File "C:\CyAudit\CyAudit_3.5\Run-CyAuditPipeline.ps1"
   ```
6. **Start in:** `C:\CyAudit\CyAudit_3.5`

---

## 6. Verify in Splunk (2 minutes)

Wait ~30 seconds after test run, then search in Splunk Cloud:

```spl
index=cyaudit | stats count by sourcetype
```

**Expected:** 20+ sourcetypes with event counts

---

## Complete!

Your automated pipeline is now operational:

- **Scheduled Execution:** Every Sunday at 2:00 AM (or your configured time)
- **Automatic Transformation:** Raw audit → Splunk-ready JSON
- **Automatic Forwarding:** Universal Forwarder → Splunk Cloud
- **Automatic Cleanup:** Old assessments deleted after 30 days

---

## Useful Commands

### Check Last Run
```powershell
Get-ScheduledTask -TaskName "CyAudit Automated Assessment" | Get-ScheduledTaskInfo
```

### View Recent Log
```powershell
Get-ChildItem "C:\CyAudit\Logs" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content -Tail 50
```

### Manual Execution
```powershell
cd "C:\CyAudit\CyAudit_3.5"
.\Run-CyAuditPipeline.ps1
```

### Forwarder Status
```powershell
Get-Service SplunkForwarder
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Task fails to run | Check execution policy: `Get-ExecutionPolicy -List` |
| No data in Splunk | Verify forwarder service running: `Get-Service SplunkForwarder` |
| Pipeline errors | Check log: `C:\CyAudit\Logs\CyAuditPipeline_*.log` |
| Disk space full | Reduce RetentionDays in config file |

---

## Documentation

- **DEPLOYMENT_GUIDE.md** - Complete deployment instructions with troubleshooting
- **README_Splunk_Integration.md** - Detailed Splunk configuration and sample searches
- **CyAuditPipeline.config.json** - Configuration file with inline help

---

**Next Steps:**
1. Deploy Splunk props.conf configurations for optimal field extraction (see `splunk_configs/` folder)
2. Upload lookup tables to Splunk (see `splunk_configs/lookups/` folder)
3. Create Splunk dashboards for STIG compliance tracking (see README_Splunk_Integration.md for sample searches)

**Questions?** See DEPLOYMENT_GUIDE.md for comprehensive troubleshooting and advanced scenarios.
