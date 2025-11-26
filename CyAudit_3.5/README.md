# CyAudit 3.5 - Automated Security Assessment & Splunk Integration

**Version:** 3.5.0
**Release Date:** 2025-11-25
**Package Size:** 420 KB (complete)

---

## What's Included

This package provides everything needed for **fully automated** Windows security assessments with Splunk Cloud integration:

✅ **CyAudit Opus v3.5** - Comprehensive Windows security audit engine
✅ **Automated Orchestration** - Schedule and run assessments without manual intervention
✅ **Splunk Transformation** - Convert audit data to Splunk-optimized NDJSON format
✅ **Universal Forwarder Integration** - Automatic data forwarding to Splunk Cloud
✅ **Validation & Testing** - Built-in quality assurance
✅ **Retention Management** - Automatic cleanup of old assessments
✅ **Production-Ready** - Error handling, logging, and email alerts

---

## Quick Links

| Document | Purpose | Audience |
|----------|---------|----------|
| **[QUICK_START.md](QUICK_START.md)** | Get running in 15 minutes | Experienced Admins |
| **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** | Complete deployment & scheduling guide | All Users |
| **[README_Splunk_Integration.md](README_Splunk_Integration.md)** | Splunk configuration & sample searches | Splunk Admins |
| **[CyAuditPipeline.config.json](CyAuditPipeline.config.json)** | Configuration file with inline help | All Users |

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│ Windows Task Scheduler                                        │
│ Runs: Weekly (Sunday 2:00 AM, configurable)                  │
└───────────────────────┬──────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────────┐
│ Run-CyAuditPipeline.ps1 (Master Orchestrator)               │
│ • Loads configuration                                         │
│ • Runs CyAudit assessment                                     │
│ • Transforms data for Splunk                                  │
│ • Validates output quality                                    │
│ • Manages retention/cleanup                                   │
│ • Logs all operations                                         │
└───────────────────────┬──────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────────┐
│ Universal Forwarder (Continuous Monitoring)                   │
│ • Watches: C:\CyAudit\SplunkReady\*.json                    │
│ • Automatically forwards new files to Splunk Cloud           │
│ • No manual upload required                                   │
└───────────────────────┬──────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────────┐
│ Splunk Cloud                                                  │
│ • Index: cyaudit                                              │
│ • 20+ sourcetypes with search-time extraction                │
│ • STIG compliance tracking & trending                         │
│ • Dashboards & alerting                                       │
└──────────────────────────────────────────────────────────────┘
```

---

## Package Contents

### Core Scripts

| File | Description | Size |
|------|-------------|------|
| **CyAudit_Opus_V3.5.ps1** | Main security assessment engine | 203 KB |
| **Run-CyAuditPipeline.ps1** | Orchestration & scheduling script | 25 KB |
| **Transform-CyAuditForSplunk.ps1** | Data transformation for Splunk | 58 KB |
| **Test-SplunkTransformation.ps1** | Validation & quality assurance | 17 KB |
| **Upload-ToSplunkCloud.ps1** | Manual HEC upload (alternative method) | 14 KB |

### Configuration

| File | Description |
|------|-------------|
| **CyAuditPipeline.config.json** | Pipeline configuration with inline documentation |

### Documentation

| File | Description | Pages |
|------|-------------|-------|
| **QUICK_START.md** | Get started in 15 minutes | 4 |
| **DEPLOYMENT_GUIDE.md** | Complete deployment & troubleshooting | 35 |
| **README_Splunk_Integration.md** | Splunk configuration reference | 30 |
| **README.md** | This file | 8 |

### Splunk Configuration Files

```
splunk_configs/
├── props.conf           # 20+ sourcetype definitions
├── inputs.conf          # Universal Forwarder monitoring config
├── transforms.conf      # Field transformations
├── indexes.conf         # Index definitions
└── lookups/             # Enrichment tables
    ├── registry_types.csv
    ├── filesystemrights.csv
    └── stig_severity.csv
```

---

## Getting Started

### For Experienced Administrators

**Want to get running quickly?** → **[QUICK_START.md](QUICK_START.md)** (15 minutes)

### For Complete Deployment

**Need step-by-step instructions?** → **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** (comprehensive)

### Basic Workflow

1. **Install** - Extract to `C:\CyAudit\CyAudit_3.5\`
2. **Configure** - Edit `CyAuditPipeline.config.json`
3. **Test** - Run `Run-CyAuditPipeline.ps1` manually
4. **Schedule** - Create Windows scheduled task (weekly recommended)
5. **Monitor** - Verify data in Splunk Cloud

---

## What This System Does

### Security Assessment (CyAudit)

Collects 50+ security data points including:
- System information & Windows version
- User accounts, groups, and rights assignments
- Password and audit policies
- Registry values and STIG compliance
- Services, features, and shares
- File/directory permissions
- Hotfixes and missing patches
- Event log settings
- PowerSTIG findings (DISA STIG compliance)
- Executive summary reports

**Output:** 52 files in various formats (CSV, JSON, XML, TXT)

### Transformation (Splunk Optimization)

Converts raw audit data to Splunk-ready format:
- ✅ UTF-16 LE → UTF-8 encoding (38-40% smaller files)
- ✅ Multiple timestamp formats → ISO 8601 standard
- ✅ Nested structures → Flattened for search efficiency
- ✅ Numeric codes → Human-readable values (lookups)
- ✅ Multi-value fields → JSON arrays
- ✅ Metadata enrichment → Computer name, audit date, event type

**Output:** 25 NDJSON files optimized for Splunk search-time extraction

### Validation

Quality assurance checks:
- ✅ JSON syntax validation
- ✅ UTF-8 encoding verification
- ✅ Required fields presence
- ✅ ISO 8601 timestamp compliance
- ✅ File structure integrity

### Automated Forwarding

Splunk Universal Forwarder continuously monitors output directory and forwards new files to Splunk Cloud within seconds.

---

## System Requirements

| Component | Requirement |
|-----------|-------------|
| **Operating System** | Windows 10/11, Server 2016+ |
| **PowerShell** | Version 5.1 or later |
| **Privileges** | Local Administrator |
| **Disk Space** | 500 MB (assessments + logs) |
| **Network** | HTTPS to Splunk Cloud (port 9997) |
| **Splunk UF** | Version 9.x or later |
| **Splunk Cloud** | Active subscription, cyaudit index |

---

## Deployment Options

### Option 1: Fully Automated (Recommended)

**Use Case:** Production environments with regular assessments

**Setup:**
1. Deploy files
2. Configure pipeline
3. Create scheduled task (weekly)
4. Install & configure Universal Forwarder
5. Done - runs automatically

**Pros:**
- No manual intervention required
- Consistent assessment schedule
- Automatic data forwarding
- Retention management built-in
- Email alerts on failures

### Option 2: Manual Execution

**Use Case:** Ad-hoc assessments, testing, one-time audits

**Setup:**
1. Deploy files
2. Configure pipeline
3. Run manually: `.\Run-CyAuditPipeline.ps1`
4. Optionally upload via HEC: `.\Upload-ToSplunkCloud.ps1`

**Pros:**
- On-demand execution
- No scheduled task required
- Flexible timing

---

## Configuration

### Essential Settings

Edit `CyAuditPipeline.config.json`:

```json
{
  "ClientName": "YourOrganization",
  "ComputerName": "",
  "OutputBasePath": "C:\\CyAudit\\Assessments",
  "SplunkReadyPath": "C:\\CyAudit\\SplunkReady",
  "LogPath": "C:\\CyAudit\\Logs",
  "ValidateOutput": true,
  "RetentionDays": 30
}
```

**Key Fields:**
- `ClientName` - Your organization name (used in reports)
- `ComputerName` - System to audit (blank = localhost)
- `SplunkReadyPath` - **Must match Universal Forwarder monitor path**
- `RetentionDays` - Auto-delete assessments older than N days

### Optional: Email Alerts

```json
{
  "EmailAlerts": {
    "Enabled": true,
    "SendOnSuccess": false,
    "SmtpServer": "smtp.office365.com",
    "Port": 587,
    "UseSsl": true,
    "From": "cyaudit@yourcompany.com",
    "To": "security-team@yourcompany.com"
  }
}
```

Receives email on pipeline failures for immediate attention.

---

## Monitoring

### Check Pipeline Status

```powershell
# View scheduled task status
Get-ScheduledTask -TaskName "CyAudit Automated Assessment" | Get-ScheduledTaskInfo

# View recent log
Get-ChildItem "C:\CyAudit\Logs" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content -Tail 50

# Check forwarder status
Get-Service SplunkForwarder
```

### Verify in Splunk

```spl
# Count events by sourcetype
index=cyaudit | stats count by sourcetype

# Latest assessment per system
index=cyaudit | stats latest(_time) as last_assessment by computer_name

# STIG compliance rate
index=cyaudit sourcetype=cyaudit:stig_* | stats count by compliance_status
```

---

## Troubleshooting

| Issue | Quick Fix | Documentation |
|-------|-----------|---------------|
| Task fails to run | Check execution policy: `Set-ExecutionPolicy RemoteSigned -Scope LocalMachine` | [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md#pipeline-fails-to-run) |
| No data in Splunk | Verify forwarder running: `Get-Service SplunkForwarder` | [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md#forwarder-not-forwarding-data) |
| Pipeline errors | Check log: `C:\CyAudit\Logs\CyAuditPipeline_*.log` | [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md#troubleshooting) |
| Config not found | Verify file exists: `Test-Path "C:\CyAudit\CyAudit_3.5\CyAuditPipeline.config.json"` | [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md#configuration-file-not-found) |

**See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md#troubleshooting) for comprehensive troubleshooting**

---

## Advanced Features

### Multi-System Scanning
Audit multiple systems from a central server with separate configurations per system.

### Custom Retention Policies
Configure different retention periods for different data types.

### Email Notifications
Receive alerts on failures or optionally on successful completion.

### Performance Tuning
Optimize for resource-constrained systems (disable HTML, skip validation, reduce scope).

**See [DEPLOYMENT_GUIDE.md - Advanced Scenarios](DEPLOYMENT_GUIDE.md#advanced-scenarios) for details**

---

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Success | None - pipeline completed successfully |
| 1 | Configuration error | Check config file and prerequisites |
| 2 | CyAudit failed | Review assessment logs |
| 3 | Transformation failed | Check input data integrity |
| 4 | Validation failed | Review validation errors (if FailOnValidationError=true) |
| 5 | Cleanup failed | Check disk space and permissions |
| 99 | Unhandled exception | Review pipeline log for stack trace |

---

## Sample Splunk Searches

```spl
# STIG Compliance Summary
index=cyaudit sourcetype=cyaudit:stig_*
| stats count by compliance_status, Severity
| chart count over compliance_status by Severity

# Non-Compliant High/Critical Findings
index=cyaudit sourcetype=cyaudit:stig_* compliance_status=fail Severity IN ("High", "Critical")
| table computer_name, STIG_ID, Title, Description, Status

# User Account Summary
index=cyaudit sourcetype=cyaudit:users
| stats count by AccountDisabled, PasswordRequired
| addtotals

# Service Status by Start Mode
index=cyaudit sourcetype=cyaudit:services
| stats count by service_status, StartMode
| chart count over service_status by StartMode

# Missing Critical Patches
index=cyaudit sourcetype=cyaudit:missinghotfixes Rating="Critical"
| table computer_name, KBNum, Description, InstalledOn
```

**See [README_Splunk_Integration.md](README_Splunk_Integration.md#sample-searches) for 30+ search examples**

---

## Version History

### v3.5.0 (2025-11-25)
- Fixed Unicode/encoding corruption in PowerShell scripts
- Fixed STIG version mismatch for PowerSTIG compatibility
- Fixed pipeline output directory handling
- Fixed script hang during Splunk transformation
- Hardened Write-SplunkNDJson with proper disposal and error handling
- Fixed Splunk config: filename patterns, sourcetype routing, props.conf consolidation
- See CHANGELOG.md for details

### v3.4.0 (2025-11-12)
- Initial release with Splunk integration
- Automated pipeline orchestration
- Universal Forwarder integration as primary method
- HEC upload as alternative method
- 20+ Splunk sourcetypes with search-time extraction
- Comprehensive validation and testing
- Email alerts and retention management
- Complete documentation suite

---

## Support

### Documentation
- **[QUICK_START.md](QUICK_START.md)** - Fast deployment for experienced admins
- **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** - Complete reference with troubleshooting
- **[README_Splunk_Integration.md](README_Splunk_Integration.md)** - Splunk configuration details

### Logs
- Pipeline: `C:\CyAudit\Logs\CyAuditPipeline_*.log`
- CyAudit: `C:\CyAudit\Assessments\<timestamp>\CyAudit_ErrorLog.json`
- Forwarder: `C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log`

### Configuration File
All settings documented with inline comments: `CyAuditPipeline.config.json`

---

## License

This package is provided as-is for use with CyAudit Opus v3.5 and Splunk Cloud deployments.

---

## Getting Help

1. **Quick Issues** → Check [QUICK_START.md](QUICK_START.md) troubleshooting table
2. **Detailed Issues** → See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md#troubleshooting)
3. **Splunk Questions** → Refer to [README_Splunk_Integration.md](README_Splunk_Integration.md)
4. **Configuration Help** → Read inline comments in `CyAuditPipeline.config.json`

---

**Ready to get started?** → **[QUICK_START.md](QUICK_START.md)** (15 minutes to full automation!)
