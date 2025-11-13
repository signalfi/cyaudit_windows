# CyAudit Opus v3.4 - Usage Examples

This document provides practical examples for using CyAudit Opus v3.4.

## Basic Usage Examples

### Running a Manual Assessment

```powershell
# Run with default configuration
python cyaudit.py

# Run with custom configuration
python cyaudit.py --config my_config.json

# Run with verbose logging for troubleshooting
python cyaudit.py --verbose
```

### Setting Up Automated Assessments

```powershell
# Setup daily assessment at 2:00 AM (default)
python cyaudit.py --setup-scheduler

# First, customize config.json for different schedule:
# {
#   "task_scheduler": {
#     "schedule": "WEEKLY",
#     "start_time": "03:00"
#   }
# }
# Then run setup
python cyaudit.py --config custom_schedule.json --setup-scheduler
```

## Configuration Examples

### Minimal Configuration

Basic setup with only essential settings:

```json
{
  "output_directory": "assessments",
  "logging": {
    "directory": "logs"
  }
}
```

### Production Configuration

Full configuration for production use with Splunk:

```json
{
  "output_directory": "C:\\ProgramData\\CyAudit\\assessments",
  "logging": {
    "directory": "C:\\ProgramData\\CyAudit\\logs",
    "retention_days": 30
  },
  "assessment": {
    "retention_days": 180,
    "include_system_info": true,
    "include_users": true,
    "include_groups": true,
    "include_services": true,
    "include_processes": true,
    "include_network": true,
    "include_security_policies": true,
    "include_registry": true,
    "include_installed_software": true
  },
  "splunk": {
    "enabled": true,
    "forwarder_path": "C:\\Program Files\\SplunkUniversalForwarder",
    "monitor_path": "C:\\ProgramData\\CyAudit\\assessments",
    "sourcetype": "cyaudit:windows:assessment"
  },
  "task_scheduler": {
    "task_name": "CyAudit_Security_Assessment",
    "schedule": "DAILY",
    "start_time": "02:00",
    "enabled": true
  }
}
```

### Development/Testing Configuration

Lightweight configuration for testing:

```json
{
  "output_directory": "test_output",
  "logging": {
    "directory": "test_logs",
    "retention_days": 7
  },
  "assessment": {
    "retention_days": 7,
    "include_system_info": true,
    "include_users": false,
    "include_groups": false,
    "include_services": false,
    "include_processes": false,
    "include_network": true,
    "include_security_policies": false,
    "include_registry": false,
    "include_installed_software": false
  },
  "splunk": {
    "enabled": false
  },
  "task_scheduler": {
    "enabled": false
  }
}
```

## Splunk Integration Examples

### Setting Up Splunk Universal Forwarder

1. Install Splunk Universal Forwarder:
```powershell
# Download from Splunk website, then install
msiexec.exe /i splunkforwarder-x.x.x.msi AGREETOLICENSE=Yes /quiet
```

2. Configure forwarding to Splunk Cloud:
```powershell
cd "C:\Program Files\SplunkUniversalForwarder\bin"
.\splunk.exe add forward-server <your-splunk-cloud>:9997 -auth admin:changeme
```

3. Enable CyAudit in config.json:
```json
{
  "splunk": {
    "enabled": true,
    "forwarder_path": "C:\\Program Files\\SplunkUniversalForwarder",
    "monitor_path": "C:\\ProgramData\\CyAudit\\assessments",
    "sourcetype": "cyaudit:windows:assessment"
  }
}
```

4. Run an assessment - Splunk will be configured automatically

### Splunk Search Examples

#### View All CyAudit Events
```spl
sourcetype="cyaudit:windows:assessment"
| table timestamp hostname event_type
```

#### System Information Dashboard
```spl
sourcetype="cyaudit:windows:assessment" event_type=system_info
| eval MB=round(physical_memory/1024/1024, 2)
| table hostname platform platform_version architecture MB
```

#### User Account Monitoring
```spl
sourcetype="cyaudit:windows:assessment" event_type=user
| table timestamp hostname user_name enabled password_required last_logon
| sort - timestamp
```

#### Service Status Overview
```spl
sourcetype="cyaudit:windows:assessment" event_type=service
| stats count by hostname status start_type
| chart count over hostname by status
```

#### Security Changes Over Time
```spl
sourcetype="cyaudit:windows:assessment"
| timechart span=1d count by event_type
```

#### Installed Software Inventory
```spl
sourcetype="cyaudit:windows:assessment" event_type=installed_software
| stats latest(version) as version latest(publisher) as publisher by hostname software_name
| sort software_name
```

#### Network Adapter Status
```spl
sourcetype="cyaudit:windows:assessment" event_type=network_adapter
| table hostname adapter_name status mac_address link_speed
```

## PowerShell Integration Examples

### Running from PowerShell with Parameters

```powershell
# Run assessment and capture output
$result = python cyaudit.py --verbose 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "Assessment completed successfully"
} else {
    Write-Host "Assessment failed with exit code $LASTEXITCODE"
}

# Run assessment in background
Start-Process python -ArgumentList "cyaudit.py" -NoNewWindow -PassThru
```

### Checking Task Scheduler Status

```powershell
# Check if task exists
Get-ScheduledTask -TaskName "CyAudit_Security_Assessment" -ErrorAction SilentlyContinue

# Get task details
Get-ScheduledTaskInfo -TaskName "CyAudit_Security_Assessment"

# Run task manually
Start-ScheduledTask -TaskName "CyAudit_Security_Assessment"
```

## Automation Examples

### Enterprise Deployment Script

```powershell
# deploy_cyaudit.ps1
# Deploy CyAudit to Windows systems

param(
    [string]$InstallPath = "C:\Program Files\CyAudit",
    [string]$ConfigPath = "config_production.json"
)

# Create installation directory
New-Item -ItemType Directory -Force -Path $InstallPath

# Copy files
Copy-Item -Path "cyaudit.py" -Destination $InstallPath
Copy-Item -Path "src" -Destination $InstallPath -Recurse
Copy-Item -Path $ConfigPath -Destination "$InstallPath\config.json"

# Setup scheduled task
Set-Location $InstallPath
python cyaudit.py --setup-scheduler

Write-Host "CyAudit deployed successfully to $InstallPath"
```

### Monitoring Script

```powershell
# monitor_cyaudit.ps1
# Monitor CyAudit execution

$LogDir = "C:\ProgramData\CyAudit\logs"
$LatestLog = Get-ChildItem $LogDir -Filter "cyaudit_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($LatestLog) {
    Write-Host "Latest assessment: $($LatestLog.LastWriteTime)"
    
    # Check for errors
    $Errors = Get-Content $LatestLog.FullName | Select-String "ERROR"
    if ($Errors) {
        Write-Host "Found errors in latest assessment:"
        $Errors | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "No errors found"
    }
}
```

## Troubleshooting Examples

### Check Assessment Output

```powershell
# View latest assessment file
$LatestAssessment = Get-ChildItem assessments -Filter "*.ndjson" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Get-Content $LatestAssessment.FullName | ConvertFrom-Json | Format-List

# Count events by type
Get-Content $LatestAssessment.FullName | ConvertFrom-Json | Group-Object event_type | Select-Object Name, Count
```

### Check Logs

```powershell
# View latest log
$LatestLog = Get-ChildItem logs -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Get-Content $LatestLog.FullName -Tail 50

# Search for specific log level
Get-Content $LatestLog.FullName | Select-String "ERROR"
Get-Content $LatestLog.FullName | Select-String "WARNING"
```

### Test Configuration

```powershell
# Validate JSON syntax
Get-Content config.json | ConvertFrom-Json | ConvertTo-Json -Depth 10

# Test with dry run (limited assessment)
python cyaudit.py --verbose
```

## Performance Tuning Examples

### Optimize for Large Environments

For systems with many services/processes, adjust timeout values in `security_assessment.py`:

```python
# Increase PowerShell command timeout
result = self._run_powershell(command, timeout=60)  # Default is 30
```

### Selective Assessment

Disable unnecessary collection modules for faster execution:

```json
{
  "assessment": {
    "include_system_info": true,
    "include_users": true,
    "include_groups": false,
    "include_services": true,
    "include_processes": false,
    "include_network": true,
    "include_security_policies": true,
    "include_registry": true,
    "include_installed_software": false
  }
}
```

## Integration with Other Tools

### Export to CSV

```powershell
# Convert NDJSON to CSV
Get-Content assessments\cyaudit_assessment_*.ndjson | 
    ForEach-Object { ConvertFrom-Json $_ } | 
    Export-Csv -Path assessment_export.csv -NoTypeInformation
```

### Send Email Notification

```powershell
# Send email after assessment
python cyaudit.py
if ($LASTEXITCODE -eq 0) {
    Send-MailMessage -To "admin@example.com" -From "cyaudit@example.com" `
        -Subject "CyAudit Assessment Completed" `
        -Body "Security assessment completed successfully" `
        -SmtpServer "smtp.example.com"
}
```
