# CyAudit Opus v3.4 - Windows Security Assessment Tool

A comprehensive Windows security audit tool that performs automated security assessments and forwards data to Splunk Cloud for analysis.

## Overview

CyAudit Opus v3.4 is designed to provide comprehensive security auditing capabilities for Windows systems with seamless integration into Splunk Cloud for centralized security monitoring and analysis.

### Key Features

1. **Security Assessment** - Performs comprehensive Windows security audits including:
   - System information and configuration
   - User and group enumeration
   - Service and process analysis
   - Network configuration
   - Security policies and audit settings
   - Registry security settings
   - Installed software inventory

2. **Data Transformation** - Converts audit data to Splunk-optimized NDJSON format for efficient ingestion and analysis

3. **Automatic Forwarding** - Integrates with Splunk Universal Forwarder to automatically send data to Splunk Cloud

4. **Scheduled Execution** - Uses Windows Task Scheduler to run assessments on defined intervals (default: daily at 2:00 AM)

5. **Retention Management** - Automatically cleans up old assessments and logs based on configurable retention policies

## Requirements

- Windows 10/11 or Windows Server 2016+
- Python 3.7 or higher
- PowerShell 5.1 or higher
- Administrator privileges (required for comprehensive security audits)
- Splunk Universal Forwarder (optional, for automatic forwarding)

## Installation

1. Clone or download the repository:
   ```powershell
   git clone https://github.com/signalfi/cyaudit_windows.git
   cd cyaudit_windows
   ```

2. Install Python dependencies (minimal, uses standard library):
   ```powershell
   pip install -r requirements.txt
   ```

3. Configure the tool (optional, uses defaults if not configured):
   ```powershell
   # Edit config.json to customize settings
   notepad config.json
   ```

4. Set up automated scheduling (optional):
   ```powershell
   # Run as Administrator
   python cyaudit.py --setup-scheduler
   ```

## Usage

### Run a Manual Assessment

Run a single security assessment immediately:

```powershell
# Basic usage
python cyaudit.py

# With custom configuration
python cyaudit.py --config custom_config.json

# With verbose logging
python cyaudit.py --verbose
```

### Setup Automated Scheduling

Configure Windows Task Scheduler for automated daily assessments:

```powershell
# Run as Administrator
python cyaudit.py --setup-scheduler
```

This creates a scheduled task that runs daily at 2:00 AM by default. You can customize the schedule in `config.json`.

### Check Version

```powershell
python cyaudit.py --version
```

## Configuration

The tool uses a JSON configuration file (default: `config.json`). Here's a complete example:

```json
{
  "output_directory": "assessments",
  "logging": {
    "directory": "logs",
    "retention_days": 30
  },
  "assessment": {
    "retention_days": 90,
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
    "enabled": false,
    "forwarder_path": "C:\\Program Files\\SplunkUniversalForwarder",
    "monitor_path": null,
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

### Configuration Options

#### Output Settings
- `output_directory`: Directory where assessment NDJSON files are stored (default: "assessments")

#### Logging Settings
- `logging.directory`: Directory for log files (default: "logs")
- `logging.retention_days`: Days to retain log files (default: 30)

#### Assessment Settings
- `assessment.retention_days`: Days to retain assessment files (default: 90)
- `assessment.include_*`: Toggle specific assessment modules (default: all enabled)

#### Splunk Integration
- `splunk.enabled`: Enable Splunk Universal Forwarder integration (default: false)
- `splunk.forwarder_path`: Path to Splunk Universal Forwarder installation
- `splunk.monitor_path`: Directory to monitor (null = monitor individual files)
- `splunk.sourcetype`: Splunk sourcetype for events (default: "cyaudit:windows:assessment")

#### Task Scheduler
- `task_scheduler.task_name`: Name of the scheduled task (default: "CyAudit_Security_Assessment")
- `task_scheduler.schedule`: Schedule frequency (DAILY, WEEKLY, MONTHLY)
- `task_scheduler.start_time`: Time to run assessment (HH:MM format)
- `task_scheduler.enabled`: Enable task scheduler integration (default: true)

## Output Format

Assessment data is stored in NDJSON (Newline Delimited JSON) format, optimized for Splunk ingestion. Each line is a complete JSON object representing a single event.

Example output structure:

```json
{"event_type": "system_info", "timestamp": "2025-11-13T20:00:00Z", "hostname": "WORKSTATION01", "platform": "Windows", ...}
{"event_type": "user", "timestamp": "2025-11-13T20:00:00Z", "hostname": "WORKSTATION01", "user_name": "admin", ...}
{"event_type": "service", "timestamp": "2025-11-13T20:00:00Z", "hostname": "WORKSTATION01", "service_name": "wuauserv", ...}
```

Each event includes:
- `event_type`: Type of security data (system_info, user, group, service, etc.)
- `timestamp`: ISO 8601 formatted timestamp
- `hostname`: Source system hostname
- `source`: "cyaudit_opus"
- `sourcetype`: Configured Splunk sourcetype
- `cyaudit_version`: Tool version number

## Splunk Integration

### Setting Up Splunk Universal Forwarder

1. Install Splunk Universal Forwarder on the Windows system
2. Configure forwarding to your Splunk Cloud instance
3. Enable Splunk integration in `config.json`:
   ```json
   {
     "splunk": {
       "enabled": true,
       "forwarder_path": "C:\\Program Files\\SplunkUniversalForwarder",
       "monitor_path": "C:\\path\\to\\cyaudit_windows\\assessments",
       "sourcetype": "cyaudit:windows:assessment"
     }
   }
   ```
4. Run an assessment - the tool will automatically configure monitoring

### Splunk Search Examples

```spl
# View all CyAudit events
sourcetype="cyaudit:windows:assessment"

# View security assessment by type
sourcetype="cyaudit:windows:assessment" event_type=user

# Count events by type
sourcetype="cyaudit:windows:assessment" | stats count by event_type

# Monitor system changes over time
sourcetype="cyaudit:windows:assessment" event_type=system_info | timechart span=1d count
```

## Directory Structure

```
cyaudit_windows/
├── cyaudit.py              # Main entry point
├── config.json             # Configuration file
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── src/                   # Core modules
│   ├── __init__.py
│   ├── config_loader.py       # Configuration management
│   ├── security_assessment.py # Security audit engine
│   ├── ndjson_converter.py    # NDJSON transformation
│   ├── splunk_forwarder.py    # Splunk integration
│   ├── task_scheduler.py      # Windows Task Scheduler
│   └── retention_manager.py   # File retention management
├── assessments/           # Assessment output (created at runtime)
└── logs/                  # Application logs (created at runtime)
```

## Security Considerations

- **Administrator Privileges**: Many security assessments require administrator privileges to access system information
- **Sensitive Data**: Assessment files may contain sensitive system information. Protect them appropriately
- **Credentials**: If using Splunk integration, ensure Splunk credentials are properly secured
- **Network**: If forwarding to Splunk Cloud, ensure appropriate network security measures

## Troubleshooting

### Common Issues

**Issue**: "Access Denied" errors during assessment
- **Solution**: Run the tool with administrator privileges

**Issue**: PowerShell commands timing out
- **Solution**: Increase timeout values in the code or optimize system performance

**Issue**: Splunk Universal Forwarder not found
- **Solution**: Verify the `splunk.forwarder_path` in config.json points to the correct installation

**Issue**: Task Scheduler setup fails
- **Solution**: Run the setup command as Administrator

### Logging

Detailed logs are stored in the `logs/` directory. Check the most recent log file for detailed error information:

```powershell
# View latest log
Get-Content logs\cyaudit_*.log -Tail 50
```

## License

Copyright © 2025 SignalFI. All rights reserved.

## Support

For issues, questions, or contributions, please contact SignalFI support or visit the project repository.
