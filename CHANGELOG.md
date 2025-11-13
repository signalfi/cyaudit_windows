# Changelog

All notable changes to CyAudit Opus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.4] - 2025-11-13

### Added
- Initial release of CyAudit Opus v3.4
- Comprehensive Windows security assessment capabilities
  - System information collection
  - User and group enumeration
  - Service and process analysis
  - Network configuration auditing
  - Security policy assessment
  - Registry security settings
  - Installed software inventory
- NDJSON data transformation for Splunk optimization
- Splunk Universal Forwarder integration
- Windows Task Scheduler integration for automated assessments
- Retention management with configurable cleanup policies
- Comprehensive logging system
- JSON-based configuration with defaults
- Command-line interface with multiple options
- Complete documentation including README, examples, and usage guides

### Features
- **Security Assessment**: Collects comprehensive security data from Windows systems
- **Data Transformation**: Converts assessment data to NDJSON format optimized for Splunk
- **Automatic Forwarding**: Integrates with Splunk Universal Forwarder for automatic data forwarding
- **Scheduled Execution**: Configures Windows Task Scheduler for automated daily assessments
- **Retention Management**: Automatically cleans up old assessments and logs based on retention policies
- **Modular Architecture**: Clean separation of concerns with independent modules
- **Zero External Dependencies**: Uses only Python standard library
- **Configurable**: Extensive configuration options via JSON file
- **Logging**: Comprehensive logging to both file and console

### Technical Details
- Python 3.7+ compatible
- Uses only Python standard library (no external dependencies)
- Modular architecture for easy maintenance and extension
- PowerShell integration for Windows-specific data collection
- ISO 8601 timestamp format for all events
- NDJSON format for efficient Splunk ingestion

### Documentation
- Comprehensive README with installation and usage instructions
- Configuration guide with multiple examples
- Splunk integration documentation
- Usage examples including PowerShell scripts
- Troubleshooting guide
