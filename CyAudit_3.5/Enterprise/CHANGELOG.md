# Changelog

All notable changes to CyAudit 3.5 Enterprise will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.5.1] - 2025-12-11

### Fixed
- **PowerSTIG Race Condition**: Resolved issue where Splunk transformation started before PowerSTIG checks completed on enterprise systems, resulting in incomplete SplunkReady files missing PowerSTIG data.

### Added
- **Completion Manifest System**: CyAudit now writes `_CyAudit_Complete.json` as its final operation containing:
  - Total file count and complete file list
  - PowerSTIG status (Success/Failed/Skipped/NotRun)
  - Expected vs present PowerSTIG files
  - Completion timestamps (local and UTC)
  - File sizes and metadata

- **Wait-ForCyAuditCompletion Function**: Pipeline now includes robust validation that:
  - Waits for completion manifest (30 minute timeout)
  - Validates manifest contents and file counts
  - Verifies expected PowerSTIG files exist when PowerSTIG is enabled
  - Reports warnings for missing files
  - Only proceeds to Splunk transformation after validation passes

- **Phase 1b: Validating Assessment Output**: New pipeline phase provides visibility into validation process

### Changed
- Pipeline now shows PowerSTIG status (enabled/disabled, success/failed) after validation
- Validation warnings are logged for troubleshooting incomplete assessments

## [3.5.0] - 2025-12-10

### Added
- **PS2EXE Protected Build**: Scripts compiled to standalone EXE files for enterprise deployment
- **Standalone Installer**: Inno Setup installer (`CyAudit_3.5_Setup_Clean.exe`) with:
  - Compiled executables (no exposed source code)
  - Optional scheduled task creation (weekly Sunday 2:00 AM)
  - Optional PowerSTIG module installation
  - SCCM/MECM deployment support
  - Silent install capability (`/VERYSILENT /TASKS="scheduledtask,powerstig"`)

- **Run-CyAuditElevated.exe**: UAC-aware launcher with embedded manifest for proper elevation
- **Enterprise Deployment Scripts**:
  - `Install-CyAudit.ps1` - SCCM deployment script
  - `Uninstall-CyAudit.ps1` - Clean removal with data preservation options
  - `Detection.ps1` - SCCM detection method

- **Documentation**:
  - `SCCM_Deployment_Guide.md` - Enterprise deployment instructions
  - `GPO_Recommendations.md` - Group Policy configuration guidance

### Fixed
- **Scheduled Task Creation (v2.7)**: Fixed reliable quoting using `schtasks.exe` instead of PowerShell `Register-ScheduledTask`
- **PS2EXE Performance (v2.9/v2.10)**: Optimized log buffering to prevent UI freezing during long operations

### Changed
- Default installation path: `C:\CyAudit\`
- Scheduled task runs as `NT AUTHORITY\SYSTEM` with highest privileges
- Assessment data preserved during uninstall (user prompted for deletion)

## [3.4.x] - Previous Releases

### Features
- V3.3 registry-based STIG compliance checks (76+ settings)
- PowerSTIG DSC-based evaluation (200+ controls)
- Side-by-side comparison reports (V3.3 vs PowerSTIG)
- STIG Viewer .ckl file generation
- Splunk data transformation pipeline
- NDJSON output for Splunk Universal Forwarder

---

## Upgrade Notes

### From 3.5.0 to 3.5.1
- No configuration changes required
- Simply replace the installer/executables
- The completion manifest (`_CyAudit_Complete.json`) will be automatically generated in each assessment output folder

### From 3.4.x to 3.5.x
- Backup existing configuration (`CyAuditPipeline.config.json`)
- Uninstall previous version
- Install new version
- Restore configuration file
- Verify scheduled task settings if using automated assessments
