# Changelog

All notable changes to CyAudit 3.5 Enterprise will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.5.1] - 2025-12-11

### Fixed
- **PowerSTIG Race Condition**: Resolved critical issue where Splunk transformation started before PowerSTIG checks completed on enterprise systems, resulting in incomplete SplunkReady files missing PowerSTIG data.
  - **Root Cause**: On enterprise systems with slow storage, antivirus scanning, or large DSC configurations, PowerSTIG's `Test-DscConfiguration` takes significantly longer. The pipeline was not waiting for all files to be written before starting transformation.
  - **Solution**: Implemented completion manifest validation system to ensure all assessment operations complete before proceeding.

### Added
- **Completion Manifest System** (`_CyAudit_Complete.json`):
  - Written as the absolute final operation in `CyAudit_Opus_V3.5.ps1` after all file exports
  - Contains total file count, complete file list with sizes, and timestamps
  - Tracks PowerSTIG status: Success, Failed, Skipped, or NotRun
  - Lists expected PowerSTIG files vs actually present files
  - Enables pipeline to verify all data is written before transformation

- **Wait-ForCyAuditCompletion Function** in `Run-CyAuditPipeline.ps1`:
  - Polls for completion manifest with 30-minute timeout (configurable)
  - Validates manifest JSON structure and contents
  - Verifies expected PowerSTIG output files exist when PowerSTIG ran successfully:
    - `(HOSTNAME)_PowerSTIG_DSC_Results.xml`
    - `(HOSTNAME)_PowerSTIG_Findings.csv`
    - `(HOSTNAME)_STIG_Comparison.csv`
    - `(HOSTNAME)_STIG_Merged_Results.csv`
    - `(HOSTNAME)_Enhanced_Summary.json`
  - Reports warnings for missing or incomplete files
  - Only proceeds to Splunk transformation after validation passes

- **Phase 1b: Validating Assessment Output**: New pipeline phase between CyAudit execution and Splunk transformation provides visibility into the validation process

### Changed
- Pipeline now displays PowerSTIG status (enabled/disabled, success/failed) after validation
- Validation warnings are logged for troubleshooting incomplete assessments
- Minimum expected file count validation (20+ core audit files)

### Files Modified
- `CyAudit_3.5/CyAudit_Opus_V3.5.ps1` - Added completion manifest generation (+82 lines)
- `CyAudit_3.5/Run-CyAuditPipeline.ps1` - Added Wait-ForCyAuditCompletion function (+202 lines)
- `WindowsBuild/Scripts/CyAudit_Opus_V3.5.ps1` - PS2EXE version with same changes
- `WindowsBuild/Scripts/Run-CyAuditPipeline.ps1` - PS2EXE version with same changes

### Recompiled Executables
- `CyAudit_3.5/Build/CyAudit_Opus_V3.5.exe` - Recompiled with completion manifest code (+4KB)
- `CyAudit_3.5/Build/Run-CyAuditPipeline.exe` - Recompiled with validation logic (+8KB)

### Rebuilt Installer
- `Output/CyAudit_3.5_Setup_Clean.exe` - Protected installer rebuilt with updated executables

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
