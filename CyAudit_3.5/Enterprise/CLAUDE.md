# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CyAudit 3.5 Enterprise is a Windows security assessment framework that performs comprehensive DISA STIG compliance audits. The project includes:
- PowerShell-based security assessment engine with PowerSTIG integration
- Splunk data transformation pipeline
- Enterprise deployment via Inno Setup installers (standard and protected/obfuscated versions)
- SCCM/MECM deployment support

## Build Commands

### Build Windows Installer (Docker)
```bash
# Standard installer (contains .ps1 scripts)
./build.sh

# Protected installer (contains compiled .exe files)
./build.sh --protected

# Build both variants
./build.sh --all

# Clean and rebuild
./build.sh --all --clean
```

### Compile PowerShell to EXE (Windows only)
```powershell
# Run on Windows machine with PS2EXE module
cd WindowsBuild
powershell -ExecutionPolicy Bypass -File Build-Executables.ps1
# Copy Build/ folder back to Enterprise/CyAudit_3.5/Build/
```

### Direct Docker Build (alternative)
```bash
docker run --rm -v $(pwd):/work amake/innosetup CyAudit_Setup.iss
docker run --rm -v $(pwd):/work amake/innosetup CyAudit_Setup_Clean.iss
```

## Running Assessments

```powershell
# Full pipeline with config file
powershell -ExecutionPolicy Bypass -File "CyAudit_3.5\Run-CyAuditPipeline.ps1"

# Direct assessment
powershell -ExecutionPolicy Bypass -File "CyAudit_3.5\CyAudit_Opus_V3.5.ps1" -ClientName "OrgName"

# Transform output for Splunk
powershell -ExecutionPolicy Bypass -File "CyAudit_3.5\Transform-CyAuditForSplunk.ps1" -InputPath ".\Assessments\HOSTNAME-TIMESTAMP"
```

## Architecture

### Core Assessment Engine (`CyAudit_3.5/`)
- **CyAudit_Opus_V3.5.ps1**: Main assessment script (~200KB). Performs:
  - V3.3 registry checks (76+ settings)
  - PowerSTIG DSC-based evaluation (200+ controls)
  - Side-by-side comparison reports
  - STIG Viewer .ckl file generation
- **Run-CyAuditPipeline.ps1**: Orchestrates full workflow (assessment → transform → validate → cleanup)
- **Transform-CyAuditForSplunk.ps1**: Converts 52 output files to Splunk NDJSON format
- **CyAuditPipeline.config.json**: Runtime configuration (client name, paths, retention, email alerts)

### Enterprise Deployment
- **Install-CyAudit.ps1**: SCCM deployment script with scheduled task creation
- **Uninstall-CyAudit.ps1**: Clean removal with data preservation options
- **Detection.ps1**: SCCM detection method (validates installation)
- **CyAudit_Setup.iss**: Inno Setup script for standard installer
- **CyAudit_Setup_Clean.iss**: Inno Setup script for protected installer

### Protected Build System (`WindowsBuild/`)
- **Build-Executables.ps1**: Compiles .ps1 → .exe using PS2EXE
- **Scripts/**: Source files with PS2EXE-specific fixes (e.g., `-end` parameter handling)
- Output goes to `Build/` folder, which must be copied to `CyAudit_3.5/Build/`

### Data Flow
```
CyAudit Assessment → Assessments/{HOSTNAME-TIMESTAMP}/
    └── 52 JSON/XML files (registry, audit, STIG results)
         ↓
Transform-CyAuditForSplunk.ps1
         ↓
SplunkReady/ → NDJSON files for Universal Forwarder
```

## Key Configuration

Edit `CyAudit_3.5/CyAuditPipeline.config.json`:
- `ClientName`: Organization identifier in reports
- `OutputBasePath`: Assessment output directory (default: `.\Assessments`)
- `SplunkReadyPath`: Transformed output for Splunk (default: `.\SplunkReady`)
- `RetentionDays`: Auto-cleanup threshold (default: 30)
- `StigDataSource`: `auto`, `local`, or `powerstig`

## Installation Paths

Default installation: `C:\CyAudit\`
- `C:\CyAudit\CyAudit_3.5\` - Application files
- `C:\CyAudit\Assessments\` - Assessment output
- `C:\CyAudit\SplunkReady\` - Splunk-ready files
- `C:\CyAudit\Logs\` - Pipeline logs

## Exit Codes

**Install-CyAudit.ps1**: 0=Success, 1=Not admin, 2=Dir fail, 3=Copy fail, 4=Unblock fail, 5=PowerSTIG fail, 6=Task fail

**Run-CyAuditPipeline.ps1**: 0=Success, 1=Config error, 2=CyAudit fail, 3=Transform fail, 4=Validation fail, 5=Cleanup fail

**Detection.ps1**: 0=Installed, 1=Not installed

## PS2EXE Notes

When calling PS2EXE-compiled executables from other EXEs, use the `-end` parameter:
```powershell
& $exePath -end -InputPath "C:\path" -OutputPath "C:\out"
```

Scripts in `WindowsBuild/Scripts/` contain these fixes and should be the source for protected builds.
