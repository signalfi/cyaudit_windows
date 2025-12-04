# CyAudit 3.5 Standalone Installer

## Overview

This package contains everything needed to build and deploy standalone Windows installers for CyAudit 3.5.

**Two Installer Variants:**

| Variant | Filename | Description |
|---------|----------|-------------|
| **Standard** | `CyAudit_3.5_Setup.exe` | Contains PowerShell scripts (.ps1) |
| **Protected** | `CyAudit_3.5_Setup_Clean.exe` | Contains compiled executables (.exe) |

**Installer Features:**
- GUI wizard for interactive installation
- Silent mode for automated deployment
- Optional scheduled task creation
- Optional PowerSTIG module installation
- Proper uninstaller with Add/Remove Programs entry

---

## Quick Start

### Build Standard Installer (Docker)

```bash
cd Enterprise
./build.sh
# Output: Output/CyAudit_3.5_Setup.exe
```

### Build Protected Installer (Docker + Windows)

The protected build requires two steps:

**Step 1: Compile PowerShell to EXE (requires Windows)**
```powershell
# 1. Copy the WindowsBuild folder to a Windows machine
# 2. Open PowerShell and navigate to the folder
cd C:\path\to\WindowsBuild

# 3. Run the build script
powershell -ExecutionPolicy Bypass -File Build-Executables.ps1

# Creates: WindowsBuild/Build/*.exe
# 4. Copy the Build folder back to Mac at: Enterprise/CyAudit_3.5/Build/
```

**Step 2: Build installer (Docker)**
```bash
# On macOS/Linux/Windows:
./build.sh --protected
# Output: Output/CyAudit_3.5_Setup_Clean.exe
```

### Build Both Installers

```bash
# After running Build-CyAuditExe.ps1 on Windows:
./build.sh --all

# Output:
#   Output/CyAudit_3.5_Setup.exe
#   Output/CyAudit_3.5_Setup_Clean.exe
```

---

## Build Options

```bash
./build.sh                  # Build standard installer (default)
./build.sh --protected      # Build protected installer
./build.sh --all            # Build both installers
./build.sh --clean          # Clean output directory before building
./build.sh --all --clean    # Clean and build both
./build.sh --help           # Show help
```

---

## Protected Build Process

The protected (Clean) version compiles PowerShell scripts to standalone executables using PS2EXE. This provides source code obfuscation but is not true compilation.

**Important Notes:**
- Obfuscation, not encryption - determined users can still reverse engineer
- Adds visual deterrent against casual inspection
- No exposed `.ps1` files in the installation
- Requires Windows to run `WindowsBuild/Build-Executables.ps1`

**Compiled Files:**

| Original Script | Compiled EXE |
|-----------------|--------------|
| `CyAudit_Opus_V3.5.ps1` | `CyAudit_Opus_V3.5.exe` |
| `Run-CyAuditPipeline.ps1` | `Run-CyAuditPipeline.exe` |
| `Run-CyAuditElevated.ps1` | `Run-CyAuditElevated.exe` |
| `Transform-CyAuditForSplunk.ps1` | `Transform-CyAuditForSplunk.exe` |
| `Test-SplunkTransformation.ps1` | `Test-SplunkTransformation.exe` |
| `Upload-ToSplunkCloud.ps1` | `Upload-ToSplunkCloud.exe` |

---

## Installation Methods

### GUI Installation

1. Copy installer (`CyAudit_3.5_Setup.exe` or `CyAudit_3.5_Setup_Clean.exe`) to target Windows system
2. Right-click and select **Run as administrator**
3. Follow the installation wizard:
   - Accept license agreement
   - Choose installation directory (default: `C:\CyAudit`)
   - Select optional tasks:
     - Create scheduled task (weekly Sunday 2 AM)
     - Install PowerSTIG module
     - Create desktop shortcut
4. Click **Install**

### Silent Installation

For automated deployment without user interaction:

```cmd
CyAudit_3.5_Setup.exe /VERYSILENT /TASKS="scheduledtask,powerstig"
```

Or for the protected version:
```cmd
CyAudit_3.5_Setup_Clean.exe /VERYSILENT /TASKS="scheduledtask,powerstig"
```

#### Silent Installation Parameters

| Parameter | Description |
|-----------|-------------|
| `/SILENT` | Silent install with progress bar |
| `/VERYSILENT` | Completely silent (no UI) |
| `/SUPPRESSMSGBOXES` | Suppress all message boxes |
| `/DIR="C:\Path"` | Custom installation directory |
| `/TASKS="task1,task2"` | Enable specific tasks |
| `/LOG="logfile.txt"` | Create installation log |
| `/NORESTART` | Don't restart (not typically needed) |

#### Available Tasks

| Task Name | Description |
|-----------|-------------|
| `scheduledtask` | Create weekly scheduled task |
| `powerstig` | Install PowerSTIG module |
| `desktopshortcut` | Create desktop shortcut |

#### Examples

**Full silent install with all options:**
```cmd
CyAudit_3.5_Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /TASKS="scheduledtask,powerstig" /LOG="C:\Temp\cyaudit_install.log"
```

**Silent install to custom path:**
```cmd
CyAudit_3.5_Setup.exe /VERYSILENT /DIR="D:\Security\CyAudit" /TASKS="scheduledtask"
```

**Silent install without optional tasks:**
```cmd
CyAudit_3.5_Setup.exe /VERYSILENT /TASKS=""
```

---

## SmartScreen Warning

Since the installer is not code-signed, Windows SmartScreen may display a warning.

### For Interactive Installation

1. Click **More info**
2. Click **Run anyway**

### For Silent/Automated Deployment

Unblock the file before running:

```powershell
# PowerShell - Unblock the installer
Unblock-File -Path "CyAudit_3.5_Setup.exe"

# Then run silently
.\CyAudit_3.5_Setup.exe /VERYSILENT /TASKS="scheduledtask,powerstig"
```

### Enterprise GPO Option

Configure SmartScreen via Group Policy:
- Path: `Computer Configuration > Administrative Templates > Windows Components > File Explorer`
- Setting: `Configure Windows Defender SmartScreen`
- Value: `Warn` or `Disabled`

---

## UAC and Elevation

### Scheduled Task Execution (No UAC Prompt)

When CyAudit runs via the scheduled task, **no UAC prompt appears**. This is because:
- The task runs as `NT AUTHORITY\SYSTEM` (not a user account)
- SYSTEM tasks execute in session 0 (no user desktop)
- Windows UAC only applies to interactive user sessions

This is the recommended execution method for automated assessments.

### Interactive Desktop Shortcut (UAC Prompt Expected)

When clicking "Run CyAudit Assessment" from the Start Menu or desktop:
- A UAC elevation prompt will appear
- This is normal Windows security behavior
- Click "Yes" to approve elevation and run the assessment

The UAC prompt for interactive execution cannot be suppressed without compromising security. This is by Windows design for admin tools.

### Why SYSTEM Account is Used

| Benefit | Description |
|---------|-------------|
| No credentials stored | Unlike user accounts, no password in Task Scheduler |
| Highest privilege | SYSTEM has more access than Administrator |
| No UAC | Session 0 execution bypasses UAC entirely |
| Audit trail | Clearly identifies automated vs manual runs |

---

## Post-Installation

### Verify Installation

**Standard version:**
```powershell
# Check files exist
Test-Path "C:\CyAudit\CyAudit_3.5\CyAudit_Opus_V3.5.ps1"
```

**Protected version:**
```powershell
# Check files exist
Test-Path "C:\CyAudit\CyAudit_3.5\CyAudit_Opus_V3.5.exe"
```

**Both versions:**
```powershell
# Check scheduled task (if created)
Get-ScheduledTask -TaskName "CyAudit Automated Assessment"

# Check PowerSTIG (if installed)
Get-Module -ListAvailable -Name PowerSTIG
```

### Configure CyAudit

Edit the configuration file:
```
C:\CyAudit\CyAudit_3.5\CyAuditPipeline.config.json
```

Key settings:
- `ClientName` - Your organization name
- `OutputBasePath` - Assessment output directory
- `SplunkReadyPath` - Splunk-optimized output directory

### Run First Assessment

**Via Start Menu:**
Start Menu > CyAudit > Run CyAudit Assessment

**Via PowerShell (standard version):**
```powershell
powershell -ExecutionPolicy Bypass -File "C:\CyAudit\CyAudit_3.5\Run-CyAuditPipeline.ps1"
```

**Via command line (protected version):**
```cmd
"C:\CyAudit\CyAudit_3.5\Run-CyAuditElevated.exe"
```

**Via Scheduled Task:**
```powershell
Start-ScheduledTask -TaskName "CyAudit Automated Assessment"
```

---

## Manual Scheduled Task Setup

If the scheduled task was not created during installation (or needs to be recreated), follow these steps.

### Quick Setup (PowerShell)

Run PowerShell **as Administrator**:

```powershell
# For Protected (Clean) Install - EXE version
$Action = New-ScheduledTaskAction -Execute "C:\CyAudit\CyAudit_3.5\Run-CyAuditPipeline.exe"

# For Standard Install - PS1 version (uncomment below, comment above)
# $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File "C:\CyAudit\CyAudit_3.5\Run-CyAuditPipeline.ps1"'

$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "02:00"

$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" `
    -LogonType ServiceAccount -RunLevel Highest

$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 4)

Register-ScheduledTask `
    -TaskName "CyAudit Automated Assessment" `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Description "CyAudit 3.5 automated security assessment. Runs weekly at 2:00 AM Sunday." `
    -Force

# Verify creation
Get-ScheduledTask -TaskName "CyAudit Automated Assessment"
```

### Task Scheduler GUI Setup

1. **Open Task Scheduler** - Press `Win + R`, type `taskschd.msc`, press Enter
2. **Create Task** - Click **Action > Create Task** (NOT "Create Basic Task")
3. **General Tab:**
   - Name: `CyAudit Automated Assessment`
   - Select "Run whether user is logged on or not"
   - Select "Run with highest privileges"
   - Click "Change User or Group" > type `SYSTEM` > Check Names > OK
4. **Triggers Tab:** New > Weekly > Sunday > 2:00 AM > OK
5. **Actions Tab:** New > Start a program:
   - **Protected:** `C:\CyAudit\CyAudit_3.5\Run-CyAuditPipeline.exe`
   - **Standard:** `powershell.exe` with arguments: `-ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File "C:\CyAudit\CyAudit_3.5\Run-CyAuditPipeline.ps1"`
6. **Conditions Tab:** Uncheck "Start only if on AC power"
7. **Settings Tab:** Check "Run task as soon as possible after a scheduled start is missed"
8. **Click OK** to save

### Command Line (schtasks.exe)

```cmd
:: For Protected Install (EXE)
schtasks /Create /TN "CyAudit Automated Assessment" /TR "C:\CyAudit\CyAudit_3.5\Run-CyAuditPipeline.exe" /SC WEEKLY /D SUN /ST 02:00 /RU "NT AUTHORITY\SYSTEM" /RL HIGHEST /F
```

### Verify Task Creation

```powershell
# Check task exists
Get-ScheduledTask -TaskName "CyAudit Automated Assessment"

# Run task immediately for testing
Start-ScheduledTask -TaskName "CyAudit Automated Assessment"
```

### Remove Scheduled Task

```powershell
Unregister-ScheduledTask -TaskName "CyAudit Automated Assessment" -Confirm:$false
```

---

## Uninstallation

### GUI Uninstall

1. Open **Settings > Apps > Apps & features**
2. Search for "CyAudit"
3. Click **Uninstall**

Or use Control Panel > Programs and Features

### Silent Uninstall

```cmd
"C:\CyAudit\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES
```

### What Gets Removed

- All application files in `C:\CyAudit\CyAudit_3.5\`
- Scheduled task (if created)
- Start menu shortcuts
- Desktop shortcut (if created)

### What Gets Preserved

- Assessment data (`C:\CyAudit\CyAudit_3.5\Assessments\`) - user prompted during uninstall
- PowerSTIG module (installed system-wide, not removed)

---

## Troubleshooting

### Installation Fails

**Check the log file:**
```cmd
CyAudit_3.5_Setup.exe /LOG="C:\Temp\install.log"
```

**Common issues:**

| Issue | Solution |
|-------|----------|
| "Requires administrator" | Right-click > Run as administrator |
| SmartScreen blocks | Unblock-File or click "Run anyway" |
| PowerSTIG fails | Check internet connectivity, try manual install |
| Files blocked | Installer auto-unblocks, but check AV software |

### Protected Build Errors

**Missing EXE files:**
```
Protected build requires compiled EXE files
Missing files in CyAudit_3.5/Build/
```

Solution: Copy the `WindowsBuild/` folder to a Windows machine, run `Build-Executables.ps1`, then copy the `Build/` folder back to `Enterprise/CyAudit_3.5/Build/`.

**PS2EXE module not found:**
```powershell
# On Windows, install PS2EXE:
Install-Module -Name ps2exe -Scope CurrentUser -Force
```

### Scheduled Task Not Running

```powershell
# Check task exists
Get-ScheduledTask -TaskName "CyAudit Automated Assessment"

# Check task status
Get-ScheduledTaskInfo -TaskName "CyAudit Automated Assessment"

# Run task manually
Start-ScheduledTask -TaskName "CyAudit Automated Assessment"
```

### PowerSTIG Not Installed

```powershell
# Manual installation
Install-Module -Name PowerSTIG -Force -Scope AllUsers -SkipPublisherCheck
```

---

## Building the Installer

### Requirements

- **Docker** (for macOS/Linux/Windows builds)
- **Windows** with PowerShell 5.1+ (only for protected build - EXE compilation step)

### Directory Structure

```
Enterprise/
├── CyAudit_Setup.iss           # Inno Setup script (standard)
├── CyAudit_Setup_Clean.iss     # Inno Setup script (protected)
├── build.sh                    # Docker build script
├── Install-CyAudit.ps1         # SCCM install script
├── Uninstall-CyAudit.ps1       # SCCM uninstall script
├── Detection.ps1               # SCCM detection script
├── CyAudit_3.5/                # Application files (standard installer source)
│   ├── *.ps1                   # PowerShell scripts
│   ├── Build/                  # Compiled EXEs (copy from WindowsBuild/Build/)
│   │   └── *.exe
│   ├── CyAuditPipeline.config.json
│   ├── STIGData/
│   └── splunk_configs/
├── WindowsBuild/               # PS2EXE compilation package
│   ├── Build-Executables.ps1   # Run this on Windows to compile EXEs
│   ├── README.txt              # Windows build instructions
│   ├── Scripts/                # Source scripts (with PS2EXE fixes)
│   │   └── *.ps1
│   └── Build/                  # Output (copy to CyAudit_3.5/Build/)
│       └── *.exe
└── Output/                     # Final installers
    ├── CyAudit_3.5_Setup.exe        # Standard installer
    └── CyAudit_3.5_Setup_Clean.exe  # Protected installer
```

### Build Commands

**Standard Build (Docker):**
```bash
./build.sh
```

**Protected Build (Docker):**
```bash
# After running WindowsBuild/Build-Executables.ps1 on Windows
# and copying Build/ folder to CyAudit_3.5/Build/
./build.sh --protected
```

**Both Builds (Docker):**
```bash
./build.sh --all
```

**Docker Direct (Windows PowerShell):**
```powershell
# Standard
docker run --rm -v ${PWD}:/work amake/innosetup CyAudit_Setup.iss

# Protected
docker run --rm -v ${PWD}:/work amake/innosetup CyAudit_Setup_Clean.iss
```

**Inno Setup Direct (Windows):**
```cmd
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" CyAudit_Setup.iss
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" CyAudit_Setup_Clean.iss
```

---

## File Checksums

After building, generate checksums for verification:

```powershell
# Generate SHA256
Get-FileHash -Path "Output\CyAudit_3.5_Setup.exe" -Algorithm SHA256
Get-FileHash -Path "Output\CyAudit_3.5_Setup_Clean.exe" -Algorithm SHA256

# Generate MD5
Get-FileHash -Path "Output\CyAudit_3.5_Setup.exe" -Algorithm MD5
Get-FileHash -Path "Output\CyAudit_3.5_Setup_Clean.exe" -Algorithm MD5
```

---

## Support

### Log Locations

| Log | Path |
|-----|------|
| Install log | `C:\CyAudit\Logs\Install.log` |
| Pipeline log | `C:\CyAudit\Logs\CyAuditPipeline_*.log` |
| Assessment errors | `C:\CyAudit\CyAudit_3.5\Assessments\*\CyAudit_ErrorLog.json` |

### Documentation

- `SCCM_Deployment_Guide.md` - SCCM deployment instructions
- `GPO_Recommendations.md` - Group Policy recommendations

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.6.0 | 2025-12-04 | Fixed scheduled task creation in protected installer, added manual task setup documentation |
| 2.3.0 | 2025-12-02 | Fixed PS2EXE argument parsing (`-end` parameter), timestamp format (underscore), directory cleanup |
| 2.1.0 | 2025-12-02 | Fixed `$PSScriptRoot` empty in PS2EXE executables |
| 2.0.0 | 2025-12-02 | Added protected (Clean) build with PS2EXE compilation |
| 1.0.0 | 2025-12-01 | Initial release |

### PS2EXE Technical Notes

When calling PS2EXE-compiled executables from other EXEs, use the `-end` parameter to ensure arguments are passed correctly to the embedded script:

```powershell
# Correct way to call PS2EXE executables
& $exePath -end -InputPath "C:\path" -OutputPath "C:\out"
```

Scripts in `WindowsBuild/Scripts/` contain these PS2EXE-specific fixes and should be used as the source for protected builds.
