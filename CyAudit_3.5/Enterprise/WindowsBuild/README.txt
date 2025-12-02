================================================================================
  CyAudit Windows Build Package
================================================================================

This package compiles PowerShell scripts to EXE files using PS2EXE.
Run this on any Windows machine with PowerShell 5.1+ and internet access.

================================================================================
  QUICK START
================================================================================

1. Copy this entire "WindowsBuild" folder to a Windows machine

2. Open PowerShell as Administrator

3. Navigate to the WindowsBuild folder:
   cd C:\path\to\WindowsBuild

4. Run the build script:
   powershell -ExecutionPolicy Bypass -File Build-Executables.ps1

5. Wait for compilation to complete (~30 seconds)

6. Copy the "Build" folder back to your Mac at:
   Enterprise/CyAudit_3.5/Build/

7. On your Mac, run:
   ./build.sh --protected

================================================================================
  FOLDER STRUCTURE
================================================================================

WindowsBuild/
├── Build-Executables.ps1    <- Run this on Windows
├── README.txt               <- You are here
├── Scripts/                 <- Source PowerShell scripts
│   ├── CyAudit_Opus_V3.5.ps1
│   ├── Run-CyAuditPipeline.ps1
│   ├── Run-CyAuditElevated.ps1
│   ├── Transform-CyAuditForSplunk.ps1
│   ├── Test-SplunkTransformation.ps1
│   └── Upload-ToSplunkCloud.ps1
└── Build/                   <- Output (created after running script)
    ├── CyAudit_Opus_V3.5.exe
    ├── Run-CyAuditPipeline.exe
    ├── Run-CyAuditElevated.exe
    ├── Transform-CyAuditForSplunk.exe
    ├── Test-SplunkTransformation.exe
    └── Upload-ToSplunkCloud.exe

================================================================================
  REQUIREMENTS
================================================================================

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 (included with Windows)
- Internet connection (to download PS2EXE module on first run)
- Administrator privileges (recommended)

================================================================================
  TROUBLESHOOTING
================================================================================

ERROR: "Execution of scripts is disabled on this system"
  -> Run: Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass

ERROR: "Install-Module is not recognized"
  -> You need PowerShell 5.1 or later. Check version with: $PSVersionTable

ERROR: "Unable to download from PSGallery"
  -> Check internet connection
  -> Try: [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

ERROR: "PS2EXE compilation failed"
  -> Ensure you're running Windows PowerShell (not PowerShell Core)
  -> Try running PowerShell as Administrator

================================================================================
  WHAT GETS COMPILED
================================================================================

| Script                          | EXE                            | Admin? |
|---------------------------------|--------------------------------|--------|
| CyAudit_Opus_V3.5.ps1          | CyAudit_Opus_V3.5.exe         | Yes    |
| Run-CyAuditPipeline.ps1        | Run-CyAuditPipeline.exe       | Yes    |
| Run-CyAuditElevated.ps1        | Run-CyAuditElevated.exe       | No     |
| Transform-CyAuditForSplunk.ps1 | Transform-CyAuditForSplunk.exe| No     |
| Test-SplunkTransformation.ps1  | Test-SplunkTransformation.exe | No     |
| Upload-ToSplunkCloud.ps1       | Upload-ToSplunkCloud.exe      | No     |

================================================================================
