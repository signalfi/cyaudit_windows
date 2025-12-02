; CyAudit 3.5 Inno Setup Script - CLEAN (Protected) Version
; =========================================================
; Creates standalone EXE installer with compiled executables
; Source code is NOT exposed in this version
;
; Build process:
;   1. Run Build-CyAuditExe.ps1 to compile scripts to EXE
;   2. Run Inno Setup with this script
;
; Silent install example:
;   CyAudit_3.5_Setup_Clean.exe /VERYSILENT /TASKS="scheduledtask,powerstig"

#define MyAppName "CyAudit"
#define MyAppVersion "3.5.0"
#define MyAppPublisher "Cymantis"
#define MyAppURL "https://cymantis.com"
#define MyAppExeName "Run-CyAuditPipeline.exe"

[Setup]
; Application identity
AppId={{8A7B9C1D-2E3F-4A5B-6C7D-8E9F0A1B2C3D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Installation settings
DefaultDirName=C:\CyAudit
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableDirPage=no
AllowNoIcons=yes

; Output settings
OutputDir=Output
OutputBaseFilename=CyAudit_3.5_Setup_Clean
SetupIconFile=
; Uncomment and set path if you have an icon:
; SetupIconFile=icon.ico

; Compression (LZMA2 for best compression)
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes

; Privileges
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

; Windows version requirements (Windows 10+)
MinVersion=10.0

; Uninstaller
UninstallDisplayIcon={app}\CyAudit_3.5\CyAudit_Opus_V3.5.exe
UninstallDisplayName={#MyAppName} {#MyAppVersion}

; Installer appearance
WizardStyle=modern
WizardSizePercent=100

; Architecture
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel1=Welcome to the {#MyAppName} {#MyAppVersion} Setup Wizard
WelcomeLabel2=This will install {#MyAppName} {#MyAppVersion} on your computer.%n%n{#MyAppName} is an automated Windows security assessment framework that performs comprehensive audits including STIG compliance checks.%n%nAdministrator privileges are required.%n%nThis is the protected (Clean) version with compiled executables.

[Tasks]
Name: "scheduledtask"; Description: "Create scheduled task (weekly Sunday 2:00 AM)"; GroupDescription: "Automation:"; Flags: checkedonce
Name: "powerstig"; Description: "Install PowerSTIG module (requires internet)"; GroupDescription: "Dependencies:"; Flags: checkedonce
Name: "desktopshortcut"; Description: "Create desktop shortcut to run assessment"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
; Compiled executables (from Build directory)
Source: "CyAudit_3.5\Build\CyAudit_Opus_V3.5.exe"; DestDir: "{app}\CyAudit_3.5"; Flags: ignoreversion
Source: "CyAudit_3.5\Build\Run-CyAuditPipeline.exe"; DestDir: "{app}\CyAudit_3.5"; Flags: ignoreversion
Source: "CyAudit_3.5\Build\Run-CyAuditElevated.exe"; DestDir: "{app}\CyAudit_3.5"; Flags: ignoreversion
Source: "CyAudit_3.5\Build\Transform-CyAuditForSplunk.exe"; DestDir: "{app}\CyAudit_3.5"; Flags: ignoreversion
Source: "CyAudit_3.5\Build\Test-SplunkTransformation.exe"; DestDir: "{app}\CyAudit_3.5"; Flags: ignoreversion
Source: "CyAudit_3.5\Build\Upload-ToSplunkCloud.exe"; DestDir: "{app}\CyAudit_3.5"; Flags: ignoreversion

; Configuration
Source: "CyAudit_3.5\CyAuditPipeline.config.json"; DestDir: "{app}\CyAudit_3.5"; Flags: ignoreversion onlyifdoesntexist

; STIG Data files
Source: "CyAudit_3.5\STIGData\*.xml"; DestDir: "{app}\CyAudit_3.5\STIGData"; Flags: ignoreversion

; Splunk configuration files
Source: "CyAudit_3.5\splunk_configs\*"; DestDir: "{app}\CyAudit_3.5\splunk_configs"; Flags: ignoreversion recursesubdirs createallsubdirs

; Deployment scripts (for reference/manual use)
Source: "Install-CyAudit.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "Uninstall-CyAudit.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "Detection.ps1"; DestDir: "{app}"; Flags: ignoreversion

; Documentation
Source: "SCCM_Deployment_Guide.md"; DestDir: "{app}\Docs"; Flags: ignoreversion
Source: "GPO_Recommendations.md"; DestDir: "{app}\Docs"; Flags: ignoreversion

[Icons]
; Start menu shortcuts - Uses compiled EXE with embedded UAC manifest
Name: "{group}\Run CyAudit Assessment"; Filename: "{app}\CyAudit_3.5\Run-CyAuditElevated.exe"; WorkingDir: "{app}\CyAudit_3.5"; Comment: "Run CyAudit security assessment (requires admin)"
Name: "{group}\CyAudit Configuration"; Filename: "notepad.exe"; Parameters: """{app}\CyAudit_3.5\CyAuditPipeline.config.json"""; WorkingDir: "{app}\CyAudit_3.5"
Name: "{group}\CyAudit Logs"; Filename: "{app}\CyAudit_3.5\Logs"
Name: "{group}\CyAudit Assessments"; Filename: "{app}\CyAudit_3.5\Assessments"
Name: "{group}\Uninstall CyAudit"; Filename: "{uninstallexe}"

; Desktop shortcut (optional) - Uses compiled EXE with embedded UAC manifest
Name: "{autodesktop}\Run CyAudit Assessment"; Filename: "{app}\CyAudit_3.5\Run-CyAuditElevated.exe"; WorkingDir: "{app}\CyAudit_3.5"; Comment: "Run CyAudit security assessment (requires admin)"; Tasks: desktopshortcut

[Run]
; Post-installation tasks

; Always unblock all files (remove Zone.Identifier) - still needed for config/data files
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -Command ""Get-ChildItem -Path '{app}' -Recurse | Unblock-File -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated; StatusMsg: "Unblocking files..."

; Install PowerSTIG if selected
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -Command ""if (-not (Get-Module -ListAvailable -Name PowerSTIG)) {{ Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null; Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; Install-Module -Name PowerSTIG -Force -AllowClobber -Scope AllUsers -SkipPublisherCheck }}"""; Flags: runhidden waituntilterminated; Tasks: powerstig; StatusMsg: "Installing PowerSTIG module (this may take a few minutes)..."

; Create scheduled task if selected - runs EXE directly
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -Command ""$Action = New-ScheduledTaskAction -Execute '{app}\CyAudit_3.5\Run-CyAuditPipeline.exe'; $Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At '02:00'; $Principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\SYSTEM' -LogonType ServiceAccount -RunLevel Highest; $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 4); Register-ScheduledTask -TaskName 'CyAudit Automated Assessment' -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null"""; Flags: runhidden waituntilterminated; Tasks: scheduledtask; StatusMsg: "Creating scheduled task..."

; Optional: Launch README after install
Filename: "notepad.exe"; Parameters: """{app}\Docs\GPO_Recommendations.md"""; Description: "View documentation"; Flags: nowait postinstall skipifsilent unchecked

; Optional: Run first assessment - runs EXE directly (has UAC manifest)
Filename: "{app}\CyAudit_3.5\Run-CyAuditElevated.exe"; Description: "Run first assessment now"; Flags: nowait postinstall skipifsilent unchecked

[UninstallRun]
; Remove scheduled task on uninstall
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -Command ""Unregister-ScheduledTask -TaskName 'CyAudit Automated Assessment' -Confirm:$false -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated

[UninstallDelete]
; Clean up directories that may have been created during use
Type: filesandordirs; Name: "{app}\CyAudit_3.5\Logs"
Type: filesandordirs; Name: "{app}\CyAudit_3.5\SplunkReady"
; Note: Assessments directory is NOT deleted to preserve data
; User can manually delete {app}\CyAudit_3.5\Assessments if needed

[Code]
// Pascal Script for custom installer logic

var
  WarningPage: TOutputMsgWizardPage;

// Helper function - must be defined before it's called
function BoolToStr(Value: Boolean): String;
begin
  if Value then
    Result := 'Yes'
  else
    Result := 'No';
end;

procedure InitializeWizard;
begin
  // Add a warning page about SmartScreen
  WarningPage := CreateOutputMsgPage(wpWelcome,
    'Important Information',
    'Please read before continuing',
    'This installer is not code-signed. You may see SmartScreen warnings.' + #13#10 + #13#10 +
    'This is the CLEAN (protected) version of CyAudit. The PowerShell scripts have been compiled to standalone executables.' + #13#10 + #13#10 +
    'CyAudit requires Administrator privileges to perform security assessments. The scheduled task (if enabled) will run as SYSTEM.' + #13#10 + #13#10 +
    'For enterprise deployment via SCCM, use the deployment scripts included in the installation directory.');
end;

function InitializeSetup(): Boolean;
begin
  Result := True;

  // Check if PowerShell is available (still needed for PowerSTIG installation and scheduled task creation)
  if not FileExists(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe')) then
  begin
    MsgBox('PowerShell is required but was not found. Please ensure PowerShell 5.1 or later is installed.', mbError, MB_OK);
    Result := False;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    // Log installation completion
    SaveStringToFile(ExpandConstant('{app}\Logs\Install.log'),
      'CyAudit 3.5 (Clean) installed on ' + GetDateTimeString('yyyy-mm-dd hh:nn:ss', '-', ':') + #13#10 +
      'Install path: ' + ExpandConstant('{app}') + #13#10 +
      'Scheduled task: ' + BoolToStr(IsTaskSelected('scheduledtask')) + #13#10 +
      'PowerSTIG: ' + BoolToStr(IsTaskSelected('powerstig')) + #13#10,
      False);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    // Ask if user wants to delete assessment data
    if MsgBox('Do you want to delete all assessment data?' + #13#10 + #13#10 +
              'This will permanently remove all saved assessments from:' + #13#10 +
              ExpandConstant('{app}\Assessments'),
              mbConfirmation, MB_YESNO) = IDYES then
    begin
      DelTree(ExpandConstant('{app}\Assessments'), True, True, True);
    end;

    // Try to remove the main directory if empty
    RemoveDir(ExpandConstant('{app}'));
  end;
end;
