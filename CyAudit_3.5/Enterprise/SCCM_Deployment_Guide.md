# CyAudit 3.5 SCCM Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying CyAudit 3.5 via Microsoft System Center Configuration Manager (SCCM/ConfigMgr) or Microsoft Endpoint Configuration Manager (MECM).

**Package Contents:**
- `Install-CyAudit.ps1` - Deployment script
- `Uninstall-CyAudit.ps1` - Removal script
- `Detection.ps1` - SCCM detection method
- `CyAudit_3.5/` - Application files

**Estimated Package Size:** ~25 MB

---

## Prerequisites

### Target Systems
- Windows 10/11 or Windows Server 2019/2022
- PowerShell 5.1 or later (built-in)
- Administrator privileges
- Network access to PowerShell Gallery (for PowerSTIG module)

### SCCM Infrastructure
- SCCM/MECM 2012 R2 or later
- Distribution points configured
- Client agents installed on target systems

---

## Step 1: Prepare the Deployment Package

### 1.1 Create Content Source

1. Copy the entire `Enterprise` folder to your SCCM content source location:
   ```
   \\SCCMServer\Sources\Applications\CyAudit_3.5_Enterprise\
   ```

2. Verify the structure:
   ```
   CyAudit_3.5_Enterprise\
   ├── Install-CyAudit.ps1
   ├── Uninstall-CyAudit.ps1
   ├── Detection.ps1
   └── CyAudit_3.5\
       ├── CyAudit_Opus_V3.5.ps1
       ├── Run-CyAuditPipeline.ps1
       ├── Transform-CyAuditForSplunk.ps1
       ├── Test-SplunkTransformation.ps1
       ├── Upload-ToSplunkCloud.ps1
       ├── CyAuditPipeline.config.json
       ├── STIGData\
       │   └── *.xml
       └── splunk_configs\
           └── *.conf
   ```

### 1.2 Customize Configuration (Optional)

Edit `CyAudit_3.5\CyAuditPipeline.config.json` before deployment to set:
- `ClientName` - Your organization name
- `OutputBasePath` - Assessment output location
- `SplunkReadyPath` - Splunk-ready file location
- Email settings for alerts

---

## Step 2: Create the SCCM Application

### 2.1 Create New Application

1. In SCCM Console, navigate to:
   **Software Library > Application Management > Applications**

2. Right-click **Applications** > **Create Application**

3. Select **Manually specify the application information** > Next

4. Enter application details:
   - **Name:** CyAudit 3.5
   - **Publisher:** Cymantis
   - **Software Version:** 3.5.0
   - **Optional Comments:** Automated Windows security assessment framework

### 2.2 Configure Application Catalog

1. **Localized application name:** CyAudit 3.5 Security Assessment
2. **User documentation link:** (optional)
3. **Privacy policy link:** (optional)
4. **Keywords:** security, audit, STIG, compliance, assessment

### 2.3 Create Deployment Type

1. Click **Add** to create a deployment type

2. Select **Script Installer** > Next

3. Enter deployment type details:
   - **Name:** CyAudit 3.5 - PowerShell Deployment
   - **Administrator comments:** Deploys via PowerShell with optional scheduled task

4. **Content location:**
   ```
   \\SCCMServer\Sources\Applications\CyAudit_3.5_Enterprise
   ```

5. **Installation program:**
   ```
   powershell.exe -ExecutionPolicy Bypass -NoProfile -File "Install-CyAudit.ps1" -CreateScheduledTask
   ```

   Or without scheduled task:
   ```
   powershell.exe -ExecutionPolicy Bypass -NoProfile -File "Install-CyAudit.ps1"
   ```

6. **Uninstall program:**
   ```
   powershell.exe -ExecutionPolicy Bypass -NoProfile -File "Uninstall-CyAudit.ps1" -Force
   ```

### 2.4 Configure Detection Method

1. Select **Add Clause**

2. Choose **Setting Type:** Script

3. **Script Type:** PowerShell

4. Click **Edit Script** and paste the contents of `Detection.ps1`

   Alternatively, use the inline detection:
   ```powershell
   $installPath = "C:\CyAudit\CyAudit_3.5"
   if (Test-Path "$installPath\CyAudit_Opus_V3.5.ps1") {
       Write-Output "Installed"
   }
   ```

5. **Data Type:** String
6. **Operator:** Equals
7. **Value:** (leave empty - presence of output indicates success)

### 2.5 Configure User Experience

1. **Installation behavior:** Install for system
2. **Logon requirement:** Whether or not a user is logged on
3. **Installation program visibility:** Hidden
4. **Maximum allowed run time:** 60 minutes
5. **Estimated installation time:** 10 minutes

### 2.6 Configure Requirements

Add requirements as needed:
- **Operating system:** Windows 10, Windows 11, Windows Server 2019, Windows Server 2022
- **Primary device:** (optional)
- **Free disk space:** Minimum 500 MB

---

## Step 3: Distribute Content

1. Right-click the application > **Distribute Content**

2. Select distribution points or distribution point groups

3. Complete the wizard and verify content status

---

## Step 4: Deploy the Application

### 4.1 Create Deployment

1. Right-click the application > **Deploy**

2. **Select Collection:**
   - For testing: Create a test collection with a few systems
   - For production: Target appropriate device collection

3. **Deployment Settings:**
   - **Action:** Install
   - **Purpose:** Required (for automatic deployment) or Available (for user-initiated)

4. **Scheduling:**
   - **Installation deadline:** As soon as possible (or scheduled time)
   - **Assignment behavior:** Install as soon as possible after deadline

5. **User Experience:**
   - **User notifications:** Hide in Software Center and all notifications
   - **When installation deadline is reached:** Software install and system restart (if required)

### 4.2 Deployment for Different Scenarios

**Scenario A: Silent Background Deployment**
- Purpose: Required
- User notification: Hide all notifications
- Runs silently with scheduled task creation

**Scenario B: User-Initiated Installation**
- Purpose: Available
- Show in Software Center
- User can install when ready

**Scenario C: Staged Rollout**
1. Deploy to pilot collection first
2. Monitor for 1-2 weeks
3. Expand to production collections

---

## Step 5: Monitor Deployment

### 5.1 Check Deployment Status

1. Navigate to **Monitoring > Deployments**

2. Select the CyAudit deployment

3. Review:
   - Success count
   - In Progress count
   - Error count
   - Requirements not met

### 5.2 Review Client Logs

On target systems, check:
- `C:\Windows\CCM\Logs\AppEnforce.log` - Application enforcement
- `C:\Windows\CCM\Logs\AppDiscovery.log` - Detection method results
- `C:\CyAudit\Logs\Install_*.log` - CyAudit installation log

### 5.3 Verify Installation

Run on target system:
```powershell
# Check files exist
Test-Path "C:\CyAudit\CyAudit_3.5\CyAudit_Opus_V3.5.ps1"

# Check scheduled task (if created)
Get-ScheduledTask -TaskName "CyAudit Automated Assessment"

# Run detection script
& "C:\Path\To\Detection.ps1" -Verbose
```

---

## Installation Options

### Install-CyAudit.ps1 Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-InstallPath` | String | `C:\CyAudit` | Installation directory |
| `-CreateScheduledTask` | Switch | Off | Create weekly assessment task |
| `-TaskSchedule` | String | `Weekly` | Daily, Weekly, or Monthly |
| `-TaskTime` | String | `02:00` | Task execution time |
| `-TaskDay` | String | `Sunday` | Day for weekly schedule |
| `-SkipPowerSTIG` | Switch | Off | Skip PowerSTIG installation |
| `-ConfigFile` | String | None | Custom config file path |

### Example Installation Commands

**Standard deployment with task:**
```
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "Install-CyAudit.ps1" -CreateScheduledTask
```

**Custom install path:**
```
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "Install-CyAudit.ps1" -InstallPath "D:\Security\CyAudit" -CreateScheduledTask
```

**Daily assessment at 3 AM:**
```
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "Install-CyAudit.ps1" -CreateScheduledTask -TaskSchedule Daily -TaskTime "03:00"
```

**Offline environment (skip PowerSTIG):**
```
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "Install-CyAudit.ps1" -SkipPowerSTIG
```

---

## Uninstall Options

### Uninstall-CyAudit.ps1 Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-InstallPath` | String | `C:\CyAudit` | Installation directory |
| `-KeepData` | Switch | Off | Preserve assessment data |
| `-KeepLogs` | Switch | Off | Preserve log files |
| `-Force` | Switch | Off | Skip confirmation (for SCCM) |

### Example Uninstall Commands

**Silent uninstall (SCCM):**
```
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "Uninstall-CyAudit.ps1" -Force
```

**Keep assessment data:**
```
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "Uninstall-CyAudit.ps1" -Force -KeepData
```

---

## Troubleshooting

### Issue: Installation Fails - Execution Policy

**Symptom:** Script won't run, execution policy error

**Solution:** The install command includes `-ExecutionPolicy Bypass`. If still failing:
1. Check GPO for execution policy restrictions
2. See `GPO_Recommendations.md` for policy settings

### Issue: Installation Fails - Access Denied

**Symptom:** Cannot create directories or copy files

**Solution:**
1. Ensure SCCM client runs as SYSTEM
2. Verify no antivirus blocking
3. Check NTFS permissions on target drive

### Issue: PowerSTIG Installation Fails

**Symptom:** Cannot connect to PowerShell Gallery

**Solution:**
1. Verify network access to `https://www.powershellgallery.com`
2. Configure proxy if required
3. Use `-SkipPowerSTIG` and install module manually
4. For air-gapped networks, see offline installation section

### Issue: Scheduled Task Not Running

**Symptom:** Task shows but doesn't execute

**Solution:**
1. Check Task Scheduler history for errors
2. Verify SYSTEM account has appropriate permissions
3. Test manual execution:
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File "C:\CyAudit\CyAudit_3.5\Run-CyAuditPipeline.ps1"
   ```

### Issue: Scheduled Task Not Created

**Symptom:** Task doesn't exist after installation

**Solution:** Create the task manually using PowerShell (as Administrator):

```powershell
$Action = New-ScheduledTaskAction -Execute "C:\CyAudit\CyAudit_3.5\Run-CyAuditPipeline.exe"
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "02:00"
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 4)

Register-ScheduledTask -TaskName "CyAudit Automated Assessment" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force
```

See `INSTALLER_README.md` for detailed manual setup instructions including GUI and command-line options.

### Note on UAC

Scheduled tasks created with `NT AUTHORITY\SYSTEM` account and `RunLevel Highest` do **NOT** trigger UAC prompts. This is by design—UAC applies to interactive processes, not service accounts running in session 0.

The CyAudit scheduled task will execute without user intervention at the configured time (default: Sunday 2:00 AM). No UAC-related configuration changes are required for automated execution.

### Issue: Detection Script Returns False Negative

**Symptom:** SCCM shows "not installed" but files exist

**Solution:**
1. Verify all required files are present
2. Check file sizes (detection validates minimum sizes)
3. Run detection manually with verbose:
   ```powershell
   .\Detection.ps1 -Verbose
   ```

---

## Offline/Air-Gapped Installation

For environments without PowerShell Gallery access:

### Pre-download PowerSTIG

On an internet-connected system:
```powershell
Save-Module -Name PowerSTIG -Path "C:\Temp\Modules"
```

### Modify Install Script

Add the saved module to your content source and modify installation to use local path:
```powershell
# In Install-CyAudit.ps1, replace Install-Module with:
Copy-Item -Path "$PSScriptRoot\Modules\PowerSTIG" -Destination "$env:ProgramFiles\WindowsPowerShell\Modules\PowerSTIG" -Recurse -Force
```

---

## Post-Deployment Validation Checklist

Use this checklist to verify successful deployment:

- [ ] Application files exist at `C:\CyAudit\CyAudit_3.5\`
- [ ] STIG XML files present in `STIGData\` directory
- [ ] Configuration file is properly formatted JSON
- [ ] Scheduled task exists and is enabled (if requested)
- [ ] PowerSTIG module is installed (check with `Get-Module -ListAvailable PowerSTIG`)
- [ ] Manual test run completes without errors
- [ ] Assessment output created in `C:\CyAudit\Assessments\`
- [ ] Logs generated in `C:\CyAudit\Logs\`

---

## Support

### Log Locations
- **Installation:** `C:\CyAudit\Logs\Install_*.log`
- **Pipeline:** `C:\CyAudit\Logs\CyAuditPipeline_*.log`
- **SCCM Client:** `C:\Windows\CCM\Logs\`

### Exit Codes

**Install-CyAudit.ps1:**
| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Not administrator |
| 2 | Directory creation failed |
| 3 | File copy failed |
| 4 | Unblock failed |
| 5 | PowerSTIG install failed |
| 6 | Scheduled task creation failed |

**Uninstall-CyAudit.ps1:**
| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Not administrator |
| 2 | User cancelled |
| 3 | Task removal failed |
| 4 | File removal failed |

**Detection.ps1:**
| Code | Meaning |
|------|---------|
| 0 | Installed (detection success) |
| 1 | Not installed |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.2.0 | 2025-12-04 | Updated installer to use schtasks.exe for reliable scheduled task creation |
| 1.1.0 | 2025-12-04 | Added manual scheduled task creation troubleshooting section |
| 1.0.0 | 2025-12-01 | Initial release |
