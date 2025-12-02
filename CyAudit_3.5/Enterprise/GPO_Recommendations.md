# CyAudit 3.5 GPO Recommendations

## Overview

This document provides Group Policy Object (GPO) recommendations for deploying CyAudit 3.5 in enterprise environments. These policies ensure smooth silent execution of PowerShell scripts without manual intervention.

**Scope:** Windows 10/11 and Windows Server 2019/2022 systems running CyAudit

---

## Policy Configuration Summary

| Policy | Setting | Priority |
|--------|---------|----------|
| PowerShell Execution Policy | RemoteSigned or Bypass | **Required** |
| Script Block Logging | Enabled (recommended) | Optional |
| Module Logging | Enabled (recommended) | Optional |
| PowerShell Transcription | Enabled (recommended) | Optional |

---

## 1. PowerShell Execution Policy

### Policy Path
```
Computer Configuration
  └─ Administrative Templates
       └─ Windows Components
            └─ Windows PowerShell
                 └─ Turn on Script Execution
```

### Recommended Setting
**Enabled** with **Allow local scripts and remote signed scripts** (RemoteSigned)

### Configuration Options

| Option | Description | Recommendation |
|--------|-------------|----------------|
| **Allow only signed scripts** | Most restrictive - all scripts must be signed | Not recommended (requires code signing) |
| **Allow local scripts and remote signed scripts** | Local scripts run, remote need signing | **Recommended** |
| **Allow all scripts** | Least restrictive - all scripts run | Acceptable for trusted environments |

### Why RemoteSigned Works

CyAudit scripts are deployed locally to `C:\CyAudit`, making them "local scripts" under RemoteSigned policy. The `Unblock-File` command during installation removes the Zone.Identifier that would otherwise mark them as "remote."

### Alternative: Bypass via Scheduled Task

If you cannot modify the execution policy GPO, CyAudit's scheduled task uses:
```
powershell.exe -ExecutionPolicy Bypass -File "script.ps1"
```

This bypasses the system policy for that specific execution only.

---

## 2. PowerShell Logging (Recommended for Security)

### 2.1 Script Block Logging

Records the content of all script blocks processed by PowerShell.

**Policy Path:**
```
Computer Configuration
  └─ Administrative Templates
       └─ Windows Components
            └─ Windows PowerShell
                 └─ Turn on PowerShell Script Block Logging
```

**Setting:** Enabled

**Benefits:**
- Audits all PowerShell activity including CyAudit assessments
- Helps with troubleshooting
- Required for many compliance frameworks

**Log Location:** `Microsoft-Windows-PowerShell/Operational` Event Log

### 2.2 Module Logging

Records pipeline execution details for specified modules.

**Policy Path:**
```
Computer Configuration
  └─ Administrative Templates
       └─ Windows Components
            └─ Windows PowerShell
                 └─ Turn on Module Logging
```

**Setting:** Enabled
**Module Names:** `*` (all modules) or specific modules like `PowerSTIG`

### 2.3 PowerShell Transcription

Creates a text record of all PowerShell sessions.

**Policy Path:**
```
Computer Configuration
  └─ Administrative Templates
       └─ Windows Components
            └─ Windows PowerShell
                 └─ Turn on PowerShell Transcription
```

**Setting:** Enabled
**Transcript Output Directory:** `C:\PSTranscripts\` or network share

**Note:** Can generate significant disk usage. Consider for high-security environments only.

---

## 3. Windows Defender Exclusions (If Needed)

If Windows Defender interferes with CyAudit execution, add exclusions:

### Via GPO

**Policy Path:**
```
Computer Configuration
  └─ Administrative Templates
       └─ Windows Components
            └─ Microsoft Defender Antivirus
                 └─ Exclusions
                      └─ Path Exclusions
```

**Add Paths:**
- `C:\CyAudit`
- `C:\CyAudit\CyAudit_3.5\CyAudit_Opus_V3.5.ps1`

### Via PowerShell (Alternative)
```powershell
Add-MpPreference -ExclusionPath "C:\CyAudit"
```

**Note:** Only add exclusions if experiencing false positives. CyAudit is legitimate security software.

---

## 4. Scheduled Task GPO (Alternative to SCCM)

If using GPO-based scheduled task deployment instead of SCCM:

### Via Group Policy Preferences

**Policy Path:**
```
Computer Configuration
  └─ Preferences
       └─ Control Panel Settings
            └─ Scheduled Tasks
```

**Task Configuration:**
- **Action:** Create
- **Name:** CyAudit Automated Assessment
- **Security Options:**
  - Run as: `NT AUTHORITY\SYSTEM`
  - Run with highest privileges: Yes
- **Triggers:**
  - Weekly, Sunday at 02:00
- **Actions:**
  - Program: `powershell.exe`
  - Arguments: `-ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File "C:\CyAudit\CyAudit_3.5\Run-CyAuditPipeline.ps1"`

---

## 5. Network and Firewall Policies

### PowerShell Gallery Access (for PowerSTIG)

CyAudit installs PowerSTIG from PowerShell Gallery. Ensure outbound access to:

| URL | Port | Purpose |
|-----|------|---------|
| `https://www.powershellgallery.com` | 443 | Module downloads |
| `https://psg-prod-eastus.azureedge.net` | 443 | CDN for modules |
| `https://onegetcdn.azureedge.net` | 443 | NuGet provider |

### Splunk Forwarding (if using Universal Forwarder)

| URL | Port | Purpose |
|-----|------|---------|
| Your Splunk indexer/HEC | 9997/8088 | Data forwarding |

---

## 6. User Rights Assignment

CyAudit runs as SYSTEM via scheduled task, which has all necessary rights. However, if running interactively or troubleshooting:

### Required Privileges
- **Log on as a batch job** (for scheduled tasks)
- **Replace a process level token** (for some WMI queries)
- **Debug programs** (optional, for advanced diagnostics)

**Policy Path:**
```
Computer Configuration
  └─ Windows Settings
       └─ Security Settings
            └─ Local Policies
                 └─ User Rights Assignment
```

---

## 7. Audit Policies (Recommended)

Enable auditing to track CyAudit execution:

### Process Creation Auditing

**Policy Path:**
```
Computer Configuration
  └─ Windows Settings
       └─ Security Settings
            └─ Advanced Audit Policy Configuration
                 └─ System Audit Policies
                      └─ Detailed Tracking
                           └─ Audit Process Creation
```

**Setting:** Success and Failure

### Include Command Line in Process Creation Events

**Policy Path:**
```
Computer Configuration
  └─ Administrative Templates
       └─ System
            └─ Audit Process Creation
                 └─ Include command line in process creation events
```

**Setting:** Enabled

---

## GPO Implementation Guide

### Step 1: Create New GPO

1. Open Group Policy Management Console (GPMC)
2. Right-click your domain or OU > **Create a GPO in this domain**
3. Name: `CyAudit 3.5 Configuration`

### Step 2: Configure Policies

Apply the recommended settings above:

1. **Required:**
   - PowerShell Execution Policy = RemoteSigned

2. **Recommended:**
   - Script Block Logging = Enabled
   - Module Logging = Enabled

3. **Optional:**
   - PowerShell Transcription = Enabled
   - Defender Exclusions (if needed)

### Step 3: Link GPO

Link the GPO to:
- Specific OUs containing target systems
- Or domain-wide (if all systems should run CyAudit)

### Step 4: Force Update (Testing)

On target systems:
```cmd
gpupdate /force
```

### Step 5: Verify Policy Application

```powershell
# Check execution policy
Get-ExecutionPolicy -List

# Check GPO application
gpresult /r /scope computer
```

---

## Security Considerations

### Execution Policy Is Not a Security Boundary

Microsoft states that PowerShell execution policy is not a security boundary but a convenience feature. Users with administrative access can always bypass it.

CyAudit uses `-ExecutionPolicy Bypass` as a fallback to ensure reliable execution even in environments with restrictive base policies.

### Defense in Depth

Combine execution policy with:
1. **AppLocker or WDAC** - Control which scripts can run
2. **Constrained Language Mode** - Limit PowerShell capabilities
3. **Script signing** - Require signed scripts (future enhancement)
4. **Logging** - Record all PowerShell activity

### Least Privilege

CyAudit requires administrator privileges because it:
- Reads security policies (secedit, auditpol)
- Queries WMI security classes
- Accesses registry security settings
- Runs PowerSTIG DSC checks

Running as SYSTEM via scheduled task provides these privileges without exposing user credentials.

---

## Troubleshooting GPO Issues

### Policy Not Applying

1. Check GPO link is enabled
2. Verify security filtering includes target computers
3. Check WMI filters (if used)
4. Run `gpresult /r` to see applied policies

### Execution Policy Conflicts

Multiple sources can set execution policy:
1. Group Policy (highest precedence)
2. Local machine setting
3. Current user setting
4. Session setting (lowest)

Check all levels:
```powershell
Get-ExecutionPolicy -List
```

### Script Still Blocked

If scripts still fail to run:

1. **Check Zone.Identifier:**
   ```powershell
   Get-Item "C:\CyAudit\CyAudit_3.5\*.ps1" -Stream Zone.Identifier
   ```

2. **Remove Zone.Identifier:**
   ```powershell
   Get-ChildItem "C:\CyAudit" -Recurse | Unblock-File
   ```

3. **Verify file is local:**
   Scripts on network shares are "remote" even with UNC paths

---

## Quick Reference: Minimum Required GPO

For basic CyAudit operation, only one policy is strictly required:

**Turn on Script Execution**
- Path: `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`
- Setting: **Enabled**
- Execution Policy: **Allow local scripts and remote signed scripts**

All other policies are recommended but optional.

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-12-01 | Initial release |
