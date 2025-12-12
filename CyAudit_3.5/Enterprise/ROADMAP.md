# CyAudit 3.5 Enterprise - Future Updates Roadmap

This document captures planned improvements and enhancement options that have been analyzed but not yet implemented.

---

## Issue: PowerSTIG Installation Not Mandatory

### Problem Statement

In enterprise deployments, CyAudit fails on the PowerSTIG portion because PowerSTIG is not being installed as part of the installation process. The current installer makes PowerSTIG installation **optional**, not mandatory.

### Current Behavior Analysis

#### Inno Setup Installer (`CyAudit_Setup_Clean.iss`)

```ini
; Line 77 - PowerSTIG is an OPTIONAL task with "checkedonce" flag
Name: "powerstig"; Description: "Install PowerSTIG module (requires internet)"; GroupDescription: "Dependencies:"; Flags: checkedonce

; Line 125 - Only runs if task was selected
Filename: "powershell.exe"; Parameters: "..."; Tasks: powerstig; StatusMsg: "Installing PowerSTIG module..."
```

**Issue**: Users can uncheck this option during installation, or if the installation fails (no internet, firewall blocks, etc.), the main installation still succeeds.

#### SCCM Deployment Script (`Install-CyAudit.ps1`)

```powershell
# Lines 497-504 - Failures are warnings only, exit code 0
if (-not (Install-PowerSTIGModule)) {
    if (-not $SkipPowerSTIG) {
        Write-Log "PowerSTIG installation failed. CyAudit may not function correctly without it." -Level WARN
        Write-Log "You can install it manually: Install-Module -Name PowerSTIG -Force -Scope AllUsers" -Level WARN
        # Don't exit - continue with warning  ← THIS IS THE PROBLEM
    }
}
```

**Issue**: Installation succeeds (exit 0) even when PowerSTIG fails to install. SCCM sees success but CyAudit won't function correctly.

### Root Causes in Enterprise Environments

1. **No Internet Access**: Many enterprise systems are air-gapped or have restricted internet
2. **Firewall Rules**: PSGallery may be blocked by corporate firewalls
3. **Proxy Configuration**: PowerShell may not be configured for corporate proxy
4. **Module Already Present (Wrong Version)**: Old version conflicts with installation
5. **User Unchecked Option**: Interactive installations where user deselected PowerSTIG

---

## Proposed Solutions

### Option 1: Make PowerSTIG Mandatory in Current Installer

**Changes Required:**

1. **Inno Setup**: Remove `Flags: checkedonce`, add `Flags: fixed` to make it mandatory
2. **Install-CyAudit.ps1**: Change exit code to failure (1) when PowerSTIG installation fails
3. **Add pre-flight check**: Verify PowerSTIG is available before starting assessment

**Pros:**
- Minimal changes to existing installer
- Clear failure when prerequisites aren't met

**Cons:**
- Requires internet access during installation
- May fail in air-gapped environments

---

### Option 2: Hybrid Bundle + Online Check (Recommended for Connected Environments)

**Approach:**
1. Bundle a baseline version of PowerSTIG with the installer
2. During installation, check online for newer version
3. If online check fails, use bundled version
4. If online check succeeds and newer version available, download it

**Implementation:**
```powershell
# Pseudo-code for hybrid installation
$bundledVersion = "4.22.0"  # Version bundled with installer
$bundledPath = "$PSScriptRoot\PowerSTIG-$bundledVersion.nupkg"

try {
    # Try online installation first
    $latestVersion = (Find-Module PowerSTIG -ErrorAction Stop).Version
    if ($latestVersion -gt $bundledVersion) {
        Install-Module PowerSTIG -Force -Scope AllUsers
        Write-Log "Installed PowerSTIG $latestVersion from PSGallery"
    } else {
        # Use bundled version
        Install-BundledModule -Path $bundledPath
        Write-Log "Installed bundled PowerSTIG $bundledVersion"
    }
} catch {
    # Offline fallback - use bundled version
    Install-BundledModule -Path $bundledPath
    Write-Log "Network unavailable - Installed bundled PowerSTIG $bundledVersion"
}
```

**Pros:**
- Works in both connected and air-gapped environments
- Gets latest version when possible
- Guaranteed to have at least baseline functionality

**Cons:**
- Increases installer size (~15MB for PowerSTIG + dependencies)
- Bundled version may become outdated

---

### Option 3: Separate PowerSTIG Offline Installer Package (Recommended for Air-Gapped)

**Approach:**
Create a separate "PowerSTIG Offline Package" that:
1. Contains PowerSTIG and all dependencies
2. Can be distributed independently of CyAudit
3. Includes version management for updates

**Package Contents:**
```
PowerSTIG_Offline_Package_v4.22.0/
├── Install-PowerSTIG-Offline.ps1
├── Modules/
│   ├── PowerSTIG/
│   ├── PSDesiredStateConfiguration/
│   ├── AuditPolicyDsc/
│   ├── SecurityPolicyDsc/
│   ├── WindowsDefenderDsc/
│   └── ComputerManagementDsc/
├── STIGData/
│   └── (STIG XML files)
└── README.md
```

**Installation Script:**
```powershell
# Install-PowerSTIG-Offline.ps1
param(
    [string]$ModulePath = "$env:ProgramFiles\WindowsPowerShell\Modules"
)

$sourceModules = Join-Path $PSScriptRoot "Modules"
$modules = Get-ChildItem -Path $sourceModules -Directory

foreach ($module in $modules) {
    $destPath = Join-Path $ModulePath $module.Name

    if (Test-Path $destPath) {
        # Backup existing version
        $backupPath = "$destPath.backup.$(Get-Date -Format 'yyyyMMdd')"
        Move-Item -Path $destPath -Destination $backupPath -Force
    }

    Copy-Item -Path $module.FullName -Destination $destPath -Recurse -Force
    Write-Host "Installed: $($module.Name)" -ForegroundColor Green
}

Write-Host "`nPowerSTIG offline installation complete!" -ForegroundColor Cyan
```

**Pros:**
- Works in completely air-gapped environments
- Can be updated independently of CyAudit
- Clear versioning and control
- Can be hosted on internal file shares

**Cons:**
- Separate package to maintain
- Users must remember to update it
- Additional deployment step

---

### Option 4: Internal PSRepository (Recommended for Large Enterprises)

**Approach:**
Set up an internal PowerShell repository that mirrors PSGallery modules.

**Implementation Options:**
1. **NuGet Server**: Self-hosted NuGet repository
2. **Azure Artifacts**: Cloud-hosted private feed
3. **ProGet**: Enterprise artifact repository
4. **File Share Repository**: Simple folder-based repository

**File Share Repository Setup:**
```powershell
# One-time setup on file server
$repoPath = "\\fileserver\PSRepository"
New-Item -Path $repoPath -ItemType Directory -Force

# Register repository on all machines (via GPO or SCCM)
Register-PSRepository -Name "InternalRepo" -SourceLocation $repoPath -InstallationPolicy Trusted

# Download and publish modules to internal repo
Save-Module -Name PowerSTIG -Path $repoPath
Save-Module -Name AuditPolicyDsc -Path $repoPath
# ... etc
```

**Modified Installation:**
```powershell
# Install from internal repository
Install-Module -Name PowerSTIG -Repository InternalRepo -Force -Scope AllUsers
```

**Pros:**
- Full control over module versions
- No external internet dependency
- Centralized update management
- Works for all PowerShell module needs

**Cons:**
- Infrastructure to set up and maintain
- Someone must manually update the repository
- More complex initial setup

---

## Automatic Update Notification System

To stay informed when PowerSTIG releases updates (for Options 2-4), implement a monitoring system:

### Monitoring Script

```powershell
<#
.SYNOPSIS
    Monitors PowerShell Gallery for PowerSTIG updates

.DESCRIPTION
    Queries PSGallery for the latest PowerSTIG version and compares
    to the currently bundled/deployed version. Sends notification
    when updates are available.
#>

param(
    [string]$CurrentVersion = "4.22.0",
    [string]$NotificationWebhook = "https://your-teams-webhook-url",
    [string]$NotificationEmail = "admin@yourcompany.com"
)

# Query PowerShell Gallery API
$galleryUrl = "https://www.powershellgallery.com/api/v2/FindPackagesById()?id='PowerSTIG'"
try {
    $response = Invoke-RestMethod -Uri $galleryUrl -ErrorAction Stop
    $latestEntry = $response | Sort-Object { [version]$_.properties.Version } -Descending | Select-Object -First 1
    $latestVersion = $latestEntry.properties.Version

    if ([version]$latestVersion -gt [version]$CurrentVersion) {
        $message = @"
PowerSTIG Update Available!
Current bundled version: $CurrentVersion
Latest available version: $latestVersion
Published: $($latestEntry.properties.Published)

Release Notes:
$($latestEntry.properties.ReleaseNotes)

Action Required:
1. Download new version: Save-Module -Name PowerSTIG -Path C:\Temp -RequiredVersion $latestVersion
2. Test in dev environment
3. Update CyAudit bundle/repository
4. Deploy to production
"@

        # Send Teams notification
        if ($NotificationWebhook) {
            $body = @{ text = $message } | ConvertTo-Json
            Invoke-RestMethod -Uri $NotificationWebhook -Method Post -Body $body -ContentType "application/json"
        }

        # Send email notification
        if ($NotificationEmail) {
            Send-MailMessage -To $NotificationEmail -Subject "PowerSTIG Update: $latestVersion Available" -Body $message -SmtpServer "smtp.yourcompany.com"
        }

        Write-Host "UPDATE AVAILABLE: PowerSTIG $latestVersion" -ForegroundColor Yellow
        return $true
    } else {
        Write-Host "Current version $CurrentVersion is up to date" -ForegroundColor Green
        return $false
    }
} catch {
    Write-Error "Failed to check for updates: $_"
    return $null
}
```

### Scheduled Task for Monitoring

```powershell
# Create scheduled task to run weekly
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File C:\CyAudit\Scripts\Check-PowerSTIGUpdates.ps1"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 9am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
Register-ScheduledTask -TaskName "CyAudit-PowerSTIG-UpdateCheck" -Action $action -Trigger $trigger -Principal $principal
```

### Alternative: RSS/Atom Feed Monitoring

PowerShell Gallery provides RSS feeds:
- Feed URL: `https://www.powershellgallery.com/packages/PowerSTIG/atom.xml`
- Can be monitored with any RSS reader or automation tool (Azure Logic Apps, Power Automate, n8n, etc.)

---

## PowerSTIG Version History (Reference)

| Version | Release Date | Key Changes |
|---------|--------------|-------------|
| 4.22.0  | 2024-11-xx   | Latest stable |
| 4.21.0  | 2024-08-xx   | Windows 11 updates |
| 4.20.0  | 2024-05-xx   | Server 2022 updates |
| 4.19.0  | 2024-02-xx   | Office 365 STIGs |

*Note: Check PSGallery for current version information*

---

## Recommendation Summary

| Environment Type | Recommended Option |
|------------------|-------------------|
| Connected (internet access) | Option 2: Hybrid Bundle |
| Air-gapped (no internet) | Option 3: Separate Offline Package |
| Large enterprise (100+ systems) | Option 4: Internal PSRepository |
| Small deployment (<10 systems) | Option 1: Mandatory installation |

---

## Implementation Priority

1. **Phase 1 (Immediate)**: Add pre-flight check in CyAudit to verify PowerSTIG is present before running assessment
2. **Phase 2 (Short-term)**: Implement Option 3 (Offline Package) for air-gapped support
3. **Phase 3 (Medium-term)**: Implement Option 2 (Hybrid Bundle) for default installer
4. **Phase 4 (Long-term)**: Document Option 4 (Internal Repository) for large enterprise customers

---

## Related Files

- `CyAudit_Setup_Clean.iss` - Inno Setup installer script
- `Install-CyAudit.ps1` - SCCM deployment script
- `Test-PowerSTIGPrerequisites.ps1` - Diagnostic script for checking prerequisites
- `CyAudit_Opus_V3.5.ps1` - Main assessment engine

---

*Document created: 2025-12-11*
*Last updated: 2025-12-12*
*Status: Planning - Not Yet Implemented*
