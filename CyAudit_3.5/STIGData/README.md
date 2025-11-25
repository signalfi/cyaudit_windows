# STIGData - Local STIG Data Folder

This folder provides a fallback location for STIG data files when PowerSTIG module is unavailable or when you want to use specific pre-approved STIG versions.

## Default Behavior

CyAudit uses the following priority for STIG data sources:

1. **PowerSTIG Module** (primary) - Auto-detects available versions from installed PowerSTIG
2. **Local STIGData Folder** (fallback) - Uses files in this folder or `../STIGS/`
3. **User-specified** - Explicit `-StigVersions` parameter overrides all

## Configuration Options

### Via Command Line
```powershell
# Auto-detect (default)
.\CyAudit_Opus_V3.4.ps1 -ClientName "MyOrg" -StigDataSource auto

# Force local STIG data only
.\CyAudit_Opus_V3.4.ps1 -ClientName "MyOrg" -StigDataSource local

# Force PowerSTIG only (will fail if not installed)
.\CyAudit_Opus_V3.4.ps1 -ClientName "MyOrg" -StigDataSource powerstig

# Custom local STIG path
.\CyAudit_Opus_V3.4.ps1 -ClientName "MyOrg" -StigDataSource local -LocalStigDataPath "C:\STIGs"
```

### Via Pipeline Config (CyAuditPipeline.config.json)
```json
{
  "CyAuditOptions": {
    "StigDataSource": "auto",
    "LocalStigDataPath": "../STIGS"
  }
}
```

## Existing STIG Packages

The `../STIGS/` folder contains official DISA STIG packages:

| OS | Version | XCCDF File Path |
|----|---------|-----------------|
| Windows 10 | V3R4 | `../STIGS/U_MS_Windows_10_V3R4_STIG/U_MS_Windows_10_V3R4_Manual_STIG/U_MS_Windows_10_STIG_V3R4_Manual-xccdf.xml` |
| Windows 11 | V2R3 | `../STIGS/U_MS_Windows_11_V2R3_STIG/U_MS_Windows_11_V2R3_Manual_STIG/U_MS_Windows_11_STIG_V2R3_Manual-xccdf.xml` |
| Server 2019 | V3R4 | `../STIGS/U_MS_Windows_Server_2019_V3R4_STIG/U_MS_Windows_Server_2019_V3R4_Manual_STIG/U_MS_Windows_Server_2019_STIG_V3R4_Manual-xccdf.xml` |
| Server 2022 | V2R4 | `../STIGS/U_MS_Windows_Server_2022_V2R4_STIG/U_MS_Windows_Server_2022_V2R4_Manual_STIG/U_MS_Windows_Server_2022_STIG_V2R4_Manual-xccdf.xml` |

## Adding Custom STIG Data

To add custom STIG data files:

1. Download STIG packages from [DISA STIG Library](https://public.cyber.mil/stigs/)
2. Extract to this folder or `../STIGS/`
3. Ensure XML files follow PowerSTIG naming convention or XCCDF format

### PowerSTIG Format
Files should be named: `{STIGType}-{OSVersion}-{StigVersion}.xml`
- Example: `WindowsServer-2019-3.4.xml`

### XCCDF Format
Standard DISA XCCDF files are supported:
- Example: `U_MS_Windows_Server_2019_STIG_V3R4_Manual-xccdf.xml`

## Troubleshooting

### Error: "No STIG data found"
1. Check if PowerSTIG is installed: `Get-Module PowerSTIG -ListAvailable`
2. Verify local STIG files exist in this folder or `../STIGS/`
3. Ensure file naming matches expected patterns

### Error: "STIG version X.X not found"
1. Check available versions in PowerSTIG:
   ```powershell
   $module = Get-Module PowerSTIG -ListAvailable | Select -First 1
   Get-ChildItem "$($module.ModuleBase)\StigData\Processed\*.xml" | Select Name
   ```
2. Use `-StigVersions` parameter to specify available version
3. Download matching STIG package from DISA

## Version History

| Date | Change |
|------|--------|
| 2025-11-25 | Initial creation with auto-detection support |
