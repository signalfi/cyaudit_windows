# CyAudit 3.5 Changelog

## Version 3.5.0 (2025-11-25)

This release focuses on stability and compatibility fixes identified during production testing.

---

### Bug Fixes

#### STIG Version Mismatch (Issue 1)
**Severity:** High | **Impact:** PowerSTIG compliance scanning blocked

**Problem:** Script failed to complete STIG compliance scanning due to hardcoded STIG version references that didn't match the installed PowerSTIG module version.

**Solution:**
- Added `Get-AvailableSTIGVersion` function for auto-detection of available STIG versions
- Removed hardcoded version map that caused version mismatch errors
- Added local STIG data fallback when PowerSTIG unavailable
- New configuration options: `StigDataSource` and `LocalStigDataPath`

**Files Modified:**
- `CyAudit_Opus_V3.5.ps1` - Auto-detection logic and new parameters
- `CyAuditPipeline.config.json` - New STIG configuration options
- `STIGData/` - Local STIG data folder structure

---

#### Pipeline Output Directory Mismatch (Issue 2)
**Severity:** Medium | **Impact:** Pipeline failed after successful assessment

**Problem:** Pipeline script looked for CyAudit output in a different directory than where CyAudit actually wrote files.

**Solution:**
- Modified `Run-CyAuditPipeline.ps1` to track actual output path
- Pipeline now looks in the same location CyAudit outputs to
- Eliminated contradictory SUCCESS/ERROR messages

**Files Modified:**
- `Run-CyAuditPipeline.ps1` - Output path tracking fix

---

#### Unicode/Encoding Corruption (Issue 3)
**Severity:** High | **Impact:** Scripts failed to parse on Windows systems

**Problem:** UTF-8 Unicode characters (emoji, box-drawing) corrupted when files transferred to Windows systems with default Windows-1252 encoding.

**Solution:**
- Replaced Unicode emoji characters with ASCII equivalents:
  - `[check]` -> `[OK]`
  - `[x]` -> `[X]`
  - `[bullet]` -> `[*]`
  - `[warning]` -> `[!]`
- Replaced box-drawing characters with ASCII:
  - Double lines -> `===`
  - Single lines -> `---`
- Replaced ampersands in phase titles with "and"

**Files Modified:**
- `Transform-CyAuditForSplunk.ps1` - Character replacements
- `Run-CyAuditPipeline.ps1` - Character replacements
- `Test-SplunkTransformation.ps1` - Character replacements
- `Upload-ToSplunkCloud.ps1` - Character replacements
- `CyAudit_Opus_V3.5.ps1` - Character replacements

---

#### Script Hang During Transformation (Issue 4)
**Severity:** High | **Impact:** Pipeline hung indefinitely during Splunk transformation

**Problem:** Pipeline hung after "Transformed 149 log entries" message, never completing the transformation phase.

**Root Cause:**
- Encoding mismatch when reading ErrorLog.txt (forced UTF-8 vs default encoding)
- StreamWriter not properly disposed on errors
- No progress feedback during large file operations
- Return value noise cluttering console output

**Solution:**
- Hardened `Write-SplunkNDJson` function:
  - Added try-finally for guaranteed StreamWriter disposal
  - Added per-record serialization guards with fallback handling
  - Added context-aware progress logging
  - Optional simple JSON serializer for problematic data
- Fixed `Transform-ErrorLog` to read with default encoding
- Suppressed return values at all call sites (24 locations)
- Added validation and error throwing for failed writes

**Files Modified:**
- `Transform-CyAuditForSplunk.ps1` - Comprehensive hardening

---

## Previous Versions

### Version 3.4.0 (2025-11-12)
- Initial release with Splunk Cloud integration
- PowerSTIG integration for comprehensive STIG automation
- Automated pipeline orchestration
- Universal Forwarder integration
- 20+ Splunk sourcetypes with search-time extraction
- STIG Viewer .ckl file generation
- Email alerts and retention management

### Version 3.3.x
- Comprehensive STIG registry compliance (76+ registry settings)
- Windows version-specific STIG requirement determination
- Enhanced registry collection with STIG-specific validation

### Version 3.0.x
- DISA STIG Windows Server 2019 compliance checking
- Extended registry data collection
- Windows Features compliance checking
- Inactive account detection (35+ days)
- Enhanced service compliance checking

---

## Upgrade Notes

### From 3.4 to 3.5
1. Replace entire `CyAudit_3.4` folder with `CyAudit_3.5`
2. No configuration changes required - all fixes are backward compatible
3. Existing scheduled tasks will continue working with updated paths

### Compatibility
- Windows 10/11, Server 2016/2019/2022
- PowerShell 5.1+
- PowerSTIG 4.24.0+ (any version supported via auto-detection)
- Splunk Universal Forwarder 9.x
- Splunk Cloud

---

## Known Issues

None at this time.

---

## Support

For issues or questions:
1. Review troubleshooting section in `DEPLOYMENT_GUIDE.md`
2. Check pipeline logs in `C:\CyAudit\Logs\`
3. Review CyAudit error logs in assessment output folder
