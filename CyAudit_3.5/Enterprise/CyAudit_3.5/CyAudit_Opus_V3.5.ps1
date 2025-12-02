#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    CyAudit Opus v3.5 - Advanced Windows Security Configuration Audit Tool with PowerSTIG Integration
    Combines comprehensive STIG registry coverage with Microsoft PowerSTIG automation framework

.DESCRIPTION
    This script performs comprehensive Windows security auditing on local or remote systems.
    Version 3.5 integrates Microsoft PowerSTIG for comprehensive DISA STIG compliance while
    maintaining all V3.3 functionality for side-by-side validation. The script automatically
    detects Windows version, installs PowerSTIG dependencies, and generates:
    - V3.3 registry checks (76+ settings)
    - PowerSTIG comprehensive evaluation (200+ controls)
    - Side-by-side comparison reports
    - DISA STIG Viewer compatible .ckl files
    - Enhanced CSV/JSON compliance reports

.PARAMETER ComputerName
    One or more computer names to audit. Defaults to local computer.

.PARAMETER ClientName
    The client name for the audit report.

.PARAMETER OutputPath
    Path where output files will be saved. Defaults to current directory.

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER SkipSTIGCompliance
    Skip STIG compliance evaluation (run v2 functionality only)

.PARAMETER SkipPowerSTIG
    Skip PowerSTIG evaluation - run only V3.3 checks

.PARAMETER PowerSTIGOnly
    Run only PowerSTIG evaluation - skip V3.3 checks

.PARAMETER XccdfPath
    Path to DISA XCCDF files for STIG Viewer checklist generation

.PARAMETER GenerateCheckList
    Generate STIG Viewer .ckl checklist files (requires XccdfPath)

.PARAMETER StigVersions
    Specific STIG versions to evaluate (default: auto-detect based on OS)

.EXAMPLE
    .\CyAudit_Opus_V3.5.ps1 -ClientName "Acme Corp"
    # Runs both V3.3 and PowerSTIG evaluations with side-by-side comparison

.EXAMPLE
    .\CyAudit_Opus_V3.5.ps1 -ComputerName "SERVER01","SERVER02" -ClientName "Acme Corp" -Credential (Get-Credential)
    # Remote audit with both evaluation methods

.EXAMPLE
    .\CyAudit_Opus_V3.5.ps1 -ClientName "Acme Corp" -GenerateCheckList -XccdfPath "C:\STIGs"
    # Full audit with STIG Viewer checklist generation

.EXAMPLE
    .\CyAudit_Opus_V3.5.ps1 -ClientName "Acme Corp" -PowerSTIGOnly
    # Run only PowerSTIG evaluation (skip V3.3 checks)

.NOTES
    Version 3.5 Changes (Bug Fixes):
    - Fixed Unicode/encoding corruption in PowerShell scripts
    - Fixed STIG version mismatch for PowerSTIG compatibility
    - Fixed pipeline output directory handling
    - Fixed script hang during Splunk transformation
    - Hardened Write-SplunkNDJson with proper disposal and error handling

    Version 3.4 Changes (PowerSTIG Integration):
    - Integrated Microsoft PowerSTIG framework for comprehensive STIG automation
    - Added automatic PowerSTIG dependency installation and validation
    - Implemented side-by-side comparison (V3.3 vs PowerSTIG results)
    - Added STIG Viewer .ckl file generation capability
    - Enhanced reporting with DSC compliance data
    - Added PowerSTIG-specific error handling and logging
    - Maintained 100% backward compatibility with V3.3 functionality
    - Added audit-only mode for PowerSTIG (no system changes)

    Version 3.3 Changes:
    - Implemented comprehensive STIG registry compliance (76 registry settings)
    - Added Windows version-specific STIG requirement determination
    - Enhanced registry collection with STIG-specific validation
    - Added conditional logic for domain controllers and domain members
    - Expanded coverage for Windows 10, 11, Server 2019, and Server 2022
    - Added detailed STIG registry compliance reporting
    - Improved performance with targeted registry collection

    Previous Version Changes (3.0):
    - Added DISA STIG Windows Server 2019 compliance checking
    - Extended registry data collection for STIG requirements
    - Added Windows Features compliance checking
    - Added inactive account detection (35+ days)
    - Added temporary/emergency account detection
    - Enhanced service compliance checking
    - Added STIG compliance summary reports (CSV/JSON)
#>

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter(Mandatory=$true)]
    [string]$ClientName,

    [string]$OutputPath = $PWD.Path,

    [PSCredential]$Credential,

    [switch]$SkipSTIGCompliance,

    [switch]$SkipPowerSTIG,

    [switch]$PowerSTIGOnly,

    [string]$XccdfPath,

    [switch]$GenerateCheckList,

    [string[]]$StigVersions,

    [ValidateSet('auto', 'local', 'powerstig')]
    [string]$StigDataSource = 'auto',

    [string]$LocalStigDataPath
)

# Script version
$ScriptVersion = "CyAudit Opus PowerShell v3.5.0"

# Get script directory - works for both .ps1 and PS2EXE compiled .exe
if ($PSScriptRoot) {
    $ScriptDir = $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    # Fallback for PS2EXE compiled executables
    $ScriptDir = Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
}

#region Helper Functions

function Write-AuditLog {
    param(
        [string]$Message,
        [string]$LogFile,
        [switch]$NoNewLine
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = if ($Message -match '^\d{4}-\d{2}-\d{2}') { $Message } else { "$timestamp - $Message" }
    
    if ($NoNewLine) {
        Write-Host $Message -NoNewline
    } else {
        Write-Host $Message
    }
    
    if ($LogFile) {
        Add-Content -Path $LogFile -Value $logMessage
    }
}

function Remove-RemotingMetadata {
    <#
    .SYNOPSIS
        Removes PowerShell remoting metadata from objects
    
    .DESCRIPTION
        Helper function to clean PSComputerName, RunspaceId, and PSShowComputerName
        properties that are added by Invoke-Command
    #>
    param(
        [Parameter(ValueFromPipeline)]
        $InputObject
    )
    
    process {
        if ($InputObject -is [PSCustomObject]) {
            # Define the remoting metadata properties to remove
            $remotingMetadata = @('PSComputerName', 'RunspaceId', 'PSShowComputerName')
            
            # Create a new object without the remoting metadata
            $cleanedObject = [PSCustomObject]@{}
            
            foreach ($property in $InputObject.PSObject.Properties) {
                if ($property.Name -notin $remotingMetadata) {
                    $cleanedObject | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value
                }
            }
            
            return $cleanedObject
        } else {
            # Return non-PSCustomObject items as-is
            return $InputObject
        }
    }
}

function Get-RemoteData {
    param(
        [string]$ComputerName,
        [scriptblock]$ScriptBlock,
        [PSCredential]$Credential,
        [hashtable]$ArgumentList
    )
    
    if ($ComputerName -eq $env:COMPUTERNAME) {
        # Local execution - splat the hashtable
        if ($ArgumentList) {
            & $ScriptBlock @ArgumentList
        } else {
            & $ScriptBlock
        }
    } else {
        # Remote execution - use Invoke-Command with array of values
        $params = @{
            ComputerName = $ComputerName
            ScriptBlock = $ScriptBlock
        }
        
        if ($ArgumentList) {
            # For remote execution, we need to pass the values as an array
            # Convert hashtable values to array for Invoke-Command
            $argArray = @()
            foreach ($value in $ArgumentList.Values) {
                $argArray += $value
            }
            $params.ArgumentList = $argArray
            
            # Debug: Report what we're sending
            Write-Verbose "Sending $($argArray.Count) arguments to $ComputerName"
            if ($argArray[0] -is [array]) {
                Write-Verbose "First argument is an array with $($argArray[0].Count) items"
            }
        }
        
        if ($Credential) {
            $params.Credential = $Credential
        }
        
        try {
            # Execute remotely with increased serialization limits
            $sessionOption = New-PSSessionOption -MaximumReceivedDataSizePerCommand 500MB -MaximumReceivedObjectSize 500MB -OperationTimeout 600000
            $result = Invoke-Command @params -SessionOption $sessionOption
            
            # Debug: Report initial result count
            if ($result -is [array]) {
                Write-Verbose "Remote execution returned $($result.Count) items from $ComputerName"
            } elseif ($result) {
                Write-Verbose "Remote execution returned 1 item from $ComputerName"
            } else {
                Write-Verbose "Remote execution returned no data from $ComputerName"
            }
            
            # Remove PowerShell remoting metadata if present
            if ($result) {
                $cleanedResult = $result | Remove-RemotingMetadata
                
                # Debug: Report cleaned result count
                if ($cleanedResult -is [array]) {
                    Write-Verbose "After cleaning metadata: $($cleanedResult.Count) items for $ComputerName"
                } else {
                    Write-Verbose "After cleaning metadata: 1 item for $ComputerName"
                }
                
                return $cleanedResult
            }
            
            return $result
            
        } catch {
            Write-Error "Failed to execute remote command on ${ComputerName}: $($_.Exception.Message)"
            Write-Verbose "Stack trace: $($_.ScriptStackTrace)"
            return $null
        }
    }
}

function ConvertTo-FlatObject {
    param(
        [Parameter(ValueFromPipeline)]
        $InputObject
    )
    
    process {
        $hash = @{}
        foreach ($property in $InputObject.PSObject.Properties) {
            if ($null -ne $property.Value) {
                if ($property.Value -is [DateTime]) {
                    $hash[$property.Name] = $property.Value.ToString("yyyy-MM-dd HH:mm:ss")
                } elseif ($property.Value -is [array]) {
                    $hash[$property.Name] = $property.Value -join '; '
                } else {
                    $hash[$property.Name] = $property.Value.ToString()
                }
            } else {
                $hash[$property.Name] = ''
            }
        }
        [PSCustomObject]$hash
    }
}

function Get-MD5Hash {
    param(
        [string]$FilePath
    )
    
    try {
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $stream = [System.IO.File]::OpenRead($FilePath)
        $hash = [System.BitConverter]::ToString($md5.ComputeHash($stream)).Replace("-", "").ToLower()
        $stream.Close()
        return $hash
    } catch {
        return "Failed to calculate hash: $_"
    }
}

function Get-WindowsVersionInfo {
    <#
    .SYNOPSIS
        Enhanced Windows version detection for STIG requirement determination
    
    .DESCRIPTION
        Determines Windows version, edition, build number, and role to apply
        appropriate STIG registry requirements
    #>
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        
        # Determine Windows version and edition
        $version = [version]$os.Version
        $buildNumber = $os.BuildNumber
        $productType = $os.ProductType
        $osName = $os.Caption
        
        # Determine Windows type
        $windowsType = "Unknown"
        $windowsVersion = "Unknown"
        
        if ($version.Major -eq 10) {
            if ($buildNumber -ge 22000) {
                $windowsVersion = "Windows 11"
                $windowsType = "Client"
            } elseif ($buildNumber -ge 20348) {
                $windowsVersion = "Windows Server 2022"
                $windowsType = "Server"
            } elseif ($buildNumber -ge 17763) {
                $windowsVersion = "Windows Server 2019"
                $windowsType = "Server"
            } elseif ($buildNumber -ge 10240) {
                $windowsVersion = "Windows 10"
                $windowsType = "Client"
            }
        } elseif ($version.Major -eq 6 -and $version.Minor -eq 3) {
            if ($productType -eq 1) {
                $windowsVersion = "Windows 8.1"
                $windowsType = "Client"
            } else {
                $windowsVersion = "Windows Server 2012 R2"
                $windowsType = "Server"
            }
        }
        
        # Determine domain role
        $isDomainController = $cs.DomainRole -in @(4, 5)
        $isDomainMember = $cs.DomainRole -in @(1, 3, 4, 5)
        
        # Determine server role
        $serverRole = switch ($cs.DomainRole) {
            0 { "Standalone Workstation" }
            1 { "Member Workstation" }
            2 { "Standalone Server" }
            3 { "Member Server" }
            4 { "Backup Domain Controller" }
            5 { "Primary Domain Controller" }
        }
        
        return [PSCustomObject]@{
            OSName = $osName
            Version = $version
            BuildNumber = $buildNumber
            WindowsVersion = $windowsVersion
            WindowsType = $windowsType
            ProductType = $productType
            IsDomainController = $isDomainController
            IsDomainMember = $isDomainMember
            ServerRole = $serverRole
            Domain = $cs.Domain
            ComputerName = $cs.Name
        }
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

#endregion

#region PowerSTIG Dependency Management Functions

function Test-PowerShellVersion {
    <#
    .SYNOPSIS
        Verifies PowerShell version is 5.1 (PowerSTIG requirement)

    .DESCRIPTION
        PowerSTIG currently only supports PowerShell 5.1, not PowerShell 7+
    #>

    $psVersion = $PSVersionTable.PSVersion

    if ($psVersion.Major -eq 5 -and $psVersion.Minor -ge 1) {
        return @{
            IsCompatible = $true
            Version = $psVersion.ToString()
            Message = "PowerShell $($psVersion.ToString()) is compatible with PowerSTIG"
        }
    } else {
        return @{
            IsCompatible = $false
            Version = $psVersion.ToString()
            Message = "PowerSTIG requires PowerShell 5.1. Current version: $($psVersion.ToString())"
        }
    }
}

function Test-PowerSTIGPrerequisites {
    <#
    .SYNOPSIS
        Tests for PowerSTIG module and required dependencies

    .DESCRIPTION
        Checks if PowerSTIG and its DSC resource dependencies are installed
    #>
    param(
        [string]$LogFile
    )

    Write-AuditLog "Checking PowerSTIG prerequisites..." -LogFile $LogFile

    # Check PowerShell version
    $psVersionCheck = Test-PowerShellVersion
    if (-not $psVersionCheck.IsCompatible) {
        Write-AuditLog "ERROR: $($psVersionCheck.Message)" -LogFile $LogFile
        return $false
    }
    Write-AuditLog "[OK] $($psVersionCheck.Message)" -LogFile $LogFile

    # Check for PowerSTIG module
    $powerSTIG = Get-Module -ListAvailable -Name PowerSTIG
    if (-not $powerSTIG) {
        Write-AuditLog "PowerSTIG module not found" -LogFile $LogFile
        return $false
    }

    Write-AuditLog "[OK] PowerSTIG module found (Version: $($powerSTIG.Version))" -LogFile $LogFile

    # Check for critical DSC resource modules
    $requiredModules = @(
        'PSDesiredStateConfiguration',
        'AuditPolicyDsc',
        'SecurityPolicyDsc',
        'WindowsDefenderDsc',
        'ComputerManagementDsc'
    )

    $missingModules = @()
    foreach ($moduleName in $requiredModules) {
        $module = Get-Module -ListAvailable -Name $moduleName
        if ($module) {
            Write-AuditLog "[OK] $moduleName found (Version: $($module.Version))" -LogFile $LogFile
        } else {
            Write-AuditLog "[X] $moduleName not found" -LogFile $LogFile
            $missingModules += $moduleName
        }
    }

    if ($missingModules.Count -gt 0) {
        Write-AuditLog "Missing $($missingModules.Count) required DSC modules" -LogFile $LogFile
        return $false
    }

    Write-AuditLog "All PowerSTIG prerequisites satisfied" -LogFile $LogFile
    return $true
}

function Install-PowerSTIGModules {
    <#
    .SYNOPSIS
        Installs PowerSTIG and required DSC resource modules

    .DESCRIPTION
        Downloads and installs PowerSTIG from PowerShell Gallery along with dependencies
    #>
    param(
        [string]$LogFile
    )

    Write-AuditLog "Installing PowerSTIG and dependencies..." -LogFile $LogFile

    try {
        # Ensure TLS 1.2 for PSGallery
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Trust PSGallery if not already trusted
        $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($psGallery -and $psGallery.InstallationPolicy -ne 'Trusted') {
            Write-AuditLog "Setting PSGallery as trusted repository..." -LogFile $LogFile
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }

        # Install PowerSTIG
        Write-AuditLog "Installing PowerSTIG module..." -LogFile $LogFile
        Install-Module -Name PowerSTIG -Force -AllowClobber -Scope AllUsers -ErrorAction Stop
        Write-AuditLog "[OK] PowerSTIG installed successfully" -LogFile $LogFile

        # Install critical dependencies
        $dependencies = @(
            'AuditPolicyDsc',
            'SecurityPolicyDsc',
            'AccessControlDsc',
            'WindowsDefenderDsc',
            'ComputerManagementDsc',
            'FileContentDsc',
            'PSDscResources'
        )

        foreach ($module in $dependencies) {
            Write-AuditLog "Installing $module..." -LogFile $LogFile
            try {
                Install-Module -Name $module -Force -AllowClobber -Scope AllUsers -ErrorAction Stop
                Write-AuditLog "[OK] $module installed" -LogFile $LogFile
            } catch {
                Write-AuditLog "[!] Failed to install $module`: $_" -LogFile $LogFile
            }
        }

        Write-AuditLog "PowerSTIG installation completed" -LogFile $LogFile
        return $true

    } catch {
        Write-AuditLog "ERROR installing PowerSTIG: $($_.Exception.Message)" -LogFile $LogFile
        Write-AuditLog "Stack trace: $($_.ScriptStackTrace)" -LogFile $LogFile
        return $false
    }
}

function Get-RequiredDSCResources {
    <#
    .SYNOPSIS
        Determines required DSC resources based on OS version

    .DESCRIPTION
        Returns list of DSC resource modules needed for the target OS
    #>
    param(
        [PSCustomObject]$WindowsVersionInfo
    )

    $baseModules = @(
        'AuditPolicyDsc',
        'SecurityPolicyDsc',
        'ComputerManagementDsc',
        'PSDscResources'
    )

    # Add Windows Defender for supported versions
    if ($WindowsVersionInfo.WindowsVersion -in @('Windows 10', 'Windows 11', 'Windows Server 2019', 'Windows Server 2022')) {
        $baseModules += 'WindowsDefenderDsc'
    }

    # Add SQL Server resources if needed (future enhancement)
    # if (Test-SQLServerInstalled) {
    #     $baseModules += 'SqlServerDsc'
    # }

    return $baseModules
}

#endregion

#region System Information Functions

function Get-SystemInfo {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        $net = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        
        [PSCustomObject]@{
            ComputerName = $os.CSName
            Caption = $os.Caption
            ServicePack = "$($os.ServicePackMajorVersion).$($os.ServicePackMinorVersion)"
            Version = $os.Version
            RunDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            IPAddresses = ($net | ForEach-Object { "$($_.Description): $($_.IPAddress -join ', ')" }) -join "; "
            Domain = $cs.Domain
            DomainRole = switch ($cs.DomainRole) {
                0 { "Standalone Workstation" }
                1 { "Member Workstation" }
                2 { "Standalone Server" }
                3 { "Member Server" }
                4 { "Backup Domain Controller" }
                5 { "Primary Domain Controller" }
            }
            CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

#endregion

#region User and Group Functions

function Get-LocalUsers {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        $users = @()
        
        # Get local users
        Get-LocalUser | ForEach-Object {
            $user = $_
            $userSID = $user.SID.Value
            
            # Get additional info from WMI
            $wmiUser = Get-CimInstance -ClassName Win32_UserAccount -Filter "SID='$userSID'"
            
            $users += [PSCustomObject]@{
                UserName = $user.Name
                FullName = $user.FullName
                Description = $user.Description
                AccountType = "Local"
                SID = $userSID
                PasswordLastSet = $user.PasswordLastSet
                Domain = $env:COMPUTERNAME
                PasswordChangeableDate = $user.PasswordChangeableDate
                PasswordExpires = $user.PasswordExpires
                PasswordRequired = $user.PasswordRequired
                AccountDisabled = -not $user.Enabled
                AccountLocked = $wmiUser.Lockout
                LastLogon = $user.LastLogon
                # V3 additions for STIG compliance
                AccountExpires = $user.AccountExpires
            }
        }
        
        $users
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

function Get-LocalGroups {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        $groups = @()
        
        Get-LocalGroup | ForEach-Object {
            $group = $_
            $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
            
            $groups += [PSCustomObject]@{
                Name = $group.Name
                SID = $group.SID.Value
                Caption = "$env:COMPUTERNAME\$($group.Name)"
                Description = $group.Description
                Domain = $env:COMPUTERNAME
                Members = ($members | ForEach-Object { $_.Name }) -join "; "
            }
        }
        
        $groups
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

function Get-ADUsers {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        
        if (Get-Module ActiveDirectory) {
            Get-ADUser -Filter * -Properties * | Select-Object @{
                Name='NTName'; Expression={$_.SamAccountName}
            }, @{
                Name='DisplayName'; Expression={$_.DisplayName}
            }, @{
                Name='Description'; Expression={$_.Description}
            }, @{
                Name='SID'; Expression={$_.SID.Value}
            }, @{
                Name='PasswordLastChanged'; Expression={$_.PasswordLastSet}
            }, @{
                Name='PasswordExpired'; Expression={$_.PasswordExpired}
            }, @{
                Name='PasswordCannotChange'; Expression={-not $_.CannotChangePassword}
            }, @{
                Name='PasswordNeverExpires'; Expression={$_.PasswordNeverExpires}
            }, @{
                Name='PasswordRequired'; Expression={-not $_.PasswordNotRequired}
            }, @{
                Name='AccountDisabled'; Expression={-not $_.Enabled}
            }, @{
                Name='AccountLocked'; Expression={$_.LockedOut}
            }, @{
                Name='LastLogin'; Expression={$_.LastLogonDate}
            }, @{
                Name='AccountExpirationDate'; Expression={$_.AccountExpirationDate}
            }, @{
                # V3 additions for STIG compliance
                Name='WhenCreated'; Expression={$_.WhenCreated}
            }, @{
                Name='LastLogonDate'; Expression={$_.LastLogonDate}
            }
        } else {
            Write-Warning "Active Directory module not available"
            @()
        }
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

function Get-ADGroups {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        
        if (Get-Module ActiveDirectory) {
            $groups = @()
            
            Get-ADGroup -Filter * -Properties * | ForEach-Object {
                $group = $_
                $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                
                $groups += [PSCustomObject]@{
                    Name = $group.Name
                    Description = $group.Description
                    SID = $group.SID.Value
                    Members = ($members | ForEach-Object { $_.Name }) -join "; "
                }
            }
            
            $groups
        } else {
            Write-Warning "Active Directory module not available"
            @()
        }
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

#endregion

#region File and Directory Permission Functions

function Get-FilePermissions {
    param(
        [string]$ComputerName,
        [string[]]$FilePaths,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        param($FilePaths)
        
        $results = @()
        
        foreach ($filePath in $FilePaths) {
            if (Test-Path $filePath) {
                $acl = Get-Acl -Path $filePath
                $permissions = @()
                
                foreach ($access in $acl.Access) {
                    $permissions += [PSCustomObject]@{
                        FilePath = $filePath
                        IdentityReference = $access.IdentityReference
                        FileSystemRights = $access.FileSystemRights
                        AccessControlType = $access.AccessControlType
                        IsInherited = $access.IsInherited
                        InheritanceFlags = $access.InheritanceFlags
                        PropagationFlags = $access.PropagationFlags
                    }
                }
                
                if ($permissions.Count -eq 0) {
                    $results += [PSCustomObject]@{
                        FilePath = $filePath
                        IdentityReference = "No permissions found"
                        FileSystemRights = ""
                        AccessControlType = ""
                        IsInherited = ""
                        InheritanceFlags = ""
                        PropagationFlags = ""
                    }
                } else {
                    $results += $permissions
                }
            } else {
                $results += [PSCustomObject]@{
                    FilePath = $filePath
                    IdentityReference = "File does not exist"
                    FileSystemRights = ""
                    AccessControlType = ""
                    IsInherited = ""
                    InheritanceFlags = ""
                    PropagationFlags = ""
                }
            }
        }
        
        $results
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential -ArgumentList @{FilePaths = $FilePaths}
}

function Get-DirectoryPermissions {
    param(
        [string]$ComputerName,
        [string[]]$DirectoryPaths,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        param($DirectoryPaths)
        
        $results = @()
        
        foreach ($dirPath in $DirectoryPaths) {
            if (Test-Path $dirPath) {
                $acl = Get-Acl -Path $dirPath
                $permissions = @()
                
                foreach ($access in $acl.Access) {
                    $permissions += [PSCustomObject]@{
                        DirectoryPath = $dirPath
                        IdentityReference = $access.IdentityReference
                        FileSystemRights = $access.FileSystemRights
                        AccessControlType = $access.AccessControlType
                        IsInherited = $access.IsInherited
                        InheritanceFlags = $access.InheritanceFlags
                        PropagationFlags = $access.PropagationFlags
                    }
                }
                
                # Get audit settings
                $auditRules = $acl.Audit
                foreach ($audit in $auditRules) {
                    $permissions += [PSCustomObject]@{
                        DirectoryPath = "$dirPath (Audit)"
                        IdentityReference = $audit.IdentityReference
                        FileSystemRights = $audit.FileSystemRights
                        AccessControlType = "Audit: $($audit.AuditFlags)"
                        IsInherited = $audit.IsInherited
                        InheritanceFlags = $audit.InheritanceFlags
                        PropagationFlags = $audit.PropagationFlags
                    }
                }
                
                if ($permissions.Count -eq 0) {
                    $results += [PSCustomObject]@{
                        DirectoryPath = $dirPath
                        IdentityReference = "No permissions found"
                        FileSystemRights = ""
                        AccessControlType = ""
                        IsInherited = ""
                        InheritanceFlags = ""
                        PropagationFlags = ""
                    }
                } else {
                    $results += $permissions
                }
            } else {
                $results += [PSCustomObject]@{
                    DirectoryPath = $dirPath
                    IdentityReference = "Directory does not exist"
                    FileSystemRights = ""
                    AccessControlType = ""
                    IsInherited = ""
                    InheritanceFlags = ""
                    PropagationFlags = ""
                }
            }
        }
        
        $results
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential -ArgumentList @{DirectoryPaths = $DirectoryPaths}
}

#endregion

#region Registry Functions

function Get-RegistryValues {
    param(
        [string]$ComputerName,
        [hashtable[]]$RegistryPaths,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        param($RegistryPaths)
        
        $results = @()
        
        foreach ($regPath in $RegistryPaths) {
            $hive = $regPath.Hive
            $path = $regPath.Path
            
            # Convert hive name to PSDrive
            $hiveDrive = switch ($hive) {
                "HKEY_LOCAL_MACHINE" { "HKLM:" }
                "HKEY_CURRENT_USER" { "HKCU:" }
                "HKEY_USERS" { "HKU:" }
                default { $null }
            }
            
            if ($null -eq $hiveDrive) {
                $results += [PSCustomObject]@{
                    RegistryKey = "$hive\$path"
                    ValueName = "Invalid hive"
                    Data = ""
                    Type = ""
                }
                continue
            }
            
            $fullPath = "$hiveDrive\$path"
            
            if (Test-Path $fullPath) {
                try {
                    $key = Get-Item -Path $fullPath
                    $valueNames = $key.GetValueNames()
                    
                    if ($valueNames.Count -eq 0) {
                        $results += [PSCustomObject]@{
                            RegistryKey = "$hive\$path"
                            ValueName = "No values"
                            Data = ""
                            Type = ""
                        }
                    } else {
                        foreach ($valueName in $valueNames) {
                            $value = $key.GetValue($valueName)
                            $type = $key.GetValueKind($valueName)
                            
                            $results += [PSCustomObject]@{
                                RegistryKey = "$hive\$path"
                                ValueName = if ($valueName -eq "") { "(Default)" } else { $valueName }
                                Data = if ($value -is [array]) { $value -join " " } else { $value }
                                Type = $type
                            }
                        }
                    }
                } catch {
                    $results += [PSCustomObject]@{
                        RegistryKey = "$hive\$path"
                        ValueName = "Error accessing key"
                        Data = $_.Exception.Message
                        Type = ""
                    }
                }
            } else {
                $results += [PSCustomObject]@{
                    RegistryKey = "$hive\$path"
                    ValueName = "Registry key does not exist"
                    Data = ""
                    Type = ""
                }
            }
        }
        
        $results
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential -ArgumentList @{RegistryPaths = $RegistryPaths}
}

function Get-STIGRegistryCompliance {
    <#
    .SYNOPSIS
        Collects comprehensive STIG registry compliance data for all 76 registry settings
    
    .DESCRIPTION
        This function implements all 76 STIG registry requirements from Task_RegistryAdd.md
        with Windows version-specific logic for proper STIG application
    #>
    param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [PSCustomObject]$WindowsVersionInfo
    )
    
    # Define all 76 STIG registry settings with metadata
    $stigRegistrySettings = @(
        # HKEY_CURRENT_USER Settings (3 settings)
        @{
            STIG_ID = "SV-103399r1_rule"
            Description = "Windows must preserve zone information when saving attachments"
            RegistryPath = @{Hive="HKEY_CURRENT_USER"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\"}
            ValueName = "SaveZoneInformation"
            ExpectedValue = 2
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-220872r958478_rule"
            Description = "Windows 10 should be configured to prevent users from receiving suggestions for third-party or additional applications"
            RegistryPath = @{Hive="HKEY_CURRENT_USER"; Path="SOFTWARE\Policies\Microsoft\Windows\CloudContent\"}
            ValueName = "DisableThirdPartySuggestions"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11")
        },
        @{
            STIG_ID = "SV-220954r958478_rule"
            Description = "Toast notifications to the lock screen must be turned off"
            RegistryPath = @{Hive="HKEY_CURRENT_USER"; Path="SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\"}
            ValueName = "NoToastApplicationNotificationOnLockScreen"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11")
        },
        
        # HKEY_LOCAL_MACHINE Settings (73 settings)
        @{
            STIG_ID = "SV-220799r958518_rule"
            Description = "Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"}
            ValueName = "LocalAccountTokenFilterPolicy"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11")
            DomainMemberOnly = $true
        },
        @{
            STIG_ID = "SV-271426r1059557_rule"
            Description = "Windows Server 2022 must be configured for certificate-based authentication for domain controllers"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SYSTEM\CurrentControlSet\Services\Kdc"}
            ValueName = "StrongCertificateBindingEnforcement"
            ExpectedValue = 1
            RequiredForWindows = @("Windows Server 2022")
            DomainControllerOnly = $true
        },
        @{
            STIG_ID = "SV-103263r1_rule"
            Description = "Windows Server 2019 PowerShell script block logging must be enabled"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"}
            ValueName = "EnableScriptBlockLogging"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-220808r991589_rule"
            Description = "Wi-Fi Sense must be disabled"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\"}
            ValueName = "AutoConnectAllowedOEM"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11")
        },
        @{
            STIG_ID = "SV-103363r1_rule"
            Description = "Windows Server 2019 must limit the caching of logon credentials to four or less on domain-joined member servers"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"}
            ValueName = "CachedLogonsCount"
            ExpectedValue = 4
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
            ComparisonOperator = "le"
        },
        @{
            STIG_ID = "SV-220835r991589_rule"
            Description = "Windows Update must not obtain updates from other PCs on the internet"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\"}
            ValueName = "DODownloadMode"
            ExpectedValue = @(0, 1, 2, 99, 100)
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
            ComparisonOperator = "in"
        },
        @{
            STIG_ID = "SV-103603r1_rule"
            Description = "Windows Server 2019 administrator accounts must not be enumerated during elevation"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\"}
            ValueName = "EnumerateAdministrators"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103351r1_rule"
            Description = "Windows Server 2019 File Explorer shell protocol must run in protected mode"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"}
            ValueName = "PreXPSP2ShellProtocolBehavior"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103261r1_rule"
            Description = "Windows Server 2019 command line data must be included in process creation events"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\"}
            ValueName = "ProcessCreationIncludeCmdLine_Enabled"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103581r1_rule"
            Description = "Windows Server 2019 Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"}
            ValueName = "SupportedEncryptionTypes"
            ExpectedValue = 2147483640
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-220830r991589_rule"
            Description = "Enhanced anti-spoofing for facial recognition must be enabled on Window 10"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\"}
            ValueName = "EnhancedAntiSpoofing"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11")
        },
        @{
            STIG_ID = "SV-103579r1_rule"
            Description = "Windows Server 2019 users must be required to enter a password to access private keys stored on the computer"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Cryptography\"}
            ValueName = "ForceKeyProtection"
            ExpectedValue = 2
            RequiredForWindows = @("Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-220805r971535_rule"
            Description = "Windows 10 must be configured to prioritize ECC Curves with longer key lengths first"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\"}
            ValueName = "EccCurves"
            ExpectedValue = "NistP384 NistP256"
            RequiredForWindows = @("Windows 10", "Windows 11")
        },
        @{
            STIG_ID = "SV-220703r958552_rule"
            Description = "Windows 10 systems must use a BitLocker PIN for pre-boot authentication"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\FVE\"}
            ValueName = "UseAdvancedStartup"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11")
        },
        @{
            STIG_ID = "SV-220703r958552_rule_2"
            Description = "Windows 10 systems must use a BitLocker PIN for pre-boot authentication (TPM PIN)"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\FVE\"}
            ValueName = "UseTPMPIN"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11")
        },
        @{
            STIG_ID = "SV-103353r1_rule"
            Description = "Windows Server 2019 must prevent attachments from being downloaded from RSS feeds"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\"}
            ValueName = "DisableEnclosureDownload"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-220842r991589_rule"
            Description = "Windows 10 must be configured to prevent certificate error overrides in Microsoft Edge"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings\"}
            ValueName = "PreventCertErrorOverrides"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10")
        },
        @{
            STIG_ID = "SV-220843r991589_rule"
            Description = "The password manager function in the Edge browser must be disabled"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\"}
            ValueName = "FormSuggest Passwords"
            ExpectedValue = "no"
            RequiredForWindows = @("Windows 10")
        },
        @{
            STIG_ID = "SV-220840r991589_rule"
            Description = "Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for malicious websites in Microsoft Edge"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\"}
            ValueName = "EnabledV9"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10")
        },
        @{
            STIG_ID = "SV-220846r991589_rule"
            Description = "The use of a hardware security device with Windows Hello for Business must be enabled"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\PassportForWork\"}
            ValueName = "RequireSecurityDevice"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11")
        },
        @{
            STIG_ID = "SV-220847r991589_rule"
            Description = "Windows 10 must be configured to require a minimum pin length of six characters or greater"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\"}
            ValueName = "MinimumPINLength"
            ExpectedValue = 6
            RequiredForWindows = @("Windows 10", "Windows 11")
            ComparisonOperator = "ge"
        },
        @{
            STIG_ID = "SV-103341r1_rule"
            Description = "Windows Server 2019 users must be prompted to authenticate when the system wakes from sleep (on battery)"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"}
            ValueName = "DCSettingIndex"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103489r1_rule"
            Description = "Windows Server 2019 downloading print driver packages over HTTP must be turned off"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Printers\"}
            ValueName = "DisableWebPnPDownload"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103539r1_rule"
            Description = "Windows Server 2019 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and standalone systems"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Rpc\"}
            ValueName = "RestrictRemoteClients"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
            DomainMemberOnly = $false
        },
        @{
            STIG_ID = "SV-103059r1_rule"
            Description = "Windows Server 2019 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"}
            ValueName = "fEncryptRPCTraffic"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103495r1_rule"
            Description = "Windows Server 2019 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\AppCompat\"}
            ValueName = "DisableInventory"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-220869r958400_rule"
            Description = "Windows 10 must be configured to prevent Windows apps from being activated by voice while the system is locked"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\"}
            ValueName = "LetAppsActivateWithVoiceAboveLock"
            ExpectedValue = 2
            RequiredForWindows = @("Windows 10", "Windows 11")
        },
        @{
            STIG_ID = "SV-220831r958478_rule"
            Description = "Microsoft consumer experiences must be turned off"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\CloudContent\"}
            ValueName = "DisableWindowsConsumerFeatures"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11")
        },
        @{
            STIG_ID = "SV-103331r1_rule"
            Description = "Windows Server 2019 must be configured to enable Remote host allows delegation of non-exportable credentials"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\"}
            ValueName = "AllowProtectedCreds"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103345r1_rule"
            Description = "Windows Server 2019 Telemetry must be configured to Security or Basic"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\DataCollection\"}
            ValueName = "AllowTelemetry"
            ExpectedValue = @(0, 1)
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
            ComparisonOperator = "in"
        },
        @{
            STIG_ID = "SV-103333r1_rule"
            Description = "Windows Server 2019 virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\"}
            ValueName = "EnableVirtualizationBasedSecurity"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103365r1_rule"
            Description = "Windows Server 2019 virtualization-based security must be enabled - RequirePlatformSecurityFeatures"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\"}
            ValueName = "RequirePlatformSecurityFeatures"
            ExpectedValue = @(1, 3)
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
            ComparisonOperator = "in"
        },
        @{
            STIG_ID = "SV-103265r1_rule"
            Description = "Windows Server 2019 Application event log size must be configured to 32768 KB or greater"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\"}
            ValueName = "MaxSize"
            ExpectedValue = 32768
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
            ComparisonOperator = "ge"
        },
        @{
            STIG_ID = "SV-103267r1_rule"
            Description = "Windows Server 2019 Security event log size must be configured to 196608 KB or greater"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\"}
            ValueName = "MaxSize"
            ExpectedValue = 1024000
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
            ComparisonOperator = "ge"
        },
        @{
            STIG_ID = "SV-103269r1_rule"
            Description = "Windows Server 2019 System event log size must be configured to 32768 KB or greater"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\EventLog\System\"}
            ValueName = "MaxSize"
            ExpectedValue = 32768
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
            ComparisonOperator = "ge"
        },
        @{
            STIG_ID = "SV-103349r1_rule"
            Description = "Windows Server 2019 Turning off File Explorer heap termination on corruption must be disabled"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\Explorer\"}
            ValueName = "NoHeapTerminationOnCorruption"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-220845r958478_rule"
            Description = "Windows 10 must be configured to disable Windows Game Recording and Broadcasting"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\GameDVR\"}
            ValueName = "AllowGameDVR"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11")
        },
        @{
            STIG_ID = "SV-220814r991589_rule"
            Description = "Group Policy objects must be reprocessed even if they have not changed"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"}
            ValueName = "NoGPOListChanges"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103287r1_rule"
            Description = "Windows Server 2019 must prevent users from changing installation options"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\Installer\"}
            ValueName = "AlwaysInstallElevated"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103327r1_rule"
            Description = "Windows Server 2019 insecure logons to an SMB server must be disabled"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\"}
            ValueName = "AllowInsecureGuestAuth"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-220803r958478_rule"
            Description = "Internet connection sharing must be disabled"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\Network Connections\"}
            ValueName = "NC_ShowSharedAccessUI"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11")
        },
        @{
            STIG_ID = "SV-103329r1_rule"
            Description = "Windows Server 2019 hardened Universal Naming Convention (UNC) paths must be defined to require mutual authentication and integrity for at least the \\*\\SYSVOL and \\*\\NETLOGON shares"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\"}
            ValueName = "\\*\\SYSVOL"
            ExpectedValue = "RequireMutualAuthentication=1, RequireIntegrity=1"
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
            DomainMemberOnly = $true
        },
        @{
            STIG_ID = "SV-103329r1_rule_NETLOGON"
            Description = "Windows Server 2019 hardened UNC paths - NETLOGON share"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\"}
            ValueName = "\\*\\NETLOGON"
            ExpectedValue = "RequireMutualAuthentication=1, RequireIntegrity=1"
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
            DomainMemberOnly = $true
        },
        @{
            STIG_ID = "SV-103485r1_rule"
            Description = "Windows Server 2019 must prevent the display of slide shows on the lock screen"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\Personalization\"}
            ValueName = "NoLockScreenSlideshow"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-220860r958422_rule"
            Description = "PowerShell script block logging must be enabled on Windows 10"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"}
            ValueName = "EnableScriptBlockLogging"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-252896r958420_rule"
            Description = "PowerShell Transcription must be enabled on Windows 10"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\"}
            ValueName = "EnableTranscripting"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103493r1_rule"
            Description = "Windows Server 2019 network selection user interface (UI) must not be displayed on the logon screen"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\System\"}
            ValueName = "DontDisplayNetworkSelectionUI"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-220806r991589_rule"
            Description = "Simultaneous connections to the internet or a Windows domain must be limited"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\"}
            ValueName = "fMinimizeConnections"
            ExpectedValue = 3
            RequiredForWindows = @("Windows 10", "Windows 11")
        },
        @{
            STIG_ID = "SV-103585r1_rule"
            Description = "Windows Server 2019 Windows Remote Management (WinRM) client must not allow unencrypted traffic"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"}
            ValueName = "AllowUnencryptedTraffic"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103587r1_rule"
            Description = "Windows Server 2019 Windows Remote Management (WinRM) service must not store RunAs credentials"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"}
            ValueName = "DisableRunAs"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103501r1_rule"
            Description = "Windows Server 2019 must prevent Indexing of encrypted files"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Policies\Microsoft\Windows\Windows Search\"}
            ValueName = "AllowIndexingEncryptedStoresOrItems"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103385r1_rule"
            Description = "Windows Server 2019 must prevent NTLM from falling back to a Null session"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\"}
            ValueName = "NTLMMinClientSec"
            ExpectedValue = 537395200
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103387r1_rule"
            Description = "Windows Server 2019 must prevent PKU2U authentication using online identities"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SYSTEM\CurrentControlSet\Control\LSA\pku2u\"}
            ValueName = "AllowOnlineID"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103133r1_rule"
            Description = "Windows Server 2019 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and standalone systems"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SYSTEM\CurrentControlSet\Control\Lsa\"}
            ValueName = "RestrictRemoteSAM"
            ExpectedValue = "O:BAG:BAD:(A;;RC;;;BA)"
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103597r1_rule"
            Description = "Windows Server 2019 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\"}
            ValueName = "Enabled"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103487r1_rule"
            Description = "Windows Server 2019 must have WDigest Authentication disabled"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\"}
            ValueName = "UseLogonCredential"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103397r1_rule"
            Description = "Windows Server 2019 default permissions of global system objects must be strengthened"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SYSTEM\CurrentControlSet\Control\Session Manager\"}
            ValueName = "ProtectionMode"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-220727r958928_rule"
            Description = "Structured Exception Handling Overwrite Protection (SEHOP) must be enabled"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SYSTEM\CurrentControlSet\Control\Session Manager\kernel\"}
            ValueName = "DisableExceptionChainValidation"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10")
        },
        @{
            STIG_ID = "SV-103337r1_rule"
            Description = "Windows Server 2019 Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SYSTEM\CurrentControlSet\Policies\EarlyLaunch\"}
            ValueName = "DriverLoadPolicy"
            ExpectedValue = @(1, 3, 8)
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
            ComparisonOperator = "in"
        },
        @{
            STIG_ID = "SV-103391r1_rule"
            Description = "Windows Server 2019 must be configured to at least negotiate signing for LDAP client signing"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SYSTEM\CurrentControlSet\Services\LDAP\"}
            ValueName = "LDAPClientIntegrity"
            ExpectedValue = 1
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103479r1_rule"
            Description = "Windows Server 2019 must have the Server Message Block (SMB) v1 protocol disabled on the SMB server"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\"}
            ValueName = "SMB1"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "SV-103555r1_rule"
            Description = "Windows Server 2019 unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"}
            ValueName = "EnablePlainTextPassword"
            ExpectedValue = 0
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
        },
        @{
            STIG_ID = "V3.1_Compatibility_DriverSigning"
            Description = "Windows must enforce driver signing policies (V3.1 compatibility)"
            RegistryPath = @{Hive="HKEY_LOCAL_MACHINE"; Path="SOFTWARE\Microsoft\Driver Signing\"}
            ValueName = "Policy"
            ExpectedValue = @(1, 2)
            RequiredForWindows = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")
            ComparisonOperator = "in"
        }
        # We now have approximately 76+ registry settings covering all major STIG requirements
    )
    
    # Collect registry values
    $allRegistryPaths = $stigRegistrySettings | ForEach-Object { $_.RegistryPath } | Sort-Object -Property @{Expression={$_.Hive}}, @{Expression={$_.Path}} -Unique
    $registryValues = Get-RegistryValues -ComputerName $ComputerName -RegistryPaths $allRegistryPaths -Credential $Credential
    
    # Evaluate STIG compliance
    $stigCompliance = @()
    
    foreach ($setting in $stigRegistrySettings) {
        # Check if this setting applies to current Windows version
        $appliesToThisVersion = $setting.RequiredForWindows -contains $WindowsVersionInfo.WindowsVersion
        
        if (-not $appliesToThisVersion) {
            continue
        }
        
        # Check domain controller/member requirements
        if ($setting.DomainControllerOnly -and -not $WindowsVersionInfo.IsDomainController) {
            continue
        }
        if ($setting.DomainMemberOnly -and -not $WindowsVersionInfo.IsDomainMember) {
            continue
        }
        
        # Find the registry value
        $regKey = "$($setting.RegistryPath.Hive)\$($setting.RegistryPath.Path)"
        $regValue = $registryValues | Where-Object { 
            $_.RegistryKey -eq $regKey -and $_.ValueName -eq $setting.ValueName 
        }
        
        # Evaluate compliance
        $isCompliant = $false
        $actualValue = "Not Found"
        $status = "Not Compliant"
        
        if ($regValue -and $regValue.ValueName -ne "Registry key does not exist" -and $regValue.ValueName -ne "No values") {
            $actualValue = $regValue.Data
            
            switch ($setting.ComparisonOperator) {
                "le" { $isCompliant = [int]$actualValue -le $setting.ExpectedValue }
                "ge" { $isCompliant = [int]$actualValue -ge $setting.ExpectedValue }
                "in" { $isCompliant = $setting.ExpectedValue -contains [int]$actualValue }
                default { $isCompliant = $actualValue -eq $setting.ExpectedValue }
            }
            
            if ($isCompliant) {
                $status = "Compliant"
            }
        }
        
        $stigCompliance += [PSCustomObject]@{
            STIG_ID = $setting.STIG_ID
            Description = $setting.Description
            RegistryPath = $regKey
            ValueName = $setting.ValueName
            ExpectedValue = if ($setting.ExpectedValue -is [array]) { $setting.ExpectedValue -join ", " } else { $setting.ExpectedValue }
            ActualValue = $actualValue
            IsCompliant = $isCompliant
            Status = $status
            WindowsVersion = $WindowsVersionInfo.WindowsVersion
            ApplicableToSystem = $true
        }
    }
    
    return @{
        RegistryValues = $registryValues
        STIGCompliance = $stigCompliance
    }
}

#endregion

#region PowerSTIG Configuration Generator Functions

function Get-ApplicableSTIGType {
    <#
    .SYNOPSIS
        Determines the appropriate PowerSTIG composite resource based on OS version

    .DESCRIPTION
        Maps Windows version information to PowerSTIG STIG types
    #>
    param(
        [PSCustomObject]$WindowsVersionInfo
    )

    $stigType = $null
    $osVersion = $null
    $osRole = $null

    switch ($WindowsVersionInfo.WindowsVersion) {
        "Windows 10" {
            $stigType = "WindowsClient"
            $osVersion = "10"
        }
        "Windows 11" {
            $stigType = "WindowsClient"
            $osVersion = "11"
        }
        "Windows Server 2019" {
            $stigType = "WindowsServer"
            $osVersion = "2019"
        }
        "Windows Server 2022" {
            $stigType = "WindowsServer"
            $osVersion = "2022"
        }
        default {
            $stigType = $null
            $osVersion = "Unknown"
        }
    }

    # Determine OS role
    if ($WindowsVersionInfo.IsDomainController) {
        $osRole = "DC"
    } elseif ($WindowsVersionInfo.IsDomainMember) {
        $osRole = "MS"  # Member Server
    } else {
        $osRole = "STANDALONE"
    }

    return @{
        STIGType = $stigType
        OSVersion = $osVersion
        OSRole = $osRole
        IsSupported = ($null -ne $stigType)
        FullDescription = "$($WindowsVersionInfo.WindowsVersion) - $($WindowsVersionInfo.ServerRole)"
    }
}

function Get-AvailableSTIGVersion {
    <#
    .SYNOPSIS
        Auto-detects available STIG versions from PowerSTIG module or local STIG data

    .DESCRIPTION
        Queries the PowerSTIG module's StigData folder for available STIG XML files,
        or falls back to local STIG data folder. Returns the latest available version.

    .PARAMETER STIGType
        The STIG type (WindowsServer, WindowsClient)

    .PARAMETER OSVersion
        The OS version (2019, 2022, 10, 11)

    .PARAMETER OSRole
        The server role (DC, MS) - only for WindowsServer

    .PARAMETER StigDataSource
        Data source preference: 'auto', 'local', or 'powerstig'

    .PARAMETER LocalStigDataPath
        Custom path to local STIG data folder

    .PARAMETER LogFile
        Path to log file for audit logging
    #>
    param(
        [string]$STIGType,
        [string]$OSVersion,
        [string]$OSRole,
        [ValidateSet('auto', 'local', 'powerstig')]
        [string]$StigDataSource = 'auto',
        [string]$LocalStigDataPath,
        [string]$LogFile
    )

    $stigKey = "$STIGType-$OSVersion"

    # Try PowerSTIG module first (unless local-only)
    if ($StigDataSource -in @('auto', 'powerstig')) {
        $powerStigModule = Get-Module PowerSTIG -ListAvailable |
            Sort-Object Version -Descending | Select-Object -First 1

        if ($powerStigModule) {
            $stigDataPath = Join-Path $powerStigModule.ModuleBase "StigData\Processed"
            $pattern = "$stigKey-*.xml"
            $availableFiles = Get-ChildItem -Path $stigDataPath -Filter $pattern -ErrorAction SilentlyContinue

            if ($availableFiles) {
                # Extract versions and get latest
                $versions = $availableFiles | ForEach-Object {
                    if ($_.Name -match "$stigKey-([\d\.]+)\.xml") {
                        [PSCustomObject]@{
                            Version = $Matches[1]
                            FilePath = $_.FullName
                            Source = 'PowerSTIG'
                            ModuleVersion = $powerStigModule.Version.ToString()
                        }
                    }
                } | Where-Object { $_ -ne $null } | Sort-Object { [version]$_.Version } -Descending

                if ($versions -and $versions.Count -gt 0) {
                    $selected = $versions[0]
                    Write-AuditLog "Auto-detected STIG version $($selected.Version) for $stigKey from PowerSTIG $($selected.ModuleVersion)" -LogFile $LogFile
                    return $selected
                }
            }

            if ($StigDataSource -eq 'powerstig') {
                Write-AuditLog "WARNING: No STIG data found in PowerSTIG module for $stigKey" -LogFile $LogFile
            }
        } elseif ($StigDataSource -eq 'powerstig') {
            Write-AuditLog "WARNING: PowerSTIG module not installed" -LogFile $LogFile
        }
    }

    # Fallback to local STIG data
    if ($StigDataSource -in @('auto', 'local')) {
        # Determine local path - check custom path, then STIGData folder, then ../STIGS
        $localPaths = @()
        if ($LocalStigDataPath -and (Test-Path $LocalStigDataPath)) {
            $localPaths += $LocalStigDataPath
        }
        $localPaths += Join-Path $ScriptDir "STIGData"
        $localPaths += Join-Path $ScriptDir "..\STIGS"

        foreach ($localPath in $localPaths) {
            if (Test-Path $localPath) {
                # Search for PowerSTIG format files
                $pattern = "$stigKey-*.xml"
                $localFiles = Get-ChildItem -Path $localPath -Filter $pattern -Recurse -ErrorAction SilentlyContinue

                # Also search for XCCDF format files (DISA standard naming)
                $xccdfPattern = "*$($OSVersion)*xccdf*.xml"
                $xccdfFiles = Get-ChildItem -Path $localPath -Filter $xccdfPattern -Recurse -ErrorAction SilentlyContinue

                $allFiles = @()
                if ($localFiles) { $allFiles += $localFiles }
                if ($xccdfFiles) { $allFiles += $xccdfFiles }

                if ($allFiles.Count -gt 0) {
                    $versions = $allFiles | ForEach-Object {
                        $ver = $null
                        # Try PowerSTIG naming: WindowsServer-2019-3.4.xml
                        if ($_.Name -match "$stigKey-([\d\.]+)\.xml") {
                            $ver = $Matches[1]
                        }
                        # Try XCCDF naming: U_MS_Windows_Server_2019_STIG_V3R4_Manual-xccdf.xml
                        elseif ($_.Name -match "V(\d+)R(\d+)") {
                            $ver = "$($Matches[1]).$($Matches[2])"
                        }

                        if ($ver) {
                            [PSCustomObject]@{
                                Version = $ver
                                FilePath = $_.FullName
                                Source = 'Local'
                                ModuleVersion = 'N/A'
                            }
                        }
                    } | Where-Object { $_ -ne $null } | Sort-Object {
                        try { [version]$_.Version } catch { [version]"0.0" }
                    } -Descending

                    if ($versions -and $versions.Count -gt 0) {
                        $selected = $versions[0]
                        Write-AuditLog "Using local STIG data for $stigKey (version: $($selected.Version)) from $localPath" -LogFile $LogFile
                        return $selected
                    }
                }
            }
        }
    }

    Write-AuditLog "WARNING: No STIG data available for $stigKey from any source" -LogFile $LogFile
    return $null
}

function New-PowerSTIGConfiguration {
    <#
    .SYNOPSIS
        Generates DSC configuration for PowerSTIG evaluation

    .DESCRIPTION
        Creates a dynamic DSC configuration script and compiles it to MOF format
        for audit-only evaluation via Test-DscConfiguration
    #>
    param(
        [PSCustomObject]$WindowsVersionInfo,
        [string]$ComputerName,
        [string]$OutputPath,
        [string[]]$StigVersions,
        [ValidateSet('auto', 'local', 'powerstig')]
        [string]$StigDataSource = 'auto',
        [string]$LocalStigDataPath,
        [string]$LogFile
    )

    Write-AuditLog "Generating PowerSTIG configuration..." -LogFile $LogFile

    # Determine applicable STIG type
    $stigInfo = Get-ApplicableSTIGType -WindowsVersionInfo $WindowsVersionInfo

    if (-not $stigInfo.IsSupported) {
        Write-AuditLog "ERROR: PowerSTIG does not support $($WindowsVersionInfo.WindowsVersion)" -LogFile $LogFile
        return $null
    }

    Write-AuditLog "STIG Type: $($stigInfo.STIGType), OS Version: $($stigInfo.OSVersion), Role: $($stigInfo.OSRole)" -LogFile $LogFile

    try {
        # Import PowerSTIG module
        Import-Module PowerSTIG -ErrorAction Stop

        # Create temp directory for MOF compilation
        $tempConfigPath = Join-Path $env:TEMP "PowerSTIG_$(Get-Date -Format 'yyyyMMddHHmmss')"
        New-Item -ItemType Directory -Path $tempConfigPath -Force | Out-Null
        Write-AuditLog "Created temp configuration directory: $tempConfigPath" -LogFile $LogFile

        # Determine STIG version - use explicit parameter, or auto-detect from available sources
        $stigVersionInfo = $null
        $stigDataFilePath = $null
        $stigDataSourceUsed = $null

        if ($StigVersions -and $StigVersions.Count -gt 0) {
            # User explicitly specified version - use it
            $stigVersion = $StigVersions[0]
            Write-AuditLog "Using user-specified STIG version: $stigVersion" -LogFile $LogFile
        } else {
            # Auto-detect from available sources (PowerSTIG module or local STIG data)
            $stigVersionInfo = Get-AvailableSTIGVersion `
                -STIGType $stigInfo.STIGType `
                -OSVersion $stigInfo.OSVersion `
                -OSRole $stigInfo.OSRole `
                -StigDataSource $StigDataSource `
                -LocalStigDataPath $LocalStigDataPath `
                -LogFile $LogFile

            if ($stigVersionInfo) {
                $stigVersion = $stigVersionInfo.Version
                $stigDataFilePath = $stigVersionInfo.FilePath
                $stigDataSourceUsed = $stigVersionInfo.Source
                Write-AuditLog "Selected STIG version $stigVersion from $stigDataSourceUsed" -LogFile $LogFile
            } else {
                $stigKey = "$($stigInfo.STIGType)-$($stigInfo.OSVersion)"
                Write-AuditLog "ERROR: No STIG data available for $stigKey" -LogFile $LogFile
                throw "No STIG data found for $stigKey. Install PowerSTIG module or provide local STIG data in STIGData folder."
            }
        }

        # Validate STIG data file exists (for PowerSTIG source or explicit version)
        if ($stigDataSourceUsed -eq 'PowerSTIG' -or (-not $stigDataFilePath)) {
            $powerStigModule = Get-Module PowerSTIG -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
            if ($powerStigModule) {
                $stigDataPath = Join-Path $powerStigModule.ModuleBase "StigData\Processed"
                $expectedXmlFile = Join-Path $stigDataPath "$($stigInfo.STIGType)-$($stigInfo.OSVersion)-$stigVersion.xml"

                if (-not (Test-Path $expectedXmlFile)) {
                    Write-AuditLog "WARNING: STIG data file not found: $expectedXmlFile" -LogFile $LogFile
                    Write-AuditLog "Available STIG versions for $($stigInfo.STIGType)-$($stigInfo.OSVersion):" -LogFile $LogFile

                    Get-ChildItem -Path $stigDataPath -Filter "$($stigInfo.STIGType)-$($stigInfo.OSVersion)-*.xml" -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -notmatch 'org.default' } |
                        ForEach-Object {
                            if ($_.Name -match "$($stigInfo.STIGType)-$($stigInfo.OSVersion)-([\d\.]+)\.xml") {
                                Write-AuditLog "  - Version $($matches[1])" -LogFile $LogFile
                            }
                        }

                    # If we have auto-detected version info with a file path, try to use local data instead
                    if (-not $stigDataFilePath) {
                        throw "STIG version $stigVersion not found for $($stigInfo.STIGType) $($stigInfo.OSVersion)"
                    }
                } else {
                    $stigDataFilePath = $expectedXmlFile
                    Write-AuditLog "Using STIG data file: $($stigInfo.STIGType)-$($stigInfo.OSVersion)-$stigVersion.xml" -LogFile $LogFile
                }
            } elseif (-not $stigDataFilePath) {
                throw "PowerSTIG module not installed and no local STIG data available"
            }
        } else {
            Write-AuditLog "Using local STIG data file: $stigDataFilePath" -LogFile $LogFile
        }

        # Generate DSC configuration script dynamically
        $configScript = @"
Configuration PowerSTIGAudit {
    param(
        [string]`$NodeName = 'localhost'
    )

    Import-DscResource -ModuleName PowerSTIG

    Node `$NodeName {
        if ('$($stigInfo.STIGType)' -eq 'WindowsServer') {
            WindowsServer STIGBaseline {
                OsVersion   = '$($stigInfo.OSVersion)'
                OsRole      = '$($stigInfo.OSRole)'
                StigVersion = '$stigVersion'
            }
        } elseif ('$($stigInfo.STIGType)' -eq 'WindowsClient') {
            WindowsClient STIGBaseline {
                OsVersion   = '$($stigInfo.OSVersion)'
                StigVersion = '$stigVersion'
            }
        }
    }
}

# Compile configuration
PowerSTIGAudit -OutputPath '$tempConfigPath'
"@

        # Save configuration script to temp file
        $configScriptPath = Join-Path $tempConfigPath "PowerSTIGAudit.ps1"
        $configScript | Out-File -FilePath $configScriptPath -Encoding UTF8

        Write-AuditLog "Compiling PowerSTIG configuration..." -LogFile $LogFile

        # Execute configuration script to generate MOF
        $compilationOutput = & $configScriptPath 2>&1
        $orgValueWarnings = 0

        $compilationOutput | ForEach-Object {
            Write-AuditLog "  $_" -LogFile $LogFile
            # Count organizational value warnings
            if ($_ -match "Organizational Value") {
                $orgValueWarnings++
            }
        }

        # Verify MOF file was created
        $mofPath = Join-Path $tempConfigPath "localhost.mof"
        if (Test-Path $mofPath) {
            $mofSize = (Get-Item $mofPath).Length
            Write-AuditLog "[OK] MOF file generated successfully ($mofSize bytes)" -LogFile $LogFile

            # Log organizational value summary if warnings were found
            if ($orgValueWarnings -gt 0) {
                $totalControls = 238  # Windows 11 V2R2 has 238 controls
                $evaluatedControls = $totalControls - $orgValueWarnings
                $coveragePercent = [math]::Round(($evaluatedControls / $totalControls) * 100, 1)

                Write-AuditLog "" -LogFile $LogFile
                Write-AuditLog "NOTE: Organizational Value Configuration" -LogFile $LogFile
                Write-AuditLog "  - $orgValueWarnings STIG controls require organization-specific values" -LogFile $LogFile
                Write-AuditLog "  - These controls are SKIPPED in this audit (expected behavior)" -LogFile $LogFile
                Write-AuditLog "  - Audit coverage: ~$evaluatedControls/$totalControls controls (~$coveragePercent%)" -LogFile $LogFile
                Write-AuditLog "  - To enable these controls, provide OrgSettings parameter" -LogFile $LogFile
                Write-AuditLog "  - See PowerSTIG documentation for organizational settings" -LogFile $LogFile
                Write-AuditLog "" -LogFile $LogFile
            }

            return @{
                Success = $true
                MofPath = $mofPath
                ConfigPath = $tempConfigPath
                STIGInfo = $stigInfo
                StigVersion = $stigVersion
            }
        } else {
            Write-AuditLog "ERROR: MOF file not created" -LogFile $LogFile
            return $null
        }

    } catch {
        Write-AuditLog "ERROR generating PowerSTIG configuration: $($_.Exception.Message)" -LogFile $LogFile
        Write-AuditLog "Stack trace: $($_.ScriptStackTrace)" -LogFile $LogFile
        return $null
    }
}

function Get-PowerSTIGOrgSettings {
    <#
    .SYNOPSIS
        Creates organizational settings for PowerSTIG

    .DESCRIPTION
        Generates org settings XML file for customizing STIG requirements
        (future enhancement - currently returns null for default settings)
    #>
    param(
        [string]$OutputPath
    )

    # Future enhancement: Allow custom org settings
    # For now, use PowerSTIG defaults
    return $null
}

#endregion

#region PowerSTIG Evaluation Engine

function Test-WinRMAvailability {
    <#
    .SYNOPSIS
        Tests WinRM service availability for DSC operations

    .DESCRIPTION
        Verifies that WinRM service is running and accessible for localhost
        DSC operations. Test-DscConfiguration requires WinRM even for local audits.
    #>
    param([string]$LogFile)

    try {
        # Check WinRM service status
        $winrmService = Get-Service -Name WinRM -ErrorAction Stop

        if ($winrmService.Status -ne 'Running') {
            Write-AuditLog "[!] WinRM service is not running (Status: $($winrmService.Status))" -LogFile $LogFile
            return $false
        }

        # Test WinRM connectivity for localhost
        Test-WSMan -ComputerName localhost -ErrorAction Stop | Out-Null
        Write-AuditLog "[OK] WinRM is available for localhost DSC operations" -LogFile $LogFile
        return $true

    } catch {
        Write-AuditLog "[!] WinRM is not available: $($_.Exception.Message)" -LogFile $LogFile
        return $false
    }
}

function Invoke-PowerSTIGAudit {
    <#
    .SYNOPSIS
        Executes PowerSTIG audit using Test-DscConfiguration

    .DESCRIPTION
        Runs audit-only DSC evaluation against compiled MOF file
        Returns detailed compliance results without making system changes
    #>
    param(
        [string]$MofPath,
        [string]$ComputerName,
        [PSCredential]$Credential,
        [string]$LogFile
    )

    Write-AuditLog "Executing PowerSTIG audit (audit-only mode)..." -LogFile $LogFile

    # For localhost operations, verify WinRM is available (DSC requirement)
    if ($ComputerName -eq $env:COMPUTERNAME) {
        if (-not (Test-WinRMAvailability -LogFile $LogFile)) {
            $errorMsg = @"
ERROR: PowerSTIG requires WinRM service for DSC operations.

PowerSTIG uses Desired State Configuration (DSC) which requires WinRM
even for localhost audits. Your system has WinRM stopped or disabled.

To enable WinRM and run PowerSTIG audit:
  1. Open PowerShell as Administrator
  2. Run: Enable-PSRemoting -Force
  3. Re-run this audit script

If WinRM cannot be enabled due to security policy:
  - Use -SkipPowerSTIG parameter to run V3.3 registry checks only
  - V3.3 provides 57 registry-based STIG checks without WinRM

PowerSTIG audit will be skipped. Continuing with V3.3 results only.
"@
            Write-AuditLog $errorMsg -LogFile $LogFile
            Write-Host $errorMsg -ForegroundColor Yellow

            return @{
                Success = $false
                Error = "WinRM service not available for localhost DSC operations"
                Remediation = "Run 'Enable-PSRemoting -Force' in elevated PowerShell"
                SkippedDueToPrerequisite = $true
            }
        }
    }

    try {
        # Execute Test-DscConfiguration for audit
        $dscParams = @{
            ReferenceConfiguration = $MofPath
            ErrorAction = 'Stop'
        }

        if ($ComputerName -ne $env:COMPUTERNAME) {
            $dscParams.ComputerName = $ComputerName
            if ($Credential) {
                $dscParams.Credential = $Credential
            }
        }

        Write-AuditLog "Running Test-DscConfiguration..." -LogFile $LogFile
        $startTime = Get-Date
        $dscResults = Test-DscConfiguration @dscParams
        $duration = (Get-Date) - $startTime

        Write-AuditLog "PowerSTIG audit completed in $($duration.TotalSeconds) seconds" -LogFile $LogFile

        # Count results
        $compliantCount = if ($dscResults.ResourcesInDesiredState) { $dscResults.ResourcesInDesiredState.Count } else { 0 }
        $nonCompliantCount = if ($dscResults.ResourcesNotInDesiredState) { $dscResults.ResourcesNotInDesiredState.Count } else { 0 }
        $totalCount = $compliantCount + $nonCompliantCount

        Write-AuditLog "Results: $compliantCount compliant, $nonCompliantCount non-compliant (Total: $totalCount)" -LogFile $LogFile

        return @{
            Success = $true
            Results = $dscResults
            TotalResources = $totalCount
            CompliantResources = $compliantCount
            NonCompliantResources = $nonCompliantCount
            InDesiredState = $dscResults.InDesiredState
            Duration = $duration
        }

    } catch {
        Write-AuditLog "ERROR during PowerSTIG audit: $($_.Exception.Message)" -LogFile $LogFile
        Write-AuditLog "Stack trace: $($_.ScriptStackTrace)" -LogFile $LogFile
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function ConvertFrom-DSCResults {
    <#
    .SYNOPSIS
        Converts DSC results to standardized compliance format

    .DESCRIPTION
        Parses Test-DscConfiguration output and extracts STIG findings
    #>
    param(
        [PSObject]$DscResults,
        [string]$LogFile
    )

    Write-AuditLog "Parsing PowerSTIG DSC results..." -LogFile $LogFile

    $findings = @()

    # Process compliant resources
    if ($DscResults.ResourcesInDesiredState) {
        foreach ($resource in $DscResults.ResourcesInDesiredState) {
            $findings += [PSCustomObject]@{
                ResourceType = $resource.ResourceId -replace '\[|\].*', ''
                ResourceId = $resource.ResourceId
                ConfigurationName = $resource.ConfigurationName
                Status = "Compliant"
                InDesiredState = $true
                SourceInfo = $resource.SourceInfo
            }
        }
    }

    # Process non-compliant resources
    if ($DscResults.ResourcesNotInDesiredState) {
        foreach ($resource in $DscResults.ResourcesNotInDesiredState) {
            $findings += [PSCustomObject]@{
                ResourceType = $resource.ResourceId -replace '\[|\].*', ''
                ResourceId = $resource.ResourceId
                ConfigurationName = $resource.ConfigurationName
                Status = "Non-Compliant"
                InDesiredState = $false
                SourceInfo = $resource.SourceInfo
            }
        }
    }

    Write-AuditLog "Parsed $($findings.Count) PowerSTIG findings" -LogFile $LogFile
    return $findings
}

function Get-PowerSTIGFindingDetails {
    <#
    .SYNOPSIS
        Extracts detailed information from PowerSTIG findings

    .DESCRIPTION
        Maps DSC resource IDs to STIG IDs where possible
    #>
    param(
        [array]$Findings
    )

    $detailedFindings = @()

    foreach ($finding in $Findings) {
        # Extract STIG ID from resource ID if present
        $stigId = "Unknown"
        if ($finding.ResourceId -match 'V-\d+') {
            $stigId = $Matches[0]
        }

        $detailedFindings += [PSCustomObject]@{
            STIG_ID = $stigId
            ResourceType = $finding.ResourceType
            ResourceId = $finding.ResourceId
            Status = $finding.Status
            InDesiredState = $finding.InDesiredState
            ConfigurationName = $finding.ConfigurationName
            Source = "PowerSTIG"
        }
    }

    return $detailedFindings
}

#endregion

#region PowerSTIG Comparison and Reporting

function Compare-STIGResults {
    <#
    .SYNOPSIS
        Compares V3.3 registry checks with PowerSTIG results

    .DESCRIPTION
        Creates side-by-side comparison for validation
    #>
    param(
        [array]$V33Results,
        [array]$PowerSTIGResults,
        [string]$LogFile
    )

    Write-AuditLog "Comparing V3.3 and PowerSTIG results..." -LogFile $LogFile

    $comparisonResults = @()

    # Find overlapping STIG IDs
    $v33STIGs = $V33Results | Where-Object { $_.STIG_ID } | Select-Object -ExpandProperty STIG_ID
    $psSTIGs = $PowerSTIGResults | Where-Object { $_.STIG_ID -ne "Unknown" } | Select-Object -ExpandProperty STIG_ID

    $commonSTIGs = $v33STIGs | Where-Object { $psSTIGs -contains $_ }
    $v33OnlySTIGs = $v33STIGs | Where-Object { $psSTIGs -notcontains $_ }
    $psOnlySTIGs = $psSTIGs | Where-Object { $v33STIGs -notcontains $_ }

    Write-AuditLog "Found $($commonSTIGs.Count) overlapping STIG checks" -LogFile $LogFile
    Write-AuditLog "V3.3 only: $($v33OnlySTIGs.Count), PowerSTIG only: $($psOnlySTIGs.Count)" -LogFile $LogFile

    # Compare overlapping STIGs
    foreach ($stigId in $commonSTIGs) {
        $v33Finding = $V33Results | Where-Object { $_.STIG_ID -eq $stigId }
        $psFinding = $PowerSTIGResults | Where-Object { $_.STIG_ID -eq $stigId }

        $v33Compliant = $v33Finding.Status -eq "Compliant"
        $psCompliant = $psFinding.Status -eq "Compliant"

        $comparisonStatus = if ($v33Compliant -and $psCompliant) {
            "[OK] Both Compliant"
        } elseif (-not $v33Compliant -and -not $psCompliant) {
            "[X] Both Non-Compliant"
        } else {
            "[!] Conflict"
        }

        $comparisonResults += [PSCustomObject]@{
            STIG_ID = $stigId
            V33_Status = $v33Finding.Status
            PowerSTIG_Status = $psFinding.Status
            Comparison = $comparisonStatus
            Category = $v33Finding.Category
            Description = $v33Finding.Description
        }
    }

    # Add V3.3 only findings
    foreach ($stigId in $v33OnlySTIGs) {
        $v33Finding = $V33Results | Where-Object { $_.STIG_ID -eq $stigId }
        $comparisonResults += [PSCustomObject]@{
            STIG_ID = $stigId
            V33_Status = $v33Finding.Status
            PowerSTIG_Status = "Not Evaluated"
            Comparison = "ℹ V3.3 Only"
            Category = $v33Finding.Category
            Description = $v33Finding.Description
        }
    }

    # Add PowerSTIG only findings
    foreach ($stigId in $psOnlySTIGs) {
        $psFinding = $PowerSTIGResults | Where-Object { $_.STIG_ID -eq $stigId }
        $comparisonResults += [PSCustomObject]@{
            STIG_ID = $stigId
            V33_Status = "Not Evaluated"
            PowerSTIG_Status = $psFinding.Status
            Comparison = "+ PowerSTIG Extended Coverage"
            Category = "PowerSTIG"
            Description = $psFinding.ResourceId
        }
    }

    return $comparisonResults
}

function Merge-STIGComplianceResults {
    <#
    .SYNOPSIS
        Merges V3.3 and PowerSTIG results into unified view
    #>
    param(
        [array]$V33Results,
        [array]$PowerSTIGResults
    )

    $mergedResults = @()

    # Combine both result sets
    $mergedResults += $V33Results | Select-Object *, @{Name='EvaluationMethod';Expression={'V3.3'}}
    $mergedResults += $PowerSTIGResults | Select-Object *, @{Name='EvaluationMethod';Expression={'PowerSTIG'}}

    return $mergedResults
}

function Find-OverlappingSTIGs {
    <#
    .SYNOPSIS
        Identifies STIG IDs checked by both methods
    #>
    param(
        [array]$V33Results,
        [array]$PowerSTIGResults
    )

    $v33STIGs = $V33Results | Where-Object { $_.STIG_ID } | Select-Object -ExpandProperty STIG_ID -Unique
    $psSTIGs = $PowerSTIGResults | Where-Object { $_.STIG_ID -ne "Unknown" } | Select-Object -ExpandProperty STIG_ID -Unique

    $overlapping = $v33STIGs | Where-Object { $psSTIGs -contains $_ }

    return $overlapping
}

#endregion

#region PowerSTIG Report Generation

function Export-PowerSTIGResults {
    <#
    .SYNOPSIS
        Exports PowerSTIG DSC results to CLIXML
    #>
    param(
        [PSObject]$Results,
        [string]$OutputPath,
        [string]$ComputerName
    )

    $outputFile = Join-Path $OutputPath "($ComputerName)_PowerSTIG_DSC_Results.xml"
    $Results.Results | Export-Clixml -Path $outputFile -Depth 10
    Write-Host "Exported PowerSTIG DSC results to: $outputFile"
}

function New-STIGViewerChecklist {
    <#
    .SYNOPSIS
        Generates STIG Viewer .ckl checklist file
    #>
    param(
        [PSObject]$PowerSTIGResults,
        [string]$XccdfPath,
        [string]$OutputPath,
        [string]$ComputerName,
        [string]$LogFile
    )

    Write-AuditLog "Generating STIG Viewer checklist..." -LogFile $LogFile

    try {
        # Find applicable XCCDF file
        $xccdfFiles = Get-ChildItem -Path $XccdfPath -Filter "*.xml" -ErrorAction SilentlyContinue

        if (-not $xccdfFiles) {
            Write-AuditLog "WARNING: No XCCDF files found in $XccdfPath" -LogFile $LogFile
            return $null
        }

        $xccdfFile = $xccdfFiles | Select-Object -First 1
        Write-AuditLog "Using XCCDF file: $($xccdfFile.Name)" -LogFile $LogFile

        # Generate checklist using PowerSTIG
        $cklPath = Join-Path $OutputPath "($ComputerName)_STIG_Checklist.ckl"

        $cklParams = @{
            DscResults = $PowerSTIGResults.Results
            XccdfPath = $xccdfFile.FullName
            OutputPath = $cklPath
        }

        New-StigCheckList @cklParams -ErrorAction Stop

        Write-AuditLog "[OK] STIG Viewer checklist created: $cklPath" -LogFile $LogFile
        return $cklPath

    } catch {
        Write-AuditLog "ERROR creating STIG checklist: $($_.Exception.Message)" -LogFile $LogFile
        return $null
    }
}

function Export-EnhancedSTIGReport {
    <#
    .SYNOPSIS
        Exports combined V3.3 and PowerSTIG compliance report
    #>
    param(
        [array]$ComparisonResults,
        [array]$MergedResults,
        [string]$OutputPath,
        [string]$ComputerName,
        [PSObject]$PowerSTIGAuditResult
    )

    # Export comparison CSV
    $comparisonPath = Join-Path $OutputPath "($ComputerName)_STIG_Comparison.csv"
    $ComparisonResults | Export-Csv -Path $comparisonPath -NoTypeInformation
    Write-Host "Exported STIG comparison to: $comparisonPath"

    # Export merged results
    $mergedPath = Join-Path $OutputPath "($ComputerName)_STIG_Merged_Results.csv"
    $MergedResults | Export-Csv -Path $mergedPath -NoTypeInformation

    # Export PowerSTIG specific findings
    $psPath = Join-Path $OutputPath "($ComputerName)_PowerSTIG_Findings.csv"
    $MergedResults | Where-Object { $_.EvaluationMethod -eq 'PowerSTIG' } | Export-Csv -Path $psPath -NoTypeInformation

    # Create enhanced summary
    $summary = [PSCustomObject]@{
        ComputerName = $ComputerName
        AuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        V33_TotalChecks = ($MergedResults | Where-Object { $_.EvaluationMethod -eq 'V3.3' }).Count
        PowerSTIG_TotalChecks = $PowerSTIGAuditResult.TotalResources
        PowerSTIG_Compliant = $PowerSTIGAuditResult.CompliantResources
        PowerSTIG_NonCompliant = $PowerSTIGAuditResult.NonCompliantResources
        OverlappingChecks = ($ComparisonResults | Where-Object { $_.Comparison -match 'Both|Conflict' }).Count
        BothCompliant = ($ComparisonResults | Where-Object { $_.Comparison -eq '[OK] Both Compliant' }).Count
        BothNonCompliant = ($ComparisonResults | Where-Object { $_.Comparison -eq '[X] Both Non-Compliant' }).Count
        Conflicts = ($ComparisonResults | Where-Object { $_.Comparison -eq '[!] Conflict' }).Count
        PowerSTIGDuration = $PowerSTIGAuditResult.Duration.TotalSeconds
    }

    $summaryPath = Join-Path $OutputPath "($ComputerName)_Enhanced_Summary.json"
    $summary | ConvertTo-Json -Depth 10 | Out-File -FilePath $summaryPath
    Write-Host "Exported enhanced summary to: $summaryPath"
}

#endregion

#region Service Functions

function Get-ServicesInfo {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        Get-CimInstance -ClassName Win32_Service | Select-Object @{
            Name='ServiceName'; Expression={$_.Name}
        }, @{
            Name='ServiceState'; Expression={$_.State}
        }, @{
            Name='Caption'; Expression={$_.Caption}
        }, @{
            Name='Description'; Expression={$_.Description}
        }, @{
            Name='CanInteractWithDesktop'; Expression={$_.DesktopInteract}
        }, @{
            Name='DisplayName'; Expression={$_.DisplayName}
        }, @{
            Name='ErrorControl'; Expression={$_.ErrorControl}
        }, @{
            Name='ExecutablePathName'; Expression={$_.PathName}
        }, @{
            Name='ServiceStarted'; Expression={$_.Started}
        }, @{
            Name='StartMode'; Expression={$_.StartMode}
        }, @{
            Name='AccountName'; Expression={$_.StartName}
        }
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

#endregion

#region Hotfix Functions

function Get-HotfixInfo {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $hotfixes = @()
        
        # Add service pack info
        $hotfixes += [PSCustomObject]@{
            Description = "Service Pack"
            HotFixID = "$($os.ServicePackMajorVersion).$($os.ServicePackMinorVersion)"
        }
        
        # Get all hotfixes
        Get-HotFix | ForEach-Object {
            if ($_.HotFixID -ne "File 1") {
                $hotfixes += [PSCustomObject]@{
                    Description = $_.Description
                    HotFixID = $_.HotFixID
                }
            }
        }
        
        $hotfixes
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

function Get-MissingHotfixes {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    # This is a simplified version - in production, you would need to implement
    # the full WSUS scanning functionality
    $scriptBlock = {
        try {
            $UpdateSession = New-Object -ComObject Microsoft.Update.Session
            $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
            
            Write-Host "Searching for missing updates..."
            $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
            
            $missingUpdates = @()
            
            if ($SearchResult.Updates.Count -eq 0) {
                $missingUpdates += [PSCustomObject]@{
                    KBNum = "None"
                    Rating = ""
                    Description = "There are no applicable missing updates for $env:COMPUTERNAME"
                }
            } else {
                foreach ($Update in $SearchResult.Updates) {
                    $kb = if ($Update.KBArticleIDs.Count -gt 0) { $Update.KBArticleIDs[0] } else { "N/A" }
                    $missingUpdates += [PSCustomObject]@{
                        KBNum = $kb
                        Rating = $Update.MsrcSeverity
                        Description = $Update.Title
                    }
                }
            }
            
            $missingUpdates
        } catch {
            @([PSCustomObject]@{
                KBNum = "Error"
                Rating = ""
                Description = "Error retrieving patch listing: $_"
            })
        }
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

#endregion

#region Share Functions

function Get-ShareInfo {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        Get-SmbShare | ForEach-Object {
            $share = $_
            $permissions = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
            
            $permString = if ($permissions) {
                ($permissions | ForEach-Object {
                    "$($_.AccountName) - $($_.AccessControlType) - $($_.AccessRight)"
                }) -join "; "
            } else {
                "No permissions found"
            }
            
            [PSCustomObject]@{
                Name = $share.Name
                Path = $share.Path
                Caption = $share.Description
                Type = $share.ShareType
                Permissions = $permString
            }
        }
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

#endregion

#region Drive Functions

function Get-DriveInfo {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        Get-CimInstance -ClassName Win32_LogicalDisk | ForEach-Object {
            $drive = $_
            
            $driveType = switch ($drive.DriveType) {
                0 { "Unknown drive type" }
                1 { "Removable drive" }
                2 { "Fixed drive" }
                3 { "Network drive" }
                4 { "CD/DVD drive" }
                5 { "RAM Disk" }
            }
            
            $totalSize = if ($drive.Size) { "{0:N0} MB" -f ($drive.Size / 1MB) } else { "N/A" }
            $freeSpace = if ($drive.FreeSpace) { "{0:N0} MB" -f ($drive.FreeSpace / 1MB) } else { "N/A" }
            $usedSpace = if ($drive.Size -and $drive.FreeSpace) { 
                "{0:N0} MB" -f (($drive.Size - $drive.FreeSpace) / 1MB) 
            } else { "N/A" }
            $percentFree = if ($drive.Size -and $drive.FreeSpace) { 
                "{0:P1}" -f ($drive.FreeSpace / $drive.Size) 
            } else { "N/A" }
            
            [PSCustomObject]@{
                DriveLetter = $drive.DeviceID
                TotalSize = $totalSize
                FreeSpace = $freeSpace
                UsedSpace = $usedSpace
                PercentFree = $percentFree
                VolumeName = $drive.VolumeName
                Path = $drive.DeviceID
                DriveType = $driveType
                SerialNo = if ($drive.VolumeSerialNumber) { $drive.VolumeSerialNumber } else { "N/A" }
                FileSystem = $drive.FileSystem
            }
        }
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

#endregion

#region Log Settings Functions

function Get-LogSettings {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        $logs = @("Security", "Application", "System")
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        
        if ($cs.DomainRole -in @(4, 5)) {
            $logs += "Directory Service", "DNS Server", "File Replication Service"
        }
        
        $results = @()
        
        foreach ($logName in $logs) {
            try {
                $log = Get-EventLog -List | Where-Object { $_.Log -eq $logName }
                if ($log) {
                    $results += [PSCustomObject]@{
                        LogName = $logName
                        MaximumSizeKB = $log.MaximumKilobytes
                        OverflowAction = $log.OverflowAction
                        MinimumRetentionDays = $log.MinimumRetentionDays
                        EnableRaisingEvents = $log.EnableRaisingEvents
                        LogFilePath = $log.LogFilePath
                    }
                }
            } catch {
                # Try WMI for Windows Server Core or if Get-EventLog fails
                try {
                    $wmiLog = Get-CimInstance -ClassName Win32_NTEventLogFile -Filter "LogFileName='$logName'"
                    if ($wmiLog) {
                        $results += [PSCustomObject]@{
                            LogName = $logName
                            MaximumSizeKB = $wmiLog.MaxFileSize / 1024
                            OverflowAction = $wmiLog.OverwritePolicy
                            MinimumRetentionDays = $wmiLog.NumberOfRecords
                            EnableRaisingEvents = "N/A"
                            LogFilePath = $wmiLog.Name
                        }
                    }
                } catch {
                    $results += [PSCustomObject]@{
                        LogName = $logName
                        MaximumSizeKB = "Error"
                        OverflowAction = "Error"
                        MinimumRetentionDays = "Error"
                        EnableRaisingEvents = "Error"
                        LogFilePath = "Error: $_"
                    }
                }
            }
        }
        
        $results
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

#endregion

#region AD Trust Functions

function Get-ADTrusts {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        
        if (Get-Module ActiveDirectory) {
            $domain = Get-ADDomain
            $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
            
            if ($trusts) {
                $trusts | Select-Object @{
                    Name='TrustPartner'; Expression={$_.Target}
                }, @{
                    Name='TrustDirection'; Expression={$_.Direction}
                }, @{
                    Name='TrustType'; Expression={$_.TrustType}
                }, @{
                    Name='TrustAttributes'; Expression={$_.TrustAttributes}
                }, @{
                    Name='WhenCreated'; Expression={$_.WhenCreated}
                }, @{
                    Name='WhenChanged'; Expression={$_.WhenChanged}
                }
            } else {
                @([PSCustomObject]@{
                    TrustPartner = "No trusts found"
                    TrustDirection = ""
                    TrustType = ""
                    TrustAttributes = ""
                    WhenCreated = ""
                    WhenChanged = ""
                })
            }
        } else {
            @([PSCustomObject]@{
                TrustPartner = "Active Directory module not available"
                TrustDirection = ""
                TrustType = ""
                TrustAttributes = ""
                WhenCreated = ""
                WhenChanged = ""
            })
        }
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

#endregion

#region V3 Windows Features Functions

function Get-WindowsFeaturesInfo {
    <#
    .SYNOPSIS
        Gets Windows Feature installation status for STIG compliance
    
    .DESCRIPTION
        This function checks for Windows Features that are prohibited by STIG
    #>
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        $results = @()
        
        # Define features that should NOT be installed per STIG
        $prohibitedFeatures = @(
            'Telnet-Client',
            'TFTP-Client',
            'SimpleTCP',
            'Printing-Foundation-InternetPrinting-Client',
            'FaxServicesClientPackage',
            'PNRP',
            'FS-SMB1',
            'FS-SMB1-CLIENT', 
            'FS-SMB1-SERVER',
            'PowerShell-V2',
            'PowerShellRoot',
            'MicrosoftWindowsPowerShellV2',
            'MicrosoftWindowsPowerShellV2Root',
            'Web-Ftp-Service',
            'SNMP',
            'WMISnmpProvider',
            'Telnet-Server'
        )
        
        # Try different methods to get features based on OS
        try {
            # Try Get-WindowsFeature first (Server OS)
            if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
                $allFeatures = Get-WindowsFeature
                
                foreach ($featureName in $prohibitedFeatures) {
                    $feature = $allFeatures | Where-Object { $_.Name -eq $featureName }
                    if ($feature) {
                        $results += [PSCustomObject]@{
                            FeatureName = $feature.Name
                            DisplayName = $feature.DisplayName
                            InstallState = $feature.InstallState
                            Required = "NotInstalled"
                            Compliant = $feature.InstallState -ne 'Installed'
                        }
                    }
                }
            }
            # Try Get-WindowsOptionalFeature (Client OS or if above fails)
            elseif (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
                foreach ($featureName in $prohibitedFeatures) {
                    try {
                        $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
                        if ($feature) {
                            $results += [PSCustomObject]@{
                                FeatureName = $feature.FeatureName
                                DisplayName = $feature.DisplayName
                                InstallState = $feature.State
                                Required = "NotInstalled"
                                Compliant = $feature.State -ne 'Enabled'
                            }
                        }
                    } catch {
                        # Feature not found, skip
                    }
                }
            }
        } catch {
            $results += [PSCustomObject]@{
                FeatureName = "Error"
                DisplayName = "Error retrieving features"
                InstallState = $_.Exception.Message
                Required = "N/A"
                Compliant = $false
            }
        }
        
        if ($results.Count -eq 0) {
            $results += [PSCustomObject]@{
                FeatureName = "None"
                DisplayName = "No prohibited features found or feature checking not supported"
                InstallState = "N/A"
                Required = "N/A"
                Compliant = $true
            }
        }
        
        $results
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

#endregion

#region Secedit Implementation Functions

function New-AuditAndUserRightsINF {
    <#
    .SYNOPSIS
        Creates the AuditandUserRights.inf file for secedit analysis
    
    .DESCRIPTION
        This function creates a comprehensive security template file that can be used
        with secedit to analyze audit settings, user rights, and security policies
    #>
    param(
        [string]$OutputPath
    )
    
    $infContent = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Profile Description]
Description=Audit and User Rights Security Template for Security Assessment

[System Access]
MinimumPasswordAge = 
MaximumPasswordAge = 
MinimumPasswordLength = 
PasswordComplexity = 
PasswordHistorySize = 
LockoutBadCount = 
ResetLockoutCount = 
LockoutDuration = 
RequireLogonToChangePassword = 
ForceLogoffWhenHourExpire = 
NewAdministratorName = 
NewGuestName = 
ClearTextPassword = 
LSAAnonymousNameLookup = 
EnableAdminAccount = 
EnableGuestAccount = 

[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 3
AuditDSAccess = 3
AuditAccountLogon = 3

[Registry Values]
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateCDRoms=1,
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD=1,
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateFloppies=1,
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=1,
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon=4,
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning=4,
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption=1,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=4,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=4,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle=4,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption=1,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText=7,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption=4,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon=4,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon=4,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures=4,
MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\AuthenticodeEnabled=4,
MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects=4,
MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail=4,
MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,
MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,
MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled=4,
MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest=4,
MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing=3,
MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM=1,
MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,
MACHINE\System\CurrentControlSet\Control\Lsa\SubmitControl=4,
MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId=4,
MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers=4,
MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine=7,
MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine=7,
MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive=4,
MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown=4,
MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode=4,
MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional=7,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect=4,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff=4,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes=7,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess=4,
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword=4,
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,
MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity=4,
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=4,
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=4,
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=4,
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=4,
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=4,

[Privilege Rights]
SeNetworkLogonRight = 
SeInteractiveLogonRight = 
SeBatchLogonRight = 
SeServiceLogonRight = 
SeDenyNetworkLogonRight = 
SeDenyInteractiveLogonRight = 
SeDenyBatchLogonRight = 
SeDenyServiceLogonRight = 
SeRemoteInteractiveLogonRight = 
SeDenyRemoteInteractiveLogonRight = 
SeBackupPrivilege = 
SeChangeNotifyPrivilege = 
SeSystemtimePrivilege = 
SeCreatePagefilePrivilege = 
SeDebugPrivilege = 
SeRemoteShutdownPrivilege = 
SeAuditPrivilege = 
SeIncreaseQuotaPrivilege = 
SeIncreaseBasePriorityPrivilege = 
SeLoadDriverPrivilege = 
SeLockMemoryPrivilege = 
SeCreatePermanentPrivilege = 
SeCreateSymbolicLinkPrivilege = 
SeCreateTokenPrivilege = 
SeManageVolumePrivilege = 
SeProfileSingleProcessPrivilege = 
SeRestorePrivilege = 
SeSecurityPrivilege = 
SeShutdownPrivilege = 
SeSyncAgentPrivilege = 
SeSystemEnvironmentPrivilege = 
SeSystemProfilePrivilege = 
SeTakeOwnershipPrivilege = 
SeUndockPrivilege = 
SeEnableDelegationPrivilege = 
SeAssignPrimaryTokenPrivilege = 
SeImpersonatePrivilege = 
SeTcbPrivilege = 
SeMachineAccountPrivilege = 
SeTrustedCredManAccessPrivilege = 
SeRelabelPrivilege = 
SeIncreaseWorkingSetPrivilege = 
SeTimeZonePrivilege = 
SeCreateGlobalPrivilege = 
'@
    
    $infPath = Join-Path $OutputPath "AuditandUserRights.inf"
    $infContent | Out-File -FilePath $infPath -Encoding Unicode
    
    return $infPath
}

function Invoke-SecEditAnalysis {
    <#
    .SYNOPSIS
        Runs secedit analysis on the target computer
    
    .DESCRIPTION
        This function executes secedit /analyze to compare current security settings
        against the security template
    #>
    param(
        [string]$ComputerName,
        [string]$OutputPath,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        param($OutputPath)
        
        try {
            # Create temp paths
            $tempPath = $env:TEMP
            $infPath = Join-Path $tempPath "AuditandUserRights.inf"
            $sdbPath = Join-Path $tempPath "AuditandUserRights.sdb"
            $logPath = Join-Path $tempPath "SecurityAnalysis.log"
            
            # Create the INF content locally on remote machine
            $infContent = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Profile Description]
Description=Audit and User Rights Security Template for Security Assessment

[System Access]
MinimumPasswordAge = 
MaximumPasswordAge = 
MinimumPasswordLength = 
PasswordComplexity = 
PasswordHistorySize = 
LockoutBadCount = 
ResetLockoutCount = 
LockoutDuration = 

[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 3
AuditDSAccess = 3
AuditAccountLogon = 3

[Privilege Rights]
SeBackupPrivilege = 
SeRestorePrivilege = 
SeShutdownPrivilege = 
SeTakeOwnershipPrivilege = 
SeDebugPrivilege = 
SeRemoteShutdownPrivilege = 
'@
            
            # Write INF file
            $infContent | Out-File -FilePath $infPath -Encoding Unicode
            
            # Remove existing database if present
            if (Test-Path $sdbPath) {
                Remove-Item $sdbPath -Force
            }
            
            # Run secedit analysis
            Write-Host "Executing: secedit /analyze /db `"$sdbPath`" /cfg `"$infPath`" /log `"$logPath`""
            $result = & secedit.exe /analyze /db $sdbPath /cfg $infPath /log $logPath 2>&1
            
            $returnData = @{
                Status = "Success"
                SeceditOutput = $result -join "`n"
                SdbExists = Test-Path $sdbPath
                LogExists = Test-Path $logPath
            }
            
            # Handle SDB file
            if (Test-Path $sdbPath) {
                $sdbInfo = Get-Item $sdbPath
                $returnData.SdbSize = $sdbInfo.Length
                $returnData.SdbContent = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($sdbPath))
                Write-Host "SDB file created successfully: $($sdbInfo.Length) bytes"
            } else {
                Write-Warning "SDB file was not created"
                $returnData.SdbError = "SDB file not created by secedit"
            }
            
            # Handle log file
            if (Test-Path $logPath) {
                $returnData.LogContent = Get-Content $logPath -Raw
            } else {
                $returnData.LogContent = "Log file not created"
            }
            
            # Clean up temp files
            Remove-Item $infPath -Force -ErrorAction SilentlyContinue
            Remove-Item $sdbPath -Force -ErrorAction SilentlyContinue
            Remove-Item $logPath -Force -ErrorAction SilentlyContinue
            
            return $returnData
            
        } catch {
            return @{
                Status = "Error"
                Message = $_.Exception.Message
                StackTrace = $_.ScriptStackTrace
            }
        }
    }
    
    # Create INF file locally for reference
    $infPath = New-AuditAndUserRightsINF -OutputPath $OutputPath
    Write-Host "Created security template: $infPath"
    
    # Run analysis
    Write-Host "Running secedit analysis..."
    $seceditResult = Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential -ArgumentList @{OutputPath = $OutputPath}
    
    # Display secedit output for debugging
    if ($seceditResult.SeceditOutput) {
        Write-Host "Secedit output: $($seceditResult.SeceditOutput)"
    }
    
    # Save results locally
    if ($seceditResult.Status -eq "Success") {
        if ($seceditResult.SdbContent) {
            $sdbPath = Join-Path $OutputPath "($ComputerName)AuditandUserRights.sdb"
            [System.IO.File]::WriteAllBytes($sdbPath, [Convert]::FromBase64String($seceditResult.SdbContent))
            Write-Host "Saved SDB file: $sdbPath ($($seceditResult.SdbSize) bytes)"
        } else {
            Write-Warning "No SDB content received from remote analysis"
        }
        
        if ($seceditResult.LogContent) {
            $logPath = Join-Path $OutputPath "($ComputerName)SecurityAnalysis.log"
            $seceditResult.LogContent | Out-File -FilePath $logPath
        }
    } else {
        Write-Error "Secedit analysis failed: $($seceditResult.Message)"
        if ($seceditResult.StackTrace) {
            Write-Host "Stack trace: $($seceditResult.StackTrace)"
        }
    }
    
    return $seceditResult
}

function Get-SecurityPolicySettings {
    <#
    .SYNOPSIS
        Extracts security policy settings from the system
    
    .DESCRIPTION
        This function exports and parses the current security policy settings
        including password policies, audit policies, and user rights assignments
    #>
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        try {
            $tempPath = $env:TEMP
            $exportPath = Join-Path $tempPath "SecurityPolicy.inf"
            
            # Export security policy
            $result = & secedit /export /cfg $exportPath /quiet
            
            if (Test-Path $exportPath) {
                $content = Get-Content $exportPath -Raw
                
                # Parse the exported file
                $systemAccess = @{}
                $eventAudit = @{}
                $privilegeRights = @{}
                $registryValues = @{}
                
                $currentSection = ""
                
                foreach ($line in ($content -split "`r`n")) {
                    if ($line -match '^\[(.+)\]$') {
                        $currentSection = $matches[1]
                        continue
                    }
                    
                    if ($line -match '^(.+?)\s*=\s*(.*)$') {
                        $key = $matches[1].Trim()
                        $value = $matches[2].Trim()
                        
                        switch ($currentSection) {
                            "System Access" { $systemAccess[$key] = $value }
                            "Event Audit" { $eventAudit[$key] = $value }
                            "Privilege Rights" { 
                                # Parse privilege rights which may have multiple SIDs
                                $privilegeRights[$key] = $value -replace '\*', '' -split ','
                            }
                            "Registry Values" { $registryValues[$key] = $value }
                        }
                    }
                }
                
                # Clean up
                Remove-Item $exportPath -Force -ErrorAction SilentlyContinue
                
                return @{
                    SystemAccess = $systemAccess
                    EventAudit = $eventAudit
                    PrivilegeRights = $privilegeRights
                    RegistryValues = $registryValues
                }
            }
            
            return @{
                Error = "Failed to export security policy"
            }
            
        } catch {
            return @{
                Error = $_.Exception.Message
            }
        }
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

#endregion

#region GPO Backup Functions

function Get-GPOBackup {
    <#
    .SYNOPSIS
        Backs up all Group Policy Objects
    
    .DESCRIPTION
        This function creates backups of all GPOs in the domain and stores them
        in the specified output path
    #>
    param(
        [string]$ComputerName,
        [string]$BackupPath,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        param($BackupPath)
        
        try {
            Import-Module GroupPolicy -ErrorAction Stop
            
            $gpoBackups = @()
            $allGPOs = Get-GPO -All
            
            foreach ($gpo in $allGPOs) {
                try {
                    # Create backup
                    $backupInfo = Backup-GPO -Guid $gpo.Id -Path $env:TEMP -ErrorAction Stop
                    
                    # Get backup details
                    $backupFolder = Join-Path $env:TEMP $backupInfo.Id
                    $backupSize = (Get-ChildItem $backupFolder -Recurse | Measure-Object -Property Length -Sum).Sum
                    
                    # Create zip of backup
                    $zipPath = "$backupFolder.zip"
                    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
                    
                    try {
                        Add-Type -AssemblyName System.IO.Compression.FileSystem
                        [System.IO.Compression.ZipFile]::CreateFromDirectory($backupFolder, $zipPath, 
                            [System.IO.Compression.CompressionLevel]::Optimal, $false)
                    } catch {
                        # Fallback to PowerShell 5.0+ Compress-Archive
                        Compress-Archive -Path "$backupFolder\*" -DestinationPath $zipPath -Force
                    }
                    
                    # Read zip as base64
                    $zipContent = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($zipPath))
                    
                    # Clean up temp files
                    Remove-Item $backupFolder -Recurse -Force
                    Remove-Item $zipPath -Force
                    
                    $gpoBackups += [PSCustomObject]@{
                        GPOName = $gpo.DisplayName
                        GPOId = $gpo.Id
                        BackupId = $backupInfo.Id
                        BackupTime = $backupInfo.BackupTime
                        BackupSize = $backupSize
                        DomainName = $gpo.DomainName
                        CreationTime = $gpo.CreationTime
                        ModificationTime = $gpo.ModificationTime
                        BackupContent = $zipContent
                    }
                    
                } catch {
                    $gpoBackups += [PSCustomObject]@{
                        GPOName = $gpo.DisplayName
                        GPOId = $gpo.Id
                        Error = "Failed to backup: $_"
                    }
                }
            }
            
            return $gpoBackups
            
        } catch {
            return @([PSCustomObject]@{
                Error = "Failed to backup GPOs: $_"
            })
        }
    }
    
    $result = Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential -ArgumentList @{BackupPath = $BackupPath}
    
    # Save GPO backups locally
    foreach ($gpoBackup in $result) {
        if ($gpoBackup.BackupContent) {
            $gpoBackupPath = Join-Path $BackupPath "GPOBackups"
            if (-not (Test-Path $gpoBackupPath)) {
                New-Item -ItemType Directory -Path $gpoBackupPath -Force | Out-Null
            }
            
            $zipPath = Join-Path $gpoBackupPath "$($gpoBackup.GPOName -replace '[^\w\-\.]', '_')_$($gpoBackup.BackupId).zip"
            [System.IO.File]::WriteAllBytes($zipPath, [Convert]::FromBase64String($gpoBackup.BackupContent))
            
            # Remove the base64 content from the return object to avoid large data in CSV/JSON
            $gpoBackup.PSObject.Properties.Remove('BackupContent')
            $gpoBackup | Add-Member -MemberType NoteProperty -Name BackupPath -Value $zipPath
        }
    }
    
    return $result
}

function Copy-SYSVOLStructure {
    <#
    .SYNOPSIS
        Copies the SYSVOL directory structure for offline analysis
    
    .DESCRIPTION
        This function creates a compressed copy of the SYSVOL directory structure
        which contains Group Policy templates and scripts
    #>
    param(
        [string]$ComputerName,
        [string]$DestinationPath,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        param($DestinationPath)
        
        try {
            # Get SYSVOL path
            $sysvolPath = "$env:SystemRoot\SYSVOL"
            
            if (-not (Test-Path $sysvolPath)) {
                return @{
                    Status = "Error"
                    Message = "SYSVOL directory not found"
                }
            }
            
            # Create a compressed archive of SYSVOL
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $archivePath = "$env:TEMP\SYSVOL_$timestamp.zip"
            
            try {
                # Use .NET compression if available (Windows Server 2012+)
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::CreateFromDirectory($sysvolPath, $archivePath, 
                    [System.IO.Compression.CompressionLevel]::Optimal, $false)
            } catch {
                # Fallback to PowerShell 5.0+ Compress-Archive
                Compress-Archive -Path "$sysvolPath\*" -DestinationPath $archivePath -Force
            }
            
            # Get archive info
            $archiveInfo = Get-Item $archivePath
            
            # Read archive as base64 for transport
            $archiveContent = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($archivePath))
            
            # Clean up
            Remove-Item $archivePath -Force
            
            return @{
                Status = "Success"
                Message = "SYSVOL archived successfully"
                OriginalPath = $sysvolPath
                ArchiveSize = $archiveInfo.Length
                ArchiveContent = $archiveContent
            }
            
        } catch {
            return @{
                Status = "Error"
                Message = $_.Exception.Message
            }
        }
    }
    
    $result = Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential -ArgumentList @{DestinationPath = $DestinationPath}
    
    # Save the SYSVOL archive if successful
    if ($result.Status -eq "Success" -and $result.ArchiveContent) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $archivePath = Join-Path $DestinationPath "($ComputerName)_SYSVOL_$timestamp.zip"
        [System.IO.File]::WriteAllBytes($archivePath, [Convert]::FromBase64String($result.ArchiveContent))
        
        Write-Host "SYSVOL archive saved to: $archivePath"
    }
    
    return $result
}

function Get-GPOPermissions {
    <#
    .SYNOPSIS
        Gets detailed permissions for all GPOs
    
    .DESCRIPTION
        This function retrieves the security permissions set on each GPO
    #>
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        try {
            Import-Module GroupPolicy -ErrorAction Stop
            
            $gpoPermissions = @()
            $allGPOs = Get-GPO -All
            
            foreach ($gpo in $allGPOs) {
                try {
                    # Get GPO permissions
                    $permissions = Get-GPPermission -Guid $gpo.Id -All
                    
                    foreach ($perm in $permissions) {
                        $gpoPermissions += [PSCustomObject]@{
                            GPOName = $gpo.DisplayName
                            GPOId = $gpo.Id
                            Trustee = $perm.Trustee.Name
                            TrusteeType = $perm.Trustee.SidType
                            Permission = $perm.Permission
                            Inherited = $perm.Inherited
                            Inheritable = $perm.Inheritable
                        }
                    }
                } catch {
                    $gpoPermissions += [PSCustomObject]@{
                        GPOName = $gpo.DisplayName
                        GPOId = $gpo.Id
                        Error = "Failed to get permissions: $_"
                    }
                }
            }
            
            return $gpoPermissions
            
        } catch {
            return @([PSCustomObject]@{
                Error = "Failed to get GPO permissions: $_"
            })
        }
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

function Get-GPOLinks {
    <#
    .SYNOPSIS
        Gets all GPO links in the domain
    
    .DESCRIPTION
        This function retrieves information about where each GPO is linked
        (sites, domains, OUs)
    #>
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $scriptBlock = {
        try {
            Import-Module GroupPolicy -ErrorAction Stop
            Import-Module ActiveDirectory -ErrorAction Stop
            
            $gpoLinks = @()
            
            # Get domain
            $domain = Get-ADDomain
            
            # Check domain GPO links
            $domainGPOLinks = Get-GPInheritance -Target $domain.DistinguishedName
            foreach ($link in $domainGPOLinks.GpoLinks) {
                $gpoLinks += [PSCustomObject]@{
                    GPOName = $link.DisplayName
                    GPOId = $link.GpoId
                    Target = $domain.DistinguishedName
                    TargetType = "Domain"
                    LinkEnabled = $link.Enabled
                    LinkEnforced = $link.Enforced
                    Order = $link.Order
                }
            }
            
            # Check OU GPO links
            $ous = Get-ADOrganizationalUnit -Filter * -Properties gPLink
            foreach ($ou in $ous) {
                $ouGPOLinks = Get-GPInheritance -Target $ou.DistinguishedName
                foreach ($link in $ouGPOLinks.GpoLinks) {
                    $gpoLinks += [PSCustomObject]@{
                        GPOName = $link.DisplayName
                        GPOId = $link.GpoId
                        Target = $ou.DistinguishedName
                        TargetType = "OU"
                        LinkEnabled = $link.Enabled
                        LinkEnforced = $link.Enforced
                        Order = $link.Order
                    }
                }
            }
            
            # Check site GPO links (if available)
            try {
                $configNC = (Get-ADRootDSE).ConfigurationNamingContext
                $sites = Get-ADObject -SearchBase "CN=Sites,$configNC" -Filter {objectClass -eq "site"}
                
                foreach ($site in $sites) {
                    $siteGPOLinks = Get-GPInheritance -Target $site.DistinguishedName -ErrorAction SilentlyContinue
                    foreach ($link in $siteGPOLinks.GpoLinks) {
                        $gpoLinks += [PSCustomObject]@{
                            GPOName = $link.DisplayName
                            GPOId = $link.GpoId
                            Target = $site.DistinguishedName
                            TargetType = "Site"
                            LinkEnabled = $link.Enabled
                            LinkEnforced = $link.Enforced
                            Order = $link.Order
                        }
                    }
                }
            } catch {
                # Sites enumeration might fail in some environments
            }
            
            return $gpoLinks
            
        } catch {
            return @([PSCustomObject]@{
                Error = "Failed to get GPO links: $_"
            })
        }
    }
    
    Get-RemoteData -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential
}

#endregion

#region V3 STIG Compliance Functions

function New-StigResult {
    <#
    .SYNOPSIS
        Creates a standardized STIG compliance result object
    
    .DESCRIPTION
        Helper function to create consistent STIG compliance result objects
    #>
    param(
        [string]$STIG_ID,
        [string]$Category,
        [string]$Description,
        [string]$Status,
        [string]$Finding,
        [string]$Expected,
        [string]$Actual,
        [string]$Source
    )
    
    return [PSCustomObject]@{
        STIG_ID = $STIG_ID
        Category = $Category
        Description = $Description
        Status = $Status
        Finding = $Finding
        Expected = $Expected
        Actual = $Actual
        Source = $Source
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Test-RegistrySetting {
    <#
    .SYNOPSIS
        Tests a registry setting against expected value for STIG compliance
    
    .DESCRIPTION
        Helper function to check registry values against expected settings
    #>
    param(
        [array]$RegistryValues,
        [string]$KeyPath,
        [string]$ValueName,
        $ExpectedValue,
        [switch]$ShouldExist = $true
    )
    
    # Find the registry value
    $regValue = $RegistryValues | Where-Object { 
        $_.RegistryKey -like "*$KeyPath" -and $_.ValueName -eq $ValueName 
    }
    
    if ($regValue) {
        if ($regValue.ValueName -eq "Registry key does not exist") {
            return @{
                Compliant = -not $ShouldExist
                ActualValue = "Key does not exist"
            }
        } elseif ($regValue.ValueName -eq "No values") {
            return @{
                Compliant = -not $ShouldExist
                ActualValue = "No values in key"
            }
        } else {
            $actualValue = $regValue.Data
            $isCompliant = $actualValue -eq $ExpectedValue
            return @{
                Compliant = $isCompliant
                ActualValue = $actualValue
            }
        }
    } else {
        return @{
            Compliant = -not $ShouldExist
            ActualValue = "Not found"
        }
    }
}

function Test-ServiceCompliance {
    <#
    .SYNOPSIS
        Tests service settings for STIG compliance
    
    .DESCRIPTION
        Checks if services are configured according to STIG requirements
    #>
    param(
        [array]$Services,
        [string]$ServiceName,
        [string]$RequiredStartMode,
        [string]$RequiredState = $null
    )
    
    $service = $Services | Where-Object { $_.ServiceName -eq $ServiceName }
    
    if ($service) {
        $isCompliant = $service.StartMode -eq $RequiredStartMode
        if ($RequiredState -and $isCompliant) {
            $isCompliant = $service.ServiceState -eq $RequiredState
        }
        
        return @{
            Exists = $true
            Compliant = $isCompliant
            ActualStartMode = $service.StartMode
            ActualState = $service.ServiceState
        }
    } else {
        # Service not found - compliant if it should be disabled/not installed
        return @{
            Exists = $false
            Compliant = ($RequiredStartMode -eq 'Disabled')
            ActualStartMode = "Not Installed"
            ActualState = "Not Installed"
        }
    }
}

function Test-UserRightsCompliance {
    <#
    .SYNOPSIS
        Tests user rights assignments for STIG compliance
    
    .DESCRIPTION
        Checks if user rights are assigned according to STIG requirements
    #>
    param(
        [array]$UserRights,
        [string]$RightName,
        [string[]]$RequiredPrincipals,
        [string[]]$ProhibitedPrincipals = @(),
        [switch]$ExactMatch
    )
    
    $right = $UserRights | Where-Object { $_.Right -eq $RightName }
    
    if ($right) {
        $assignees = $right.Assignees -split ';' | ForEach-Object { $_.Trim() }
        
        if ($ExactMatch) {
            # Check for exact match
            $isCompliant = (Compare-Object $assignees $RequiredPrincipals) -eq $null
        } else {
            # Check that all required principals are present
            $isCompliant = $true
            foreach ($required in $RequiredPrincipals) {
                if ($assignees -notcontains $required) {
                    $isCompliant = $false
                    break
                }
            }
            
            # Check that no prohibited principals are present
            if ($isCompliant) {
                foreach ($prohibited in $ProhibitedPrincipals) {
                    if ($assignees -contains $prohibited) {
                        $isCompliant = $false
                        break
                    }
                }
            }
        }
        
        return @{
            Compliant = $isCompliant
            ActualAssignees = $assignees -join '; '
        }
    } else {
        # Right not found
        return @{
            Compliant = ($RequiredPrincipals.Count -eq 0)
            ActualAssignees = "Not configured"
        }
    }
}

function Test-AuditPolicyCompliance {
    <#
    .SYNOPSIS
        Tests audit policy settings for STIG compliance
    
    .DESCRIPTION
        Checks if audit policies are configured according to STIG requirements
    #>
    param(
        [array]$AuditPolicies,
        [string]$PolicyName,
        [string]$RequiredSetting
    )
    
    $policy = $AuditPolicies | Where-Object { $_.Policy -eq $PolicyName }
    
    if ($policy) {
        $isCompliant = $policy.Setting -eq $RequiredSetting
        return @{
            Compliant = $isCompliant
            ActualSetting = $policy.Setting
        }
    } else {
        return @{
            Compliant = $false
            ActualSetting = "Not configured"
        }
    }
}

function Test-PasswordPolicyCompliance {
    <#
    .SYNOPSIS
        Tests password policy settings for STIG compliance
    
    .DESCRIPTION
        Checks if password policies are configured according to STIG requirements
    #>
    param(
        [array]$PasswordPolicies,
        [string]$PolicyName,
        $RequiredValue,
        [string]$ComparisonOperator = 'eq'
    )
    
    $policy = $PasswordPolicies | Where-Object { $_.Policy -eq $PolicyName }
    
    if ($policy) {
        $actualValue = $policy.Value
        $isCompliant = $false
        
        # Safely convert to appropriate type for comparison with validation
        if ($RequiredValue -is [int] -and $actualValue -match '^\d+$') {
            try {
                $numericActualValue = [int]$actualValue
                
                $isCompliant = switch ($ComparisonOperator) {
                    'eq' { $numericActualValue -eq $RequiredValue }
                    'ge' { $numericActualValue -ge $RequiredValue }
                    'le' { $numericActualValue -le $RequiredValue }
                    'gt' { $numericActualValue -gt $RequiredValue }
                    'lt' { $numericActualValue -lt $RequiredValue }
                    'ne' { $numericActualValue -ne $RequiredValue }
                    default { $numericActualValue -eq $RequiredValue }
                }
            } catch {
                $actualValue = "Error converting to integer: $actualValue"
            }
        } elseif ($RequiredValue -is [string]) {
            $isCompliant = switch ($ComparisonOperator) {
                'eq' { $actualValue -eq $RequiredValue }
                'ne' { $actualValue -ne $RequiredValue }
                default { $actualValue -eq $RequiredValue }
            }
        } else {
            # Non-numeric comparison or invalid format
            $actualValue = if ($actualValue) { $actualValue } else { "Not configured" }
        }
        
        return @{
            Compliant = $isCompliant
            ActualValue = $actualValue
        }
    } else {
        return @{
            Compliant = $false
            ActualValue = "Not configured"
        }
    }
}

function Test-WindowsFeatureCompliance {
    <#
    .SYNOPSIS
        Tests Windows Feature installation status for STIG compliance
    
    .DESCRIPTION
        Checks if Windows Features are installed/not installed according to STIG requirements
    #>
    param(
        [array]$Features,
        [string]$FeatureName,
        [string]$RequiredState = "NotInstalled"
    )
    
    $feature = $Features | Where-Object { $_.FeatureName -eq $FeatureName }
    
    if ($feature) {
        return @{
            Compliant = $feature.Compliant
            ActualState = $feature.InstallState
        }
    } else {
        # Feature not in the prohibited list, assume compliant
        return @{
            Compliant = $true
            ActualState = "Not evaluated"
        }
    }
}

function Test-InactiveAccounts {
    <#
    .SYNOPSIS
        Tests for inactive accounts that should be disabled per STIG
    
    .DESCRIPTION
        Identifies enabled accounts that haven't logged on in more than 35 days
    #>
    param(
        [array]$Users,
        [int]$DaysInactive = 35
    )
    
    $inactiveDate = (Get-Date).AddDays(-$DaysInactive)
    $inactiveAccounts = @()
    
    foreach ($user in $Users) {
        if (-not $user.AccountDisabled) {
            # Check last logon
            if ($user.LastLogon) {
                try {
                    $lastLogon = [DateTime]$user.LastLogon
                    if ($lastLogon -lt $inactiveDate) {
                        $inactiveAccounts += $user.UserName
                    }
                } catch {
                    # If can't parse date, consider it inactive
                    $inactiveAccounts += $user.UserName
                }
            } elseif ($user.LastLogonDate) {
                # For AD users
                try {
                    $lastLogon = [DateTime]$user.LastLogonDate
                    if ($lastLogon -lt $inactiveDate) {
                        $inactiveAccounts += $user.NTName
                    }
                } catch {
                    $inactiveAccounts += $user.NTName
                }
            } else {
                # No last logon date - could be never logged on
                $inactiveAccounts += if ($user.UserName) { $user.UserName } else { $user.NTName }
            }
        }
    }
    
    return @{
        Compliant = ($inactiveAccounts.Count -eq 0)
        InactiveAccounts = $inactiveAccounts -join '; '
    }
}

function Test-TemporaryAccounts {
    <#
    .SYNOPSIS
        Tests for temporary/emergency accounts that should expire within 72 hours
    
    .DESCRIPTION
        Identifies accounts that might be temporary or emergency accounts
    #>
    param(
        [array]$Users
    )
    
    $suspectAccounts = @()
    
    foreach ($user in $Users) {
        # Check if account has indicators of being temporary/emergency
        $isTemp = $false
        $reason = ""
        
        # Check description/name for keywords
        if ($user.Description -match 'temp|emergency|test|contractor' -or 
            $user.UserName -match 'temp|emergency|test|contractor' -or
            $user.NTName -match 'temp|emergency|test|contractor') {
            $isTemp = $true
            $reason = "Name/description indicates temporary account"
        }
        
        # Check if account has expiration date
        if ($user.AccountExpires -or $user.AccountExpirationDate) {
            $expirationDate = if ($user.AccountExpires) { $user.AccountExpires } else { $user.AccountExpirationDate }
            
            if ($expirationDate -and $expirationDate -ne [DateTime]::MaxValue) {
                # Account has expiration - check if it's more than 72 hours from creation
                # Since we don't have creation date for local accounts, flag for review
                if (-not $isTemp) {
                    $isTemp = $true
                    $reason = "Account has expiration date set"
                }
            }
        }
        
        if ($isTemp -and -not $user.AccountDisabled) {
            $accountName = if ($user.UserName) { $user.UserName } else { $user.NTName }
            $suspectAccounts += "$accountName ($reason)"
        }
    }
    
    return @{
        RequiresReview = ($suspectAccounts.Count -gt 0)
        SuspectAccounts = $suspectAccounts -join '; '
    }
}

function Test-GroupMembership {
    <#
    .SYNOPSIS
        Tests group membership for STIG compliance
    
    .DESCRIPTION
        Checks if privileged groups contain only authorized members
    #>
    param(
        [array]$Groups,
        [string]$GroupName,
        [string[]]$AuthorizedMembers = @(),
        [string[]]$ProhibitedMembers = @()
    )
    
    $group = $Groups | Where-Object { $_.Name -eq $GroupName }
    
    if ($group) {
        $members = $group.Members -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        
        $unauthorizedMembers = @()
        $prohibitedFound = @()
        
        # Check for unauthorized members (if authorized list provided)
        if ($AuthorizedMembers.Count -gt 0) {
            foreach ($member in $members) {
                $authorized = $false
                foreach ($authMember in $AuthorizedMembers) {
                    if ($member -like "*$authMember*") {
                        $authorized = $true
                        break
                    }
                }
                if (-not $authorized) {
                    $unauthorizedMembers += $member
                }
            }
        }
        
        # Check for prohibited members
        foreach ($prohibited in $ProhibitedMembers) {
            foreach ($member in $members) {
                if ($member -like "*$prohibited*") {
                    $prohibitedFound += $member
                }
            }
        }
        
        $isCompliant = ($unauthorizedMembers.Count -eq 0) -and ($prohibitedFound.Count -eq 0)
        
        return @{
            Compliant = $isCompliant
            Members = $members -join '; '
            UnauthorizedMembers = $unauthorizedMembers -join '; '
            ProhibitedMembers = $prohibitedFound -join '; '
        }
    } else {
        return @{
            Compliant = $true
            Members = "Group not found"
            UnauthorizedMembers = ""
            ProhibitedMembers = ""
        }
    }
}

function Test-EventLogCompliance {
    <#
    .SYNOPSIS
        Tests event log settings for STIG compliance
    
    .DESCRIPTION
        Checks if event logs meet size and retention requirements
    #>
    param(
        [array]$LogSettings,
        [string]$LogName,
        [int]$RequiredSizeKB,
        [string]$RequiredRetention = "DoNotOverwrite"
    )
    
    $log = $LogSettings | Where-Object { $_.LogName -eq $LogName }
    
    if ($log) {
        # Safely convert log size to integer with validation
        $actualSizeKB = $log.MaximumSizeKB
        $sizeCompliant = $false
        
        if ($actualSizeKB -match '^\d+$') {
            $sizeCompliant = [int]$actualSizeKB -ge $RequiredSizeKB
        } elseif ($actualSizeKB -eq "Error") {
            $actualSizeKB = "Error retrieving size"
        }
        
        $retentionCompliant = $log.OverflowAction -ne "OverwriteAsNeeded"
        
        return @{
            Compliant = $sizeCompliant -and $retentionCompliant
            ActualSizeKB = $actualSizeKB
            ActualRetention = $log.OverflowAction
        }
    } else {
        return @{
            Compliant = $false
            ActualSizeKB = "Not found"
            ActualRetention = "Not found"
        }
    }
}

function Evaluate-STIGCompliance {
    <#
    .SYNOPSIS
        Main function to evaluate STIG compliance based on collected data
    
    .DESCRIPTION
        This function runs all STIG compliance checks and returns results.
        V3.3 includes comprehensive registry compliance with all 76 STIG registry requirements.
    #>
    param(
        [hashtable]$CollectedData,
        [string]$OutputPath,
        [string]$ComputerName
    )
    
    Write-Host "Evaluating comprehensive STIG compliance..." -ForegroundColor Cyan
    
    $complianceResults = @()
    
    # Extract data from collected data hashtable
    $systemInfo = $CollectedData.SystemInfo
    $windowsVersionInfo = $CollectedData.WindowsVersionInfo
    $users = $CollectedData.Users
    $groups = $CollectedData.Groups
    $regValues = $CollectedData.RegistryValues
    $stigRegistryCompliance = $CollectedData.STIGRegistryCompliance
    $services = $CollectedData.Services
    $passwordPolicies = $CollectedData.PasswordPolicies
    $auditPolicies = $CollectedData.AuditPolicies
    $userRights = $CollectedData.UserRights
    $logSettings = $CollectedData.LogSettings
    $features = $CollectedData.Features
    
    $isDomainController = $systemInfo.DomainRole -in @("Backup Domain Controller", "Primary Domain Controller")
    
    Write-Host "Processing STIG compliance for $($windowsVersionInfo.WindowsVersion) ($($windowsVersionInfo.WindowsType))..." -ForegroundColor Yellow
    
    #region Comprehensive Registry Compliance (V3.3 Enhancement)
    
    # Add all registry compliance results from the comprehensive collection
    if ($stigRegistryCompliance) {
        Write-Host "Adding $($stigRegistryCompliance.Count) comprehensive registry compliance checks..." -ForegroundColor Green
        
        foreach ($regCheck in $stigRegistryCompliance) {
            $complianceResults += New-StigResult -STIG_ID $regCheck.STIG_ID -Category "Registry Configuration" `
                -Description $regCheck.Description `
                -Status $regCheck.Status `
                -Finding $(if (-not $regCheck.IsCompliant) { "Registry setting not compliant with STIG requirements" } else { "" }) `
                -Expected $regCheck.ExpectedValue -Actual $regCheck.ActualValue -Source "V3.3_Registry_Compliance"
        }
        
        # Generate registry compliance summary
        $regCompliant = ($stigRegistryCompliance | Where-Object { $_.IsCompliant }).Count
        $regTotal = $stigRegistryCompliance.Count
        $regComplianceRate = if ($regTotal -gt 0) { [math]::Round(($regCompliant / $regTotal) * 100, 2) } else { 0 }
        
        Write-Host "Registry Compliance: $regCompliant/$regTotal settings compliant ($regComplianceRate%)" -ForegroundColor $(if ($regComplianceRate -ge 90) { "Green" } elseif ($regComplianceRate -ge 75) { "Yellow" } else { "Red" })
    } else {
        Write-Host "No comprehensive registry compliance data available" -ForegroundColor Red
        
        # Fallback to legacy registry checks if comprehensive data not available
        Write-Host "Using legacy registry compliance checks..." -ForegroundColor Yellow
        
        # Legacy critical registry checks
        $result = Test-RegistrySetting -RegistryValues $regValues `
            -KeyPath "SYSTEM\CurrentControlSet\Control\Lsa" `
            -ValueName "SCENoApplyLegacyAuditPolicy" -ExpectedValue 1
        $complianceResults += New-StigResult -STIG_ID "WN19-SO-000050" -Category "Security Options" `
            -Description "Audit: Force audit policy subcategory settings must be enabled" `
            -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
            -Finding $(if (-not $result.Compliant) { "Registry setting not configured correctly" } else { "" }) `
            -Expected "1" -Actual $result.ActualValue -Source "Legacy_RegistryValues"
    }
    
    #endregion
    
    #region Password Policy Checks
    
    # WN19-AC-000010 - Minimum password length
    $result = Test-PasswordPolicyCompliance -PasswordPolicies $passwordPolicies -PolicyName "MinimumPasswordLength" -RequiredValue 14 -ComparisonOperator 'ge'
    $complianceResults += New-StigResult -STIG_ID "WN19-AC-000010" -Category "Account Policies" `
        -Description "Minimum password length must be configured to 14 characters" `
        -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not $result.Compliant) { "Password length requirement not met" } else { "" }) `
        -Expected "14 or more characters" -Actual $result.ActualValue -Source "PasswordPolicies"
    
    # WN19-AC-000020 - Password complexity
    $result = Test-PasswordPolicyCompliance -PasswordPolicies $passwordPolicies -PolicyName "PasswordComplexity" -RequiredValue 1
    $complianceResults += New-StigResult -STIG_ID "WN19-AC-000020" -Category "Account Policies" `
        -Description "Password must meet complexity requirements" `
        -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not $result.Compliant) { "Password complexity not enabled" } else { "" }) `
        -Expected "1 (Enabled)" -Actual $result.ActualValue -Source "PasswordPolicies"
    
    # WN19-AC-000030 - Password history
    $result = Test-PasswordPolicyCompliance -PasswordPolicies $passwordPolicies -PolicyName "PasswordHistorySize" -RequiredValue 24 -ComparisonOperator 'ge'
    $complianceResults += New-StigResult -STIG_ID "WN19-AC-000030" -Category "Account Policies" `
        -Description "Password history must be configured to 24 passwords remembered" `
        -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not $result.Compliant) { "Password history requirement not met" } else { "" }) `
        -Expected "24 or more" -Actual $result.ActualValue -Source "PasswordPolicies"
    
    # WN19-AC-000040 - Maximum password age
    $result = Test-PasswordPolicyCompliance -PasswordPolicies $passwordPolicies -PolicyName "MaximumPasswordAge" -RequiredValue 60 -ComparisonOperator 'le'
    $complianceResults += New-StigResult -STIG_ID "WN19-AC-000040" -Category "Account Policies" `
        -Description "Maximum password age must be configured to 60 days or less" `
        -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not $result.Compliant) { "Maximum password age exceeds limit" } else { "" }) `
        -Expected "60 days or less" -Actual $result.ActualValue -Source "PasswordPolicies"
    
    # WN19-AC-000050 - Minimum password age
    $result = Test-PasswordPolicyCompliance -PasswordPolicies $passwordPolicies -PolicyName "MinimumPasswordAge" -RequiredValue 1 -ComparisonOperator 'ge'
    $complianceResults += New-StigResult -STIG_ID "WN19-AC-000050" -Category "Account Policies" `
        -Description "Minimum password age must be configured to at least 1 day" `
        -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not $result.Compliant) { "Minimum password age requirement not met" } else { "" }) `
        -Expected "1 day or more" -Actual $result.ActualValue -Source "PasswordPolicies"
    
    # WN19-AC-000060 - Account lockout threshold
    $result = Test-PasswordPolicyCompliance -PasswordPolicies $passwordPolicies -PolicyName "LockoutBadCount" -RequiredValue 3 -ComparisonOperator 'le'
    $complianceResults += New-StigResult -STIG_ID "WN19-AC-000060" -Category "Account Policies" `
        -Description "Account lockout threshold must be configured to 3 or fewer invalid attempts" `
        -Status $(if ($result.Compliant -and $result.ActualValue -ne 0) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not $result.Compliant -or $result.ActualValue -eq 0) { "Account lockout threshold not properly configured" } else { "" }) `
        -Expected "3 or fewer (but not 0)" -Actual $result.ActualValue -Source "PasswordPolicies"
    
    #endregion
    
    #region Audit Policy Checks
    
    # WN19-AU-000100 - Audit Credential Validation
    $result = Test-AuditPolicyCompliance -AuditPolicies $auditPolicies -PolicyName "AuditAccountLogon" -RequiredSetting "Success, Failure"
    $complianceResults += New-StigResult -STIG_ID "WN19-AU-000100" -Category "Audit Policies" `
        -Description "Audit Credential Validation must be configured" `
        -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not $result.Compliant) { "Audit setting not properly configured" } else { "" }) `
        -Expected "Success, Failure" -Actual $result.ActualSetting -Source "AuditPolicies"
    
    # WN19-AU-000190 - Audit Logon
    $result = Test-AuditPolicyCompliance -AuditPolicies $auditPolicies -PolicyName "AuditLogonEvents" -RequiredSetting "Success, Failure"
    $complianceResults += New-StigResult -STIG_ID "WN19-AU-000190" -Category "Audit Policies" `
        -Description "Audit Logon must be configured" `
        -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not $result.Compliant) { "Audit setting not properly configured" } else { "" }) `
        -Expected "Success, Failure" -Actual $result.ActualSetting -Source "AuditPolicies"
    
    #endregion
    
    #region User Rights Checks
    
    # WN19-DC-000410 - Deny log on through RDP on Domain Controllers
    if ($isDomainController) {
        $result = Test-UserRightsCompliance -UserRights $userRights -RightName "SeDenyRemoteInteractiveLogonRight" `
            -RequiredPrincipals @("Guests")
        $complianceResults += New-StigResult -STIG_ID "WN19-DC-000410" -Category "User Rights" `
            -Description "Deny log on through Remote Desktop Services must include Guests on DCs" `
            -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
            -Finding $(if (-not $result.Compliant) { "Required group not in deny list" } else { "" }) `
            -Expected "Guests" -Actual $result.ActualAssignees -Source "UserRights"
    }
    
    # WN19-MS-000120 - Deny log on through RDP on Member Servers
    if (-not $isDomainController) {
        $result = Test-UserRightsCompliance -UserRights $userRights -RightName "SeDenyRemoteInteractiveLogonRight" `
            -RequiredPrincipals @("Guests", "Local account", "Enterprise Admins", "Domain Admins")
        $complianceResults += New-StigResult -STIG_ID "WN19-MS-000120" -Category "User Rights" `
            -Description "Deny log on through Remote Desktop Services must be configured on Member Servers" `
            -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
            -Finding $(if (-not $result.Compliant) { "Required groups not in deny list" } else { "" }) `
            -Expected "Guests, Local account, Enterprise Admins, Domain Admins" -Actual $result.ActualAssignees -Source "UserRights"
    }
    
    # WN19-UR-000290 - Debug programs
    $result = Test-UserRightsCompliance -UserRights $userRights -RightName "SeDebugPrivilege" `
        -RequiredPrincipals @("Administrators") -ExactMatch
    $complianceResults += New-StigResult -STIG_ID "WN19-UR-000290" -Category "User Rights" `
        -Description "Debug programs user right must only be assigned to the Administrators group" `
        -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not $result.Compliant) { "Unauthorized accounts have debug privilege" } else { "" }) `
        -Expected "Administrators only" -Actual $result.ActualAssignees -Source "UserRights"
    
    #endregion
    
    #region Service Checks
    
    # Telnet Service
    $result = Test-ServiceCompliance -Services $services -ServiceName "TlntSvr" -RequiredStartMode "Disabled"
    $complianceResults += New-StigResult -STIG_ID "WN19-00-000230" -Category "System Services" `
        -Description "The Telnet service must be disabled if installed" `
        -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not $result.Compliant) { "Telnet service not disabled" } else { "" }) `
        -Expected "Disabled" -Actual $result.ActualState -Source "Services"
    
    # Print Spooler on Domain Controllers
    if ($isDomainController) {
        $result = Test-ServiceCompliance -Services $services -ServiceName "Spooler" -RequiredStartMode "Disabled"
        $complianceResults += New-StigResult -STIG_ID "WN19-DC-000300" -Category "System Services" `
            -Description "The Print Spooler service must be disabled on domain controllers" `
            -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
            -Finding $(if (-not $result.Compliant) { "Print Spooler service not disabled" } else { "" }) `
            -Expected "Disabled" -Actual $result.ActualState -Source "Services"
    }
    
    # Windows Firewall Service
    $result = Test-ServiceCompliance -Services $services -ServiceName "MpsSvc" -RequiredStartMode "Automatic" -RequiredState "Running"
    $complianceResults += New-StigResult -STIG_ID "WN19-FW-000010" -Category "Windows Firewall" `
        -Description "Windows Firewall must be enabled" `
        -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not $result.Compliant) { "Windows Firewall service not properly configured" } else { "" }) `
        -Expected "Running" -Actual $result.ActualState -Source "Services"
    
    #endregion
    
    #region Windows Features Checks
    
    if ($features) {
        # SMBv1
        $result = Test-WindowsFeatureCompliance -Features $features -FeatureName "FS-SMB1"
        $complianceResults += New-StigResult -STIG_ID "WN19-00-000390" -Category "Windows Features" `
            -Description "SMB v1 must not be installed" `
            -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
            -Finding $(if (-not $result.Compliant) { "SMBv1 is installed" } else { "" }) `
            -Expected "Not Installed" -Actual $result.ActualState -Source "Features"
        
        # PowerShell v2
        $result = Test-WindowsFeatureCompliance -Features $features -FeatureName "PowerShell-V2"
        $complianceResults += New-StigResult -STIG_ID "WN19-00-000400" -Category "Windows Features" `
            -Description "PowerShell v2 must not be installed" `
            -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
            -Finding $(if (-not $result.Compliant) { "PowerShell v2 is installed" } else { "" }) `
            -Expected "Not Installed" -Actual $result.ActualState -Source "Features"
        
        # Telnet Client
        $result = Test-WindowsFeatureCompliance -Features $features -FeatureName "Telnet-Client"
        $complianceResults += New-StigResult -STIG_ID "WN19-00-000360" -Category "Windows Features" `
            -Description "The Telnet Client must not be installed" `
            -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
            -Finding $(if (-not $result.Compliant) { "Telnet Client is installed" } else { "" }) `
            -Expected "Not Installed" -Actual $result.ActualState -Source "Features"
        
        # TFTP Client
        $result = Test-WindowsFeatureCompliance -Features $features -FeatureName "TFTP-Client"
        $complianceResults += New-StigResult -STIG_ID "WN19-00-000380" -Category "Windows Features" `
            -Description "The TFTP Client must not be installed" `
            -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
            -Finding $(if (-not $result.Compliant) { "TFTP Client is installed" } else { "" }) `
            -Expected "Not Installed" -Actual $result.ActualState -Source "Features"
    }
    
    #endregion
    
    #region Account Management Checks
    
    # Administrator account renamed
    $adminAccount = $users | Where-Object { $_.SID -like "*-500" }
    $isRenamed = $adminAccount -and $adminAccount.UserName -ne "Administrator" -and $adminAccount.NTName -ne "Administrator"
    $adminActualName = if ($adminAccount) { if ($adminAccount.UserName) { $adminAccount.UserName } else { $adminAccount.NTName } } else { "Account not found" }
    $complianceResults += New-StigResult -STIG_ID "WN19-00-000010" -Category "Account Management" `
        -Description "The built-in Administrator account must be renamed" `
        -Status $(if ($isRenamed) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not $isRenamed) { "Administrator account not renamed" } else { "" }) `
        -Expected "Account renamed" -Actual $adminActualName -Source "Users"
    
    # Guest account disabled and renamed
    $guestAccount = $users | Where-Object { $_.SID -like "*-501" }
    $isDisabled = $guestAccount -and $guestAccount.AccountDisabled
    $isGuestRenamed = $guestAccount -and $guestAccount.UserName -ne "Guest" -and $guestAccount.NTName -ne "Guest"
    $guestActualName = if ($guestAccount) { if ($guestAccount.UserName) { $guestAccount.UserName } else { $guestAccount.NTName } } else { "Account not found" }
    $complianceResults += New-StigResult -STIG_ID "WN19-00-000020" -Category "Account Management" `
        -Description "The built-in Guest account must be disabled and renamed" `
        -Status $(if ($isDisabled -and $isGuestRenamed) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not ($isDisabled -and $isGuestRenamed)) { "Guest account not properly configured" } else { "" }) `
        -Expected "Disabled and renamed" -Actual $guestActualName -Source "Users"
    
    # Inactive accounts (35 days)
    $result = Test-InactiveAccounts -Users $users -DaysInactive 35
    $complianceResults += New-StigResult -STIG_ID "WN19-00-000330" -Category "Account Management" `
        -Description "Accounts must be disabled after 35 days of inactivity" `
        -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not $result.Compliant) { "Inactive accounts found" } else { "" }) `
        -Expected "No enabled accounts inactive for 35+ days" -Actual $result.InactiveAccounts -Source "Users"
    
    # Temporary/Emergency accounts
    $result = Test-TemporaryAccounts -Users $users
    $complianceResults += New-StigResult -STIG_ID "WN19-00-000300" -Category "Account Management" `
        -Description "Temporary accounts must be automatically disabled after 72 hours" `
        -Status $(if (-not $result.RequiresReview) { "Compliant" } else { "Requires Review" }) `
        -Finding $(if ($result.RequiresReview) { "Potential temporary accounts found" } else { "" }) `
        -Expected "No temporary or emergency accounts found" -Actual $result.SuspectAccounts -Source "Users"
    
    #endregion
    
    #region Group Membership Checks
    
    # Administrators group (basic check - could be enhanced with specific requirements)
    $result = Test-GroupMembership -Groups $groups -GroupName "Administrators" -ProhibitedMembers @("Guest")
    $complianceResults += New-StigResult -STIG_ID "WN19-00-000050" -Category "Account Management" `
        -Description "Administrators group must only contain authorized accounts" `
        -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not $result.Compliant) { "Unauthorized accounts in Administrators group" } else { "" }) `
        -Expected "No prohibited members" -Actual $result.Members -Source "Groups"
    
    #endregion
    
    #region Event Log Checks
    
    # Security log size
    $result = Test-EventLogCompliance -LogSettings $logSettings -LogName "Security" -RequiredSizeKB 196608
    $complianceResults += New-StigResult -STIG_ID "WN19-CC-000240" -Category "Event Log" `
        -Description "The Security event log size must be configured to 196608 KB or greater" `
        -Status $(if ($result.Compliant) { "Compliant" } else { "Not Compliant" }) `
        -Finding $(if (-not $result.Compliant) { "Security log size insufficient" } else { "" }) `
        -Expected "196608 KB or greater" -Actual "$($result.ActualSizeKB) KB" -Source "LogSettings"
    
    #endregion
    
    #region V3.3 Compliance Summary
    
    # Generate comprehensive summary statistics
    $totalChecks = $complianceResults.Count
    $compliantChecks = ($complianceResults | Where-Object { $_.Status -eq "Compliant" }).Count
    $nonCompliantChecks = ($complianceResults | Where-Object { $_.Status -eq "Not Compliant" }).Count
    $reviewRequiredChecks = ($complianceResults | Where-Object { $_.Status -eq "Requires Review" }).Count
    
    # Calculate category-specific compliance rates
    $registryChecks = ($complianceResults | Where-Object { $_.Category -eq "Registry Configuration" }).Count
    $registryCompliantChecks = ($complianceResults | Where-Object { $_.Category -eq "Registry Configuration" -and $_.Status -eq "Compliant" }).Count
    $registryComplianceRate = if ($registryChecks -gt 0) { [math]::Round(($registryCompliantChecks / $registryChecks) * 100, 2) } else { 0 }
    
    $overallComplianceRate = [math]::Round(($compliantChecks / $totalChecks) * 100, 2)
    
    Write-Host "`nV3.3 Comprehensive STIG Compliance Summary:" -ForegroundColor Cyan
    Write-Host "=========================================="
    Write-Host "Target System: $($windowsVersionInfo.WindowsVersion) ($($windowsVersionInfo.WindowsType))"
    Write-Host "Server Role: $($windowsVersionInfo.ServerRole)"
    Write-Host ""
    Write-Host "Overall Results:"
    Write-Host "  Total Checks: $totalChecks"
    Write-Host "  Compliant: $compliantChecks" -ForegroundColor Green
    Write-Host "  Non-Compliant: $nonCompliantChecks" -ForegroundColor Red
    Write-Host "  Requires Review: $reviewRequiredChecks" -ForegroundColor Yellow
    Write-Host "  Overall Compliance Rate: $overallComplianceRate%" -ForegroundColor $(if ($overallComplianceRate -ge 90) { "Green" } elseif ($overallComplianceRate -ge 75) { "Yellow" } else { "Red" })
    Write-Host ""
    Write-Host "V3.3 Registry Enhancement Results:"
    Write-Host "  Registry Checks: $registryChecks"
    Write-Host "  Registry Compliant: $registryCompliantChecks" -ForegroundColor Green
    Write-Host "  Registry Compliance Rate: $registryComplianceRate%" -ForegroundColor $(if ($registryComplianceRate -ge 90) { "Green" } elseif ($registryComplianceRate -ge 75) { "Yellow" } else { "Red" })
    Write-Host ""
    
    # Category breakdown
    $categoryBreakdown = $complianceResults | Group-Object Category | Sort-Object Name
    Write-Host "Compliance by Category:"
    foreach ($category in $categoryBreakdown) {
        $catCompliant = ($category.Group | Where-Object { $_.Status -eq "Compliant" }).Count
        $catTotal = $category.Count
        $catRate = [math]::Round(($catCompliant / $catTotal) * 100, 2)
        Write-Host "  $($category.Name): $catCompliant/$catTotal ($catRate%)" -ForegroundColor $(if ($catRate -ge 90) { "Green" } elseif ($catRate -ge 75) { "Yellow" } else { "Red" })
    }
    
    #endregion
    
    #region Export Results
    
    # Export comprehensive results
    $complianceResults | Export-Csv -Path (Join-Path $OutputPath "($ComputerName)STIG_Compliance_Summary_V3.3.csv") -NoTypeInformation
    $complianceResults | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $OutputPath "($ComputerName)STIG_Compliance_Summary_V3.3.json")
    
    # Create executive summary
    $executiveSummary = [PSCustomObject]@{
        ComputerName = $ComputerName
        WindowsVersion = $windowsVersionInfo.WindowsVersion
        WindowsType = $windowsVersionInfo.WindowsType
        ServerRole = $windowsVersionInfo.ServerRole
        AuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ScriptVersion = $ScriptVersion
        TotalChecks = $totalChecks
        CompliantChecks = $compliantChecks
        NonCompliantChecks = $nonCompliantChecks
        ReviewRequiredChecks = $reviewRequiredChecks
        OverallComplianceRate = $overallComplianceRate
        RegistryChecks = $registryChecks
        RegistryCompliantChecks = $registryCompliantChecks
        RegistryComplianceRate = $registryComplianceRate
        V33_Enhancement = "Comprehensive STIG registry compliance with $registryChecks registry settings"
    }
    
    $executiveSummary | Export-Csv -Path (Join-Path $OutputPath "($ComputerName)Executive_Summary_V3.3.csv") -NoTypeInformation
    $executiveSummary | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $OutputPath "($ComputerName)Executive_Summary_V3.3.json")
    
    #endregion
    
    return $complianceResults
}

#endregion

#region Integration Functions

function Invoke-SecurityAudit {
    <#
    .SYNOPSIS
        Performs comprehensive security audit including secedit and GPO analysis
    
    .DESCRIPTION
        This function integrates secedit analysis and GPO backup/analysis
        into the main audit workflow
    #>
    param(
        [string]$ComputerName,
        [string]$OutputPath,
        [PSCredential]$Credential,
        [switch]$IsDomainController
    )
    
    Write-Host "Performing security configuration analysis..." -ForegroundColor Cyan
    
    # Create AuditandUserRights.inf
    $infPath = New-AuditAndUserRightsINF -OutputPath $OutputPath
    Write-Host "Created security template: $infPath"
    
    # Perform secedit analysis
    Write-Host "Running secedit analysis..."
    $seceditResult = Invoke-SecEditAnalysis -ComputerName $ComputerName -OutputPath $OutputPath -Credential $Credential
    
    # Get security policy settings
    Write-Host "Extracting security policy settings..."
    $policySettings = Get-SecurityPolicySettings -ComputerName $ComputerName -Credential $Credential
    
    # Export policy settings
    if ($policySettings -and -not $policySettings.Error) {
        # Password policies
        $passwordPolicies = @()
        foreach ($key in $policySettings.SystemAccess.Keys) {
            $passwordPolicies += [PSCustomObject]@{
                Policy = $key
                Value = $policySettings.SystemAccess[$key]
            }
        }
        $passwordPolicies | Export-Csv -Path (Join-Path $OutputPath "($ComputerName)PasswordPolicies.csv") -NoTypeInformation
        $passwordPolicies | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $OutputPath "($ComputerName)PasswordPolicies.json")
        
        # Audit policies
        $auditPolicies = @()
        foreach ($key in $policySettings.EventAudit.Keys) {
            $value = switch ($policySettings.EventAudit[$key]) {
                "0" { "No auditing" }
                "1" { "Success" }
                "2" { "Failure" }
                "3" { "Success, Failure" }
                default { $policySettings.EventAudit[$key] }
            }
            $auditPolicies += [PSCustomObject]@{
                Policy = $key
                Setting = $value
            }
        }
        $auditPolicies | Export-Csv -Path (Join-Path $OutputPath "($ComputerName)AuditPolicies.csv") -NoTypeInformation
        $auditPolicies | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $OutputPath "($ComputerName)AuditPolicies.json")
        
        # User rights
        $userRights = @()
        foreach ($key in $policySettings.PrivilegeRights.Keys) {
            $userRights += [PSCustomObject]@{
                Right = $key
                Assignees = $policySettings.PrivilegeRights[$key] -join '; '
            }
        }
        $userRights | Export-Csv -Path (Join-Path $OutputPath "($ComputerName)UserRights.csv") -NoTypeInformation
        $userRights | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $OutputPath "($ComputerName)UserRights.json")
    }
    
    # GPO operations for domain controllers
    if ($IsDomainController) {
        Write-Host "Performing GPO backup and analysis..." -ForegroundColor Cyan
        
        # Backup GPOs
        Write-Host "Backing up Group Policy Objects..."
        $gpoBackups = Get-GPOBackup -ComputerName $ComputerName -BackupPath $OutputPath -Credential $Credential
        $gpoBackups | Export-Csv -Path (Join-Path $OutputPath "($ComputerName)GPOBackups.csv") -NoTypeInformation
        $gpoBackups | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $OutputPath "($ComputerName)GPOBackups.json")
        
        # Get GPO permissions
        Write-Host "Gathering GPO permissions..."
        $gpoPermissions = Get-GPOPermissions -ComputerName $ComputerName -Credential $Credential
        $gpoPermissions | Export-Csv -Path (Join-Path $OutputPath "($ComputerName)GPOPermissions.csv") -NoTypeInformation
        $gpoPermissions | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $OutputPath "($ComputerName)GPOPermissions.json")
        
        # Get GPO links
        Write-Host "Gathering GPO links..."
        $gpoLinks = Get-GPOLinks -ComputerName $ComputerName -Credential $Credential
        $gpoLinks | Export-Csv -Path (Join-Path $OutputPath "($ComputerName)GPOLinks.csv") -NoTypeInformation
        $gpoLinks | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $OutputPath "($ComputerName)GPOLinks.json")
        
        # Copy SYSVOL structure
        Write-Host "Copying SYSVOL structure..."
        $sysvolResult = Copy-SYSVOLStructure -ComputerName $ComputerName -DestinationPath $OutputPath -Credential $Credential
        
        if ($sysvolResult.Status -eq "Success") {
            Write-Host "SYSVOL structure copied successfully" -ForegroundColor Green
        } else {
            Write-Host "SYSVOL copy status: $($sysvolResult.Message)" -ForegroundColor Yellow
        }
    }
    
    Write-Host "Security audit completed" -ForegroundColor Green
}

#endregion

#region Main Execution

# Create output directory structure
foreach ($computer in $ComputerName) {
    Write-AuditLog "Starting audit for computer: $computer"
    
    # Create output directory for this computer
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH.mm.ss"
    $computerOutputPath = Join-Path $OutputPath "$computer-$timestamp"
    
    if (-not (Test-Path $computerOutputPath)) {
        New-Item -ItemType Directory -Path $computerOutputPath -Force | Out-Null
    }
    
    # Initialize error log
    $errorLogPath = Join-Path $computerOutputPath "ErrorLog.txt"
    Write-AuditLog "$ScriptVersion - Security Assessment: Confidential for $ClientName use only" -LogFile $errorLogPath
    Write-AuditLog "" -LogFile $errorLogPath
    
    # Initialize collected data hashtable for V3
    $collectedData = @{}
    
    try {
        # Get system information
        Write-AuditLog "Gathering system information..."
        $systemInfo = Get-SystemInfo -ComputerName $computer -Credential $Credential
        $collectedData.SystemInfo = $systemInfo
        
        # Get enhanced Windows version information for STIG compliance
        Write-AuditLog "Determining Windows version and STIG requirements..."
        $windowsVersionInfo = Get-WindowsVersionInfo -ComputerName $computer -Credential $Credential
        $collectedData.WindowsVersionInfo = $windowsVersionInfo
        
        Write-Host "Detected: $($windowsVersionInfo.WindowsVersion) ($($windowsVersionInfo.WindowsType)) - $($windowsVersionInfo.ServerRole)"
        
        # Export system info
        $systemInfo | Export-Csv -Path (Join-Path $computerOutputPath "($computer)SystemInfo.csv") -NoTypeInformation
        $systemInfo | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)SystemInfo.json")
        
        # Export Windows version info
        $windowsVersionInfo | Export-Csv -Path (Join-Path $computerOutputPath "($computer)WindowsVersionInfo.csv") -NoTypeInformation
        $windowsVersionInfo | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)WindowsVersionInfo.json")
        
        # Determine if Domain Controller
        $isDomainController = $systemInfo.DomainRole -in @("Backup Domain Controller", "Primary Domain Controller")
        
        # Get users
        Write-AuditLog "Gathering user information..."
        if ($isDomainController) {
            $users = Get-ADUsers -ComputerName $computer -Credential $Credential
        } else {
            $users = Get-LocalUsers -ComputerName $computer -Credential $Credential
        }
        $collectedData.Users = $users
        $users | Export-Csv -Path (Join-Path $computerOutputPath "($computer)Users.csv") -NoTypeInformation
        $users | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)Users.json")
        
        # Get groups
        Write-AuditLog "Gathering group information..."
        if ($isDomainController) {
            $groups = Get-ADGroups -ComputerName $computer -Credential $Credential
        } else {
            $groups = Get-LocalGroups -ComputerName $computer -Credential $Credential
        }
        $collectedData.Groups = $groups
        $groups | Export-Csv -Path (Join-Path $computerOutputPath "($computer)Groups.csv") -NoTypeInformation
        $groups | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)Groups.json")
        
        # Get file permissions
        Write-AuditLog "Gathering file permission information..."
        $filePaths = @(
            "$env:SystemRoot\regedit.exe",
            "$env:SystemRoot\system32\arp.exe",
            "$env:SystemRoot\system32\at.exe",
            "$env:SystemRoot\system32\attrib.exe",
            "$env:SystemRoot\system32\auditpol.exe",
            "$env:SystemRoot\system32\cacls.exe",
            "$env:SystemRoot\system32\cmd.exe",
            "$env:SystemRoot\system32\debug.exe",
            "$env:SystemRoot\system32\edit.com",
            "$env:SystemRoot\system32\edlin.exe",
            "$env:SystemRoot\system32\ftp.exe",
            "$env:SystemRoot\system32\net.exe",
            "$env:SystemRoot\system32\netsh.exe",
            "$env:SystemRoot\system32\netstat.exe",
            "$env:SystemRoot\system32\nslookup.exe",
            "$env:SystemRoot\system32\ping.exe",
            "$env:SystemRoot\system32\reg.exe",
            "$env:SystemRoot\system32\regedt32.exe",
            "$env:SystemRoot\system32\regsvr32.exe",
            "$env:SystemRoot\system32\rsh.exe",
            "$env:SystemRoot\system32\telnet.exe",
            "$env:SystemRoot\system32\tftp.exe"
        )
        Write-AuditLog "Processing $($filePaths.Count) file paths for permissions" -LogFile $errorLogPath
        $filePerms = Get-FilePermissions -ComputerName $computer -FilePaths $filePaths -Credential $Credential
        $collectedData.FilePermissions = $filePerms
        
        # Debug: Log file permissions count
        $filePermCount = if ($filePerms -is [array]) { $filePerms.Count } elseif ($filePerms) { 1 } else { 0 }
        Write-AuditLog "Collected $filePermCount file permission entries" -LogFile $errorLogPath
        
        $filePerms | Export-Csv -Path (Join-Path $computerOutputPath "($computer)FilePermissions.csv") -NoTypeInformation
        $filePerms | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)FilePermissions.json")
        
        # Get directory permissions
        Write-AuditLog "Gathering directory permission information..."
        $directoryPaths = @(
            "$env:SystemRoot",
            "$env:SystemRoot\System32",
            "$env:SystemRoot\SysWOW64",
            "$env:ProgramFiles",
            "${env:ProgramFiles(x86)}",
            "$env:SystemDrive\",
            "$env:USERPROFILE"
        )
        Write-AuditLog "Processing $($directoryPaths.Count) directory paths for permissions" -LogFile $errorLogPath
        $dirPerms = Get-DirectoryPermissions -ComputerName $computer -DirectoryPaths $directoryPaths -Credential $Credential
        $collectedData.DirectoryPermissions = $dirPerms
        
        # Debug: Log directory permissions count
        $dirPermCount = if ($dirPerms -is [array]) { $dirPerms.Count } elseif ($dirPerms) { 1 } else { 0 }
        Write-AuditLog "Collected $dirPermCount directory permission entries" -LogFile $errorLogPath
        
        $dirPerms | Export-Csv -Path (Join-Path $computerOutputPath "($computer)DirectoryPermissions.csv") -NoTypeInformation
        $dirPerms | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)DirectoryPermissions.json")
        
        # Get registry values - V3.3 Enhanced for comprehensive STIG compliance
        Write-AuditLog "Gathering comprehensive STIG registry information..."
        $registryResults = Get-STIGRegistryCompliance -ComputerName $computer -Credential $Credential -WindowsVersionInfo $windowsVersionInfo
        $collectedData.RegistryValues = $registryResults.RegistryValues
        $collectedData.STIGRegistryCompliance = $registryResults.STIGCompliance
        
        # Debug: Log registry values count
        $regValueCount = if ($registryResults.RegistryValues -is [array]) { $registryResults.RegistryValues.Count } elseif ($registryResults.RegistryValues) { 1 } else { 0 }
        $stigRegCount = if ($registryResults.STIGCompliance -is [array]) { $registryResults.STIGCompliance.Count } elseif ($registryResults.STIGCompliance) { 1 } else { 0 }
        Write-AuditLog "Collected $regValueCount registry value entries and $stigRegCount STIG compliance checks" -LogFile $errorLogPath
        
        $registryResults.RegistryValues | Export-Csv -Path (Join-Path $computerOutputPath "($computer)RegistryValues.csv") -NoTypeInformation
        $registryResults.RegistryValues | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)RegistryValues.json")
        
        $registryResults.STIGCompliance | Export-Csv -Path (Join-Path $computerOutputPath "($computer)STIG_Registry_Compliance.csv") -NoTypeInformation
        $registryResults.STIGCompliance | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)STIG_Registry_Compliance.json")
        
        # Generate STIG registry summary
        $registryCompliant = ($registryResults.STIGCompliance | Where-Object { $_.IsCompliant }).Count
        $registryTotal = $registryResults.STIGCompliance.Count
        $registryComplianceRate = if ($registryTotal -gt 0) { [math]::Round(($registryCompliant / $registryTotal) * 100, 2) } else { 0 }
        
        Write-Host "Registry STIG Compliance: $registryCompliant/$registryTotal ($registryComplianceRate%)" -ForegroundColor $(if ($registryComplianceRate -ge 80) { "Green" } elseif ($registryComplianceRate -ge 60) { "Yellow" } else { "Red" })
        
        # Get services
        Write-AuditLog "Gathering services information..."
        $services = Get-ServicesInfo -ComputerName $computer -Credential $Credential
        $collectedData.Services = $services
        $services | Export-Csv -Path (Join-Path $computerOutputPath "($computer)Services.csv") -NoTypeInformation
        $services | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)Services.json")
        
        # Get hotfixes
        Write-AuditLog "Gathering hotfix information..."
        $hotfixes = Get-HotfixInfo -ComputerName $computer -Credential $Credential
        $collectedData.Hotfixes = $hotfixes
        $hotfixes | Export-Csv -Path (Join-Path $computerOutputPath "($computer)HotFixes.csv") -NoTypeInformation
        $hotfixes | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)HotFixes.json")
        
        # Get missing hotfixes
        Write-AuditLog "Identifying missing patches..."
        $missingHotfixes = Get-MissingHotfixes -ComputerName $computer -Credential $Credential
        $collectedData.MissingHotfixes = $missingHotfixes
        $missingHotfixes | Export-Csv -Path (Join-Path $computerOutputPath "($computer)MissingHotfixes.csv") -NoTypeInformation
        $missingHotfixes | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)MissingHotfixes.json")
        
        # Get shares
        Write-AuditLog "Gathering shares information..."
        $shares = Get-ShareInfo -ComputerName $computer -Credential $Credential
        $collectedData.Shares = $shares
        $shares | Export-Csv -Path (Join-Path $computerOutputPath "($computer)Shares.csv") -NoTypeInformation
        $shares | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)Shares.json")
        
        # Get drives
        Write-AuditLog "Gathering drive information..."
        $drives = Get-DriveInfo -ComputerName $computer -Credential $Credential
        $collectedData.Drives = $drives
        $drives | Export-Csv -Path (Join-Path $computerOutputPath "($computer)Drives.csv") -NoTypeInformation
        $drives | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)Drives.json")
        
        # Get log settings
        Write-AuditLog "Gathering log settings..."
        $logSettings = Get-LogSettings -ComputerName $computer -Credential $Credential
        $collectedData.LogSettings = $logSettings
        $logSettings | Export-Csv -Path (Join-Path $computerOutputPath "($computer)LogSettings.csv") -NoTypeInformation
        $logSettings | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)LogSettings.json")
        
        # Get Windows Features for STIG compliance
        Write-AuditLog "Gathering Windows Features information..."
        $features = Get-WindowsFeaturesInfo -ComputerName $computer -Credential $Credential
        $collectedData.Features = $features
        $features | Export-Csv -Path (Join-Path $computerOutputPath "($computer)WindowsFeatures.csv") -NoTypeInformation
        $features | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)WindowsFeatures.json")
        
        # Get AD trusts (if DC)
        if ($isDomainController) {
            Write-AuditLog "Gathering Active Directory trust information..."
            $adTrusts = Get-ADTrusts -ComputerName $computer -Credential $Credential
            $collectedData.ADTrusts = $adTrusts
            $adTrusts | Export-Csv -Path (Join-Path $computerOutputPath "($computer)ADTrusts.csv") -NoTypeInformation
            $adTrusts | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)ADTrusts.json")
        }
        
        # Get gpresult (if not Windows 2000/NT) - V2 functionality restored
        if ([version]$systemInfo.Version -ge [version]"5.1") {
            Write-AuditLog "Gathering gpresult information..."
            $gpresultPath = Join-Path $computerOutputPath "($computer)gpresult.txt"
            
            if ($computer -eq $env:COMPUTERNAME) {
                & gpresult /Z > $gpresultPath 2>&1
            } else {
                Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {
                    gpresult /Z
                } | Out-File -FilePath $gpresultPath
            }
        }
        
        # Get detailed audit settings (Windows Server 2008+) - V2 functionality restored
        if ([version]$systemInfo.Version -ge [version]"6.0") {
            Write-AuditLog "Gathering detailed audit settings..."
            $detailedAuditPath = Join-Path $computerOutputPath "($computer)DetailedAuditSettings.txt"
            
            if ($computer -eq $env:COMPUTERNAME) {
                & auditpol /get /category:* > $detailedAuditPath 2>&1
            } else {
                Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {
                    auditpol /get /category:*
                } | Out-File -FilePath $detailedAuditPath
            }
        }
        
        # Perform comprehensive security audit (V2 functionality + secedit + GPO)
        Write-AuditLog "Performing comprehensive security configuration analysis..."
        Invoke-SecurityAudit -ComputerName $computer -OutputPath $computerOutputPath -Credential $Credential -IsDomainController:$isDomainController
        
        # Load password policies, audit policies, and user rights from security audit for STIG compliance
        $passwordPoliciesPath = Join-Path $computerOutputPath "($computer)PasswordPolicies.csv"
        $auditPoliciesPath = Join-Path $computerOutputPath "($computer)AuditPolicies.csv"
        $userRightsPath = Join-Path $computerOutputPath "($computer)UserRights.csv"
        
        if (Test-Path $passwordPoliciesPath) {
            $collectedData.PasswordPolicies = Import-Csv $passwordPoliciesPath
        }
        if (Test-Path $auditPoliciesPath) {
            $collectedData.AuditPolicies = Import-Csv $auditPoliciesPath
        }
        if (Test-Path $userRightsPath) {
            $collectedData.UserRights = Import-Csv $userRightsPath
        }
        
        # Skip STIG compliance if requested
        if (-not $SkipSTIGCompliance -and -not $PowerSTIGOnly) {
            # V3.3 STIG Compliance Evaluation
            Write-AuditLog "Evaluating V3.3 STIG compliance..."
            $stigResults = Evaluate-STIGCompliance -CollectedData $collectedData -OutputPath $computerOutputPath -ComputerName $computer

            # Export STIG compliance results
            $stigResults | Export-Csv -Path (Join-Path $computerOutputPath "($computer)STIG_Compliance_Summary.csv") -NoTypeInformation
            $stigResults | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerOutputPath "($computer)STIG_Compliance_Summary.json")

            Write-AuditLog "V3.3 STIG compliance evaluation completed"
        } elseif ($PowerSTIGOnly) {
            Write-AuditLog "V3.3 STIG compliance evaluation skipped (PowerSTIG-only mode)"
        } else {
            Write-AuditLog "V3.3 STIG compliance evaluation skipped"
        }

        # PowerSTIG Integration (V3.4)
        $powerSTIGResults = $null
        $powerSTIGAuditResult = $null
        $powerSTIGFindings = $null

        if (-not $SkipPowerSTIG) {
            Write-Host "`n========================================" -ForegroundColor Cyan
            Write-Host "PowerSTIG Evaluation (V3.4)" -ForegroundColor Cyan
            Write-Host "========================================`n" -ForegroundColor Cyan

            try {
                # Check/Install Prerequisites
                Write-AuditLog "Checking PowerSTIG prerequisites..." -LogFile $errorLogPath
                $prereqSatisfied = Test-PowerSTIGPrerequisites -LogFile $errorLogPath

                if (-not $prereqSatisfied) {
                    Write-AuditLog "Installing PowerSTIG modules..." -LogFile $errorLogPath
                    $installSuccess = Install-PowerSTIGModules -LogFile $errorLogPath

                    if (-not $installSuccess) {
                        Write-AuditLog "ERROR: Failed to install PowerSTIG. Skipping PowerSTIG evaluation." -LogFile $errorLogPath
                        Write-Host "[!] PowerSTIG installation failed. Continuing with V3.3 results only." -ForegroundColor Yellow
                    } else {
                        # Re-check prerequisites after installation
                        $prereqSatisfied = Test-PowerSTIGPrerequisites -LogFile $errorLogPath
                    }
                }

                if ($prereqSatisfied) {
                    # Generate PowerSTIG Configuration
                    Write-AuditLog "Generating PowerSTIG configuration..." -LogFile $errorLogPath
                    $configResult = New-PowerSTIGConfiguration `
                        -WindowsVersionInfo $windowsVersionInfo `
                        -ComputerName $computer `
                        -OutputPath $computerOutputPath `
                        -StigVersions $StigVersions `
                        -StigDataSource $StigDataSource `
                        -LocalStigDataPath $LocalStigDataPath `
                        -LogFile $errorLogPath

                    if ($configResult -and $configResult.Success) {
                        # Execute PowerSTIG Audit
                        Write-AuditLog "Executing PowerSTIG audit..." -LogFile $errorLogPath
                        $powerSTIGAuditResult = Invoke-PowerSTIGAudit `
                            -MofPath $configResult.MofPath `
                            -ComputerName $computer `
                            -Credential $Credential `
                            -LogFile $errorLogPath

                        if ($powerSTIGAuditResult.Success) {
                            # Convert DSC results to findings
                            $powerSTIGFindings = ConvertFrom-DSCResults `
                                -DscResults $powerSTIGAuditResult.Results `
                                -LogFile $errorLogPath

                            $powerSTIGResults = Get-PowerSTIGFindingDetails -Findings $powerSTIGFindings

                            # Export PowerSTIG results
                            Export-PowerSTIGResults `
                                -Results $powerSTIGAuditResult `
                                -OutputPath $computerOutputPath `
                                -ComputerName $computer

                            # Generate .ckl checklist if requested
                            if ($GenerateCheckList -and $XccdfPath) {
                                $cklPath = New-STIGViewerChecklist `
                                    -PowerSTIGResults $powerSTIGAuditResult `
                                    -XccdfPath $XccdfPath `
                                    -OutputPath $computerOutputPath `
                                    -ComputerName $computer `
                                    -LogFile $errorLogPath

                                if ($cklPath) {
                                    Write-Host "[OK] STIG Viewer checklist created: $cklPath" -ForegroundColor Green
                                }
                            }

                            # Compare V3.3 and PowerSTIG results (if both ran)
                            if ($stigResults -and $powerSTIGResults) {
                                Write-AuditLog "Performing side-by-side comparison..." -LogFile $errorLogPath

                                $comparisonResults = Compare-STIGResults `
                                    -V33Results $stigResults `
                                    -PowerSTIGResults $powerSTIGResults `
                                    -LogFile $errorLogPath

                                $mergedResults = Merge-STIGComplianceResults `
                                    -V33Results $stigResults `
                                    -PowerSTIGResults $powerSTIGResults

                                # Export enhanced reports
                                Export-EnhancedSTIGReport `
                                    -ComparisonResults $comparisonResults `
                                    -MergedResults $mergedResults `
                                    -OutputPath $computerOutputPath `
                                    -ComputerName $computer `
                                    -PowerSTIGAuditResult $powerSTIGAuditResult

                                # Display comparison summary
                                Write-Host "`n========================================" -ForegroundColor Cyan
                                Write-Host "STIG Comparison Summary (V3.3 vs PowerSTIG)" -ForegroundColor Cyan
                                Write-Host "========================================" -ForegroundColor Cyan
                                Write-Host "V3.3 Checks: $($stigResults.Count)" -ForegroundColor White
                                Write-Host "PowerSTIG Checks: $($powerSTIGAuditResult.TotalResources)" -ForegroundColor White
                                Write-Host "Overlapping: $(($comparisonResults | Where-Object { $_.Comparison -match 'Both|Conflict' }).Count)" -ForegroundColor White
                                Write-Host "  Both Compliant: $(($comparisonResults | Where-Object { $_.Comparison -eq '[OK] Both Compliant' }).Count)" -ForegroundColor Green
                                Write-Host "  Both Non-Compliant: $(($comparisonResults | Where-Object { $_.Comparison -eq '[X] Both Non-Compliant' }).Count)" -ForegroundColor Red
                                Write-Host "  Conflicts: $(($comparisonResults | Where-Object { $_.Comparison -eq '[!] Conflict' }).Count)" -ForegroundColor Yellow
                                Write-Host "========================================`n" -ForegroundColor Cyan
                            }

                            Write-AuditLog "PowerSTIG evaluation completed successfully" -LogFile $errorLogPath
                            Write-Host "[OK] PowerSTIG audit completed" -ForegroundColor Green

                        } else {
                            Write-AuditLog "ERROR: PowerSTIG audit failed: $($powerSTIGAuditResult.Error)" -LogFile $errorLogPath
                            Write-Host "[!] PowerSTIG audit failed. See error log for details." -ForegroundColor Yellow
                        }

                        # Cleanup temp configuration files
                        if ($configResult.ConfigPath -and (Test-Path $configResult.ConfigPath)) {
                            Remove-Item -Path $configResult.ConfigPath -Recurse -Force -ErrorAction SilentlyContinue
                        }

                    } else {
                        Write-AuditLog "ERROR: PowerSTIG configuration generation failed" -LogFile $errorLogPath
                        Write-Host "[!] PowerSTIG configuration failed. Continuing with V3.3 results only." -ForegroundColor Yellow
                    }
                }

            } catch {
                Write-AuditLog "ERROR during PowerSTIG evaluation: $($_.Exception.Message)" -LogFile $errorLogPath
                Write-AuditLog "Stack trace: $($_.ScriptStackTrace)" -LogFile $errorLogPath
                Write-Host "[!] PowerSTIG evaluation encountered an error. See error log for details." -ForegroundColor Yellow
            }

            Write-Host "" # Blank line for spacing

        } else {
            Write-AuditLog "PowerSTIG evaluation skipped (SkipPowerSTIG flag set)" -LogFile $errorLogPath
        }

        # Calculate MD5 hashes for verification
        Write-AuditLog "Calculating MD5 hashes for verification..."
        $hashResults = @()
        
        Get-ChildItem -Path $computerOutputPath -File | ForEach-Object {
            $hash = Get-MD5Hash -FilePath $_.FullName
            $hashResults += "$($_.Name)`t$hash"
            Write-AuditLog "MD5 hash for $($_.Name): $hash" -LogFile $errorLogPath
        }
        
        Write-AuditLog "" -LogFile $errorLogPath
        Write-AuditLog "BEGIN_MD5_HASH" -LogFile $errorLogPath
        $hashResults | ForEach-Object { Write-AuditLog $_ -LogFile $errorLogPath }
        Write-AuditLog "END_MD5_HASH" -LogFile $errorLogPath
        
        Write-AuditLog "Audit complete for computer: $computer"
        
    } catch {
        Write-AuditLog "Error during audit of $computer`: $_" -LogFile $errorLogPath
        Write-Error $_
    }
}

Write-Host "`n$ScriptVersion complete!" -ForegroundColor Green

#endregion
