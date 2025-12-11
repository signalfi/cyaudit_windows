<#
.SYNOPSIS
    Diagnostic script to check PowerSTIG prerequisites

.DESCRIPTION
    Checks all prerequisites required for PowerSTIG to run successfully
    and provides remediation steps for any failures
#>

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PowerSTIG Prerequisites Check" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$allChecksPassed = $true

# 1. Check PowerShell Version
Write-Host "[1/5] Checking PowerShell version..." -ForegroundColor Yellow
$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -eq 5 -and $psVersion.Minor -ge 1) {
    Write-Host "  [OK] PowerShell $($psVersion.ToString()) is compatible" -ForegroundColor Green
} else {
    Write-Host "  [X] PowerShell version $($psVersion.ToString()) is NOT compatible" -ForegroundColor Red
    Write-Host "      PowerSTIG requires PowerShell 5.1" -ForegroundColor Red
    Write-Host "      Solution: Use Windows PowerShell 5.1 (not PowerShell 7+)" -ForegroundColor Yellow
    $allChecksPassed = $false
}

# 2. Check PowerSTIG Module
Write-Host "`n[2/5] Checking PowerSTIG module..." -ForegroundColor Yellow
$powerSTIG = Get-Module -ListAvailable -Name PowerSTIG -ErrorAction SilentlyContinue
if ($powerSTIG) {
    Write-Host "  [OK] PowerSTIG module found (Version: $($powerSTIG.Version))" -ForegroundColor Green
} else {
    Write-Host "  [X] PowerSTIG module not found" -ForegroundColor Red
    Write-Host "      Solution: Install-Module -Name PowerSTIG -Force -Scope AllUsers" -ForegroundColor Yellow
    $allChecksPassed = $false
}

# 3. Check Required DSC Modules
Write-Host "`n[3/5] Checking required DSC resource modules..." -ForegroundColor Yellow
$requiredModules = @(
    'PSDesiredStateConfiguration',
    'AuditPolicyDsc',
    'SecurityPolicyDsc',
    'WindowsDefenderDsc',
    'ComputerManagementDsc'
)

$missingModules = @()
foreach ($moduleName in $requiredModules) {
    $module = Get-Module -ListAvailable -Name $moduleName -ErrorAction SilentlyContinue
    if ($module) {
        Write-Host "  [OK] $moduleName found (Version: $($module.Version))" -ForegroundColor Green
    } else {
        Write-Host "  [X] $moduleName not found" -ForegroundColor Red
        $missingModules += $moduleName
    }
}

if ($missingModules.Count -gt 0) {
    Write-Host "`n  Missing modules: $($missingModules -join ', ')" -ForegroundColor Red
    Write-Host "  Solution: Install-Module -Name $($missingModules[0]) -Force -Scope AllUsers" -ForegroundColor Yellow
    Write-Host "            (Repeat for each missing module)" -ForegroundColor Yellow
    $allChecksPassed = $false
}

# 4. Check WinRM Service
Write-Host "`n[4/5] Checking WinRM service..." -ForegroundColor Yellow
try {
    $winrmService = Get-Service -Name WinRM -ErrorAction Stop
    if ($winrmService.Status -eq 'Running') {
        Write-Host "  [OK] WinRM service is running" -ForegroundColor Green
        
        # Test WinRM connectivity
        try {
            Test-WSMan -ComputerName localhost -ErrorAction Stop | Out-Null
            Write-Host "  [OK] WinRM connectivity test passed" -ForegroundColor Green
        } catch {
            Write-Host "  [X] WinRM connectivity test failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "      Solution: Run 'Enable-PSRemoting -Force' as Administrator" -ForegroundColor Yellow
            $allChecksPassed = $false
        }
    } else {
        Write-Host "  [X] WinRM service is not running (Status: $($winrmService.Status))" -ForegroundColor Red
        Write-Host "      Solution: Start-Service WinRM" -ForegroundColor Yellow
        Write-Host "                Or: Enable-PSRemoting -Force" -ForegroundColor Yellow
        $allChecksPassed = $false
    }
} catch {
    Write-Host "  [X] WinRM service not found or inaccessible: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "      Solution: Enable-PSRemoting -Force (as Administrator)" -ForegroundColor Yellow
    $allChecksPassed = $false
}

# 5. Check PowerShell Gallery Access (if modules need installation)
if (-not $allChecksPassed) {
    Write-Host "`n[5/5] Checking PowerShell Gallery access..." -ForegroundColor Yellow
    try {
        $psGallery = Get-PSRepository -Name PSGallery -ErrorAction Stop
        Write-Host "  [OK] PowerShell Gallery repository found" -ForegroundColor Green
        
        # Check if trusted
        if ($psGallery.InstallationPolicy -eq 'Trusted') {
            Write-Host "  [OK] PowerShell Gallery is trusted" -ForegroundColor Green
        } else {
            Write-Host "  [!] PowerShell Gallery is not trusted (Policy: $($psGallery.InstallationPolicy))" -ForegroundColor Yellow
            Write-Host "      Solution: Set-PSRepository -Name PSGallery -InstallationPolicy Trusted" -ForegroundColor Yellow
        }
        
        # Test connectivity
        try {
            $null = Find-Module -Name PowerSTIG -ErrorAction Stop
            Write-Host "  [OK] Can access PowerShell Gallery" -ForegroundColor Green
        } catch {
            Write-Host "  [X] Cannot access PowerShell Gallery: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "      Solution: Check internet connectivity and firewall settings" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [X] PowerShell Gallery not configured: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "      Solution: Register-PSRepository -Default" -ForegroundColor Yellow
    }
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
if ($allChecksPassed) {
    Write-Host "All prerequisites satisfied!" -ForegroundColor Green
    Write-Host "PowerSTIG should run successfully." -ForegroundColor Green
} else {
    Write-Host "Some prerequisites are missing!" -ForegroundColor Red
    Write-Host "`nTo install missing modules, run as Administrator:" -ForegroundColor Yellow
    Write-Host "  Install-Module -Name PowerSTIG -Force -Scope AllUsers" -ForegroundColor White
    foreach ($module in $missingModules) {
        Write-Host "  Install-Module -Name $module -Force -Scope AllUsers" -ForegroundColor White
    }
    Write-Host "`nTo enable WinRM:" -ForegroundColor Yellow
    Write-Host "  Enable-PSRemoting -Force" -ForegroundColor White
}
Write-Host "========================================`n" -ForegroundColor Cyan

