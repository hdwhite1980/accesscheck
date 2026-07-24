<#
.SYNOPSIS
    Permits installing signed apps that did not come from the Microsoft Store.

.DESCRIPTION
    Windows allows sideloading by default; a value of 0 means something turned it OFF
    deliberately - a security baseline, an Intune configuration profile, or group
    policy. This only flips the LOCAL setting. If the block comes from group policy or
    Intune, the managed value wins and this script says so rather than pretending to
    have fixed it.

    Sideloading still requires a trusted signature: it permits signed non-Store apps,
    it does not permit unsigned ones.
#>
[CmdletBinding()]
param([switch]$Disable)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this from an ELEVATED PowerShell."
}

$gpoPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx"
$gpo = Get-ItemProperty $gpoPath -ErrorAction SilentlyContinue

if ($gpo -and $null -ne $gpo.AllowAllTrustedApps -and $gpo.AllowAllTrustedApps -eq 0) {
    Write-Host "Sideloading is blocked by GROUP POLICY / Intune:" -ForegroundColor Red
    Write-Host "  $gpoPath\AllowAllTrustedApps = 0" -ForegroundColor Gray
    Write-Host ""
    Write-Host "A local change will be overwritten at the next policy refresh. Options:" -ForegroundColor Yellow
    Write-Host "  * Intune: Devices > Configuration > the profile setting" -ForegroundColor Gray
    Write-Host "            'App Store > Allow all trusted apps to install' -> Allowed" -ForegroundColor Gray
    Write-Host "  * GPO:    Computer Configuration > Administrative Templates > Windows" -ForegroundColor Gray
    Write-Host "            Components > App Package Deployment >" -ForegroundColor Gray
    Write-Host "            'Allow all trusted apps to install' -> Enabled" -ForegroundColor Gray
    Write-Host "  * Or skip MSIX entirely: .\dist\build-portable.ps1 needs no sideloading." -ForegroundColor Gray
    return
}

$unlockPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
if (-not (Test-Path $unlockPath)) {
    New-Item -Path $unlockPath -Force | Out-Null
}

$value = if ($Disable) { 0 } else { 1 }
Set-ItemProperty -Path $unlockPath -Name "AllowAllTrustedApps" -Value $value -Type DWord

$now = (Get-ItemProperty $unlockPath).AllowAllTrustedApps
if ($now -eq $value) {
    if ($Disable) {
        Write-Host "Sideloading disabled (AllowAllTrustedApps = 0)." -ForegroundColor Yellow
    } else {
        Write-Host "Sideloading enabled (AllowAllTrustedApps = 1)." -ForegroundColor Green
        Write-Host ""
        Write-Host "Next:  .\dist\install-local.ps1" -ForegroundColor Cyan
        Write-Host "Signed packages only - this does not permit unsigned apps." -ForegroundColor Gray
    }
} else {
    Write-Host "The value did not stick - something is enforcing it." -ForegroundColor Red
}
