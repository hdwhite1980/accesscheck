<#
.SYNOPSIS
    Installs (or reinstalls) the locally built AccessCheck MSIX.
#>
[CmdletBinding()]
param([string]$MsixPath)

$ErrorActionPreference = "Stop"

if (-not $MsixPath) {
    $outDir = Join-Path $PSScriptRoot "out"
    $MsixPath = (Get-ChildItem $outDir -Filter "AccessCheck-*.msix" -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
    if (-not $MsixPath) { throw "No MSIX found in $outDir. Run build-msix.ps1 first." }
}

Write-Host "Installing $MsixPath" -ForegroundColor Cyan

$existing = Get-AppxPackage -Name "AHTS.AccessCheck" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Removing existing $($existing.Version)..."
    Remove-AppxPackage -Package $existing.PackageFullName
}

Add-AppxPackage -Path $MsixPath
$installed = Get-AppxPackage -Name "AHTS.AccessCheck"
Write-Host "Installed $($installed.Version)" -ForegroundColor Green
Write-Host "Launch it from the Start menu, or:" -ForegroundColor Gray
Write-Host "  explorer.exe shell:AppsFolder\$($installed.PackageFamilyName)!AccessCheck" -ForegroundColor Gray
