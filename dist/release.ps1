<#
.SYNOPSIS
    Builds, signs and installs a new AccessCheck MSIX in one step.

.DESCRIPTION
    Wraps the individual scripts in the order they actually need to run, and stops with a
    specific reason rather than a generic failure. MSIX refuses to install a package whose
    version is not HIGHER than the one already installed, so -Version is required and is
    written into both the manifest and the assembly before building.

.PARAMETER Version
    Four-part, e.g. 0.2.0.0. Must exceed the installed version.

.PARAMETER CertThumbprint
    Code-signing certificate in Cert:\CurrentUser\My. Omit to be prompted with the
    thumbprints already present.

.EXAMPLE
    .\dist\release.ps1 -Version 0.2.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$CertThumbprint,
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"

if ($Version -notmatch '^\d+\.\d+\.\d+\.\d+$') {
    throw "Version must have four parts, e.g. 0.2.0.0"
}

$distDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $distDir

# --- what is already installed? MSIX will silently keep the old binary otherwise ---
$installed = Get-AppxPackage -Name "AHTS.AccessCheck" -ErrorAction SilentlyContinue
if ($installed) {
    Write-Host "Installed now: $($installed.Version)" -ForegroundColor Gray
    if ([version]$Version -le [version]$installed.Version) {
        throw "Version $Version is not higher than the installed $($installed.Version). " +
              "Windows would refuse the install and you would keep running the old build."
    }
}

# --- certificate ---
if (-not $CertThumbprint) {
    $certs = Get-ChildItem Cert:\CurrentUser\My |
             Where-Object { $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" -and $_.HasPrivateKey }
    if ($certs.Count -eq 0) {
        throw "No code-signing certificate found. Run .\dist\new-selfsigned-cert.ps1 first."
    }
    if ($certs.Count -eq 1) {
        $CertThumbprint = $certs[0].Thumbprint
        Write-Host "Using certificate: $($certs[0].Subject)" -ForegroundColor Gray
    } else {
        Write-Host "Several code-signing certificates are present:" -ForegroundColor Yellow
        $certs | Format-Table Subject, Thumbprint, NotAfter -AutoSize
        throw "Re-run with -CertThumbprint <one of the above>."
    }
}

# --- keep the assembly version in step with the package version ---
$csproj = Join-Path $repoRoot "src\AccessCheck.App\AccessCheck.App.csproj"
$short = ($Version -split '\.')[0..2] -join '.'
$text = Get-Content $csproj -Raw
$text = $text -replace '<Version>[^<]*</Version>', "<Version>$short</Version>"
$text = $text -replace '<FileVersion>[^<]*</FileVersion>', "<FileVersion>$Version</FileVersion>"
$text = $text -replace '<AssemblyVersion>[^<]*</AssemblyVersion>', "<AssemblyVersion>$Version</AssemblyVersion>"
Set-Content -Path $csproj -Value $text -NoNewline
Write-Host "Assembly version set to $Version" -ForegroundColor Gray

# --- build, sign ---
Write-Host "`nBuilding and signing..." -ForegroundColor Cyan
& (Join-Path $distDir "build-msix.ps1") -CertThumbprint $CertThumbprint -Version $Version

# --- trust, if this is a self-signed certificate ---
$cert = Get-ChildItem "Cert:\CurrentUser\My\$CertThumbprint" -ErrorAction SilentlyContinue
if ($cert -and $cert.Subject -eq $cert.Issuer) {
    $inRoot = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
              Where-Object { $_.Thumbprint -eq $CertThumbprint }
    if (-not $inRoot) {
        Write-Host "`nThis certificate is self-signed and not yet trusted." -ForegroundColor Yellow
        Write-Host "Run ONCE from an ELEVATED PowerShell, then re-run this script:" -ForegroundColor Yellow
        Write-Host "    .\dist\trust-cert.ps1" -ForegroundColor White
        return
    }
}

if ($SkipInstall) { Write-Host "`nBuilt. Skipping install as asked." -ForegroundColor Green; return }

Write-Host "`nInstalling..." -ForegroundColor Cyan
& (Join-Path $distDir "install-local.ps1")

Write-Host "`nDone. The app header shows the running version - confirm it reads $short." -ForegroundColor Green
