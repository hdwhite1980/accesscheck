<#
.SYNOPSIS
    Explains why an MSIX will or will not install on this machine.

.DESCRIPTION
    Reads the signature off the package, reports the signing certificate, checks each
    trust store, and builds the chain - so "install is greyed out" becomes a specific
    reason rather than a guess.
#>
[CmdletBinding()]
param([string]$MsixPath)

$ErrorActionPreference = "Stop"

if (-not $MsixPath) {
    $outDir = Join-Path $PSScriptRoot "out"
    $MsixPath = (Get-ChildItem $outDir -Filter "AccessCheck-*.msix" -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
    if (-not $MsixPath) { throw "No MSIX found in $outDir." }
}

Write-Host "Package: $MsixPath`n" -ForegroundColor Cyan

$sig = Get-AuthenticodeSignature -FilePath $MsixPath
Write-Host "Signature status: $($sig.Status)" -ForegroundColor $(
    if ($sig.Status -eq "Valid") { "Green" } else { "Yellow" })
if ($sig.StatusMessage) { Write-Host "  $($sig.StatusMessage)" -ForegroundColor Gray }

if (-not $sig.SignerCertificate) {
    Write-Host "`nPackage is UNSIGNED - rebuild with -CertThumbprint." -ForegroundColor Red
    return
}

$cert = $sig.SignerCertificate
$thumb = $cert.Thumbprint
$selfSigned = ($cert.Subject -eq $cert.Issuer)

Write-Host ""
Write-Host "Signed by:   $($cert.Subject)"
Write-Host "  Issuer:      $($cert.Issuer)"
Write-Host "  Thumbprint:  $thumb"
Write-Host "  Self-signed: $selfSigned"
Write-Host "  Valid until: $($cert.NotAfter.ToString('yyyy-MM-dd'))"
if ($cert.NotAfter -lt (Get-Date)) {
    Write-Host "  EXPIRED - re-issue the certificate and re-sign." -ForegroundColor Red
}

Write-Host "`nTrust stores:" -ForegroundColor Cyan
$needed = if ($selfSigned) { @("Root", "TrustedPeople") } else { @("TrustedPeople") }
$missing = @()
foreach ($store in @("Root", "TrustedPeople")) {
    $present = Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue |
               Where-Object { $_.Thumbprint -eq $thumb }
    $required = $needed -contains $store
    if ($present) {
        Write-Host "  [present] LocalMachine\$store" -ForegroundColor Green
    } elseif ($required) {
        Write-Host "  [MISSING] LocalMachine\$store  <- required" -ForegroundColor Red
        $missing += $store
    } else {
        Write-Host "  [absent]  LocalMachine\$store  (not required)" -ForegroundColor Gray
    }
}

Write-Host "`nChain:" -ForegroundColor Cyan
$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chain.ChainPolicy.RevocationMode = "NoCheck"
if ($chain.Build($cert)) {
    Write-Host "  builds successfully" -ForegroundColor Green
} else {
    foreach ($status in $chain.ChainStatus) {
        Write-Host "  $($status.Status): $($status.StatusInformation.Trim())" -ForegroundColor Red
    }
}

# Sideloading policy. Trust can be perfect and the install still blocked here.
Write-Host "`nSideloading policy:" -ForegroundColor Cyan
$sideloadBlocked = $false

$unlock = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" `
          -ErrorAction SilentlyContinue
$gpo = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" `
       -ErrorAction SilentlyContinue

if ($gpo -and $null -ne $gpo.AllowAllTrustedApps) {
    if ($gpo.AllowAllTrustedApps -eq 0) {
        Write-Host "  BLOCKED by GROUP POLICY (Policies\Microsoft\Windows\Appx\AllowAllTrustedApps = 0)" -ForegroundColor Red
        Write-Host "  A managed setting - a local registry change will be reverted." -ForegroundColor Gray
        $sideloadBlocked = $true
    } else {
        Write-Host "  allowed by group policy" -ForegroundColor Green
    }
}
elseif ($unlock -and $null -ne $unlock.AllowAllTrustedApps) {
    if ($unlock.AllowAllTrustedApps -eq 0) {
        Write-Host "  DISABLED locally (AppModelUnlock\AllowAllTrustedApps = 0)" -ForegroundColor Red
        $sideloadBlocked = $true
    } else {
        Write-Host "  allowed" -ForegroundColor Green
    }
}
else {
    Write-Host "  no explicit setting - Windows allows sideloading by default" -ForegroundColor Green
}

# The verdict must account for EVERY blocker found above, not just the certificate.
Write-Host ""
$blockers = @()
if ($missing.Count -gt 0) { $blockers += "certificate not in: $($missing -join ', ')" }
if ($sideloadBlocked)     { $blockers += "sideloading disabled" }

if ($blockers.Count -eq 0) {
    Write-Host "Nothing blocking - install with .\dist\install-local.ps1" -ForegroundColor Green
} else {
    Write-Host "BLOCKED: $($blockers -join '; ')" -ForegroundColor Red
    Write-Host ""
    if ($missing.Count -gt 0) {
        Write-Host "  Certificate - from an ELEVATED PowerShell:" -ForegroundColor Cyan
        Write-Host "      .\dist\trust-cert.ps1" -ForegroundColor White
    }
    if ($sideloadBlocked) {
        Write-Host "  Sideloading - from an ELEVATED PowerShell:" -ForegroundColor Cyan
        Write-Host "      .\dist\enable-sideloading.ps1" -ForegroundColor White
    }
}
