<#
.SYNOPSIS
    Trusts the AccessCheck signing certificate so its MSIX will install.

.DESCRIPTION
    A self-signed certificate is its OWN root. Windows builds a chain from the
    signature and requires that chain to terminate in a trusted root, so:

      Trusted Root Certification Authorities (Root)  makes the CHAIN valid
      Trusted People (TrustedPeople)                 authorises the PUBLISHER to sideload

    Importing to TrustedPeople alone leaves the chain untrusted and the install fails
    with 0x800B010A, which is exactly what it sounds like: the root is not trusted.
    Both stores are needed for a self-signed certificate. A CA-issued certificate needs
    neither, because its root already ships in Windows.

    Must be run elevated - both stores are machine-wide.
#>
[CmdletBinding()]
param(
    [string]$CerPath,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this from an ELEVATED PowerShell - both certificate stores are machine-wide."
}

if (-not $CerPath) { $CerPath = Join-Path $PSScriptRoot "AccessCheck-signing.cer" }
if (-not (Test-Path $CerPath)) {
    throw "Certificate not found at $CerPath. Run new-selfsigned-cert.ps1 first."
}

$cer = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CerPath
$thumb = $cer.Thumbprint
$selfSigned = ($cer.Subject -eq $cer.Issuer)

Write-Host "Certificate: $($cer.Subject)"
Write-Host "  Thumbprint:  $thumb"
Write-Host "  Self-signed: $selfSigned"
Write-Host "  Expires:     $($cer.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host ""

# A self-signed cert must be its own trusted root; a CA-issued one already chains.
$stores = if ($selfSigned) { @("Root", "TrustedPeople") } else { @("TrustedPeople") }

foreach ($store in $stores) {
    $path = "Cert:\LocalMachine\$store"
    $present = Get-ChildItem $path -ErrorAction SilentlyContinue |
               Where-Object { $_.Thumbprint -eq $thumb }

    if ($Remove) {
        if ($present) {
            $present | Remove-Item -Force
            Write-Host "[removed] $store" -ForegroundColor Yellow
        } else {
            Write-Host "[absent]  $store - nothing to remove" -ForegroundColor Gray
        }
        continue
    }

    if ($present) {
        Write-Host "[already] $store" -ForegroundColor Gray
    } else {
        Import-Certificate -FilePath $CerPath -CertStoreLocation $path | Out-Null
        Write-Host "[added]   $store" -ForegroundColor Green
    }
}

if ($Remove) { Write-Host "`nDone." -ForegroundColor Green; return }

# Prove the chain now builds, rather than assuming it does.
Write-Host ""
$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chain.ChainPolicy.RevocationMode = "NoCheck"
$built = $chain.Build($cer)

if ($built) {
    Write-Host "Chain builds successfully - the package will install." -ForegroundColor Green
    Write-Host ""
    Write-Host "Next:  .\dist\install-local.ps1" -ForegroundColor Cyan
} else {
    Write-Host "Chain still does not build:" -ForegroundColor Red
    foreach ($status in $chain.ChainStatus) {
        Write-Host "  $($status.Status): $($status.StatusInformation.Trim())" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "If the certificate has expired, create a new one and re-sign the package." -ForegroundColor Gray
}
