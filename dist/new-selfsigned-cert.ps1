<#
.SYNOPSIS
    Creates a self-signed code-signing certificate for internal AccessCheck builds.

.DESCRIPTION
    Good enough for your own machines and a lab tenant. NOT good enough for wide
    distribution: every machine that installs the package must trust this certificate,
    which means importing it into Trusted People or Trusted Root. For anything beyond
    your own kit, buy an OV/EV code-signing certificate instead - the same decision you
    made for the Mac build with a Developer ID.

.PARAMETER Subject
    Must match the Publisher in AppxManifest.xml. build-msix.ps1 copies it across
    automatically, so the value here is the one that wins.
#>
[CmdletBinding()]
param(
    [string]$Subject = "CN=Accelerated Hues Technology Services LLC",
    [int]$ValidYears = 3
)

$ErrorActionPreference = "Stop"

$existing = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $Subject -and $_.HasPrivateKey }
if ($existing) {
    Write-Host "A certificate with this subject already exists:" -ForegroundColor Yellow
    $existing | Format-List Subject, Thumbprint, NotAfter
    Write-Host "Re-use it, or delete it first if you want a new one."
    return
}

$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -KeyUsage DigitalSignature `
    -FriendlyName "AccessCheck code signing" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears($ValidYears) `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")

Write-Host "`nCertificate created." -ForegroundColor Green
Write-Host "  Subject:    $($cert.Subject)"
Write-Host "  Thumbprint: $($cert.Thumbprint)"
Write-Host "  Expires:    $($cert.NotAfter)"

$cerPath = Join-Path $PSScriptRoot "AccessCheck-signing.cer"
Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
Write-Host "`nPublic certificate exported to: $cerPath"

Write-Host @"

Next steps
  1. Build:   .\dist\build-msix.ps1 -CertThumbprint $($cert.Thumbprint)
  2. Trust it on every machine that will install the package (admin PowerShell):
       Import-Certificate -FilePath "$cerPath" -CertStoreLocation Cert:\LocalMachine\TrustedPeople
  3. Install: Add-AppxPackage -Path .\dist\out\AccessCheck-<version>.msix

Without step 2 the install fails with a trust error - that is the certificate doing
its job, not a broken package.
"@ -ForegroundColor Gray
