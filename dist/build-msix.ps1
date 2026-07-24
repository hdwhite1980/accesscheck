<#
.SYNOPSIS
    Publishes AccessCheck and packages it as a signed MSIX.

.DESCRIPTION
    Run from the repository root or from dist\ - paths are resolved relative to this
    script, so the working directory does not matter. (The Mac build learned that the
    hard way: two scripts disagreeing about where the output lived cost an afternoon.)

    Steps:
      1. dotnet publish, self-contained win-x64
      2. stage the manifest and assets alongside the binaries
      3. rewrite Publisher in the manifest to match the signing certificate exactly
      4. makeappx pack
      5. signtool sign

.PARAMETER CertThumbprint
    Thumbprint of a code-signing certificate in Cert:\CurrentUser\My.
    Omit to build an UNSIGNED package (useful for inspection; it will not install).

.PARAMETER Version
    Four-part version for the package, e.g. 0.1.0.0. Defaults to the manifest value.

.EXAMPLE
    .\dist\build-msix.ps1 -CertThumbprint ABC123...
#>
[CmdletBinding()]
param(
    [string]$CertThumbprint,
    [string]$Version,
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$distDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $distDir
$stageDir = Join-Path $distDir "stage"
$outDir = Join-Path $distDir "out"
$appProject = Join-Path $repoRoot "src\AccessCheck.App\AccessCheck.App.csproj"

Write-Host "Repository: $repoRoot" -ForegroundColor Cyan

# ---------- locate the Windows SDK tools ----------

function Find-SdkTool([string]$name) {
    $found = Get-Command $name -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }

    $roots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin",
        "${env:ProgramFiles(x86)}\Microsoft SDKs\ClickOnce\SignTool",
        "${env:ProgramFiles}\Microsoft Visual Studio",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio"
    ) | Where-Object { Test-Path $_ }

    # Match the machine's architecture: an arm64 signtool on an x64 box simply will
    # not execute, and the resulting error says nothing useful.
    $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { "x64" }
        "ARM64" { "arm64" }
        "x86"   { "x86" }
        default { "x64" }
    }

    $all = @()
    foreach ($root in $roots) {
        $all += Get-ChildItem -Path $root -Filter $name -Recurse -ErrorAction SilentlyContinue
    }
    if ($all.Count -eq 0) { return $null }

    foreach ($pattern in @("\\$arch\\", "\\x64\\")) {
        $hit = $all | Where-Object { $_.FullName -match $pattern } |
               Sort-Object { $_.VersionInfo.FileVersionRaw } -Descending |
               Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }

    return ($all | Sort-Object { $_.VersionInfo.FileVersionRaw } -Descending |
            Select-Object -First 1).FullName
}

$makeappx = Find-SdkTool "makeappx.exe"
$signtool = Find-SdkTool "signtool.exe"

if (-not $makeappx) {
    throw @"
makeappx.exe not found - the Windows SDK provides it.

Check whether you already have it (Visual Studio installs it):
    Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Filter makeappx.exe -Recurse

To install, pick whichever works on this machine:

  1. winget, versioned package id (the plain 'Microsoft.WindowsSDK' id was retired):
         winget search "Windows SDK"
         winget install Microsoft.WindowsSDK.10.0.26100
         # older but equally fine:
         winget install Microsoft.WindowsSDK.10.0.22621

  2. Visual Studio Installer -> Modify -> Individual components ->
     tick "Windows 11 SDK (any version)"

  3. Direct download:
         https://developer.microsoft.com/windows/downloads/windows-sdk/
     Only the "Windows SDK Signing Tools for Desktop Apps" component is needed -
     you can untick everything else and the install drops to a few hundred MB.

If you would rather not install the SDK at all, use the portable route instead:
    .\dist\build-portable.ps1
It produces an installed-feeling app with a Start-menu shortcut and needs no SDK
and no certificate.
"@
}
Write-Host "makeappx: $makeappx"
if ($signtool) { Write-Host "signtool: $signtool" }

# ---------- 1. publish ----------

Write-Host "`nPublishing ($Configuration, win-x64, self-contained)..." -ForegroundColor Cyan
if (Test-Path $stageDir) { Remove-Item $stageDir -Recurse -Force }
New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

dotnet publish $appProject `
    -c $Configuration `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=false `
    -o $stageDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed." }

$exe = Join-Path $stageDir "AccessCheck.exe"
if (-not (Test-Path $exe)) {
    throw "AccessCheck.exe is missing from $stageDir - check the AssemblyName in the csproj."
}

# ---------- 2. stage manifest and assets ----------

Write-Host "Staging manifest and assets..." -ForegroundColor Cyan
Copy-Item (Join-Path $distDir "AppxManifest.xml") $stageDir -Force
Copy-Item (Join-Path $distDir "Assets") (Join-Path $stageDir "Assets") -Recurse -Force

$manifestPath = Join-Path $stageDir "AppxManifest.xml"
[xml]$manifest = Get-Content $manifestPath

if ($Version) {
    if ($Version -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        throw "Version must have four parts, e.g. 0.1.0.0"
    }
    $manifest.Package.Identity.Version = $Version
    Write-Host "  version set to $Version"
}

# ---------- 3. align Publisher with the certificate ----------

$cert = $null
if ($CertThumbprint) {
    $cert = Get-ChildItem "Cert:\CurrentUser\My\$CertThumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) {
        $cert = Get-ChildItem "Cert:\LocalMachine\My\$CertThumbprint" -ErrorAction SilentlyContinue
    }
    if (-not $cert) { throw "No certificate with thumbprint $CertThumbprint in CurrentUser\My or LocalMachine\My." }

    # Windows compares these byte for byte; deriving it removes the guesswork.
    $manifest.Package.Identity.Publisher = $cert.Subject
    Write-Host "  publisher set from certificate: $($cert.Subject)"
}

$manifest.Save($manifestPath)

# ---------- 4. pack ----------

New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$packageVersion = $manifest.Package.Identity.Version
$msixPath = Join-Path $outDir "AccessCheck-$packageVersion.msix"
if (Test-Path $msixPath) { Remove-Item $msixPath -Force }

Write-Host "`nPacking MSIX..." -ForegroundColor Cyan
& $makeappx pack /d $stageDir /p $msixPath /o
if ($LASTEXITCODE -ne 0) { throw "makeappx failed." }

# ---------- 5. sign ----------

if ($cert) {
    if (-not $signtool) { throw "signtool.exe not found, but a certificate was supplied." }
    Write-Host "Signing..." -ForegroundColor Cyan
    & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /t http://timestamp.digicert.com $msixPath
    if ($LASTEXITCODE -ne 0) { throw "signtool failed." }
    Write-Host "Signed." -ForegroundColor Green

    # A self-signed certificate cannot chain to a trusted root until it is imported, so
    # `signtool verify` failing here says nothing about the package - it is a statement
    # about this machine's trust store. Treat it as informational for self-signed certs
    # and only fail the build when a CA-issued certificate does not verify.
    $isSelfSigned = ($cert.Subject -eq $cert.Issuer)

    & $signtool verify /pa $msixPath 2>&1 | Out-Null
    $verified = ($LASTEXITCODE -eq 0)

    if ($verified) {
        Write-Host "Signature verified against the machine's trust store." -ForegroundColor Green
    }
    elseif ($isSelfSigned) {
        $inTrustedPeople = Get-ChildItem Cert:\LocalMachine\TrustedPeople -ErrorAction SilentlyContinue |
                           Where-Object { $_.Thumbprint -eq $cert.Thumbprint }

        Write-Host ""
        Write-Host "Package is signed, but not yet TRUSTED on this machine." -ForegroundColor Yellow
        Write-Host "That is expected for a self-signed certificate - nothing is wrong with the package." -ForegroundColor Gray

        if (-not $inTrustedPeople) {
            $cerPath = Join-Path $distDir "AccessCheck-signing.cer"
            if (-not (Test-Path $cerPath)) {
                Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
                Write-Host "Exported the public certificate to $cerPath" -ForegroundColor Gray
            }
            Write-Host ""
            Write-Host "Trust it once, from an ADMIN PowerShell:" -ForegroundColor Cyan
            Write-Host "    Import-Certificate -FilePath `"$cerPath`" -CertStoreLocation Cert:\LocalMachine\TrustedPeople" -ForegroundColor White
            Write-Host ""
            Write-Host "Then install:" -ForegroundColor Cyan
            Write-Host "    .\dist\install-local.ps1" -ForegroundColor White
        }
        else {
            Write-Host "The certificate IS in LocalMachine\TrustedPeople, so the install should work." -ForegroundColor Gray
            Write-Host "(`signtool verify /pa` checks Trusted Root specifically, which is stricter" -ForegroundColor Gray
            Write-Host " than what MSIX installation requires.)" -ForegroundColor Gray
        }
    }
    else {
        throw "Signature verification failed for a CA-issued certificate - investigate before distributing."
    }
}
else {
    Write-Warning "Package is UNSIGNED and will not install. Re-run with -CertThumbprint."
}

Write-Host "`nDone: $msixPath" -ForegroundColor Green
Write-Host "Install locally with:  Add-AppxPackage -Path `"$msixPath`"" -ForegroundColor Gray
