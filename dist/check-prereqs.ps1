<#
.SYNOPSIS
    Reports which packaging prerequisites are already on this machine.

.DESCRIPTION
    Run this before installing anything - Visual Studio ships the Windows SDK, so the
    tools are often already present under a versioned Windows Kits folder.
#>
[CmdletBinding()]
param()

# The SDK ships each tool for arm, arm64, x64 and x86. Picking the wrong architecture
# yields a binary that simply refuses to run, with an unhelpful error, so match the
# machine explicitly rather than taking whatever the filesystem returns first.
function Get-NativeArchFolder {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { return "x64" }
        "ARM64" { return "arm64" }
        "x86"   { return "x86" }
        default { return "x64" }
    }
}

function Find-Tool([string]$name) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $arch = Get-NativeArchFolder

    $roots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Microsoft Visual Studio",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio"
    ) | Where-Object { Test-Path $_ }

    $all = @()
    foreach ($root in $roots) {
        $all += Get-ChildItem -Path $root -Filter $name -Recurse -ErrorAction SilentlyContinue
    }
    if ($all.Count -eq 0) { return $null }

    # Native architecture first, newest SDK version first.
    $native = $all | Where-Object { $_.FullName -match "\\$arch\\" } |
              Sort-Object { $_.VersionInfo.FileVersionRaw } -Descending |
              Select-Object -First 1
    if ($native) { return $native.FullName }

    # x64 tools run fine on ARM64 Windows under emulation, so try that next.
    $x64 = $all | Where-Object { $_.FullName -match "\\x64\\" } |
           Sort-Object { $_.VersionInfo.FileVersionRaw } -Descending |
           Select-Object -First 1
    if ($x64) { return $x64.FullName }

    return ($all | Sort-Object { $_.VersionInfo.FileVersionRaw } -Descending |
            Select-Object -First 1).FullName
}

Write-Host "AccessCheck packaging prerequisites`n" -ForegroundColor Cyan

$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if ($dotnet) {
    $sdkList = @(dotnet --list-sdks)
    $latestSdk = if ($sdkList.Count -gt 0) { $sdkList[-1] } else { "(none reported)" }
    Write-Host "[ok]      .NET SDK" -ForegroundColor Green
    Write-Host "          $latestSdk" -ForegroundColor Gray
} else {
    Write-Host "[MISSING] .NET SDK - winget install Microsoft.DotNet.SDK.8" -ForegroundColor Red
}

$nativeArch = Get-NativeArchFolder
Write-Host "[info]    machine architecture: $env:PROCESSOR_ARCHITECTURE (want $nativeArch tools)" -ForegroundColor Gray

foreach ($tool in "makeappx.exe", "signtool.exe") {
    $path = Find-Tool $tool
    if ($path) {
        $toolArch = if ($path -match "\\(arm64|arm|x64|x86)\\") { $Matches[1] } else { "unknown" }
        $mismatch = ($toolArch -ne "unknown" -and $toolArch -ne $nativeArch -and $toolArch -ne "x64")
        if ($mismatch) {
            Write-Host "[WARN]    $tool found, but it is $toolArch on a $nativeArch machine" -ForegroundColor Yellow
            Write-Host "          $path" -ForegroundColor Gray
            Write-Host "          It will not run. Install the $nativeArch SDK components." -ForegroundColor Yellow
        } else {
            Write-Host "[ok]      $tool ($toolArch)" -ForegroundColor Green
            Write-Host "          $path" -ForegroundColor Gray
        }
    } else {
        Write-Host "[MISSING] $tool - needed only for the MSIX route" -ForegroundColor Yellow
    }
}

$certs = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
         Where-Object { $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" -and $_.HasPrivateKey }
if ($certs) {
    Write-Host "[ok]      code-signing certificate(s):" -ForegroundColor Green
    foreach ($c in $certs) {
        Write-Host "          $($c.Subject)  $($c.Thumbprint)  expires $($c.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
    }
} else {
    Write-Host "[MISSING] code-signing certificate - .\dist\new-selfsigned-cert.ps1" -ForegroundColor Yellow
}

$pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
if ($pwsh) {
    Write-Host "[ok]      PowerShell 7 (for Exchange/Purview features)" -ForegroundColor Green
} else {
    Write-Host "[note]    PowerShell 7 not found - Windows PowerShell 5.1 works, but 7 is better" -ForegroundColor Gray
    Write-Host "          winget install Microsoft.PowerShell" -ForegroundColor Gray
}

Write-Host @"

If makeappx/signtool are missing, either:
  * install the SDK  ->  winget search "Windows SDK"   then install a versioned id,
                         e.g. winget install Microsoft.WindowsSDK.10.0.26100
  * or Visual Studio Installer -> Modify -> Individual components ->
    "Windows 11 SDK (any version)"
  * or skip MSIX entirely and run .\dist\build-portable.ps1 - no SDK, no certificate.
"@ -ForegroundColor Gray
