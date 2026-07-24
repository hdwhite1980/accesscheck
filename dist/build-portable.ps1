<#
.SYNOPSIS
    Builds an unpackaged, self-contained folder plus a Start-menu shortcut.

.DESCRIPTION
    The fallback when MSIX signing is not available yet. No certificate, no installer:
    a folder that runs anywhere, and a shortcut so it behaves like an installed app.
    SmartScreen will warn on first run because the exe is unsigned - that is expected.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\AccessCheck",
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$distDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $distDir
$appProject = Join-Path $repoRoot "src\AccessCheck.App\AccessCheck.App.csproj"

Write-Host "Publishing to $InstallDir..." -ForegroundColor Cyan
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }

dotnet publish $appProject -c $Configuration -r win-x64 --self-contained true -o $InstallDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed." }

$exe = Join-Path $InstallDir "AccessCheck.exe"
if (-not (Test-Path $exe)) { throw "AccessCheck.exe not produced." }

$startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$shortcut = Join-Path $startMenu "AccessCheck.lnk"
$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut($shortcut)
$link.TargetPath = $exe
$link.WorkingDirectory = $InstallDir
$link.Description = "Least-privilege access broker"
$icon = Join-Path $distDir "Assets\AccessCheck.ico"
if (Test-Path $icon) { $link.IconLocation = $icon }
$link.Save()

Write-Host "`nInstalled to $InstallDir" -ForegroundColor Green
Write-Host "Start-menu shortcut: $shortcut" -ForegroundColor Gray
Write-Host "Settings and data stay in %APPDATA%\AccessCheck and survive reinstalls." -ForegroundColor Gray
