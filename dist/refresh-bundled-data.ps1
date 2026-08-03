<#
.SYNOPSIS
    Refreshes the reference data that ships inside the package.

.DESCRIPTION
    Two files are bundled because no tenant can produce them for itself:

      purview-roles.json          Microsoft's published Purview role list. The Security and
                                  Compliance session cannot report what a role contains.
      exchange-descriptions.json  Exchange and Purview cmdlet descriptions. No API supplies
                                  these, and Exchange Online's proxy cmdlets carry no help.

    Both are identical for every tenant. Shipping without them means every new install
    silently reproduces failures that were already fixed — 8 usable Purview roles instead
    of 119, and a model reading cmdlet names with nothing to check them against.

    Run this before cutting a release so the package carries current data. Microsoft
    revises both regularly.

.EXAMPLE
    .\dist\refresh-bundled-data.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$distDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $distDir
$dataDir  = Join-Path $repoRoot "src\AccessCheck.App\data"

New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

# Import into the app's data folder rather than %APPDATA%, so the build picks up exactly
# what was just fetched instead of whatever happens to be on the machine.
$purview = Join-Path $dataDir "purview-roles.md"
$purviewJson = Join-Path $dataDir "purview-roles.json"
$exoJson = Join-Path $dataDir "exchange-descriptions.json"

Write-Host "Refreshing Purview role list..." -ForegroundColor Cyan
& (Join-Path $distDir "import-purview-roles.ps1") -Path $purview

Write-Host "Refreshing Exchange cmdlet descriptions..." -ForegroundColor Cyan
& (Join-Path $distDir "import-exchange-descriptions.ps1") -Path $exoJson

Write-Host ""
foreach ($f in @($purview, $exoJson)) {
    if (Test-Path $f) {
        $kb = [math]::Round((Get-Item $f).Length / 1KB)
        Write-Host ("  {0,-32} {1} KB" -f (Split-Path $f -Leaf), $kb) -ForegroundColor Gray
    } else {
        # LOUDLY, NOT QUIETLY. A package built without these looks healthy and answers
        # nothing for two whole services.
        Write-Warning "MISSING: $f — the package would ship without it."
    }
}

Write-Host ""
Write-Host "Bundled data is current. Build and package as usual." -ForegroundColor Green
Write-Host "purview-roles.md ships as-is — the app parses it on first use, so the parser" -ForegroundColor Gray
Write-Host "and the data can never drift apart inside the package." -ForegroundColor Gray
