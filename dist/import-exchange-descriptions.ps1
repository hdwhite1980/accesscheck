<#
.SYNOPSIS
    Imports Microsoft's Exchange and Purview cmdlet descriptions into AccessCheck.

.DESCRIPTION
    Exchange and Purview are the only services in this app whose permissions arrive with NO
    description, and every recommendation failure in those services traces back to that.
    Asked to remove malicious MESSAGES, the model proposed Remove-Mailbox — which deletes
    the mailbox and the user account with it — because a name was all it had to reason from.
    Asked to delegate a mailbox it declined outright, saying the candidate list held no
    described permission for the task, while Add-MailboxFolderPermission sat in that list
    with an empty description.

    Get-Help cannot fill the gap: Exchange Online's REST mode generates proxy cmdlets at
    connection time and they ship no help content, so Get-Help returns the syntax block and
    an empty synopsis for every one.

    Microsoft publishes the descriptions as markdown on GitHub — one file per cmdlet, ~1,440
    of them. This downloads that archive once and extracts the synopsis from each.

    The result feeds ReferenceStore, which means it also reaches ActionRisk.UseDescriptions:
    Exchange and Purview cmdlets currently fall through to the "unknown shape, treat as
    privileged" default, which is why nearly every grant in those services is rated
    escalation-capable regardless of what it does.

.PARAMETER Path
    Output JSON. Defaults to the AccessCheck data folder.

.PARAMETER KeepArchive
    Keep the downloaded zip instead of deleting it.

.EXAMPLE
    .\dist\import-exchange-descriptions.ps1
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $env:APPDATA "AccessCheck\exchange-descriptions.json"),
    [switch]$KeepArchive
)

$ErrorActionPreference = "Stop"

$repoZip = "https://codeload.github.com/MicrosoftDocs/office-docs-powershell/zip/refs/heads/main"
$archive = Join-Path ([System.IO.Path]::GetTempPath()) "office-docs-powershell.zip"
$extract = Join-Path ([System.IO.Path]::GetTempPath()) "office-docs-powershell"

$dir = Split-Path -Parent $Path
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

Write-Host "Downloading Microsoft's cmdlet documentation (about 11 MB)..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $repoZip -OutFile $archive -UseBasicParsing
}
catch {
    Write-Warning "Download failed: $($_.Exception.Message)"
    Write-Warning "With no route to github.com, fetch the archive on a connected machine:"
    Write-Warning "    $repoZip"
    Write-Warning "then run this script with -Path pointing at the extracted copy."
    throw
}

if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
Expand-Archive -Path $archive -DestinationPath $extract -Force

$docsDir = Get-ChildItem -Path $extract -Recurse -Directory -Filter "ExchangePowerShell" |
           Where-Object { $_.FullName -like "*exchange-ps*" } |
           Select-Object -First 1

if (-not $docsDir) { throw "Could not find the ExchangePowerShell docs folder in the archive." }

$files = Get-ChildItem -Path $docsDir.FullName -Filter *.md -File
Write-Host "Found $($files.Count) cmdlet documents. Extracting descriptions..." -ForegroundColor Cyan

# EVERY SYNOPSIS OPENS WITH BOILERPLATE. "This cmdlet is available in on-premises Exchange
# and in the cloud-based service" is on nearly all 1,440 of them and says nothing about what
# the cmdlet DOES — storing it would give every Exchange permission an identical description
# and leave the model exactly as blind as an empty one.
$boilerplate = @(
    'this cmdlet is available',
    'for information about the parameter sets',
    '**note**',
    'you need to be assigned permissions',
    'this cmdlet is functional only',
    'in exchange online, this cmdlet'
)

$result = @{}
$skipped = 0

foreach ($file in $files) {
    $text = Get-Content $file.FullName -Raw

    $m = [regex]::Match($text, '(?ms)^##\s+SYNOPSIS\s*$(.*?)^##\s+')
    if (-not $m.Success) { $skipped++; continue }

    $chosen = $null
    foreach ($para in ($m.Groups[1].Value -split "`r?`n`r?`n")) {
        $p = $para.Trim()
        if (-not $p) { continue }

        $low = $p.ToLowerInvariant()
        if ($boilerplate | Where-Object { $low.StartsWith($_) }) { continue }

        # [text](url) -> text. A description full of markdown links reads badly in a prompt
        # and the URLs are noise the model cannot follow.
        $p = [regex]::Replace($p, '\[([^\]]+)\]\([^)]+\)', '$1')
        $p = [regex]::Replace($p, '\s+', ' ').Trim()

        if ($p.Length -gt 20) { $chosen = $p; break }
    }

    if ($chosen) { $result[$file.BaseName] = $chosen } else { $skipped++ }
}

$payload = [pscustomobject]@{
    source          = "MicrosoftDocs/office-docs-powershell"
    importedUtc     = (Get-Date).ToUniversalTime().ToString("o")
    cmdletCount     = $result.Count
    descriptions    = $result
}

$json = $payload | ConvertTo-Json -Depth 4 -Compress:$false
[System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))

if (-not $KeepArchive) {
    Remove-Item $archive -Force -ErrorAction SilentlyContinue
    Remove-Item $extract -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Wrote $($result.Count) cmdlet description(s) to:" -ForegroundColor Green
Write-Host "    $Path" -ForegroundColor Green
if ($skipped -gt 0) {
    Write-Host "($skipped file(s) had no usable synopsis - overview pages and the like.)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Spot check:" -ForegroundColor Cyan
foreach ($c in 'Remove-Mailbox', 'Add-MailboxFolderPermission', 'New-ComplianceSearchAction') {
    if ($result.ContainsKey($c)) {
        $d = $result[$c]
        if ($d.Length -gt 90) { $d = $d.Substring(0, 90) + "..." }
        Write-Host ("  {0,-30} {1}" -f $c, $d) -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Re-run occasionally: Microsoft revises these regularly." -ForegroundColor Gray
