<#
.SYNOPSIS
    Imports Microsoft's published Purview role list into AccessCheck.

.DESCRIPTION
    The Security and Compliance PowerShell session cannot report what a Purview role
    contains. Get-ManagementRoleEntry does not exist there — it is an Exchange cmdlet — and
    Get-ManagementRole returns names with an empty RoleEntries collection. A tenant will
    therefore tell you that 120 Purview roles exist and nothing at all about what they do.

    Microsoft publishes the missing half: every role, what it permits, and which built-in
    role groups already carry it. That last column is the least-privilege argument — if a
    role is only available inside a group carrying nine others, a group carrying just that
    role is measurably narrower, and the difference is a real number rather than "unknown".

    This downloads that page as markdown and stores it for the app to parse.

.PARAMETER Path
    Where to write it. Defaults to the AccessCheck data folder.

.EXAMPLE
    .\dist\import-purview-roles.ps1
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $env:APPDATA "AccessCheck\purview-roles.md")
)

$ErrorActionPreference = "Stop"

# ?accept=text/markdown returns the source rather than the rendered page, so the two tables
# arrive as tables instead of as HTML to be scraped.
$url = "https://learn.microsoft.com/en-us/defender-office-365/scc-permissions?accept=text/markdown"

$dir = Split-Path -Parent $Path
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

Write-Host "Downloading Microsoft's Purview role tables..." -ForegroundColor Cyan

try {
    Invoke-WebRequest -Uri $url -OutFile $Path -UseBasicParsing
}
catch {
    Write-Warning "Download failed: $($_.Exception.Message)"
    Write-Warning "In an environment with no route to learn.microsoft.com, fetch the page on"
    Write-Warning "a connected machine and copy it to:"
    Write-Warning "    $Path"
    throw
}

$content = Get-Content $Path -Raw

# A SANITY CHECK, NOT A FORMALITY. A proxy or sign-in page returns HTTP 200 with a body
# that is not the article, and a silently empty role list is exactly the failure this whole
# import exists to fix.
$roleRows = ([regex]::Matches($content, '(?m)^\|')).Count
if ($roleRows -lt 100) {
    Write-Warning "Only $roleRows table rows found - that is far fewer than expected."
    Write-Warning "The download may be a sign-in or error page rather than the article."
    Write-Warning "Open $Path and check it starts with the article title."
} else {
    Write-Host "Saved $Path ($roleRows table rows)." -ForegroundColor Green
}

Write-Host ""
Write-Host "The app parses this on next launch and writes purview-roles.json beside it." -ForegroundColor Gray
Write-Host "Re-run occasionally: Microsoft adds Purview roles regularly." -ForegroundColor Gray
