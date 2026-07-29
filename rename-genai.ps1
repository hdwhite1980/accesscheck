<#
.SYNOPSIS
    Renames "GenAI" / "GenAi" to "AI" / "Ai" across the source tree.

.DESCRIPTION
    Not everything behind the endpoint is generative, so the label was wrong. This
    replaces it consistently in BOTH display text and identifiers — doing only the
    display text leaves methods called SuggestViaGenAi sitting next to UI that says AI,
    which is how a codebase ends up with two names for one thing.

    Consistent renaming keeps it compiling: every declaration and every call site moves
    together.

.PARAMETER Preview
    Show what would change without writing anything. Run this first.

.EXAMPLE
    .\dist\rename-genai.ps1 -Preview
    .\dist\rename-genai.ps1
#>
[CmdletBinding()]
param([switch]$Preview)

$ErrorActionPreference = "Stop"

$distDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $distDir
# Tolerate being run from the repo root rather than from dist\.
if (-not (Test-Path (Join-Path $repoRoot 'src'))) { $repoRoot = $distDir }

# Order matters: the longer/cased forms first, so "GenAI" is not half-consumed by a
# rule meant for "GenAi".
# AN ARRAY OF PAIRS, NOT A HASHTABLE.
#
# PowerShell hashtable keys are CASE-INSENSITIVE, so @{ 'GenAI'='AI'; 'GenAi'='Ai' } is a
# duplicate-key parse error - and the whole point here is that the casings differ and each
# needs its own replacement. An ordered array keeps them distinct, longest and most
# specific first so a later rule cannot consume half of an earlier match.
#
# [string]::Replace is ordinal and case-sensitive, which is exactly what is wanted.
$rules = @(
    @{ From = 'GenAI'; To = 'AI' }
    @{ From = 'GENAI'; To = 'AI' }
    @{ From = 'GenAi'; To = 'Ai' }
    @{ From = 'genAI'; To = 'ai' }
    @{ From = 'genAi'; To = 'ai' }
    @{ From = 'genai'; To = 'ai' }
)

$extensions = @('*.cs', '*.xaml', '*.md', '*.json', '*.ps1')
$skipDirs   = @('\bin\', '\obj\', '\.git\', '\.vs\')

$files = Get-ChildItem -Path (Join-Path $repoRoot 'src'),
                             (Join-Path $repoRoot 'tests'),
                             (Join-Path $repoRoot 'dist') `
                       -Include $extensions -Recurse -File -ErrorAction SilentlyContinue |
         Where-Object { $p = $_.FullName; -not ($skipDirs | Where-Object { $p -like "*$_*" }) }

# The root README too, if it exists.
$rootReadme = Join-Path $repoRoot 'README.md'
if (Test-Path $rootReadme) { $files = @($files) + (Get-Item $rootReadme) }

$touched = 0
$total   = 0

foreach ($file in $files) {
    $original = [System.IO.File]::ReadAllText($file.FullName)
    $updated  = $original
    $hits     = 0

    foreach ($rule in $rules) {
        $hits += ([regex]::Matches($updated, [regex]::Escape($rule.From))).Count
        $updated = $updated.Replace($rule.From, $rule.To)
    }

    if ($updated -eq $original) { continue }

    $rel = $file.FullName.Substring($repoRoot.Length + 1)
    Write-Host ("{0,-60} {1} occurrence(s)" -f $rel, $hits) -ForegroundColor Cyan

    if (-not $Preview) {
        # Preserve the existing encoding rather than forcing one. Rewriting a BOM-less
        # file with a BOM (or the reverse) shows up as a whole-file diff and buries the
        # actual change.
        $encoding = New-Object System.Text.UTF8Encoding($true)
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        if ($bytes.Length -lt 3 -or -not ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) {
            $encoding = New-Object System.Text.UTF8Encoding($false)
        }
        [System.IO.File]::WriteAllText($file.FullName, $updated, $encoding)
    }

    $touched++
    $total += $hits
}

Write-Host ""
if ($Preview) {
    Write-Host "PREVIEW - nothing written. $touched file(s), $total occurrence(s)." -ForegroundColor Yellow
    Write-Host "Re-run without -Preview to apply." -ForegroundColor Yellow
} else {
    Write-Host "Renamed in $touched file(s), $total occurrence(s)." -ForegroundColor Green
    Write-Host ""
    Write-Host "Now rebuild - a missed call site shows up as a compile error, which is the" -ForegroundColor Gray
    Write-Host "cheapest possible way to find one:" -ForegroundColor Gray
    Write-Host "    dotnet build AccessCheck.sln -c Release" -ForegroundColor White
    Write-Host "    dotnet test tests\AccessCheck.Core.Tests" -ForegroundColor White
}

Write-Host ""
Write-Host "Note: appsettings.json keys are NOT renamed by extension filter alone if they" -ForegroundColor Gray
Write-Host "live in %APPDATA%. Check that file by hand if it holds a GenAI-named setting." -ForegroundColor Gray
