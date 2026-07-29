<#
.SYNOPSIS
    Registers a Windows scheduled task that revokes expired AccessCheck grants.

.DESCRIPTION
    Only Entra directory grants expire on their own, through PIM — Entra removes those
    server-side whether or not this machine is ever switched on again.

    Every other provider is APP-TRACKED. Intune, Windows 365, Defender, Exchange, Purview
    and plain group membership record an expiry in history.jsonl, and nothing acts on it
    until housekeeping runs. Without this task, "14-day access" is 14 days in the audit
    record and permanent in the tenant.

    The task runs as the CURRENT USER, because that is whose DPAPI-protected MSAL token
    cache it needs. It cannot run as SYSTEM or as another account: the cache is bound to
    the Windows account that created it, and a different principal simply cannot read it.

.PARAMETER Time
    Daily run time, 24h. Default 06:00.

.PARAMETER GcRoles
    Also delete orphaned AccessCheck-created roles that no longer have assignments.
    OFF by default. Revoking expired access restores least privilege; deleting a role
    definition is destructive and is not what the expiry promised.

.PARAMETER CliPath
    Path to accesscheck.exe. Defaults to a published CLI beside this repo.

.PARAMETER Unregister
    Remove the task instead of creating it.

.EXAMPLE
    .\dist\register-housekeeping.ps1
    .\dist\register-housekeeping.ps1 -Time 02:30 -GcRoles
    .\dist\register-housekeeping.ps1 -Unregister
#>
[CmdletBinding()]
param(
    [string]$Time = "06:00",
    [switch]$GcRoles,
    [string]$CliPath,
    [switch]$Unregister
)

$ErrorActionPreference = "Stop"

$TaskName = "AccessCheck housekeeping"
$distDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $distDir

# ---------- unregister ----------

if ($Unregister) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Host "No task named '$TaskName' is registered." -ForegroundColor Gray
        return
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed '$TaskName'." -ForegroundColor Green
    Write-Warning "Expired grants on Intune, Windows 365, Defender, Exchange, Purview and"
    Write-Warning "direct group memberships will no longer be revoked automatically."
    return
}

# ---------- locate the CLI ----------

if (-not $CliPath) {
    $candidates = @(
        (Join-Path $repoRoot "src\AccessCheck.Cli\bin\Release\net8.0\accesscheck.exe"),
        (Join-Path $repoRoot "src\AccessCheck.Cli\bin\Release\net8.0\AccessCheck.Cli.exe"),
        (Join-Path $repoRoot "src\AccessCheck.Cli\bin\Debug\net8.0\accesscheck.exe"),
        (Join-Path $repoRoot "src\AccessCheck.Cli\bin\Debug\net8.0\AccessCheck.Cli.exe"),
        "$env:LOCALAPPDATA\Programs\AccessCheck\accesscheck.exe"
    )
    $CliPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}

if (-not $CliPath -or -not (Test-Path $CliPath)) {
    throw @"
Could not find the AccessCheck CLI.

Publish it first:
    dotnet publish src\AccessCheck.Cli -c Release -r win-x64 --self-contained true ``
        -o "`$env:LOCALAPPDATA\Programs\AccessCheck"

Then re-run this script, or pass -CliPath explicitly.
"@
}

$CliPath = (Resolve-Path $CliPath).Path
Write-Host "CLI: $CliPath" -ForegroundColor Gray

# ---------- validate the time before handing it to the scheduler ----------

try   { $when = [datetime]::ParseExact($Time, "HH:mm", $null) }
catch { throw "Time must be 24-hour HH:mm, e.g. 06:00 or 22:30. Got '$Time'." }

# ---------- pre-flight: has anyone signed in as this account? ----------

# The task inherits this user's token cache. If it has never been populated, the first
# scheduled run will need an interactive sign-in it cannot get — the CLI bounds that and
# exits 1, but it is far better to say so now than to discover it from a failed task.
$tokenCache = Join-Path $env:APPDATA "AccessCheck\secrets"
if (-not (Test-Path $tokenCache)) {
    Write-Warning "No AccessCheck credential store found for $env:USERNAME."
    Write-Warning "Open AccessCheck and sign in once as THIS account before the first run,"
    Write-Warning "or the task will exit with 'no usable cached sign-in'."
}

# ---------- build the task ----------

$arguments = "housekeeping --unattended"
if ($GcRoles) { $arguments += " --gc-roles" }

$action = New-ScheduledTaskAction -Execute $CliPath -Argument $arguments `
                                  -WorkingDirectory (Split-Path -Parent $CliPath)

$trigger = New-ScheduledTaskTrigger -Daily -At $when

# StartWhenAvailable matters on laptops: a machine asleep at 06:00 would otherwise skip
# the run entirely and the grant would live another day. RunOnlyIfNetworkAvailable stops
# a pointless failure record when there is no connectivity to reach Graph at all.
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -DontStopIfGoingOnBatteries `
    -AllowStartIfOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
    -MultipleInstances IgnoreNew

# INTERACTIVE, not S4U or a stored password. The DPAPI-protected token cache is readable
# only by this user in an interactive-equivalent logon; a service logon cannot decrypt it.
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
                                        -LogonType Interactive `
                                        -RunLevel Limited

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Replacing the existing task..." -ForegroundColor Gray
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Register-ScheduledTask -TaskName $TaskName `
                       -Action $action `
                       -Trigger $trigger `
                       -Settings $settings `
                       -Principal $principal `
                       -Description ("Revokes AccessCheck grants whose app-tracked expiry " +
                                     "has passed. Entra directory grants expire through PIM " +
                                     "and are not touched here.") | Out-Null

Write-Host "`nRegistered '$TaskName'." -ForegroundColor Green
Write-Host "  Runs daily at $Time as $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Gray
Write-Host "  Command: $CliPath $arguments" -ForegroundColor Gray
if (-not $GcRoles) {
    Write-Host "  Orphaned-role cleanup is OFF. Re-run with -GcRoles to include it." -ForegroundColor Gray
}

Write-Host "`nVerify it works now, rather than finding out in a month:" -ForegroundColor Cyan
Write-Host "    Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor White
Write-Host "    Get-ScheduledTaskInfo -TaskName '$TaskName' | Select LastRunTime, LastTaskResult" -ForegroundColor White
Write-Host "`nLastTaskResult 0 = clean. 1 = the run reported a failure; run the command by" -ForegroundColor Gray
Write-Host "hand to see which grant could not be revoked." -ForegroundColor Gray
