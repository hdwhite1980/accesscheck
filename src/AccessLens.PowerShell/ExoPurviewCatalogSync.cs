using System.Text;
using System.Text.Json;
using AccessLens.Core.Catalog;

namespace AccessLens.PowerShell;

/// <summary>
/// Deep sync of Exchange Online and Purview (Security &amp; Compliance) RBAC via
/// PowerShell: management roles with their role entries (cmdlets) and role groups.
/// Slower than Graph (one Get-ManagementRoleEntry round trip per role) — this is
/// the "deep sync" button, not part of every catalog refresh.
/// </summary>
public sealed class ExoPurviewCatalogSync
{
    private readonly PowerShellRunner _runner;
    private readonly PsEnvironment _env;
    private readonly string? _upn;

    public ExoPurviewCatalogSync(PowerShellRunner runner, PsEnvironment env, string? userPrincipalName)
    {
        _runner = runner;
        _env = env;
        _upn = userPrincipalName;
    }

    public async Task<(List<RoleDefinitionRecord> Roles, List<RoleGroupInfo> RoleGroups)> SyncAsync(
        RbacScope scope, CancellationToken ct = default)
    {
        var provider = scope == RbacScope.Exchange ? RbacProviders.Exchange : RbacProviders.Purview;
        var script = BuildScript(scope);
        var result = await _runner.RunAsync(script, TimeSpan.FromMinutes(45), ct);

        var json = result.JsonPayload
            ?? throw new InvalidOperationException(
                "PowerShell sync produced no JSON payload. stderr: " + Head(result.StdErr));

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.False)
        {
            var err = root.TryGetProperty("error", out var e) ? e.GetString() : "unknown";
            throw new InvalidOperationException("PowerShell sync failed: " + err);
        }

        var roles = new List<RoleDefinitionRecord>();
        if (root.TryGetProperty("roles", out var rolesEl) && rolesEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var r in rolesEl.EnumerateArray())
            {
                var name = r.GetProperty("name").GetString() ?? "";
                var desc = r.TryGetProperty("description", out var d) ? d.GetString() ?? "" : "";
                var entries = new List<string>();
                if (r.TryGetProperty("entries", out var en) && en.ValueKind == JsonValueKind.Array)
                    foreach (var x in en.EnumerateArray())
                    {
                        var s = x.GetString();
                        if (!string.IsNullOrWhiteSpace(s)) entries.Add(s);
                    }
                bool custom = r.TryGetProperty("isCustom", out var c) &&
                              c.ValueKind == JsonValueKind.True;
                roles.Add(new RoleDefinitionRecord
                {
                    Id = provider + ":" + name,
                    DisplayName = name,
                    Description = desc,
                    IsBuiltIn = !custom,
                    Provider = provider,
                    IsAccessLensCreated = custom &&
                        (name.StartsWith("AL - ", StringComparison.OrdinalIgnoreCase) ||
                         desc.Contains("AccessLens least-privilege role", StringComparison.OrdinalIgnoreCase)),
                    AllowedResourceActions = entries
                });
            }
        }

        var groups = new List<RoleGroupInfo>();
        if (root.TryGetProperty("roleGroups", out var rg) && rg.ValueKind == JsonValueKind.Array)
        {
            foreach (var g in rg.EnumerateArray())
            {
                var members = new List<string>();
                if (g.TryGetProperty("members", out var ms) && ms.ValueKind == JsonValueKind.Array)
                    foreach (var m in ms.EnumerateArray())
                    {
                        var s = m.GetString();
                        if (!string.IsNullOrWhiteSpace(s)) members.Add(s);
                    }
                var rolesList = new List<string>();
                if (g.TryGetProperty("roles", out var rl) && rl.ValueKind == JsonValueKind.Array)
                    foreach (var m in rl.EnumerateArray())
                    {
                        var s = m.GetString();
                        if (!string.IsNullOrWhiteSpace(s)) rolesList.Add(s);
                    }
                groups.Add(new RoleGroupInfo(
                    g.GetProperty("name").GetString() ?? "",
                    g.TryGetProperty("description", out var gd) ? gd.GetString() ?? "" : "",
                    rolesList, members));
            }
        }
        return (roles, groups);
    }

    private string BuildScript(RbacScope scope)
    {
        var sb = new StringBuilder();
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        sb.AppendLine("$ProgressPreference = 'SilentlyContinue'");
        sb.AppendLine("try {");
        sb.AppendLine("  Import-Module ExchangeOnlineManagement -ErrorAction Stop");
        sb.AppendLine("  " + _env.ConnectLine(scope, _upn));
        sb.AppendLine("  $roles = @(Get-ManagementRole | ForEach-Object {");
        sb.AppendLine("    $entries = @(Get-ManagementRoleEntry ($_.Name + '\\*') | ForEach-Object { $_.Name })");
        sb.AppendLine("    [pscustomobject]@{");
        sb.AppendLine("      name = $_.Name");
        sb.AppendLine("      description = [string]$_.Description");
        sb.AppendLine("      isCustom = -not $_.IsRootRole");
        sb.AppendLine("      entries = $entries");
        sb.AppendLine("    }");
        sb.AppendLine("  })");
        sb.AppendLine("  $groups = @(Get-RoleGroup | ForEach-Object {");
        sb.AppendLine("    [pscustomobject]@{");
        sb.AppendLine("      name = $_.Name");
        sb.AppendLine("      description = [string]$_.Description");
        sb.AppendLine("      roles = @($_.Roles | ForEach-Object { [string]$_ })");
        sb.AppendLine("      members = @($_.Members | ForEach-Object { [string]$_ })");
        sb.AppendLine("    }");
        sb.AppendLine("  })");
        sb.AppendLine("  $payload = [pscustomobject]@{ ok = $true; roles = $roles; roleGroups = $groups }");
        sb.AppendLine("  Write-Output '###JSON-BEGIN###'");
        sb.AppendLine("  Write-Output ($payload | ConvertTo-Json -Depth 6 -Compress)");
        sb.AppendLine("  Write-Output '###JSON-END###'");
        sb.AppendLine("} catch {");
        sb.AppendLine("  $err = [pscustomobject]@{ ok = $false; error = $_.Exception.Message }");
        sb.AppendLine("  Write-Output '###JSON-BEGIN###'");
        sb.AppendLine("  Write-Output ($err | ConvertTo-Json -Compress)");
        sb.AppendLine("  Write-Output '###JSON-END###'");
        sb.AppendLine("  exit 1");
        sb.AppendLine("}");
        return sb.ToString();
    }

    private static string Head(string s) => s.Length <= 400 ? s : s[..400];
}

public sealed record RoleGroupInfo(
    string Name, string Description,
    IReadOnlyList<string> Roles, IReadOnlyList<string> Members);
