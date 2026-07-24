using System.Text;
using AccessLens.Core.Recommendation;

namespace AccessLens.Exo;

public sealed record ExoGrantPlan
{
    /// <summary>UPN or identity Exchange cmdlets accept (NOT an object ID).</summary>
    public required string MemberIdentity { get; init; }
    public required string Justification { get; init; }
    /// <summary>Existing management role name when no custom role is being derived.</summary>
    public string? ExistingRoleName { get; init; }
    /// <summary>Custom derived role draft (ParentRoleName + EntriesToRemove set by the validator).</summary>
    public CustomRoleDraft? CustomRole { get; init; }
    public required bool IsPurview { get; init; }

    public string RoleName => CustomRole?.DisplayName ?? ExistingRoleName
        ?? throw new InvalidOperationException("Plan has neither a role name nor a custom draft.");
    public string RoleGroupName
    {
        get
        {
            var name = ExoCatalogSource.Marker + "RG " + RoleName;
            return name.Length <= 64 ? name : name[..64]; // role group name limit
        }
    }
}

/// <summary>
/// Builds and (after human approval) runs the PowerShell that grants, removes, and
/// garbage-collects Exchange / Purview access. The DERIVED custom-role model:
///   New-ManagementRole -Name "AL-x" -Parent {covering role}
///   Remove-ManagementRoleEntry "AL-x\{excess cmdlet}"    (per excess entry)
/// which yields a role whose entries are EXACTLY the validated cmdlets. The grant
/// vehicle is a per-grant "AL-RG ..." role group holding only that one role, so
/// removal and audit stay clean. Scripts are ALWAYS surfaced for preview first —
/// the GUI shows the exact text and nothing runs before explicit confirmation.
/// </summary>
public sealed class ExoExecutor
{
    private readonly PwshRunner _runner;
    public ExoExecutor(PwshRunner runner) => _runner = runner;

    private static string Connect(ExoEnvironment env, bool purview) =>
        "$ErrorActionPreference = 'Stop'\n" +
        "Import-Module ExchangeOnlineManagement\n" +
        (purview ? env.IppsConnectLine() : env.ExoConnectLine()) + "\n";

    private const string Disconnect = "Disconnect-ExchangeOnline -Confirm:$false | Out-Null\n";

    public string BuildGrantScript(ExoEnvironment env, ExoGrantPlan plan)
    {
        var sb = new StringBuilder();
        sb.Append(Connect(env, plan.IsPurview));

        if (plan.CustomRole is { } draft)
        {
            if (string.IsNullOrWhiteSpace(draft.ParentRoleName))
                throw new InvalidOperationException(
                    "Derived custom role requires a parent role (none was set by the validator).");
            sb.Append("New-ManagementRole -Name ").Append(Q(draft.DisplayName))
              .Append(" -Parent ").Append(Q(draft.ParentRoleName)).Append('\n');
            foreach (var entry in draft.EntriesToRemove ?? Array.Empty<string>())
                sb.Append("Remove-ManagementRoleEntry ")
                  .Append(Q(draft.DisplayName + "\\" + entry))
                  .Append(" -Confirm:$false\n");
        }

        sb.Append("New-RoleGroup -Name ").Append(Q(plan.RoleGroupName))
          .Append(" -Roles ").Append(Q(plan.RoleName))
          .Append(" -Description ").Append(Q("AccessLens least-privilege role group. " + plan.Justification))
          .Append('\n');
        sb.Append("Add-RoleGroupMember -Identity ").Append(Q(plan.RoleGroupName))
          .Append(" -Member ").Append(Q(plan.MemberIdentity)).Append('\n');
        sb.Append("Write-Output ('GRANTED: ' + ").Append(Q(plan.MemberIdentity))
          .Append(" + ' -> ' + ").Append(Q(plan.RoleGroupName)).Append(")\n");
        sb.Append(Disconnect);
        return sb.ToString();
    }

    /// <summary>
    /// Removal at expiry: drop the member; if the role group is then empty, delete it;
    /// if the role was an AL- derived role with no other role groups using it, delete it too.
    /// </summary>
    public string BuildRemovalScript(
        ExoEnvironment env, bool purview, string roleGroupName, string memberIdentity, string roleName)
    {
        var sb = new StringBuilder();
        sb.Append(Connect(env, purview));
        sb.Append("Remove-RoleGroupMember -Identity ").Append(Q(roleGroupName))
          .Append(" -Member ").Append(Q(memberIdentity)).Append(" -Confirm:$false\n");
        sb.Append("$remaining = @(Get-RoleGroupMember -Identity ").Append(Q(roleGroupName)).Append(")\n");
        sb.Append("if ($remaining.Count -eq 0) {\n");
        sb.Append("    Remove-RoleGroup -Identity ").Append(Q(roleGroupName)).Append(" -Confirm:$false\n");
        sb.Append("    Write-Output ('REMOVED-GROUP: ' + ").Append(Q(roleGroupName)).Append(")\n");
        if (roleName.StartsWith(ExoCatalogSource.Marker, StringComparison.OrdinalIgnoreCase))
        {
            sb.Append("    $stillUsed = @(Get-RoleGroup | Where-Object { $_.Roles -contains ")
              .Append(Q(roleName)).Append(" })\n");
            sb.Append("    if ($stillUsed.Count -eq 0) {\n");
            sb.Append("        Remove-ManagementRole -Identity ").Append(Q(roleName))
              .Append(" -Confirm:$false\n");
            sb.Append("        Write-Output ('REMOVED-ROLE: ' + ").Append(Q(roleName)).Append(")\n");
            sb.Append("    }\n");
        }
        sb.Append("}\n");
        sb.Append("Write-Output ('REMOVED-MEMBER: ' + ").Append(Q(memberIdentity)).Append(")\n");
        sb.Append(Disconnect);
        return sb.ToString();
    }

    public Task<PwshResult> RunAsync(string script, CancellationToken ct = default) =>
        _runner.RunAsync(script, TimeSpan.FromMinutes(20), ct);

    /// <summary>Single-quote a PowerShell string literal (doubling embedded quotes).</summary>
    private static string Q(string s) => "'" + s.Replace("'", "''") + "'";
}
