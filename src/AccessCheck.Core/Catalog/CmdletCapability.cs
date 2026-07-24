using System.Text.Json;

namespace AccessCheck.Core.Catalog;

/// <summary>
/// What a PowerShell endpoint ACTUALLY supports: which cmdlets exist there, and which
/// parameters each one accepts.
///
/// WHY THIS EXISTS. Four grants in a row failed because Exchange Online and Security &amp;
/// Compliance share cmdlet NAMES but not PARAMETER SETS — New-ManagementRole absent in
/// SCC, Get-ManagementRoleEntry absent, -BypassSecurityGroupManagerCheck absent, and
/// Set-RoleGroup -Roles which does not exist anywhere. Each was discovered by emitting a
/// script and watching it fail against a real tenant.
///
/// Microsoft's documentation does distinguish these (per-parameter "Applicable:" lines),
/// but one page covers every environment and the distinction is easy to miss. The live
/// session is both cheaper and more definitive: Get-Command answers for THIS endpoint, in
/// THIS tenant, today. The app should never emit a parameter it has not confirmed exists.
/// </summary>
public sealed class CmdletCapability
{
    public string Cmdlet { get; set; } = "";
    /// <summary>"exchange" or "purview" — the endpoint this was probed against.</summary>
    public string Scope { get; set; } = "";
    public bool Exists { get; set; }
    /// <summary>Parameter names the endpoint accepts, excluding common parameters.</summary>
    public List<string> Parameters { get; set; } = new();

    public bool HasParameter(string name) =>
        Parameters.Any(p => p.Equals(name, StringComparison.OrdinalIgnoreCase));
}

/// <summary>Cached cmdlet surface per endpoint, so a script is checked before it runs.</summary>
public sealed class CmdletCapabilityStore
{
    public List<CmdletCapability> Capabilities { get; set; } = new();
    public DateTimeOffset? LastSyncedUtc { get; set; }

    /// <summary>The cmdlets AccessCheck emits. Probing only these keeps the sync cheap.</summary>
    public static readonly IReadOnlyList<string> CmdletsWeEmit = new[]
    {
        "Get-ManagementRole", "New-ManagementRole", "Remove-ManagementRole",
        "Get-ManagementRoleEntry", "Remove-ManagementRoleEntry",
        "New-ManagementRoleAssignment", "Get-ManagementRoleAssignment",
        "Get-RoleGroup", "New-RoleGroup", "Set-RoleGroup", "Remove-RoleGroup",
        "Get-RoleGroupMember", "Add-RoleGroupMember", "Remove-RoleGroupMember"
    };

    public CmdletCapability? Find(string cmdlet, string scope) =>
        Capabilities.FirstOrDefault(c =>
            c.Cmdlet.Equals(cmdlet, StringComparison.OrdinalIgnoreCase) &&
            c.Scope.Equals(scope, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Is this cmdlet+parameter safe to emit against this endpoint?
    ///
    /// Returns TRUE when nothing has been probed yet — an unprobed endpoint must not block
    /// a grant that would otherwise work. The point is to catch known-bad combinations,
    /// not to refuse everything until a sync has run.
    /// </summary>
    public bool Supports(string cmdlet, string parameter, string scope)
    {
        var cap = Find(cmdlet, scope);
        if (cap is null) return true;          // never probed — do not block
        if (!cap.Exists) return false;         // probed and the cmdlet is absent
        if (cap.Parameters.Count == 0) return true;   // probed but parameters unreadable
        return cap.HasParameter(parameter);
    }

    /// <summary>Does the cmdlet itself exist at this endpoint?</summary>
    public bool CmdletExists(string cmdlet, string scope)
    {
        var cap = Find(cmdlet, scope);
        return cap is null || cap.Exists;
    }

    /// <summary>A line an operator can act on, or null when the combination is fine.</summary>
    public string? ExplainGap(string cmdlet, string parameter, string scope)
    {
        var cap = Find(cmdlet, scope);
        if (cap is null) return null;

        if (!cap.Exists)
            return $"{cmdlet} does not exist in {ScopeName(scope)}. "
                 + "The cmdlet name is shared with Exchange Online, but the endpoints differ.";

        if (cap.Parameters.Count > 0 && !cap.HasParameter(parameter))
            return $"{cmdlet} exists in {ScopeName(scope)} but has no -{parameter} parameter. "
                 + "Cmdlet names are shared between Exchange and Security & Compliance; "
                 + "parameter sets are not.";

        return null;
    }

    private static string ScopeName(string scope) =>
        scope.Equals("purview", StringComparison.OrdinalIgnoreCase)
            ? "Security & Compliance" : "Exchange Online";

    public static CmdletCapabilityStore Load(string path)
    {
        if (!File.Exists(path)) return new CmdletCapabilityStore();
        try
        {
            var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            return JsonSerializer.Deserialize<CmdletCapabilityStore>(File.ReadAllText(path), opts)
                   ?? new CmdletCapabilityStore();
        }
        catch (Exception)
        {
            return new CmdletCapabilityStore();   // a cache must never block the app
        }
    }

    public void Save(string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(
            this, new JsonSerializerOptions { WriteIndented = true }));
}
