using System.Text.Json;

namespace AccessCheck.Graph;

/// <summary>One API permission a service principal actually holds.</summary>
public sealed record AppPermissionGrant
{
    public required string PermissionValue { get; init; }   // e.g. Directory.ReadWrite.All
    public required string ResourceName { get; init; }      // e.g. Microsoft Graph
    /// <summary>Application (app-only) permissions run without a signed-in user.</summary>
    public required bool IsApplicationPermission { get; init; }
    public string? GrantedTo { get; init; }                 // delegated: principal or "all users"

    /// <summary>
    /// Crude but useful risk read: write scopes, .All scopes, and the known escalation
    /// paths matter far more than a narrow read.
    /// </summary>
    public bool IsHighRisk =>
        PermissionValue.Contains("ReadWrite", StringComparison.OrdinalIgnoreCase) ||
        PermissionValue.Contains("FullControl", StringComparison.OrdinalIgnoreCase) ||
        PermissionValue.StartsWith("RoleManagement.", StringComparison.OrdinalIgnoreCase) ||
        PermissionValue.StartsWith("AppRoleAssignment.", StringComparison.OrdinalIgnoreCase) ||
        PermissionValue.StartsWith("Directory.ReadWrite", StringComparison.OrdinalIgnoreCase) ||
        PermissionValue.StartsWith("PrivilegedAccess.", StringComparison.OrdinalIgnoreCase) ||
        PermissionValue.StartsWith("Application.ReadWrite", StringComparison.OrdinalIgnoreCase);

    public string Label => PermissionValue + " (" + ResourceName +
                           (IsApplicationPermission ? ", app-only" : ", delegated") + ")";
}

public sealed record AppPrincipal
{
    public required string Id { get; init; }
    public required string DisplayName { get; init; }
    public string AppId { get; init; } = "";
    public string? PublisherName { get; init; }
    public bool AppOwnedByTenant { get; init; }
    public required IReadOnlyList<AppPermissionGrant> Permissions { get; init; }
    /// <summary>Entra directory roles this service principal holds, if any.</summary>
    public IReadOnlyList<string> DirectoryRoles { get; init; } = Array.Empty<string>();

    public int HighRiskCount => Permissions.Count(p => p.IsHighRisk);
    public int AppOnlyCount => Permissions.Count(p => p.IsApplicationPermission);
}

/// <summary>
/// Reads what applications can do. This is where standing, never-expiring privilege
/// accumulates: an app-only Directory.ReadWrite.All grant outlives every user, is
/// invisible to user access reviews, and no PIM policy touches it.
/// Requires Application.Read.All (or Directory.Read.All) plus the role reads already in use.
/// </summary>
public sealed class AppPermissionReader
{
    private readonly GraphClient _graph;
    public AppPermissionReader(GraphClient graph) => _graph = graph;

    public List<string> Warnings { get; } = new();

    public async Task<IReadOnlyList<AppPrincipal>> ReadAsync(
        Action<string>? progress = null, bool onlyWithPermissions = true,
        CancellationToken ct = default)
    {
        Warnings.Clear();

        progress?.Invoke("Reading service principals...");
        var principals = new Dictionary<string, (string Name, string AppId, string? Publisher, bool Owned)>(
            StringComparer.OrdinalIgnoreCase);
        // appRoles per resource SP, so appRoleId can be resolved to a permission name
        var appRoleNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var spNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            string? url = "/v1.0/servicePrincipals?$select=id,displayName,appId,appRoles," +
                          "publisherName,appOwnerOrganizationId&$top=100";
            int guard = 0;
            while (url is not null && guard++ < 200)
            {
                using var doc = await _graph.GetAsync(url, ct);
                if (doc.RootElement.TryGetProperty("value", out var v))
                {
                    foreach (var el in v.EnumerateArray())
                    {
                        var id = el.TryGetProperty("id", out var i) ? i.GetString() ?? "" : "";
                        if (id.Length == 0) continue;
                        var name = el.TryGetProperty("displayName", out var d)
                            ? d.GetString() ?? id : id;
                        spNames[id] = name;
                        principals[id] = (
                            name,
                            el.TryGetProperty("appId", out var a) ? a.GetString() ?? "" : "",
                            el.TryGetProperty("publisherName", out var p) ? p.GetString() : null,
                            el.TryGetProperty("appOwnerOrganizationId", out _));

                        if (el.TryGetProperty("appRoles", out var roles) &&
                            roles.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var r in roles.EnumerateArray())
                            {
                                var rid = r.TryGetProperty("id", out var ri) ? ri.GetString() : null;
                                var val = r.TryGetProperty("value", out var rv) ? rv.GetString() : null;
                                if (rid is not null && val is not null) appRoleNames[rid] = val;
                            }
                        }
                    }
                }
                url = doc.RootElement.TryGetProperty("@odata.nextLink", out var n)
                    ? n.GetString() : null;
            }
        }
        catch (Exception ex)
        {
            Warnings.Add("Service principals unreadable (" + Head(ex.Message) +
                         ") — consent Application.Read.All.");
            return Array.Empty<AppPrincipal>();
        }

        // Application (app-only) permissions: appRoleAssignments granted TO each principal.
        progress?.Invoke("Reading application permissions...");
        var grants = new Dictionary<string, List<AppPermissionGrant>>(StringComparer.OrdinalIgnoreCase);
        void AddGrant(string spId, AppPermissionGrant g)
        {
            if (!grants.TryGetValue(spId, out var list)) grants[spId] = list = new List<AppPermissionGrant>();
            if (!list.Any(x => x.PermissionValue == g.PermissionValue &&
                               x.ResourceName == g.ResourceName &&
                               x.IsApplicationPermission == g.IsApplicationPermission))
                list.Add(g);
        }

        foreach (var spId in principals.Keys.ToList())
        {
            try
            {
                using var doc = await _graph.GetAsync(
                    "/v1.0/servicePrincipals/" + spId + "/appRoleAssignments?$top=100", ct);
                if (!doc.RootElement.TryGetProperty("value", out var v)) continue;
                foreach (var el in v.EnumerateArray())
                {
                    var appRoleId = el.TryGetProperty("appRoleId", out var ar)
                        ? ar.GetString() ?? "" : "";
                    var resourceName = el.TryGetProperty("resourceDisplayName", out var rn)
                        ? rn.GetString() ?? "" : "";
                    var value = appRoleNames.TryGetValue(appRoleId, out var pv) ? pv : appRoleId;
                    AddGrant(spId, new AppPermissionGrant
                    {
                        PermissionValue = value,
                        ResourceName = resourceName,
                        IsApplicationPermission = true
                    });
                }
            }
            catch (Exception) { /* individual SP unreadable — skip */ }
        }

        // Delegated permissions: oauth2PermissionGrants across the tenant.
        progress?.Invoke("Reading delegated permission grants...");
        try
        {
            string? url = "/v1.0/oauth2PermissionGrants?$top=100";
            int guard = 0;
            while (url is not null && guard++ < 200)
            {
                using var doc = await _graph.GetAsync(url, ct);
                if (doc.RootElement.TryGetProperty("value", out var v))
                {
                    foreach (var el in v.EnumerateArray())
                    {
                        var clientId = el.TryGetProperty("clientId", out var c) ? c.GetString() ?? "" : "";
                        if (clientId.Length == 0) continue;
                        var resourceId = el.TryGetProperty("resourceId", out var r) ? r.GetString() ?? "" : "";
                        var scopes = el.TryGetProperty("scope", out var sc) ? sc.GetString() ?? "" : "";
                        var consent = el.TryGetProperty("consentType", out var ct2)
                            ? ct2.GetString() ?? "" : "";
                        var resourceName = spNames.TryGetValue(resourceId, out var rname)
                            ? rname : resourceId;

                        foreach (var scope in scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                        {
                            AddGrant(clientId, new AppPermissionGrant
                            {
                                PermissionValue = scope,
                                ResourceName = resourceName,
                                IsApplicationPermission = false,
                                GrantedTo = string.Equals(consent, "AllPrincipals",
                                    StringComparison.OrdinalIgnoreCase) ? "all users" : "one user"
                            });
                        }
                    }
                }
                url = doc.RootElement.TryGetProperty("@odata.nextLink", out var n)
                    ? n.GetString() : null;
            }
        }
        catch (Exception ex)
        {
            Warnings.Add("Delegated grants unreadable (" + Head(ex.Message) + ").");
        }

        // Directory roles held by service principals.
        progress?.Invoke("Reading directory roles held by applications...");
        var spRoles = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var doc = await _graph.GetAsync(
                "/v1.0/roleManagement/directory/roleAssignments?$expand=roleDefinition&$top=100", ct);
            if (doc.RootElement.TryGetProperty("value", out var v))
            {
                foreach (var el in v.EnumerateArray())
                {
                    var pid = el.TryGetProperty("principalId", out var p) ? p.GetString() ?? "" : "";
                    if (!principals.ContainsKey(pid)) continue;
                    var rname = el.TryGetProperty("roleDefinition", out var rd) &&
                                rd.TryGetProperty("displayName", out var dn)
                        ? dn.GetString() ?? "" : "";
                    if (rname.Length == 0) continue;
                    if (!spRoles.TryGetValue(pid, out var list)) spRoles[pid] = list = new List<string>();
                    if (!list.Contains(rname)) list.Add(rname);
                }
            }
        }
        catch (Exception ex)
        {
            Warnings.Add("Directory roles for applications unreadable (" + Head(ex.Message) + ").");
        }

        var result = new List<AppPrincipal>();
        foreach (var (id, info) in principals)
        {
            var perms = grants.TryGetValue(id, out var g) ? g : new List<AppPermissionGrant>();
            var roles = spRoles.TryGetValue(id, out var r) ? r : new List<string>();
            if (onlyWithPermissions && perms.Count == 0 && roles.Count == 0) continue;
            result.Add(new AppPrincipal
            {
                Id = id,
                DisplayName = info.Name,
                AppId = info.AppId,
                PublisherName = info.Publisher,
                AppOwnedByTenant = info.Owned,
                Permissions = perms
                    .OrderByDescending(x => x.IsHighRisk)
                    .ThenBy(x => x.PermissionValue, StringComparer.OrdinalIgnoreCase)
                    .ToList(),
                DirectoryRoles = roles
            });
        }

        return result
            .OrderByDescending(a => a.HighRiskCount)
            .ThenByDescending(a => a.DirectoryRoles.Count)
            .ThenBy(a => a.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string Head(string s) => s.Length <= 160 ? s : s[..160];
}
