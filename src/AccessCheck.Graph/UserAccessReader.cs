using System.Text.Json;
using AccessCheck.Core.Catalog;
using AccessCheck.Core.Review;

namespace AccessCheck.Graph;

/// <summary>
/// Reads everything a user currently holds across the RBAC providers:
/// directory active + PIM-eligible assignments, the multi-provider assignments
/// (Intune / Windows 365 / Defender), and roles inherited through group membership.
/// Each provider is independent — one failure degrades that source only and is reported.
/// </summary>
public sealed class UserAccessReader
{
    private readonly GraphClient _graph;
    private readonly RoleCatalog _catalog;

    public UserAccessReader(GraphClient graph, RoleCatalog catalog)
    {
        _graph = graph;
        _catalog = catalog;
    }

    /// <summary>Non-fatal problems encountered while reading (shown to the reviewer).</summary>
    public List<string> Warnings { get; } = new();

    /// <summary>Classified issues — only the actionable ones deserve a banner.</summary>
    public IssueLog Issues { get; } = new();

    private void AddIssue(string text)
    {
        Warnings.Add(text);
        var source = text.Contains('(') ? text[..text.IndexOf('(')].Trim() : "read";
        Issues.AddError(source, text);
    }

    public async Task<IReadOnlyList<HeldRole>> ReadAsync(
        string principalId, Action<string>? progress = null, CancellationToken ct = default)
    {
        Warnings.Clear();
        var held = new List<HeldRole>();

        // Group memberships first — needed to attribute group-inherited roles.
        progress?.Invoke("Reading group memberships...");
        var groups = await ReadGroupsAsync(principalId, ct);

        progress?.Invoke("Reading Entra directory assignments...");
        await AddDirectoryAsync(principalId, groups, held, ct);

        foreach (var provider in new[]
                 { RbacProviders.Intune, RbacProviders.CloudPc, RbacProviders.Defender })
        {
            progress?.Invoke("Reading " + RbacProviders.DisplayName(provider) + " assignments...");
            await AddMultiAsync(provider, principalId, groups, held, ct);
        }

        return held
            .GroupBy(h => h.Provider + "|" + h.RoleId + "|" + h.Path + "|" + (h.ViaGroupName ?? ""))
            .Select(g => g.First())
            .OrderBy(h => h.Provider)
            .ThenBy(h => h.DisplayName)
            .ToList();
    }

    private async Task<Dictionary<string, string>> ReadGroupsAsync(
        string principalId, CancellationToken ct)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var url = "/v1.0/users/" + principalId +
                      "/transitiveMemberOf/microsoft.graph.group?$select=id,displayName&$top=100";
            while (url is not null)
            {
                using var doc = await _graph.GetAsync(url, ct);
                if (doc.RootElement.TryGetProperty("value", out var value))
                {
                    foreach (var el in value.EnumerateArray())
                    {
                        var id = el.TryGetProperty("id", out var i) ? i.GetString() : null;
                        var name = el.TryGetProperty("displayName", out var d) ? d.GetString() : null;
                        if (!string.IsNullOrEmpty(id)) map[id] = name ?? id;
                    }
                }
                url = doc.RootElement.TryGetProperty("@odata.nextLink", out var n)
                    ? n.GetString() : null;
            }
        }
        catch (Exception ex)
        {
            AddIssue("Group memberships unavailable (" + Head(ex.Message) +
                         ") — roles inherited via groups may be missing.");
        }
        return map;
    }

    private async Task AddDirectoryAsync(
        string principalId, Dictionary<string, string> groups,
        List<HeldRole> held, CancellationToken ct)
    {
        // Active assignments — for the user and for every group they belong to.
        var principals = new List<(string Id, string? GroupName)> { (principalId, null) };
        foreach (var g in groups) principals.Add((g.Key, g.Value));

        foreach (var (id, groupName) in principals)
        {
            try
            {
                var url = "/v1.0/roleManagement/directory/roleAssignments?$filter=" +
                          Uri.EscapeDataString("principalId eq '" + id + "'");
                using var doc = await _graph.GetAsync(url, ct);
                AddFromDirectoryPayload(doc, groupName is null ? GrantPath.Active : GrantPath.ViaGroup,
                    groupName, held);
            }
            catch (Exception ex) when (groupName is not null)
            {
                // A single group failing shouldn't kill the review.
                AddIssue("Directory roles for group '" + groupName + "' unavailable (" +
                             Head(ex.Message) + ").");
            }
            catch (Exception ex)
            {
                AddIssue("Directory role assignments unavailable (" + Head(ex.Message) + ").");
            }
        }

        // PIM eligible assignments for the user.
        try
        {
            var url = "/v1.0/roleManagement/directory/roleEligibilitySchedules?$filter=" +
                      Uri.EscapeDataString("principalId eq '" + principalId + "'");
            using var doc = await _graph.GetAsync(url, ct);
            AddFromDirectoryPayload(doc, GrantPath.Eligible, null, held);
        }
        catch (Exception ex)
        {
            AddIssue("PIM eligible assignments unavailable (" + Head(ex.Message) +
                         ") — the user may have activatable roles not shown.");
        }
    }

    private void AddFromDirectoryPayload(
        JsonDocument doc, GrantPath path, string? groupName, List<HeldRole> held)
    {
        if (!doc.RootElement.TryGetProperty("value", out var value) ||
            value.ValueKind != JsonValueKind.Array) return;

        foreach (var el in value.EnumerateArray())
        {
            var roleId = el.TryGetProperty("roleDefinitionId", out var r) ? r.GetString() : null;
            if (string.IsNullOrEmpty(roleId)) continue;
            var scope = el.TryGetProperty("directoryScopeId", out var s)
                ? s.GetString() ?? "/" : "/";
            var def = _catalog.Find(roleId);
            held.Add(new HeldRole
            {
                Provider = RbacProviders.Directory,
                RoleId = roleId,
                DisplayName = def?.DisplayName ?? roleId,
                Path = path,
                ViaGroupName = groupName,
                DirectoryScope = scope,
                GrantedActions = def?.AllowedResourceActions ?? Array.Empty<string>()
            });
        }
    }

    private async Task AddMultiAsync(
        string provider, string principalId, Dictionary<string, string> groups,
        List<HeldRole> held, CancellationToken ct)
    {
        // unifiedRoleAssignmentMultiple holds a principalIds collection; server-side
        // filtering on it is unreliable, so page the provider and match client-side.
        try
        {
            string? url = "/beta/roleManagement/" + provider + "/roleAssignments?$top=100";
            int guard = 0;
            while (url is not null && guard++ < 50)
            {
                using var doc = await _graph.GetAsync(url, ct);
                if (doc.RootElement.TryGetProperty("value", out var value) &&
                    value.ValueKind == JsonValueKind.Array)
                {
                    foreach (var el in value.EnumerateArray())
                    {
                        if (!el.TryGetProperty("principalIds", out var pids) ||
                            pids.ValueKind != JsonValueKind.Array) continue;

                        string? matchedGroup = null;
                        bool direct = false;
                        foreach (var p in pids.EnumerateArray())
                        {
                            var pid = p.GetString();
                            if (pid is null) continue;
                            if (string.Equals(pid, principalId, StringComparison.OrdinalIgnoreCase))
                                direct = true;
                            else if (groups.TryGetValue(pid, out var gname))
                                matchedGroup = gname;
                        }
                        if (!direct && matchedGroup is null) continue;

                        var roleId = el.TryGetProperty("roleDefinitionId", out var r)
                            ? r.GetString() : null;
                        if (string.IsNullOrEmpty(roleId)) continue;
                        var def = _catalog.Find(roleId);
                        held.Add(new HeldRole
                        {
                            Provider = provider,
                            RoleId = roleId,
                            DisplayName = def?.DisplayName ??
                                (el.TryGetProperty("displayName", out var dn)
                                    ? dn.GetString() ?? roleId : roleId),
                            Path = direct ? GrantPath.Active : GrantPath.ViaGroup,
                            ViaGroupName = direct ? null : matchedGroup,
                            GrantedActions = def?.AllowedResourceActions ?? Array.Empty<string>()
                        });
                    }
                }
                url = doc.RootElement.TryGetProperty("@odata.nextLink", out var n)
                    ? n.GetString() : null;
            }
        }
        catch (Exception ex)
        {
            Warnings.Add(RbacProviders.DisplayName(provider) + " assignments unavailable (" +
                         Head(ex.Message) + ").");
        }
    }

    private static string Head(string s) => s.Length <= 160 ? s : s[..160];
}
