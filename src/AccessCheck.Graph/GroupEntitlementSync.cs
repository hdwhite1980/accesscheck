using System.Text.Json;
using AccessCheck.Core.Catalog;
using AccessCheck.Core.Groups;

namespace AccessCheck.Graph;

/// <summary>
/// Builds the group entitlement catalog: every group that carries a role, and the union
/// of permissions those roles grant. Answers "is there already a group for this?" from
/// tenant truth instead of the admin's memory.
///
/// Method: collect role assignments across providers, keep the principal ids, ask Graph
/// which of those ids are GROUPS (directoryObjects/getByIds with types:["group"]), then
/// expand each held role to its actions using the synced role catalog.
/// </summary>
public sealed class GroupEntitlementSync
{
    private readonly GraphClient _graph;
    private readonly RoleCatalog _catalog;

    public GroupEntitlementSync(GraphClient graph, RoleCatalog catalog)
    {
        _graph = graph;
        _catalog = catalog;
    }

    public List<string> Warnings { get; } = new();

    /// <summary>Classified issues — expected conditions stay out of the banner.</summary>
    public IssueLog Issues { get; } = new();

    private void AddIssue(string source, string message)
    {
        Warnings.Add(source + " " + message);
        Issues.AddError(source, message);
    }

    /// <summary>Per-source counts so a zero result is explainable, not mysterious.</summary>
    public List<string> SourceCounts { get; } = new();

    /// <summary>How many distinct principals held a role (before filtering to groups).</summary>
    public int PrincipalsExamined { get; private set; }
    /// <summary>How many of those principals turned out to be groups.</summary>
    public int GroupsIdentified { get; private set; }

    /// <summary>
    /// Pages a collection endpoint. Graph caps $top at 100 on several of these
    /// (Defender rejects anything larger with a 400), so we page at 50 and, if the first
    /// attempt still fails, retry once with no $top at all before giving up.
    /// </summary>
    private async Task<int> PageAsync(
        string url, Func<JsonElement, int> handlePage, CancellationToken ct)
    {
        var attempts = new List<string> { url };
        var qIndex = url.IndexOf("$top=", StringComparison.Ordinal);
        if (qIndex > 0)
        {
            var stripped = System.Text.RegularExpressions.Regex
                .Replace(url, @"[?&]\$top=\d+", "");
            if (!stripped.Contains('?') && stripped.Contains('&'))
                stripped = stripped.Replace('&', '?');
            attempts.Add(stripped);
        }

        Exception? last = null;
        foreach (var start in attempts)
        {
            try
            {
                int total = 0;
                string? next = start;
                int guard = 0;
                while (next is not null && guard++ < 200)
                {
                    using var doc = await _graph.GetAsync(next, ct);
                    total += handlePage(doc.RootElement);
                    next = doc.RootElement.TryGetProperty("@odata.nextLink", out var n)
                        ? n.GetString() : null;
                }
                return total;
            }
            catch (Exception ex)
            {
                last = ex;
            }
        }
        throw last ?? new InvalidOperationException("Paging failed for " + url);
    }

    private sealed record RawHolding(string Provider, string RoleId, bool Eligible);

    public async Task<GroupCatalog> SyncAsync(
        Action<string>? progress = null, CancellationToken ct = default)
    {
        Warnings.Clear();
        // principalId -> holdings
        var byPrincipal = new Dictionary<string, List<RawHolding>>(StringComparer.OrdinalIgnoreCase);

        void Add(string principalId, RawHolding h)
        {
            if (string.IsNullOrWhiteSpace(principalId)) return;
            if (!byPrincipal.TryGetValue(principalId, out var list))
                byPrincipal[principalId] = list = new List<RawHolding>();
            if (!list.Any(x => x.Provider == h.Provider && x.RoleId == h.RoleId && x.Eligible == h.Eligible))
                list.Add(h);
        }

        // ---- directory: active assignments + PIM eligibilities ----
        progress?.Invoke("Reading Entra directory role assignments...");
        await CollectSingleAsync("/v1.0/roleManagement/directory/roleAssignments?$top=50",
            RbacProviders.Directory, false, Add, ct);
        await CollectSingleAsync("/v1.0/roleManagement/directory/roleEligibilitySchedules?$top=50",
            RbacProviders.Directory, true, Add, ct);

        // ---- unified multi-provider assignments ----
        foreach (var provider in new[]
                 { RbacProviders.Intune, RbacProviders.CloudPc, RbacProviders.Defender })
        {
            progress?.Invoke("Reading " + RbacProviders.DisplayName(provider) + " assignments...");
            await CollectMultiAsync("/beta/roleManagement/" + provider + "/roleAssignments?$top=50",
                provider, Add, ct);
        }

        // ---- Intune-native assignments (members = group ids) ----
        progress?.Invoke("Reading Intune-native role assignments...");
        await CollectIntuneNativeAsync(Add, ct);

        PrincipalsExamined = byPrincipal.Count;
        if (byPrincipal.Count == 0)
        {
            Warnings.Add("No role assignments were readable from any source — nothing to group.");
            return new GroupCatalog { LastSyncedUtc = DateTimeOffset.UtcNow };
        }

        // ---- which of those principals are groups? ----
        progress?.Invoke("Identifying which of " + byPrincipal.Count +
                         " principal(s) are groups...");
        var groups = await ResolveGroupsAsync(byPrincipal.Keys.ToList(), ct);
        GroupsIdentified = groups.Count;

        // Attach how many roles each principal holds, and surface unresolved ids.
        for (int i = 0; i < Holders.Count; i++)
        {
            var h = Holders[i];
            var count = byPrincipal.TryGetValue(h.Id, out var hl) ? hl.Count : 0;
            Holders[i] = h with { RoleCount = count };
        }
        foreach (var id in byPrincipal.Keys)
            if (!Holders.Any(h => string.Equals(h.Id, id, StringComparison.OrdinalIgnoreCase)))
                Holders.Add(new PrincipalHolder(id, id, "unresolved (no read access)",
                    byPrincipal[id].Count));

        Holders.Sort((a, b) =>
            string.Compare(a.Type, b.Type, StringComparison.Ordinal) != 0
                ? string.Compare(a.Type, b.Type, StringComparison.Ordinal)
                : string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));

        // ---- expand roles to actions ----
        var result = new GroupCatalog { LastSyncedUtc = DateTimeOffset.UtcNow };
        foreach (var (groupId, info) in groups)
        {
            if (!byPrincipal.TryGetValue(groupId, out var raw)) continue;

            var holdings = new List<GroupRoleHolding>();
            var actions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in raw)
            {
                var def = _catalog.Find(h.RoleId);
                holdings.Add(new GroupRoleHolding
                {
                    Provider = h.Provider,
                    RoleId = h.RoleId,
                    RoleName = def?.DisplayName ?? h.RoleId,
                    Eligible = h.Eligible
                });
                if (def is not null)
                    foreach (var a in def.AllowedResourceActions) actions.Add(a);
            }

            result.Groups.Add(new GroupEntitlement
            {
                GroupId = groupId,
                DisplayName = info.Name,
                Description = info.Description,
                IsRoleAssignable = info.RoleAssignable,
                Holdings = holdings,
                GrantedActions = actions
                    .OrderBy(a => a, StringComparer.OrdinalIgnoreCase).ToList()
            });
        }

        result.Groups = result.Groups
            .OrderBy(g => g.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
        return result;
    }

    // ---- collectors ----

    private async Task CollectSingleAsync(
        string startUrl, string provider, bool eligible,
        Action<string, RawHolding> add, CancellationToken ct)
    {
        var label = eligible ? "Entra directory (eligible)" : "Entra directory (active)";
        try
        {
            var count = await PageAsync(startUrl, root =>
            {
                int n = 0;
                if (root.TryGetProperty("value", out var value) &&
                    value.ValueKind == JsonValueKind.Array)
                {
                    foreach (var el in value.EnumerateArray())
                    {
                        var pid = el.TryGetProperty("principalId", out var p) ? p.GetString() : null;
                        var rid = el.TryGetProperty("roleDefinitionId", out var r) ? r.GetString() : null;
                        if (pid is null || rid is null) continue;
                        add(pid, new RawHolding(provider, rid, eligible));
                        n++;
                    }
                }
                return n;
            }, ct);
            SourceCounts.Add(label + ": " + count + " assignment(s)");
        }
        catch (Exception ex)
        {
            AddIssue(label, Head(ex.Message));
            SourceCounts.Add(label + ": FAILED");
        }
    }

    private async Task CollectMultiAsync(
        string startUrl, string provider, Action<string, RawHolding> add, CancellationToken ct)
    {
        var label = RbacProviders.DisplayName(provider);
        try
        {
            var count = await PageAsync(startUrl, root =>
            {
                int n = 0;
                if (root.TryGetProperty("value", out var value) &&
                    value.ValueKind == JsonValueKind.Array)
                {
                    foreach (var el in value.EnumerateArray())
                    {
                        var rid = el.TryGetProperty("roleDefinitionId", out var r) ? r.GetString() : null;
                        if (rid is null) continue;
                        if (!el.TryGetProperty("principalIds", out var pids) ||
                            pids.ValueKind != JsonValueKind.Array) continue;
                        foreach (var p in pids.EnumerateArray())
                        {
                            var pid = p.GetString();
                            if (pid is not null) { add(pid, new RawHolding(provider, rid, false)); n++; }
                        }
                    }
                }
                return n;
            }, ct);
            SourceCounts.Add(label + ": " + count + " assignment(s)");
        }
        catch (Exception ex)
        {
            AddIssue(label, Head(ex.Message));
            SourceCounts.Add(label + ": FAILED");
        }
    }

    /// <summary>
    /// Intune-native assignments. Listing /deviceManagement/roleAssignments with
    /// $expand=roleDefinition fails outright when ANY assignment has a null
    /// roleDefinition ("requires an element of type 'Object' ... has type 'Null'"),
    /// so the query is inverted: ask each known Intune role for ITS assignments.
    /// One bad assignment then costs one role, not the whole source.
    /// </summary>
    private async Task CollectIntuneNativeAsync(Action<string, RawHolding> add, CancellationToken ct)
    {
        const string label = "Intune (native group assignments)";
        var intuneRoles = _catalog.RolesFor(RbacProviders.Intune).ToList();
        if (intuneRoles.Count == 0)
        {
            SourceCounts.Add(label + ": skipped (no Intune roles in the catalog yet)");
            return;
        }

        int total = 0, failed = 0;
        foreach (var role in intuneRoles)
        {
            try
            {
                var url = "/beta/deviceManagement/roleDefinitions/" + role.Id +
                          "/roleAssignments?$top=50";
                total += await PageAsync(url, root =>
                {
                    int n = 0;
                    if (root.TryGetProperty("value", out var value) &&
                        value.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var el in value.EnumerateArray())
                        {
                            if (!el.TryGetProperty("members", out var members) ||
                                members.ValueKind != JsonValueKind.Array) continue;
                            foreach (var m in members.EnumerateArray())
                            {
                                var gid = m.GetString();
                                if (gid is not null)
                                { add(gid, new RawHolding(RbacProviders.Intune, role.Id, false)); n++; }
                            }
                        }
                    }
                    return n;
                }, ct);
            }
            catch (Exception)
            {
                failed++;   // that role's assignments are unreadable; the rest still count
            }
        }

        SourceCounts.Add(label + ": " + total + " membership(s) across " +
                         intuneRoles.Count + " role(s)" +
                         (failed > 0 ? ", " + failed + " role(s) unreadable" : ""));
    }

    private sealed record GroupInfo(string Name, string Description, bool RoleAssignable);

    /// <summary>One principal that holds a role, and what kind of object it is.</summary>
    public sealed record PrincipalHolder(string Id, string Name, string Type, int RoleCount);

    /// <summary>
    /// Every principal holding a role, classified. Direct role assignments to USERS are a
    /// governance finding in their own right — group-based assignment is what lets access
    /// be granted and revoked by membership.
    /// </summary>
    public List<PrincipalHolder> Holders { get; } = new();

    /// <summary>
    /// Resolves ALL role-holding principals (not just groups) so a zero-group result is
    /// provable rather than assumed: the caller can see the 8 principals were users.
    /// Uses POST /directoryObjects/getByIds, falling back to per-id lookups.
    /// </summary>
    private async Task<Dictionary<string, GroupInfo>> ResolveGroupsAsync(
        List<string> principalIds, CancellationToken ct)
    {
        var groups = new Dictionary<string, GroupInfo>(StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < principalIds.Count; i += 900)
        {
            var batch = principalIds.Skip(i).Take(900).ToList();
            bool bulkWorked = false;
            try
            {
                // No type filter: we want to SEE users and service principals too.
                var body = new
                {
                    ids = batch,
                    types = new[] { "user", "group", "servicePrincipal" }
                };
                using var doc = await _graph.PostAsync("/v1.0/directoryObjects/getByIds", body, ct);
                if (doc.RootElement.TryGetProperty("value", out var value))
                {
                    foreach (var el in value.EnumerateArray())
                    {
                        var id = el.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;
                        if (id is null) continue;
                        seen.Add(id);

                        var odataType = el.TryGetProperty("@odata.type", out var t)
                            ? t.GetString() ?? "" : "";
                        var kind = odataType.Contains("group", StringComparison.OrdinalIgnoreCase) ? "group"
                            : odataType.Contains("servicePrincipal", StringComparison.OrdinalIgnoreCase) ? "service principal"
                            : odataType.Contains("user", StringComparison.OrdinalIgnoreCase) ? "user"
                            : "other";

                        var name = el.TryGetProperty("displayName", out var d)
                            ? d.GetString() ?? id : id;
                        if (kind == "user" && el.TryGetProperty("userPrincipalName", out var upn))
                        {
                            var u = upn.GetString();
                            if (!string.IsNullOrWhiteSpace(u)) name = name + " (" + u + ")";
                        }

                        Holders.Add(new PrincipalHolder(id, name, kind, 0));

                        if (kind == "group")
                        {
                            groups[id] = new GroupInfo(
                                el.TryGetProperty("displayName", out var gd) ? gd.GetString() ?? id : id,
                                el.TryGetProperty("description", out var de) ? de.GetString() ?? "" : "",
                                el.TryGetProperty("isAssignableToRole", out var ra) &&
                                    ra.ValueKind == JsonValueKind.True);
                        }
                    }
                }
                bulkWorked = true;
            }
            catch (Exception ex)
            {
                Warnings.Add("Bulk principal lookup unavailable (" + Head(ex.Message) +
                             ") — falling back to per-object lookups.");
            }

            if (bulkWorked) continue;

            foreach (var id in batch)
            {
                if (seen.Contains(id)) continue;
                try
                {
                    using var doc = await _graph.GetAsync(
                        "/v1.0/groups/" + id + "?$select=id,displayName,description,isAssignableToRole", ct);
                    var root = doc.RootElement;
                    groups[id] = new GroupInfo(
                        root.TryGetProperty("displayName", out var d) ? d.GetString() ?? id : id,
                        root.TryGetProperty("description", out var de) ? de.GetString() ?? "" : "",
                        root.TryGetProperty("isAssignableToRole", out var ra) &&
                            ra.ValueKind == JsonValueKind.True);
                    Holders.Add(new PrincipalHolder(id,
                        groups[id].Name, "group", 0));
                    seen.Add(id);
                }
                catch (Exception)
                {
                    Holders.Add(new PrincipalHolder(id, id, "not a group (user or service principal)", 0));
                    seen.Add(id);
                }
            }
        }
        return groups;
    }

    private static string Head(string s) => s.Length <= 160 ? s : s[..160];
}
