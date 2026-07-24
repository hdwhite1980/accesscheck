using System.Text;
using System.Text.Json;
using AccessCheck.Core.Catalog;

namespace AccessCheck.Graph;

/// <summary>
/// Reports everything Graph knows about ONE group across every surface a role can be
/// attached to. Exists to settle "this group should have roles" arguments with evidence:
/// each surface is queried separately and reported, including the ones that return
/// nothing, so a blank result is provably blank rather than a missed query.
/// </summary>
public sealed class GroupInspector
{
    private readonly GraphClient _graph;
    private readonly RoleCatalog _catalog;

    public GroupInspector(GraphClient graph, RoleCatalog catalog)
    {
        _graph = graph;
        _catalog = catalog;
    }

    public async Task<string> InspectAsync(
        string groupId, Action<string>? progress = null, CancellationToken ct = default)
    {
        var sb = new StringBuilder();
        int totalHoldings = 0;

        // ---- 1. the group itself ----
        progress?.Invoke("Reading group properties...");
        sb.AppendLine("GROUP");
        try
        {
            using var doc = await _graph.GetAsync(
                "/v1.0/groups/" + groupId +
                "?$select=id,displayName,description,securityEnabled,mailEnabled," +
                "isAssignableToRole,groupTypes,membershipRule", ct);
            var r = doc.RootElement;
            sb.AppendLine("  Name: " + Str(r, "displayName"));
            sb.AppendLine("  Id: " + Str(r, "id"));
            sb.AppendLine("  Security-enabled: " + Bool(r, "securityEnabled") +
                          "   Mail-enabled: " + Bool(r, "mailEnabled"));
            var raRaw = r.TryGetProperty("isAssignableToRole", out var raEl) ? raEl.ValueKind : JsonValueKind.Undefined;
            var raYes = raRaw == JsonValueKind.True;
            sb.AppendLine("  Role-assignable: " + (raYes ? "YES" : "NO") +
                          (raRaw is JsonValueKind.Null or JsonValueKind.Undefined
                              ? "  (property null/absent, which means not role-assignable)" : "") +
                          Environment.NewLine +
                          "    -> " + (raYes
                              ? "can hold Entra DIRECTORY roles."
                              : "CANNOT hold Entra directory roles. That flag is set only at " +
                                "creation and cannot be changed, so a new group is required for " +
                                "directory roles. Intune / Windows 365 / Defender roles do NOT " +
                                "need it and can be assigned to this group as-is."));
            var rule = Str(r, "membershipRule");
            if (!string.IsNullOrWhiteSpace(rule) && rule != "-")
                sb.AppendLine("  Dynamic membership rule: " + rule);
        }
        catch (Exception ex)
        {
            sb.AppendLine("  Could not read the group: " + ex.Message);
            sb.AppendLine("  (If this is a 404, the id is wrong or it isn't a group.)");
            return sb.ToString();
        }

        // ---- 2. member count ----
        try
        {
            using var doc = await _graph.GetAsync(
                "/v1.0/groups/" + groupId + "/members?$select=id&$top=50", ct);
            var n = doc.RootElement.TryGetProperty("value", out var v) ? v.GetArrayLength() : 0;
            sb.AppendLine("  Direct members (first page): " + n);
        }
        catch (Exception ex) { sb.AppendLine("  Members unreadable: " + Head(ex.Message)); }

        // ---- 3. Entra directory roles held BY this group ----
        progress?.Invoke("Checking Entra directory role assignments...");
        sb.AppendLine();
        sb.AppendLine("ENTRA DIRECTORY ROLES HELD BY THIS GROUP");
        totalHoldings += await ReportFilteredAsync(sb,
            "/v1.0/roleManagement/directory/roleAssignments?$filter=" +
            Uri.EscapeDataString("principalId eq '" + groupId + "'"),
            "active assignment", ct);
        totalHoldings += await ReportFilteredAsync(sb,
            "/v1.0/roleManagement/directory/roleEligibilitySchedules?$filter=" +
            Uri.EscapeDataString("principalId eq '" + groupId + "'"),
            "PIM eligibility", ct);

        // ---- 4. unified multi-provider ----
        foreach (var provider in new[]
                 { RbacProviders.Intune, RbacProviders.CloudPc, RbacProviders.Defender })
        {
            progress?.Invoke("Checking " + RbacProviders.DisplayName(provider) + "...");
            sb.AppendLine();
            sb.AppendLine(RbacProviders.DisplayName(provider).ToUpperInvariant() +
                          " ROLES HELD BY THIS GROUP");
            totalHoldings += await ReportMultiAsync(sb, provider, groupId, ct);
        }

        // ---- 5. Intune-native (members collection) ----
        progress?.Invoke("Checking Intune-native assignments...");
        sb.AppendLine();
        sb.AppendLine("INTUNE-NATIVE ROLE ASSIGNMENTS CONTAINING THIS GROUP");
        totalHoldings += await ReportIntuneNativeAsync(sb, groupId, ct);

        // ---- 6. inherited through parent groups ----
        progress?.Invoke("Checking parent groups...");
        sb.AppendLine();
        sb.AppendLine("INHERITED VIA PARENT GROUPS (nesting)");
        try
        {
            using var doc = await _graph.GetAsync(
                "/v1.0/groups/" + groupId +
                "/transitiveMemberOf/microsoft.graph.group?$select=id,displayName&$top=50", ct);
            var parents = new List<(string Id, string Name)>();
            if (doc.RootElement.TryGetProperty("value", out var v))
                foreach (var el in v.EnumerateArray())
                    parents.Add((Str(el, "id"), Str(el, "displayName")));

            if (parents.Count == 0)
                sb.AppendLine("  This group is not a member of any other group.");
            else
                foreach (var (pid, pname) in parents)
                {
                    var count = await CountFilteredAsync(
                        "/v1.0/roleManagement/directory/roleAssignments?$filter=" +
                        Uri.EscapeDataString("principalId eq '" + pid + "'"), ct);
                    sb.AppendLine("  Member of '" + pname + "' — that group holds " +
                                  count + " directory role(s)" +
                                  (count > 0 ? "  <-- members of THIS group inherit them" : ""));
                    totalHoldings += count;
                }
        }
        catch (Exception ex) { sb.AppendLine("  Parent lookup failed: " + Head(ex.Message)); }

        // ---- 7. PIM for Groups onboarding ----
        progress?.Invoke("Checking PIM for Groups...");
        sb.AppendLine();
        sb.AppendLine("PIM FOR GROUPS (membership governance on this group)");
        await ReportPimGroupAsync(sb, groupId, ct);

        // ---- verdict ----
        sb.AppendLine();
        sb.AppendLine("VERDICT");
        sb.AppendLine(totalHoldings == 0
            ? "  No role is assigned to this group on ANY surface checked above. That is why it\n" +
              "  does not appear in the Groups tab — the tab lists groups that CARRY roles.\n" +
              "  Note: PIM-for-Groups membership grants (adding a USER to this group) do not give\n" +
              "  the GROUP a role. The group must itself be assigned a role to grant anything."
            : "  This group carries " + totalHoldings + " role holding(s) — it should appear in the\n" +
              "  Groups tab after a re-sync. If it doesn't, send this report.");
        return sb.ToString();
    }

    // ---- helpers ----

    private async Task<int> ReportFilteredAsync(
        StringBuilder sb, string url, string label, CancellationToken ct)
    {
        try
        {
            using var doc = await _graph.GetAsync(url, ct);
            int n = 0;
            if (doc.RootElement.TryGetProperty("value", out var v))
            {
                foreach (var el in v.EnumerateArray())
                {
                    var rid = Str(el, "roleDefinitionId");
                    var def = _catalog.Find(rid);
                    sb.AppendLine("  [" + label + "] " + (def?.DisplayName ?? rid) +
                                  "  (" + (def?.AllowedResourceActions.Count ?? 0) + " permissions)");
                    n++;
                }
            }
            if (n == 0) sb.AppendLine("  none (" + label + ")");
            return n;
        }
        catch (Exception ex)
        {
            sb.AppendLine("  " + label + " query failed: " + Head(ex.Message));
            return 0;
        }
    }

    private async Task<int> CountFilteredAsync(string url, CancellationToken ct)
    {
        try
        {
            using var doc = await _graph.GetAsync(url, ct);
            return doc.RootElement.TryGetProperty("value", out var v) ? v.GetArrayLength() : 0;
        }
        catch (Exception) { return 0; }
    }

    private async Task<int> ReportMultiAsync(
        StringBuilder sb, string provider, string groupId, CancellationToken ct)
    {
        try
        {
            int n = 0;
            string? url = "/beta/roleManagement/" + provider + "/roleAssignments?$top=50";
            int guard = 0;
            while (url is not null && guard++ < 50)
            {
                using var doc = await _graph.GetAsync(url, ct);
                if (doc.RootElement.TryGetProperty("value", out var v))
                {
                    foreach (var el in v.EnumerateArray())
                    {
                        if (!el.TryGetProperty("principalIds", out var pids) ||
                            pids.ValueKind != JsonValueKind.Array) continue;
                        bool match = pids.EnumerateArray().Any(p =>
                            string.Equals(p.GetString(), groupId, StringComparison.OrdinalIgnoreCase));
                        if (!match) continue;
                        var rid = Str(el, "roleDefinitionId");
                        var def = _catalog.Find(rid);
                        sb.AppendLine("  " + (def?.DisplayName ?? rid) +
                                      "  (" + (def?.AllowedResourceActions.Count ?? 0) + " permissions)");
                        n++;
                    }
                }
                url = doc.RootElement.TryGetProperty("@odata.nextLink", out var nx)
                    ? nx.GetString() : null;
            }
            if (n == 0) sb.AppendLine("  none");
            return n;
        }
        catch (Exception ex)
        {
            sb.AppendLine("  query failed: " + Head(ex.Message));
            return 0;
        }
    }

    private async Task<int> ReportIntuneNativeAsync(
        StringBuilder sb, string groupId, CancellationToken ct)
    {
        // Inverted query: listing all roleAssignments with $expand fails when any one has
        // a null roleDefinition, so each role is asked for its own assignments instead.
        var roles = _catalog.RolesFor(RbacProviders.Intune).ToList();
        if (roles.Count == 0)
        {
            sb.AppendLine("  (no Intune roles in the catalog — sync the catalog first)");
            return 0;
        }

        int n = 0, failed = 0;
        foreach (var role in roles)
        {
            try
            {
                using var doc = await _graph.GetAsync(
                    "/beta/deviceManagement/roleDefinitions/" + role.Id +
                    "/roleAssignments?$top=50", ct);
                if (!doc.RootElement.TryGetProperty("value", out var v)) continue;
                foreach (var el in v.EnumerateArray())
                {
                    if (!el.TryGetProperty("members", out var members) ||
                        members.ValueKind != JsonValueKind.Array) continue;
                    if (!members.EnumerateArray().Any(m => string.Equals(
                            m.GetString(), groupId, StringComparison.OrdinalIgnoreCase))) continue;
                    sb.AppendLine("  " + role.DisplayName + "  via assignment '" +
                                  Str(el, "displayName") + "'  (" +
                                  role.AllowedResourceActions.Count + " permissions)");
                    n++;
                }
            }
            catch (Exception) { failed++; }
        }
        if (n == 0)
            sb.AppendLine("  none" + (failed > 0 ? "  (" + failed + " role(s) unreadable)" : ""));
        return n;
    }

    private async Task ReportPimGroupAsync(StringBuilder sb, string groupId, CancellationToken ct)
    {
        foreach (var (path, label) in new[]
                 {
                     ("/v1.0/identityGovernance/privilegedAccess/group/assignmentSchedules",
                      "active membership schedule"),
                     ("/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules",
                      "eligible membership schedule")
                 })
        {
            try
            {
                var url = path + "?$filter=" + Uri.EscapeDataString("groupId eq '" + groupId + "'");
                using var doc = await _graph.GetAsync(url, ct);
                var n = doc.RootElement.TryGetProperty("value", out var v) ? v.GetArrayLength() : 0;
                sb.AppendLine("  " + label + "(s): " + n +
                              (n > 0 ? "  (governs who is IN the group — not what the group can DO)" : ""));
            }
            catch (Exception ex)
            {
                sb.AppendLine("  " + label + " query failed: " + Head(ex.Message));
            }
        }
    }

    private static string Str(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? "-" : "-";

    private static string Bool(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v)
            ? (v.ValueKind == JsonValueKind.True ? "yes"
               : v.ValueKind == JsonValueKind.False ? "no" : "-")
            : "-";

    private static string Head(string s) => s.Length <= 200 ? s : s[..200];
}
