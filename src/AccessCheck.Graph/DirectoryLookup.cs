using System.Text.Json;

namespace AccessCheck.Graph;

public sealed record GroupHit(string Id, string DisplayName, bool IsRoleAssignable)
{
    public override string ToString() =>
        DisplayName + (IsRoleAssignable ? "  [role-assignable]" : "") + "  (" + Id + ")";
}

public sealed record UserHit(string Id, string DisplayName, string Upn)
{
    public override string ToString() =>
        string.IsNullOrWhiteSpace(Upn) ? DisplayName : DisplayName + "  (" + Upn + ")";
}

/// <summary>
/// User search for the people picker. Requires delegated User.Read.All.
/// Strategy: $search (ConsistencyLevel: eventual) first — it matches ANYWHERE in the
/// name, so "test user 1" finds "Test User 1" and also "User 1, Test". Falls back to
/// startswith filters if $search is unavailable, then to a UPN-prefix match.
/// </summary>
public sealed class DirectoryLookup
{
    private readonly GraphClient _graph;
    public DirectoryLookup(GraphClient graph) => _graph = graph;

    private static readonly Dictionary<string, string> EventualHeader =
        new() { ["ConsistencyLevel"] = "eventual" };

    /// <summary>Diagnostic detail from the last search (which strategy ran, what failed).</summary>
    public string LastDiagnostics { get; private set; } = "";

    public async Task<IReadOnlyList<UserHit>> SearchUsersAsync(
        string query, CancellationToken ct = default)
    {
        var q = query.Trim();
        LastDiagnostics = "";
        if (q.Length == 0) return Array.Empty<UserHit>();

        // 1) $search — substring match across displayName / UPN / mail.
        try
        {
            var term = q.Replace("\"", "");
            var search = "\"displayName:" + term + "\" OR \"userPrincipalName:" + term +
                         "\" OR \"mail:" + term + "\"";
            var url = "/v1.0/users?$search=" + Uri.EscapeDataString(search) +
                      "&$select=id,displayName,userPrincipalName&$top=25";
            var hits = await RunAsync(url, EventualHeader, ct);
            LastDiagnostics = "$search returned " + hits.Count + " result(s).";
            if (hits.Count > 0) return hits;
        }
        catch (GraphApiException gex) when (gex.StatusCode is 401 or 403)
        {
            LastDiagnostics =
                "Graph denied the user lookup (" + gex.StatusCode + "). Add delegated " +
                "User.Read.All on the app registration and click Grant admin consent, " +
                "then sign in again.";
            return Array.Empty<UserHit>();
        }
        catch (Exception ex)
        {
            LastDiagnostics = "$search unavailable (" + Head(ex.Message) + "); trying startswith. ";
        }

        // 2) startswith filter on displayName / UPN / mail.
        try
        {
            var esc = q.Replace("'", "''");
            var filter = "startswith(displayName,'" + esc + "') or " +
                         "startswith(userPrincipalName,'" + esc + "') or " +
                         "startswith(mail,'" + esc + "')";
            var url = "/v1.0/users?$filter=" + Uri.EscapeDataString(filter) +
                      "&$select=id,displayName,userPrincipalName&$top=25";
            var hits = await RunAsync(url, null, ct);
            LastDiagnostics += "startswith returned " + hits.Count + " result(s).";
            if (hits.Count > 0) return hits;
        }
        catch (Exception ex)
        {
            LastDiagnostics += "startswith failed: " + Head(ex.Message) + " ";
        }

        // 3) Last resort: first token only (handles "Test User 1" typed against "Test").
        var firstToken = q.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        if (!string.IsNullOrEmpty(firstToken) && firstToken.Length >= 2 &&
            !string.Equals(firstToken, q, StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var esc = firstToken.Replace("'", "''");
                var filter = "startswith(displayName,'" + esc + "') or " +
                             "startswith(userPrincipalName,'" + esc + "')";
                var url = "/v1.0/users?$filter=" + Uri.EscapeDataString(filter) +
                          "&$select=id,displayName,userPrincipalName&$top=25";
                var hits = await RunAsync(url, null, ct);
                LastDiagnostics += " Fallback on '" + firstToken + "' returned " +
                                   hits.Count + " result(s).";
                return hits;
            }
            catch (Exception ex)
            {
                LastDiagnostics += " Fallback failed: " + Head(ex.Message);
            }
        }

        return Array.Empty<UserHit>();
    }

    /// <summary>
    /// Group search for the PIM group picker. isAssignableToRole matters: a group can
    /// only hold Entra DIRECTORY roles if it was created role-assignable, and that flag
    /// is immutable after creation.
    /// </summary>
    public async Task<IReadOnlyList<GroupHit>> SearchGroupsAsync(
        string query, CancellationToken ct = default)
    {
        var q = query.Trim();
        if (q.Length == 0) return Array.Empty<GroupHit>();
        var esc = q.Replace("'", "''");
        var filter = "startswith(displayName,'" + esc + "')";
        var url = "/v1.0/groups?$filter=" + Uri.EscapeDataString(filter) +
                  "&$select=id,displayName,isAssignableToRole,securityEnabled&$top=25";
        using var doc = await _graph.GetAsync(url, ct);
        var hits = new List<GroupHit>();
        if (doc.RootElement.TryGetProperty("value", out var value))
        {
            foreach (var el in value.EnumerateArray())
            {
                hits.Add(new GroupHit(
                    el.GetProperty("id").GetString() ?? "",
                    el.TryGetProperty("displayName", out var d) ? d.GetString() ?? "" : "",
                    el.TryGetProperty("isAssignableToRole", out var r) &&
                        r.ValueKind == JsonValueKind.True));
            }
        }
        return hits;
    }

    /// <summary>
    /// One group by object id, or null if it cannot be read.
    ///
    /// The picker already surfaces isAssignableToRole, but a PASTED GUID never went
    /// through the picker — it passes straight into the grant, and the first anyone hears
    /// about a plain security group is Graph refusing the role attach. This is what lets
    /// that be checked beforehand.
    ///
    /// Returns null rather than throwing on 404: a group created seconds ago may not have
    /// replicated yet, and a pre-flight that cannot read it must not block a grant that
    /// would otherwise succeed.
    /// </summary>
    public async Task<GroupHit?> GetGroupByIdAsync(string groupId, CancellationToken ct = default)
    {
        var id = groupId.Trim();
        if (id.Length == 0) return null;
        try
        {
            using var doc = await _graph.GetAsync(
                "/v1.0/groups/" + Uri.EscapeDataString(id)
                + "?$select=id,displayName,isAssignableToRole,securityEnabled", ct);
            var el = doc.RootElement;
            return new GroupHit(
                el.TryGetProperty("id", out var i) ? i.GetString() ?? id : id,
                el.TryGetProperty("displayName", out var d) ? d.GetString() ?? "" : "",
                el.TryGetProperty("isAssignableToRole", out var r) && r.ValueKind == JsonValueKind.True);
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>Resolves a group by exact display name; null if not found or ambiguous.</summary>
    public async Task<GroupHit?> ResolveGroupByNameAsync(
        string displayName, CancellationToken ct = default)
    {
        var hits = await SearchGroupsAsync(displayName, ct);
        var exact = hits
            .Where(h => string.Equals(h.DisplayName, displayName.Trim(),
                StringComparison.OrdinalIgnoreCase))
            .ToList();
        return exact.Count == 1 ? exact[0] : null;
    }

    private async Task<List<UserHit>> RunAsync(
        string url, IReadOnlyDictionary<string, string>? headers, CancellationToken ct)
    {
        using var doc = await _graph.GetAsync(url, headers, ct);
        var hits = new List<UserHit>();
        if (doc.RootElement.TryGetProperty("value", out var value))
        {
            foreach (var el in value.EnumerateArray())
            {
                hits.Add(new UserHit(
                    el.GetProperty("id").GetString() ?? "",
                    el.TryGetProperty("displayName", out var d) ? d.GetString() ?? "" : "",
                    el.TryGetProperty("userPrincipalName", out var u) ? u.GetString() ?? "" : ""));
            }
        }
        return hits;
    }

    private static string Head(string s) => s.Length <= 200 ? s : s[..200];
}
