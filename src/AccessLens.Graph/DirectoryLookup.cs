using System.Text.Json;

namespace AccessLens.Graph;

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
