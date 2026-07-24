using System.Text.Json;

namespace AccessCheck.Graph;

public sealed record AdministrativeUnitInfo(string Id, string DisplayName, string Description)
{
    /// <summary>The directoryScopeId form a role assignment uses to scope to this AU.</summary>
    public string DirectoryScopeId => "/administrativeUnits/" + Id;
    public override string ToString() =>
        DisplayName + (string.IsNullOrWhiteSpace(Description) ? "" : " — " + Description);
}

/// <summary>
/// Administrative Units are the main way an Entra directory role is narrowed from
/// tenant-wide to a slice of the directory. Scoping a role to an AU is itself a
/// least-privilege control, so the broker needs to be able to read and apply them.
/// Requires AdministrativeUnit.Read.All (or Directory.Read.All).
/// </summary>
public sealed class AdministrativeUnitReader
{
    private readonly GraphClient _graph;
    public AdministrativeUnitReader(GraphClient graph) => _graph = graph;

    public async Task<IReadOnlyList<AdministrativeUnitInfo>> ListAsync(CancellationToken ct = default)
    {
        var units = new List<AdministrativeUnitInfo>();
        string? url = "/v1.0/directory/administrativeUnits?$select=id,displayName,description&$top=100";
        int guard = 0;
        while (url is not null && guard++ < 50)
        {
            using var doc = await _graph.GetAsync(url, ct);
            if (doc.RootElement.TryGetProperty("value", out var v))
            {
                foreach (var el in v.EnumerateArray())
                {
                    units.Add(new AdministrativeUnitInfo(
                        el.TryGetProperty("id", out var i) ? i.GetString() ?? "" : "",
                        el.TryGetProperty("displayName", out var d) ? d.GetString() ?? "" : "",
                        el.TryGetProperty("description", out var de) ? de.GetString() ?? "" : ""));
                }
            }
            url = doc.RootElement.TryGetProperty("@odata.nextLink", out var n) ? n.GetString() : null;
        }
        return units.OrderBy(u => u.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Resolves a directoryScopeId back to a readable label for reviews.</summary>
    public async Task<string> DescribeScopeAsync(string directoryScopeId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(directoryScopeId) || directoryScopeId == "/")
            return "tenant-wide";
        const string prefix = "/administrativeUnits/";
        if (!directoryScopeId.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return directoryScopeId;

        var id = directoryScopeId[prefix.Length..];
        try
        {
            using var doc = await _graph.GetAsync(
                "/v1.0/directory/administrativeUnits/" + id + "?$select=id,displayName", ct);
            var name = doc.RootElement.TryGetProperty("displayName", out var d)
                ? d.GetString() : null;
            return "AU: " + (name ?? id);
        }
        catch (Exception) { return "AU: " + id; }
    }
}
