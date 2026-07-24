using System.Text.Json;
using AccessCheck.Core.Catalog;

namespace AccessCheck.Graph;

/// <summary>
/// Adds the richer role metadata that only the BETA unifiedRoleDefinition endpoint carries.
///
/// The directory catalog is read from v1.0, which returns id, displayName, description,
/// isBuiltIn and rolePermissions — and nothing else. Beta additionally carries:
///
///   isPrivileged           the ROLE is an escalation path (not the per-action flag)
///   allowedPrincipalTypes  what may hold it
///   assignmentMode         undocumented but present; likely carries AU-scopability
///   categories             Microsoft's own grouping
///   richDescription        fuller prose than the short description
///
/// This runs as a SEPARATE PASS rather than switching the catalog to beta, because a
/// working v1.0 sync is worth more than richer metadata: if beta is unavailable, throttled,
/// or shaped differently in a Gov cloud, the catalog must still be correct. An enrichment
/// step must never be able to fail the thing it decorates.
///
/// NOTE: resourceScopes is deliberately NOT read. It looks like the AU-scopability signal
/// and is not — Microsoft documents it as always "/" and marks it DO NOT USE, deprecated.
/// </summary>
public sealed class RoleMetadataEnricher
{
    private readonly GraphClient _graph;

    public RoleMetadataEnricher(GraphClient graph) => _graph = graph;

    public sealed record Result
    {
        public int Enriched { get; init; }
        public int PrivilegedRoles { get; init; }
        /// <summary>Distinct assignmentMode values seen — the point of reading it.</summary>
        public IReadOnlyList<string> AssignmentModesSeen { get; init; } = Array.Empty<string>();
        public string Detail { get; init; } = "";
    }

    /// <summary>
    /// Merges beta metadata into the directory slice of the catalog. Returns what it
    /// learned; on any failure returns a Result explaining it and leaves the catalog alone.
    /// </summary>
    public async Task<Result> EnrichDirectoryAsync(
        RoleCatalog catalog, Action<string>? progress = null, CancellationToken ct = default)
    {
        var byId = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);

        try
        {
            progress?.Invoke("Reading richer role metadata from Microsoft (beta)...");

            string? url = "/beta/roleManagement/directory/roleDefinitions"
                        + "?$select=id,displayName,isPrivileged,allowedPrincipalTypes,"
                        + "assignmentMode,categories,richDescription";
            var guard = 0;

            while (url is not null && guard++ < 50)
            {
                using var doc = await _graph.GetAsync(url, ct);
                var root = doc.RootElement;

                if (root.TryGetProperty("value", out var value)
                    && value.ValueKind == JsonValueKind.Array)
                {
                    foreach (var el in value.EnumerateArray())
                    {
                        if (el.ValueKind != JsonValueKind.Object) continue;
                        if (!el.TryGetProperty("id", out var idEl)) continue;
                        var id = idEl.GetString();
                        if (string.IsNullOrWhiteSpace(id)) continue;
                        byId[id!] = el.Clone();
                    }
                }

                url = root.TryGetProperty("@odata.nextLink", out var next)
                    ? next.GetString() : null;
            }
        }
        catch (Exception ex)
        {
            return new Result
            {
                Detail = "Richer role metadata unavailable (" + Head(ex.Message)
                       + "). The catalog is unaffected; ranking falls back to per-action "
                       + "risk only."
            };
        }

        if (byId.Count == 0)
            return new Result { Detail = "Beta returned no role metadata; catalog unaffected." };

        var existing = catalog.RolesFor(RbacProviders.Directory).ToList();
        var rebuilt = new List<RoleDefinitionRecord>(existing.Count);
        var enriched = 0;
        var privileged = 0;
        var modes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var role in existing)
        {
            if (!byId.TryGetValue(role.Id, out var meta))
            {
                rebuilt.Add(role);
                continue;
            }

            var isPriv = meta.TryGetProperty("isPrivileged", out var p)
                         && p.ValueKind is JsonValueKind.True or JsonValueKind.False
                ? p.ValueKind == JsonValueKind.True
                : (bool?)null;

            var mode = Str(meta, "assignmentMode");
            if (!string.IsNullOrWhiteSpace(mode)) modes.Add(mode!);
            if (isPriv == true) privileged++;

            rebuilt.Add(role with
            {
                IsPrivilegedRole = isPriv,
                AllowedPrincipalTypes = Str(meta, "allowedPrincipalTypes"),
                AssignmentMode = mode,
                Categories = Str(meta, "categories"),
                RichDescription = Str(meta, "richDescription")
            });
            enriched++;
        }

        if (enriched > 0) catalog.ReplaceProvider(RbacProviders.Directory, rebuilt);

        return new Result
        {
            Enriched = enriched,
            PrivilegedRoles = privileged,
            AssignmentModesSeen = modes.OrderBy(m => m, StringComparer.OrdinalIgnoreCase).ToList(),
            Detail = enriched + " directory role(s) enriched; " + privileged
                   + " flagged privileged by Microsoft"
                   + (modes.Count > 0
                       ? "; assignmentMode values seen: " + string.Join(", ", modes)
                       : "; no assignmentMode returned")
        };
    }

    private static string? Str(JsonElement el, string name) =>
        el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() : null;

    private static string Head(string s) => s.Length <= 140 ? s : s[..140];
}
