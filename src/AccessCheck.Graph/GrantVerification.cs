using AccessCheck.Core.Catalog;

namespace AccessCheck.Graph;

/// <summary>
/// Reads back what was just granted, and teaches the catalog from the result.
///
/// THE PRINCIPLE: the tenant ACCEPTING a grant is stronger evidence that a permission
/// exists than any catalog entry. A catalog is a snapshot that can be stale, partial, or
/// — for Exchange and Purview — assembled from documentation. A role the tenant actually
/// created, carrying actions the tenant actually accepted, is proof.
///
/// So a permission the catalog could not confirm is still attempted; if the grant lands
/// AND reads back, the permission is recorded as PROVEN and the catalog stops doubting it
/// next time. If the grant fails, the exact refusal is recorded instead — which is also
/// worth knowing, and is the honest answer to "does this permission exist here".
/// </summary>
public sealed class GrantVerification
{
    private readonly GraphClient _graph;

    public GrantVerification(GraphClient graph) => _graph = graph;

    public sealed record Result
    {
        public required bool Confirmed { get; init; }
        public required string Detail { get; init; }
        /// <summary>Actions the tenant demonstrably accepted. Safe to trust.</summary>
        public IReadOnlyList<string> ProvenActions { get; init; } = Array.Empty<string>();
    }

    /// <summary>
    /// Confirms a created role really exists and carries the actions we asked for.
    /// Creation returning 200 is an ATTEMPT; reading it back is the result.
    /// </summary>
    public async Task<Result> VerifyRoleAsync(
        string provider, string roleId, IReadOnlyList<string> expectedActions,
        CancellationToken ct = default)
    {
        var paths = provider == RbacProviders.Intune
            ? new[] { $"/beta/deviceManagement/roleDefinitions/{roleId}" }
            : provider == RbacProviders.Directory
                ? new[] { $"/v1.0/roleManagement/directory/roleDefinitions/{roleId}" }
                : new[] { $"/beta/roleManagement/{provider}/roleDefinitions/{roleId}" };

        foreach (var path in paths)
        {
            try
            {
                using var doc = await _graph.GetAsync(path, ct);
                var root = doc.RootElement;

                var actual = ExtractActions(root);
                var missing = expectedActions
                    .Where(a => !actual.Contains(a, StringComparer.OrdinalIgnoreCase))
                    .ToList();

                if (missing.Count == 0)
                {
                    return new Result
                    {
                        Confirmed = true,
                        ProvenActions = expectedActions,
                        Detail = $"Role {roleId} exists and carries all "
                               + $"{expectedActions.Count} requested action(s)."
                    };
                }

                return new Result
                {
                    Confirmed = false,
                    // Whatever DID land is still proven — partial truth beats none.
                    ProvenActions = expectedActions.Except(missing, StringComparer.OrdinalIgnoreCase).ToList(),
                    Detail = $"Role {roleId} exists but is MISSING {missing.Count} action(s) "
                           + "the tenant did not accept: " + string.Join(", ", missing.Take(6))
                           + ". They were requested but are not present — treat them as "
                           + "unavailable in this tenant."
                };
            }
            catch (Exception ex)
            {
                return new Result
                {
                    Confirmed = false,
                    Detail = $"Could not read back role {roleId}: " + ex.Message
                           + "  The grant may still have succeeded — check the portal before retrying."
                };
            }
        }

        return new Result { Confirmed = false, Detail = "No endpoint to verify this provider." };
    }

    /// <summary>Confirms the principal actually holds the role now.</summary>
    public async Task<Result> VerifyAssignmentAsync(
        string provider, string principalId, string roleId, CancellationToken ct = default)
    {
        try
        {
            var executor = new RoleExecutor(_graph);
            var holds = await executor.DoesPrincipalHoldRoleAsync(provider, principalId, roleId, ct);

            return new Result
            {
                Confirmed = holds,
                Detail = holds
                    ? "Confirmed: the principal now holds this role."
                    : "NOT confirmed: the assignment was submitted but the principal does not "
                      + "hold the role yet. For PIM this is normal while a request is pending "
                      + "or awaiting approval — check PIM > Pending requests."
            };
        }
        catch (Exception ex)
        {
            return new Result { Confirmed = false, Detail = "Verification failed: " + ex.Message };
        }
    }

    private static List<string> ExtractActions(System.Text.Json.JsonElement root)
    {
        var actions = new List<string>();
        if (!root.TryGetProperty("rolePermissions", out var perms)
            || perms.ValueKind != System.Text.Json.JsonValueKind.Array) return actions;

        foreach (var perm in perms.EnumerateArray())
        {
            // Flat shape (directory and the unified providers).
            if (perm.TryGetProperty("allowedResourceActions", out var flat)
                && flat.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                foreach (var a in flat.EnumerateArray())
                    if (a.GetString() is { Length: > 0 } s) actions.Add(s);
            }

            // Nested shape — Intune only, and the reason a shared extractor is worth having.
            if (perm.TryGetProperty("resourceActions", out var nested)
                && nested.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                foreach (var ra in nested.EnumerateArray())
                {
                    if (!ra.TryGetProperty("allowedResourceActions", out var inner)
                        || inner.ValueKind != System.Text.Json.JsonValueKind.Array) continue;
                    foreach (var a in inner.EnumerateArray())
                        if (a.GetString() is { Length: > 0 } s) actions.Add(s);
                }
            }
        }
        return actions;
    }
}
