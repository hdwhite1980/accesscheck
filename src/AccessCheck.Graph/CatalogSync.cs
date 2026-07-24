using System.Text.Json;
using AccessCheck.Core.Catalog;

namespace AccessCheck.Graph;

public sealed record ProviderSyncResult(string Provider, int RoleCount, string? Error)
{
    /// <summary>Classified form of Error — expected conditions never reach the banner.</summary>
    public SyncIssue? Issue => Error is null
        ? null
        : SyncIssue.FromError(RbacProviders.DisplayName(Provider), Error);

    /// <summary>Which URL finally worked (or was last attempted) — shown in the sync report.</summary>
    public string? UrlTried { get; init; }

    public string Summary => Error is null
        ? RbacProviders.DisplayName(Provider) +
          (UrlTried is not null && UrlTried.Contains("/deviceManagement/roleDefinitions",
              StringComparison.OrdinalIgnoreCase) &&
           !UrlTried.Contains("roleManagement", StringComparison.OrdinalIgnoreCase)
              ? " [native]" : "") +
          ": " + RoleCount +
          (RoleCount == 0 ? " (endpoint responded, no roles defined/licensed)" : "")
        : RbacProviders.DisplayName(Provider) + ": FAILED — " + Error;
}

/// <summary>
/// Pulls role definitions from every unified RBAC provider the tenant exposes.
/// Each provider syncs independently and records WHY it failed — a 403 (permission
/// not consented), 404 (provider absent in this cloud), or licensing gap degrades
/// that provider only, never the whole sync.
/// </summary>
public sealed class CatalogSync
{
    private readonly GraphClient _graph;
    public CatalogSync(GraphClient graph) => _graph = graph;

    /// <summary>
    /// Per provider: the base path, and whether to try a $top page size first.
    /// Some endpoints reject $top outright, so a retry without it follows any failure.
    /// </summary>
    private static readonly (string Provider, string Path)[] Sources =
    {
        (RbacProviders.Directory, "/v1.0/roleManagement/directory/roleDefinitions"),
        (RbacProviders.Intune, "/beta/roleManagement/deviceManagement/roleDefinitions"),
        (RbacProviders.Exchange, "/beta/roleManagement/exchange/roleDefinitions"),
        (RbacProviders.CloudPc, "/beta/roleManagement/cloudPC/roleDefinitions"),
        (RbacProviders.Defender, "/beta/roleManagement/defender/roleDefinitions"),
        (RbacProviders.EntitlementManagement,
            "/v1.0/roleManagement/entitlementManagement/roleDefinitions"),
        // Intune's OWN endpoint, listed last so it wins on duplicate ids. Custom roles
        // created here are invisible to the unified path above — without this, a role the
        // app just created cannot be resolved, and any group holding it shows 0 permissions.
        (RbacProviders.Intune, "/beta/deviceManagement/roleDefinitions")
    };

    /// <summary>Permission most likely missing when a provider returns 403.</summary>
    private static string PermissionHint(string provider) => provider switch
    {
        RbacProviders.Directory => "RoleManagement.Read.All or RoleManagement.ReadWrite.Directory",
        RbacProviders.Intune => "DeviceManagementRBAC.ReadWrite.All",
        RbacProviders.Exchange => "RoleManagement.Read.Exchange",
        RbacProviders.CloudPc => "RoleManagement.ReadWrite.CloudPC",
        RbacProviders.Defender => "RoleManagement.ReadWrite.Defender",
        RbacProviders.EntitlementManagement => "EntitlementManagement.Read.All",
        _ => "the matching RoleManagement permission"
    };

    public async Task<(RoleCatalog Catalog, IReadOnlyList<ProviderSyncResult> Results)> SyncAllAsync(
        Action<string>? progress = null, CancellationToken ct = default)
    {
        var roles = new List<RoleDefinitionRecord>();
        var results = new List<ProviderSyncResult>();

        foreach (var (provider, basePath) in Sources)
        {
            progress?.Invoke("Syncing " + RbacProviders.DisplayName(provider) + " ...");

            // Attempt 1: with a page size. Attempt 2: plain, for endpoints that reject $top.
            var attempts = new[] { basePath + "?$top=100", basePath };
            Exception? lastError = null;
            bool done = false;

            foreach (var url in attempts)
            {
                try
                {
                    var providerRoles = await SyncProviderAsync(provider, url, ct);
                    roles.AddRange(providerRoles);
                    results.Add(new ProviderSyncResult(provider, providerRoles.Count, null)
                    { UrlTried = url });
                    done = true;
                    break;
                }
                catch (Exception ex)
                {
                    lastError = ex;
                }
            }

            if (!done)
            {
                var msg = Explain(provider, lastError);
                results.Add(new ProviderSyncResult(provider, 0, msg)
                { UrlTried = attempts[^1] });
            }
        }

        var catalog = new RoleCatalog();
        catalog.ReplaceAll(roles, DateTimeOffset.UtcNow);
        return (catalog, results);
    }

    private static string Explain(string provider, Exception? ex)
    {
        var raw = ex?.Message ?? "unknown error";
        if (raw.Contains("403", StringComparison.Ordinal) ||
            raw.Contains("Authorization_RequestDenied", StringComparison.OrdinalIgnoreCase) ||
            raw.Contains("Forbidden", StringComparison.OrdinalIgnoreCase))
            return "403 Forbidden — add and grant admin consent for " + PermissionHint(provider) +
                   " on the app registration, or your signed-in account lacks the role. [" +
                   Head(raw) + "]";
        if (raw.Contains("404", StringComparison.Ordinal) ||
            raw.Contains("NotFound", StringComparison.OrdinalIgnoreCase))
            return "404 Not Found — this RBAC provider isn't available in this cloud/tenant. [" +
                   Head(raw) + "]";
        if (raw.Contains("401", StringComparison.Ordinal) ||
            raw.Contains("Unauthorized", StringComparison.OrdinalIgnoreCase))
            return "401 Unauthorized — token missing the scope; re-consent and sign in again. [" +
                   Head(raw) + "]";
        if (raw.Contains("400", StringComparison.Ordinal))
            return "400 Bad Request — the endpoint rejected the query. [" + Head(raw) + "]";
        return Head(raw);
    }

    private async Task<List<RoleDefinitionRecord>> SyncProviderAsync(
        string provider, string startPath, CancellationToken ct)
    {
        var roles = new List<RoleDefinitionRecord>();
        string? url = startPath;
        int guard = 0;
        while (url is not null && guard++ < 100)
        {
            using var doc = await _graph.GetAsync(url, ct);
            var root = doc.RootElement;
            if (root.TryGetProperty("value", out var value) &&
                value.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in value.EnumerateArray())
                {
                    // One malformed role must not lose the whole provider.
                    try { roles.Add(MapRole(el, provider)); }
                    catch (Exception) { /* skip this role */ }
                }
            }
            url = root.TryGetProperty("@odata.nextLink", out var next) ? next.GetString() : null;
        }
        return roles;
    }

    private static RoleDefinitionRecord MapRole(JsonElement el, string provider)
    {
        // Two shapes exist. Unified providers return FLAT
        //   rolePermissions[].allowedResourceActions
        // while Intune's own endpoint returns NESTED
        //   rolePermissions[].resourceActions[].allowedResourceActions
        // (beta also exposes the same under "permissions"). Parse all of them.
        var actions = new List<string>();

        void Collect(JsonElement arr)
        {
            if (arr.ValueKind != JsonValueKind.Array) return;
            foreach (var a in arr.EnumerateArray())
            {
                var s = a.GetString();
                if (!string.IsNullOrWhiteSpace(s)) actions.Add(s);
            }
        }

        void ReadPermissionBlock(JsonElement perms)
        {
            if (perms.ValueKind != JsonValueKind.Array) return;
            foreach (var perm in perms.EnumerateArray())
            {
                if (perm.TryGetProperty("allowedResourceActions", out var flat))
                    Collect(flat);
                if (perm.TryGetProperty("actions", out var legacy))
                    Collect(legacy);
                if (perm.TryGetProperty("resourceActions", out var nested) &&
                    nested.ValueKind == JsonValueKind.Array)
                {
                    foreach (var ra in nested.EnumerateArray())
                        if (ra.TryGetProperty("allowedResourceActions", out var inner))
                            Collect(inner);
                }
            }
        }

        if (el.TryGetProperty("rolePermissions", out var perms1)) ReadPermissionBlock(perms1);
        if (el.TryGetProperty("permissions", out var perms2)) ReadPermissionBlock(perms2);

        actions = actions.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var desc = el.TryGetProperty("description", out var d) ? d.GetString() ?? "" : "";
        bool isBuiltIn =
            (el.TryGetProperty("isBuiltIn", out var b) && b.ValueKind == JsonValueKind.True) ||
            (el.TryGetProperty("isBuiltInRoleDefinition", out var b2) &&
             b2.ValueKind == JsonValueKind.True);
        var id = el.TryGetProperty("id", out var idEl) ? idEl.GetString() ?? "" : "";
        var name = el.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? "" : "";
        if (id.Length == 0) id = provider + ":" + name;

        return new RoleDefinitionRecord
        {
            Id = id,
            DisplayName = name,
            Description = desc,
            IsBuiltIn = isBuiltIn,
            Provider = provider,
            IsAccessCheckCreated = !isBuiltIn &&
                (desc.Contains("AccessCheck least-privilege role", StringComparison.OrdinalIgnoreCase) ||
                 desc.Contains("AccessLens least-privilege role", StringComparison.OrdinalIgnoreCase)),
            AllowedResourceActions = actions
        };
    }

    private static string Head(string s) => s.Length <= 300 ? s : s[..300];
}
