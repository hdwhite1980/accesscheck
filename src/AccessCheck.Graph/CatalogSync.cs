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

    /// <summary>
    /// Syncs every Graph provider, MERGING into <paramref name="existing"/> rather than
    /// replacing it.
    ///
    /// The old behaviour built a fresh catalog and called ReplaceAll, which silently
    /// destroyed everything Graph does not supply:
    ///
    ///   PURVIEW AND AZURE are not in Sources at all. They vanished outright.
    ///
    ///   EXCHANGE is worse, because it looks like it worked. The Graph endpoint returns
    ///   Exchange role NAMES with EMPTY action lists; the cmdlets come from the PowerShell
    ///   deep sync. So a routine Graph sync overwrote fully-populated Exchange roles with
    ///   empty shells, and the catalog then held plenty of Exchange roles granting nothing.
    ///
    /// That is not hypothetical. A mailbox-delegation request answered correctly with
    /// Add-MailboxFolderPermission at 20:56 was answered with
    /// microsoft.backup/restorePoints/... at 23:29, because in between a Graph sync had
    /// emptied the Exchange vocabulary and the only remaining action whose NAME contained
    /// "mailbox" was a backup permission.
    ///
    /// SyncFreshness exists precisely so the two cadences can differ — Graph cheap and
    /// frequent, PowerShell expensive and weekly. ReplaceAll made that impossible.
    /// </summary>
    public async Task<(RoleCatalog Catalog, IReadOnlyList<ProviderSyncResult> Results)> SyncAllAsync(
        Action<string>? progress = null, CancellationToken ct = default,
        RoleCatalog? existing = null)
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
        catalog.ReplaceAll(Merge(existing, roles, results), DateTimeOffset.UtcNow);

        // Per-source sync times survive the merge. Overwriting them would report
        // PowerShell data as fresh because Graph ran, which is the reverse of what the
        // freshness display is for.
        if (existing is not null) catalog.Freshness = existing.Freshness;

        return (catalog, results);
    }

    /// <summary>
    /// Combines what Graph just returned with what the previous catalog held.
    ///
    /// Two rules, and both exist because a provider being absent from this sync says
    /// nothing about whether its data is still good:
    ///
    /// 1. A provider this sync did not SUCCESSFULLY read is carried over untouched. That
    ///    covers providers Graph does not serve (Purview, Azure) and providers that failed
    ///    this time — a 403 from a transient consent problem must not also erase roles that
    ///    were read successfully an hour ago.
    ///
    /// 2. Within a provider that WAS read, an incoming role carrying NO actions never
    ///    displaces a stored role of the same id that has some. This is the Exchange case:
    ///    Graph knows the role exists, only PowerShell knows what is in it, and an empty
    ///    list is missing information rather than a role that grants nothing.
    /// </summary>
    private static List<RoleDefinitionRecord> Merge(
        RoleCatalog? existing,
        List<RoleDefinitionRecord> incoming,
        List<ProviderSyncResult> results)
    {
        if (existing is null || existing.Roles.Count == 0) return incoming;

        var readSuccessfully = results
            .Where(r => r.Error is null)
            .Select(r => r.Provider)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var incomingById = new Dictionary<string, RoleDefinitionRecord>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var r in incoming) incomingById[r.Id] = r;

        var merged = new List<RoleDefinitionRecord>(incoming);

        foreach (var stored in existing.Roles)
        {
            // Rule 1 - provider untouched by this sync.
            if (!readSuccessfully.Contains(stored.Provider))
            {
                if (!incomingById.ContainsKey(stored.Id)) merged.Add(stored);
                continue;
            }

            // Rule 2 - do not let an empty incoming role hollow out a populated stored one.
            if (!incomingById.TryGetValue(stored.Id, out var fresh)) continue;
            if (fresh.AllowedResourceActions.Count > 0) continue;
            if (stored.AllowedResourceActions.Count == 0) continue;

            merged.Remove(fresh);
            // Keep the freshly-read metadata and restore the permissions only. A name or
            // description may legitimately have changed; the empty action list is the only
            // part that is wrong.
            merged.Add(fresh with { AllowedResourceActions = stored.AllowedResourceActions });
        }

        return merged;
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
