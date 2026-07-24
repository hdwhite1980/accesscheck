using System.Text.Json;
using AccessCheck.Core.Catalog;

namespace AccessCheck.Graph;

/// <summary>One permission as MICROSOFT defines it, not as your roles happen to expose it.</summary>
public sealed record ReferenceAction
{
    public required string Name { get; init; }
    public required string Namespace { get; init; }
    public string Description { get; init; } = "";
    /// <summary>
    /// Microsoft's OWN privilege classification. Authoritative where the source provides
    /// it (Graph resourceNamespaces); null where it does not (PowerShell role entries),
    /// in which case the app falls back to its heuristic and says so.
    /// </summary>
    public bool? IsPrivileged { get; init; }
    public string? ActionVerb { get; init; }
    /// <summary>Which RBAC provider this belongs to.</summary>
    public required string Provider { get; init; }
    /// <summary>Where it was read from — matters because the sources differ in authority.</summary>
    public required string Source { get; init; }
}

/// <summary>
/// The authoritative permission vocabulary, straight from Microsoft.
///
/// The role catalog is DERIVED: it only knows permissions that some role in your tenant
/// happens to contain. A permission Microsoft defines but no role grants is invisible to
/// it — which matters most exactly when drafting a custom role, since that is when you
/// want a permission no existing role bundles.
///
/// /roleManagement/directory/resourceNamespaces/{ns}/resourceActions is Microsoft's own
/// list, complete with descriptions and an isPrivileged flag that is stated rather than
/// guessed. It is available in the US Gov L4 and L5 clouds, so it works for MED365 too.
/// Needs RoleManagement.Read.Directory.
/// </summary>
public sealed class PermissionReference
{
    private readonly GraphClient _graph;

    public PermissionReference(GraphClient graph) => _graph = graph;

    public List<string> Warnings { get; } = new();

    /// <summary>
    /// Pages a collection endpoint, following @odata.nextLink. Local rather than shared
    /// because every other sync in this project keeps its own — matching the convention
    /// beats introducing a second one.
    /// </summary>
    private async Task PageAsync(
        string startUrl, Action<JsonElement> onItem, CancellationToken ct)
    {
        string? url = startUrl;
        var guard = 0;
        while (url is not null && guard++ < 200)
        {
            using var doc = await _graph.GetAsync(url, ct);
            var root = doc.RootElement;
            if (root.TryGetProperty("value", out var value) &&
                value.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in value.EnumerateArray()) onItem(el);
            }
            url = root.TryGetProperty("@odata.nextLink", out var next) ? next.GetString() : null;
        }
    }

    /// <summary>Which providers were reachable, and where their vocabulary came from.</summary>
    public List<string> SourceReport { get; } = new();

    /// <summary>
    /// Reads Microsoft's permission vocabulary from every source that has one.
    ///
    /// resourceNamespaces is a UNIFIED RBAC api and in practice only the directory
    /// provider implements it — Exchange Online and Purview do not use unified RBAC at
    /// all, so they have no Graph reference and their vocabulary lives in PowerShell.
    /// Rather than assume which providers support it, this TRIES each and reports what
    /// answered: an empirical answer survives Microsoft adding providers later.
    /// </summary>
    public async Task<List<ReferenceAction>> SyncAsync(
        Action<string>? progress = null, CancellationToken ct = default)
    {
        Warnings.Clear();
        SourceReport.Clear();
        var actions = new List<ReferenceAction>();

        var providers = new (string Provider, string Path)[]
        {
            (RbacProviders.Directory, "directory"),
            (RbacProviders.Intune, "deviceManagement"),
            (RbacProviders.Exchange, "exchange"),
            (RbacProviders.CloudPc, "cloudPC"),
            (RbacProviders.Defender, "defender"),
            (RbacProviders.EntitlementManagement, "entitlementManagement")
        };

        foreach (var (provider, path) in providers)
        {
            progress?.Invoke("Asking " + RbacProviders.DisplayName(provider)
                             + " for its permission reference...");

            var namespaces = new List<string>();
            try
            {
                await PageAsync(
                    $"/beta/roleManagement/{path}/resourceNamespaces?$select=id,name",
                    el =>
                    {
                        var id = el.TryGetProperty("id", out var i) ? i.GetString() : null;
                        if (!string.IsNullOrWhiteSpace(id)) namespaces.Add(id!);
                    }, ct);
            }
            catch (Exception ex)
            {
                SourceReport.Add(RbacProviders.DisplayName(provider)
                    + ": no Graph permission reference (" + ShortReason(ex.Message) + ")");
                continue;
            }

            if (namespaces.Count == 0)
            {
                SourceReport.Add(RbacProviders.DisplayName(provider)
                    + ": endpoint answered but defines no namespaces");
                continue;
            }

            var before = actions.Count;
            foreach (var ns in namespaces)
            {
                try
                {
                    await PageAsync(
                        $"/beta/roleManagement/{path}/resourceNamespaces/{ns}/resourceActions"
                        + "?$select=name,description,isPrivileged,actionVerb&$top=999",
                        el =>
                        {
                            var name = el.TryGetProperty("name", out var n) ? n.GetString() : null;
                            if (string.IsNullOrWhiteSpace(name)) return;
                            actions.Add(new ReferenceAction
                            {
                                Name = name!,
                                Namespace = ns,
                                Provider = provider,
                                Source = "Graph resourceActions",
                                Description = el.TryGetProperty("description", out var d)
                                    ? d.GetString() ?? "" : "",
                                IsPrivileged = el.TryGetProperty("isPrivileged", out var p)
                                    ? p.ValueKind == JsonValueKind.True
                                    : null,
                                ActionVerb = el.TryGetProperty("actionVerb", out var v)
                                    ? v.GetString() : null
                            });
                        }, ct);
                }
                catch (Exception)
                {
                    // A namespace that exposes no actions is normal, not a failure.
                }
            }

            SourceReport.Add(RbacProviders.DisplayName(provider) + ": "
                + (actions.Count - before) + " permission(s) from Graph, "
                + namespaces.Count + " namespace(s)");
        }

        // INTUNE does not implement resourceNamespaces, but it publishes the same
        // information at its own endpoint: resourceOperations lists every resource and the
        // actions defined on it. That is Intune's authoritative permission list, and
        // without it the Reference page shows only Entra and whatever PowerShell supplied.
        progress?.Invoke("Reading Intune resource operations...");
        var intuneBefore = actions.Count;
        try
        {
            await PageAsync("/beta/deviceManagement/resourceOperations"
                            + "?$select=id,resourceName,actionName,description&$top=999",
                el =>
                {
                    var resource = el.TryGetProperty("resourceName", out var r) ? r.GetString() : null;
                    var act = el.TryGetProperty("actionName", out var a) ? a.GetString() : null;
                    if (string.IsNullOrWhiteSpace(resource) || string.IsNullOrWhiteSpace(act)) return;

                    // Intune role definitions use the underscored form, so build the same
                    // shape the catalog holds — otherwise nothing would ever match.
                    actions.Add(new ReferenceAction
                    {
                        Name = "Microsoft.Intune_" + resource!.Replace(" ", "") + "_" + act,
                        Namespace = "Microsoft.Intune",
                        Provider = RbacProviders.Intune,
                        Source = "Graph resourceOperations",
                        Description = el.TryGetProperty("description", out var d)
                            ? d.GetString() ?? "" : "",
                        IsPrivileged = null   // Intune states no privilege flag
                    });
                }, ct);

            var added = actions.Count - intuneBefore;
            if (added > 0)
            {
                // Replace the earlier "no reference" line rather than contradicting it.
                SourceReport.RemoveAll(l => l.StartsWith(
                    RbacProviders.DisplayName(RbacProviders.Intune), StringComparison.Ordinal));
                SourceReport.Add(RbacProviders.DisplayName(RbacProviders.Intune) + ": "
                    + added + " permission(s) from Graph resourceOperations");
            }
        }
        catch (Exception ex)
        {
            SourceReport.Add(RbacProviders.DisplayName(RbacProviders.Intune)
                + ": resourceOperations unavailable (" + ShortReason(ex.Message) + ")");
        }

        if (actions.Count == 0)
        {
            Warnings.Add("No Graph permission reference was readable. This needs "
                + "RoleManagement.Read.Directory (or Directory Readers / Global Reader / "
                + "Privileged Role Administrator).");
        }

        // Exchange and Purview are not unified-RBAC services, so no Graph endpoint exists
        // for them at all. Say so plainly rather than leaving a silent gap.
        SourceReport.Add("");
        SourceReport.Add("Exchange Online and Purview / Compliance do NOT use unified RBAC, "
            + "so Microsoft publishes no Graph permission reference for them. Their "
            + "authoritative vocabulary is the role entries read through PowerShell — use "
            + "\"Add Exchange & Purview\" to pull them in.");

        return actions
            .GroupBy(a => a.Provider + "|" + a.Name, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderBy(a => a.Provider, StringComparer.OrdinalIgnoreCase)
            .ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Exchange and Purview vocabulary, from the roles already synced through PowerShell.
    /// Not a second connection: the catalog holds the cmdlet signatures, and inverting
    /// them gives the same vocabulary the Graph reference gives for directory.
    /// </summary>
    /// <summary>Why each PowerShell-sourced service did or did not contribute.</summary>
    public static List<string> LastPowerShellReport { get; } = new();

    public static List<ReferenceAction> FromPowerShellCatalog(RoleCatalog catalog)
    {
        var actions = new List<ReferenceAction>();
        LastPowerShellReport.Clear();

        foreach (var provider in new[] { RbacProviders.Exchange, RbacProviders.Purview })
        {
            var roles = catalog.RolesFor(provider).ToList();
            var byAction = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

            foreach (var role in roles)
            {
                foreach (var action in role.AllowedResourceActions)
                {
                    if (!byAction.TryGetValue(action, out var names))
                        byAction[action] = names = new List<string>();
                    if (!names.Contains(role.DisplayName)) names.Add(role.DisplayName);
                }
            }

            // Absence is information. A service contributing nothing looks identical to a
            // service that was never asked, and that ambiguity cost real debugging time.
            if (roles.Count == 0)
            {
                LastPowerShellReport.Add(RbacProviders.DisplayName(provider)
                    + ": no roles in the catalog — run a catalog sync with \"Include Exchange "
                    + "& Purview via PowerShell\" ticked.");
            }
            else if (byAction.Count == 0)
            {
                LastPowerShellReport.Add(RbacProviders.DisplayName(provider) + ": "
                    + roles.Count + " role NAME(S) but NO permissions — the sync could not read "
                    + "their entries, so there is no vocabulary to publish. Check the Purview "
                    + "line in the Sync report; the inverse lookup is the route that resolves this.");
            }
            else
            {
                LastPowerShellReport.Add(RbacProviders.DisplayName(provider) + ": "
                    + byAction.Count + " permission(s) from " + roles.Count + " role(s).");
            }

            foreach (var (action, roleNames) in byAction)
            {
                actions.Add(new ReferenceAction
                {
                    Name = action,
                    Namespace = provider,
                    Provider = provider,
                    Source = "PowerShell role entries",
                    // PowerShell gives no privilege flag; the app's heuristic fills in and
                    // the UI marks it as inferred rather than stated.
                    IsPrivileged = null,
                    Description = "Granted by " + string.Join(", ", roleNames.Take(4))
                        + (roleNames.Count > 4 ? ", +" + (roleNames.Count - 4) + " more" : "")
                });
            }
        }

        return actions
            .OrderBy(a => a.Provider, StringComparer.OrdinalIgnoreCase)
            .ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string ShortReason(string message)
    {
        if (message.Contains("404", StringComparison.Ordinal)
            || message.Contains("NotFound", StringComparison.OrdinalIgnoreCase)
            || message.Contains("No OData route exists", StringComparison.OrdinalIgnoreCase))
            return "this service does not implement the resourceNamespaces API";
        if (message.Contains("403", StringComparison.Ordinal))
            return "not licensed, or consent missing";
        if (message.Contains("not supported for AAD accounts", StringComparison.OrdinalIgnoreCase))
            return "not exposed to Graph — its vocabulary comes from PowerShell";

        // A failing endpoint sometimes returns an entire HTML error page. Dumping that into
        // a status line is unreadable and hides every other service's result.
        if (message.Contains("<!DOCTYPE", StringComparison.OrdinalIgnoreCase)
            || message.Contains("<html", StringComparison.OrdinalIgnoreCase))
            return "server error (returned an HTML error page, not JSON)";

        var oneLine = message.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return oneLine.Length <= 90 ? oneLine : oneLine[..90] + "...";
    }

    private static string Head(string s) => s.Length <= 200 ? s : s[..200];
}

/// <summary>What the reference says versus what your tenant's roles actually expose.</summary>
public sealed record ReferenceComparison
{
    public required IReadOnlyList<ReferenceAction> Reference { get; init; }
    /// <summary>Defined by Microsoft but granted by NO role in your catalog.</summary>
    public required IReadOnlyList<ReferenceAction> NotInAnyRole { get; init; }
    /// <summary>In your catalog but absent from the reference — usually a non-directory provider.</summary>
    public required IReadOnlyList<string> InCatalogOnly { get; init; }
    /// <summary>
    /// Actions where Microsoft's isPrivileged disagrees with the app's ActionRisk heuristic.
    /// Microsoft's answer is authoritative; these are worth knowing because the heuristic
    /// drives risk-weighted ranking everywhere else.
    /// </summary>
    public required IReadOnlyList<(string Action, bool MicrosoftSaysPrivileged)> RiskDisagreements { get; init; }

    public static ReferenceComparison Build(
        IReadOnlyList<ReferenceAction> reference, RoleCatalog catalog)
    {
        // Compare PER PROVIDER. A directory-only comparison declared every Exchange
        // cmdlet "not in the reference", which is true but useless — they were never in
        // scope of the directory reference in the first place.
        var providersInReference = reference
            .Select(r => r.Provider)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var catalogByProvider = providersInReference.ToDictionary(
            p => p,
            p => catalog.RolesFor(p).SelectMany(r => r.AllowedResourceActions)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase),
            StringComparer.OrdinalIgnoreCase);

        var referenceByProvider = reference
            .GroupBy(r => r.Provider, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key,
                          g => g.Select(r => r.Name).ToHashSet(StringComparer.OrdinalIgnoreCase),
                          StringComparer.OrdinalIgnoreCase);

        var notInAnyRole = reference
            .Where(r => catalogByProvider.TryGetValue(r.Provider, out var have)
                        && !have.Contains(r.Name))
            .OrderBy(r => r.Provider, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var inCatalogOnly = new List<string>();
        foreach (var (provider, have) in catalogByProvider)
        {
            if (!referenceByProvider.TryGetValue(provider, out var known)) continue;
            inCatalogOnly.AddRange(have.Where(a => !known.Contains(a)));
        }

        // Only where Microsoft actually STATES a privilege level. PowerShell-sourced
        // entries have none, so there is nothing to disagree with.
        // Against the HEURISTIC, not the live value — once Microsoft's answer is installed
        // as authoritative, comparing IsPrivileged to it always agrees by construction.
        var disagreements = reference
            .Where(a => a.IsPrivileged is not null
                        && Core.Recommendation.ActionRisk.IsPrivilegedHeuristic(a.Name) != a.IsPrivileged)
            .Select(a => (a.Name, a.IsPrivileged!.Value))
            .OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new ReferenceComparison
        {
            Reference = reference,
            NotInAnyRole = notInAnyRole,
            InCatalogOnly = inCatalogOnly
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
                .ToList(),
            RiskDisagreements = disagreements
        };
    }

    public string Summary =>
        $"{Reference.Count} permission(s) in the reference; "
        + $"{NotInAnyRole.Count} are granted by NO role in your tenant; "
        + $"{InCatalogOnly.Count} in your catalog are absent from the reference; "
        + $"{RiskDisagreements.Count} where Microsoft's privilege rating differs from this "
        + "app's inference.";
}
