using AccessCheck.Core.Catalog;

namespace AccessCheck.Core.Recommendation;

/// <summary>How much of a service a single permission covers.</summary>
public enum BreadthLevel
{
    /// <summary>A named capability on a named resource.</summary>
    Specific = 0,
    /// <summary>All properties of a resource, or a wide read.</summary>
    Broad = 1,
    /// <summary>Every entity or every task in a service — effectively the whole service.</summary>
    ServiceWide = 2
}

/// <summary>
/// The deterministic least-privilege guard.
///
/// "Zero excess" is a meaningless reassurance when the single chosen action IS the whole
/// service: microsoft.intune/allEntities/allTasks needs no excess because it already
/// grants everything. Breadth therefore has to be judged separately from excess, and by
/// code rather than by asking the model whether its own answer was too broad.
/// </summary>
public static class PermissionBreadth
{
    /// <summary>"microsoft.directory/administrativeUnits/allProperties/allTasks"
    /// -> "microsoft.directory/administrativeUnits".</summary>
    private static string ResourcePrefix(string action)
    {
        var parts = action.Split('/');
        return parts.Length >= 2 ? parts[0] + "/" + parts[1] : action;
    }

    /// <summary>"microsoft.directory/..." -> "microsoft.directory".</summary>
    private static string Namespace(string action)
    {
        var slash = action.IndexOf('/');
        return slash > 0 ? action[..slash] : action;
    }

    /// <summary>
    /// A readable name for the NAMESPACE — which is what the breadth of an action is
    /// measured against, and is not the same as the provider the grant flows through.
    ///
    /// microsoft.teams/... lives inside an ENTRA DIRECTORY ROLE, so the provider is
    /// correctly "directory" while the action's reach is Teams. Naming the provider made
    /// the card say a Teams permission "grants EVERY task on EVERY entity in Entra ID",
    /// which is alarming, wrong, and sent me chasing a provider-mapping bug that did not
    /// exist.
    /// </summary>
    private static string NamespaceLabel(string action)
    {
        var ns = Namespace(action).ToLowerInvariant();
        return ns switch
        {
            "microsoft.directory" => "the Entra ID directory",
            "microsoft.teams" => "Microsoft Teams",
            "microsoft.intune" => "Intune",
            "microsoft.cloudpc" => "Windows 365",
            "microsoft.entitlementmanagement" => "Entitlement Management",
            "microsoft.office365.sharepoint" => "SharePoint",
            "microsoft.office365.exchange" => "Exchange Online",
            "microsoft.office365.securitycomplianceCenter" => "Purview / Compliance",
            "microsoft.backup" => "Microsoft 365 Backup",
            _ => ns
        };
    }

    /// <summary>The resource an action acts on — "microsoft.teams/meetings" -> "meetings".</summary>
    private static string ResourceLabel(string action)
    {
        var parts = action.Split('/', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 ? parts[1] : action;
    }

    public static BreadthLevel Classify(string action)
    {
        var a = action.ToLowerInvariant();

        if (a.Contains("/allentities/alltasks", StringComparison.Ordinal)
            || a.Contains("/allentities/allproperties/alltasks", StringComparison.Ordinal)
            || a.EndsWith("/alltasks", StringComparison.Ordinal)
            || a.Contains("/allentities/read", StringComparison.Ordinal))
            return BreadthLevel.ServiceWide;

        if (a.Contains("/allproperties/", StringComparison.Ordinal)
            || a.Contains("/allentities/", StringComparison.Ordinal))
            return BreadthLevel.Broad;

        return BreadthLevel.Specific;
    }

    public sealed record Finding
    {
        public required string Action { get; init; }
        public required BreadthLevel Level { get; init; }
        public required string Message { get; init; }
        /// <summary>Narrower permissions in the same service, as evidence.</summary>
        public required IReadOnlyList<string> Examples { get; init; }
        /// <summary>True when the alternatives act on the SAME resource, not merely the
        /// same namespace. A same-namespace suggestion is a lead, not a substitute.</summary>
        public bool SameResource { get; init; }
    }

    /// <summary>
    /// Flags a validated action that covers a whole service WHEN narrower permissions
    /// exist in that same service. Silence means either the action is specific, or the
    /// service genuinely offers nothing narrower — both are worth distinguishing.
    /// </summary>
    public static IReadOnlyList<Finding> Findings(
        IReadOnlyCollection<string> validatedActions, RoleCatalog catalog)
    {
        var findings = new List<Finding>();
        var index = PermissionIndex.Build(catalog);

        foreach (var action in validatedActions)
        {
            var level = Classify(action);
            if (level != BreadthLevel.ServiceWide) continue;

            var provider = catalog.ProviderOf(action) ?? RbacProviders.Directory;

            // The provider is where the grant is MADE; the namespace is what it REACHES.
            // A microsoft.teams/... action is carried by an ENTRA DIRECTORY ROLE, so it is
            // correctly filed under Entra while acting on Teams. Saying so on the card stops
            // that reading as a mislabelling — it read that way to me for two days.
            var viaDirectoryRole =
                provider.Equals(RbacProviders.Directory, StringComparison.OrdinalIgnoreCase)
                && !Namespace(action).Equals("microsoft.directory", StringComparison.OrdinalIgnoreCase);

            var whereGranted = viaDirectoryRole
                ? " It is carried by an Entra DIRECTORY ROLE, which is why it appears under "
                  + "Entra ID — the role is a directory object; what it reaches is "
                  + NamespaceLabel(action) + "."
                : "";
            // Narrower on the SAME RESOURCE, not merely the same service. Offering
            // microsoft.azure.print/printers/basic/update as the "narrower alternative" to
            // an administrativeUnits grant is noise: it is specific, but it is a different
            // thing entirely, and it makes the card look broken.
            var resourcePrefix = ResourcePrefix(action);
            var narrower = index.Entries
                .Where(e => e.Provider.Equals(provider, StringComparison.OrdinalIgnoreCase)
                            && Classify(e.Action) == BreadthLevel.Specific
                            && ResourcePrefix(e.Action).Equals(resourcePrefix,
                                   StringComparison.OrdinalIgnoreCase))
                .Select(e => e.Action)
                .Take(8)
                .ToList();

            // Nothing narrower on this exact resource: fall back to the same NAMESPACE so
            // the operator still gets a lead, but say which it is.
            var sameResource = narrower.Count > 0;
            if (!sameResource)
            {
                var ns = Namespace(action);
                narrower = index.Entries
                    .Where(e => e.Provider.Equals(provider, StringComparison.OrdinalIgnoreCase)
                                && Classify(e.Action) == BreadthLevel.Specific
                                && Namespace(e.Action).Equals(ns, StringComparison.OrdinalIgnoreCase))
                    .Select(e => e.Action)
                    .Take(8)
                    .ToList();
            }

            if (narrower.Count == 0) continue;   // nothing narrower exists; not a finding

            findings.Add(new Finding
            {
                Action = action,
                Level = level,
                SameResource = sameResource,
                // TWO DIFFERENT BREADTHS WERE BEING DESCRIBED THE SAME WAY.
                // allEntities/allTasks really is the whole service; <resource>/allTasks is
                // every task on ONE resource. Calling the second "every entity" overstates
                // it, and an operator who checks will stop believing the card.
                Message = action.Contains("/allEntities/", StringComparison.OrdinalIgnoreCase)
                    ? $"'{action}' grants EVERY task on EVERY entity in " +
                      $"{NamespaceLabel(action)} — the entire service, not a specific " +
                      "capability. \"Zero excess\" is misleading here: the action itself is " +
                      "the whole service. Narrower permissions exist." + whereGranted
                    : $"'{action}' grants EVERY task on {ResourceLabel(action)} in " +
                      $"{NamespaceLabel(action)} — the whole resource, not a specific " +
                      "capability. \"Zero excess\" is misleading here: the action itself is " +
                      "everything that can be done to that resource. Narrower permissions exist."
                      + whereGranted,
                Examples = narrower
            });
        }

        return findings;
    }
}
