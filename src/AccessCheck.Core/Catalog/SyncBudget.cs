namespace AccessCheck.Core.Catalog;

/// <summary>
/// A per-service time budget for catalog syncing.
///
/// The design rule this enforces: MICROSOFT'S DOCUMENTATION is the authority on what a
/// permission IS. The tenant is the authority only on what EXISTS HERE — which roles are
/// defined (including custom ones Microsoft cannot know about) and who holds them.
///
/// So a slow tenant read is never worth waiting for. Purview's cmdlet-to-role crawl cost
/// 45 minutes and timed out; the same information is published and stable. When a service
/// exceeds its budget the sync abandons that service's DEEP read, falls back to the
/// documented vocabulary, and carries on — clearly labelled, never silently.
/// </summary>
public sealed class SyncBudget
{
    /// <summary>Per service. Beyond this, fall back to documentation.</summary>
    public TimeSpan PerService { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Listing roles is always worth doing — it is one bulk call and it is the ONLY way to
    /// discover CUSTOM roles. It is the per-role and per-cmdlet entry resolution that gets
    /// budgeted.
    /// </summary>
    public TimeSpan RoleListing { get; set; } = TimeSpan.FromMinutes(5);

    public enum Outcome { Completed, FellBackToDocumentation, Failed, Skipped }

    public sealed record Result
    {
        public required string Provider { get; init; }
        public required Outcome Outcome { get; init; }
        public required TimeSpan Elapsed { get; init; }
        public required int RolesFound { get; init; }
        public required int ActionsFound { get; init; }
        public string Detail { get; init; } = "";

        public string Describe() => Outcome switch
        {
            Outcome.Completed =>
                $"{RbacProviders.DisplayName(Provider)}: {RolesFound} role(s), {ActionsFound} "
                + $"permission(s) read from the tenant in {Elapsed.TotalSeconds:F0}s.",
            Outcome.FellBackToDocumentation =>
                $"{RbacProviders.DisplayName(Provider)}: tenant read exceeded the "
                + $"{Elapsed.TotalSeconds:F0}s budget, so permissions come from MICROSOFT'S "
                + $"DOCUMENTATION instead. {RolesFound} role(s) were still discovered from the "
                + "tenant, so custom roles are not missed. " + Detail,
            Outcome.Failed =>
                $"{RbacProviders.DisplayName(Provider)}: FAILED — {Detail}",
            _ => $"{RbacProviders.DisplayName(Provider)}: skipped. {Detail}"
        };
    }
}

/// <summary>Where a permission's definition came from, and whether the tenant has it.</summary>
public enum ActionProvenance
{
    /// <summary>Microsoft documents it AND a role in this tenant grants it. Strongest.</summary>
    TenantVerified,
    /// <summary>Microsoft documents it; no role here grants it. A custom role is the only route.</summary>
    DocumentedOnly,
    /// <summary>A role here grants it but Microsoft's reference does not list it — usually a
    /// custom role, or a service with no published reference (Exchange, Purview).</summary>
    TenantOnly,
    /// <summary>Neither. Not a real permission, or nothing has been synced yet.</summary>
    Unknown
}

/// <summary>
/// Resolves a proposed permission against BOTH sources, in the order that matters:
/// documentation says whether it is real, the tenant says whether it is available here.
/// </summary>
public sealed class PermissionResolver
{
    private readonly IReadOnlySet<string> _documented;
    private readonly RoleCatalog? _catalog;

    public PermissionResolver(IReadOnlySet<string>? documented, RoleCatalog? catalog)
    {
        _documented = documented ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _catalog = catalog;
    }

    public ActionProvenance Resolve(string action)
    {
        var inDocs = _documented.Contains(action);
        var inTenant = _catalog?.ActionExists(action) ?? false;

        if (inDocs && inTenant) return ActionProvenance.TenantVerified;
        if (inDocs) return ActionProvenance.DocumentedOnly;
        if (inTenant) return ActionProvenance.TenantOnly;
        return ActionProvenance.Unknown;
    }

    /// <summary>The line an operator needs to see for a given provenance.</summary>
    public static string Explain(ActionProvenance provenance) => provenance switch
    {
        ActionProvenance.TenantVerified =>
            "Microsoft documents it and a role in your tenant grants it.",
        ActionProvenance.DocumentedOnly =>
            // It does NOT follow that a custom role is the route. The permission may be
            // unsupported in custom roles, missing because the sync was partial, in preview,
            // or unavailable in this tenant or cloud. Say what is known and no more.
            "Microsoft documents it, but no role in your synced catalog grants it. Tenant "
            + "availability and custom-role eligibility are UNVERIFIED — this may be a "
            + "sync gap, a preview permission, or one Microsoft does not allow in custom "
            + "roles. Confirm before relying on it.",
        ActionProvenance.TenantOnly =>
            "A role in your tenant grants it, but it is absent from Microsoft's reference — "
            + "normal for custom roles and for Exchange/Purview, which publish no reference.",
        _ => "Found in neither Microsoft's reference nor your tenant. Not granted."
    };
}
