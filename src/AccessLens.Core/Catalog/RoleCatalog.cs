using System.Text.Json;
using System.Text.Json.Serialization;

namespace AccessCheck.Core.Catalog;

/// <summary>
/// One Entra role definition (built-in or custom) as synced from
/// GET /roleManagement/directory/roleDefinitions. AllowedResourceActions is the
/// flattened union of rolePermissions[].allowedResourceActions.
/// </summary>
public sealed record RoleDefinitionRecord
{
    public required string Id { get; init; }
    public required string DisplayName { get; init; }
    public string Description { get; init; } = "";
    public bool IsBuiltIn { get; init; }
    /// <summary>True when this role was created by AccessCheck itself (subject to garbage collection).</summary>
    public bool IsAccessCheckCreated { get; init; }
    /// <summary>RBAC provider this role belongs to. See RbacProviders for known values.</summary>
    public string Provider { get; init; } = RbacProviders.Directory;
    public required IReadOnlyList<string> AllowedResourceActions { get; init; }

    // ---- richer role metadata, read from the BETA unifiedRoleDefinition ----
    // v1.0 exposes only id/displayName/description/isBuiltIn/rolePermissions. Beta carries
    // several fields that answer questions the app was previously guessing at.

    /// <summary>
    /// Microsoft's ROLE-LEVEL privileged flag: true when the role contains at least one
    /// sensitive resource action. Distinct from the per-ACTION isPrivileged already used
    /// for risk scoring — this says the ROLE is an escalation path, which is what matters
    /// when deciding whether it may act on other administrators.
    /// Applies only to the microsoft.directory namespace. Null when not read.
    /// </summary>
    public bool? IsPrivilegedRole { get; init; }

    /// <summary>What may hold this role (user, group, servicePrincipal). Null when not read.</summary>
    public string? AllowedPrincipalTypes { get; init; }

    /// <summary>
    /// Present in real beta responses though absent from the documented property table.
    /// Captured verbatim because it is the most likely carrier of AU-scopability, which
    /// no documented field expresses.
    /// </summary>
    public string? AssignmentMode { get; init; }

    /// <summary>Microsoft's own categorisation, e.g. "devices,identity".</summary>
    public string? Categories { get; init; }

    /// <summary>Microsoft's fuller prose description, where the short one is terse.</summary>
    public string? RichDescription { get; init; }
}

/// <summary>
/// Known unified role management RBAC providers (Graph /roleManagement/{provider}).
/// Directory is v1.0; the rest are read/managed via /beta today.
/// </summary>
public static class RbacProviders
{
    public const string Directory = "directory";
    public const string Intune = "deviceManagement";
    public const string Exchange = "exchange";
    public const string CloudPc = "cloudPC";
    public const string Defender = "defender";
    public const string EntitlementManagement = "entitlementManagement";
    /// <summary>Purview / Security &amp; Compliance role model (PowerShell-sourced, not a Graph provider).</summary>
    public const string Purview = "purview";
    /// <summary>Azure resource RBAC (ARM) — a different API and token audience entirely.</summary>
    public const string Azure = "azure";

    /// <summary>Providers where AccessCheck creates custom roles via Graph role definitions.</summary>
    public static readonly IReadOnlySet<string> CustomRoleCapable =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { Directory, Intune, CloudPc, Defender };

    /// <summary>
    /// Providers that grant through a PowerShell ROLE GROUP rather than a Graph role
    /// assignment. Both Exchange and Purview work this way.
    /// </summary>
    public static readonly IReadOnlySet<string> DerivedRoleCapable =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Exchange, Purview };

    /// <summary>
    /// PowerShell providers where a custom management role can actually be DERIVED.
    ///
    /// Distinct from CustomRoleCapable above, which is about GRAPH role definitions.
    /// Exchange Online supports New-ManagementRole, so a parent can be derived and trimmed
    /// to exactly the needed cmdlets. Security &amp; Compliance DOES NOT — the cmdlet is
    /// absent, and attempting it fails with "This endpoint does not support creating custom
    /// management roles."
    ///
    /// So in PURVIEW the least-privilege lever is not role derivation but ROLE GROUP
    /// COMPOSITION: a group carrying exactly the built-in roles required and no others.
    /// Whatever excess those roles contain is unavoidable, and saying so is more useful
    /// than proposing a derivation that cannot run.
    /// </summary>
    public static readonly IReadOnlySet<string> DerivationCapable =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Exchange };

    /// <summary>Providers whose assignments support PIM schedule requests (server-side expiry).</summary>
    public static readonly IReadOnlySet<string> PimCapable =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Directory };

    public static string DisplayName(string provider) => provider switch
    {
        Directory => "Entra ID (directory)",
        Intune => "Intune (deviceManagement)",
        Exchange => "Exchange Online",
        CloudPc => "Windows 365 (cloudPC)",
        Defender => "Defender XDR",
        Purview => "Purview / Compliance",
        Azure => "Azure resources (ARM)",
        EntitlementManagement => "Entitlement Management",
        _ => provider
    };
}

/// <summary>
/// The synced tenant permission catalog. This is the ONLY vocabulary the AI's
/// suggestions are validated against: an action not present here is rejected.
/// </summary>
public sealed class RoleCatalog
{
    private readonly Dictionary<string, RoleDefinitionRecord> _byId =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _allActions =
        new(StringComparer.OrdinalIgnoreCase);
    /// <summary>
    /// Providers that grant each action — a SET, because an action genuinely can belong to
    /// more than one service. Modelling it as a single string forced a first-writer-wins
    /// choice decided by sync order, which is not evidence of anything.
    /// </summary>
    private readonly Dictionary<string, HashSet<string>> _actionProviders =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly Dictionary<string, string> _actionProvider =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Per-source sync times. Graph is cheap and frequent; PowerShell is
    /// expensive and weekly. Tracking one timestamp for both forced a choice between a
    /// slow app and a stale catalog.</summary>
    public SyncFreshness Freshness { get; set; } = new();

    public DateTimeOffset? LastSyncedUtc { get; private set; }

    public IReadOnlyCollection<RoleDefinitionRecord> Roles => _byId.Values;

    public void ReplaceAll(IEnumerable<RoleDefinitionRecord> roles, DateTimeOffset syncedUtc)
    {
        _byId.Clear();
        _allActions.Clear();
        _actionProvider.Clear();
        _actionProviders.Clear();
        foreach (var r in roles) Add(r);
        LastSyncedUtc = syncedUtc;
    }

    /// <summary>
    /// Drops a role the tenant no longer has. The catalog is a SNAPSHOT, so it can list
    /// roles that have since been deleted; a dead entry should be removed on discovery
    /// rather than blocking the operator with a dialog about it.
    /// </summary>
    public bool RemoveRole(string roleId)
    {
        if (string.IsNullOrWhiteSpace(roleId)) return false;
        if (!_byId.Remove(roleId)) return false;

        // The action indexes are derived, so rebuild them from what remains.
        _allActions.Clear();
        _actionProvider.Clear();
        _actionProviders.Clear();
        foreach (var r in _byId.Values)
        {
            foreach (var a in r.AllowedResourceActions)
            {
                _allActions.Add(a);
                if (!_actionProvider.ContainsKey(a)) _actionProvider[a] = r.Provider;
                if (!_actionProviders.TryGetValue(a, out var set1))
                    _actionProviders[a] = set1 = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                set1.Add(r.Provider);
            }
        }
        return true;
    }

    public void Add(RoleDefinitionRecord role)
    {
        _byId[role.Id] = role;
        foreach (var a in role.AllowedResourceActions)
        {
            _allActions.Add(a);
            if (!_actionProvider.ContainsKey(a)) _actionProvider[a] = role.Provider;
            if (!_actionProviders.TryGetValue(a, out var set2))
                _actionProviders[a] = set2 = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            set2.Add(role.Provider);
        }
    }

    /// <summary>Replace one provider's slice of the catalog (used by PowerShell deep sync).</summary>
    public void ReplaceProvider(string provider, IEnumerable<RoleDefinitionRecord> roles)
    {
        var keep = _byId.Values
            .Where(r => !string.Equals(r.Provider, provider, StringComparison.OrdinalIgnoreCase))
            .ToList();
        keep.AddRange(roles);
        ReplaceAll(keep, DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Provider owning a resource action.
    ///
    /// The backing map is FIRST-WRITER-WINS, and Exchange syncs before Purview — so a
    /// cmdlet present in both (New-ComplianceSearch is in Exchange's 'Mailbox Search' AND
    /// in Purview's Compliance Search) got attributed to whichever synced first. That put
    /// compliance cmdlets under Exchange Online and produced a grant the wrong-service
    /// guard then had to catch.
    ///
    /// CmdletServiceMap knows the true owner for the cmdlets that matter, and it is
    /// deliberate rather than incidental. Where it has an opinion, it wins.
    /// </summary>
    public string? ProviderOf(string resourceAction)
    {
        var authoritative = Recommendation.CmdletServiceMap.OwnerOf(resourceAction);
        if (authoritative is not null) return authoritative;

        // Sync order is not evidence. Resolve by what the action IS, in order of authority.
        if (!_actionProviders.TryGetValue(resourceAction, out var owners) || owners.Count == 0)
            return _actionProvider.TryGetValue(resourceAction, out var legacy) ? legacy : null;

        if (owners.Count == 1) return owners.First();

        // AMBIGUOUS — the action is granted by roles in more than one service. Prefer the
        // provider implied by the action's own SHAPE, which is a property of the action
        // rather than of when it happened to be synced.
        var byShape = ProviderFromShape(resourceAction);
        if (byShape is not null && owners.Contains(byShape)) return byShape;

        // Still ambiguous. Return null rather than guessing: callers treat null as "not
        // attributable", which is honest, whereas an arbitrary pick reads as a fact.
        return null;
    }

    /// <summary>Every provider whose roles grant this action.</summary>
    public IReadOnlyCollection<string> ProvidersOf(string resourceAction) =>
        _actionProviders.TryGetValue(resourceAction, out var set)
            ? set : Array.Empty<string>();

    /// <summary>True when more than one service grants it — worth telling the operator.</summary>
    public bool IsAmbiguous(string resourceAction) => ProvidersOf(resourceAction).Count > 1;

    /// <summary>
    /// The provider an action's own NAME implies. A resource-action string carries its
    /// namespace ("microsoft.directory/..."), and Intune's underscored form is unmistakable.
    /// Cmdlets carry no namespace, which is exactly why CmdletServiceMap exists.
    /// </summary>
    private static string? ProviderFromShape(string action)
    {
        if (action.StartsWith("microsoft.directory/", StringComparison.OrdinalIgnoreCase))
            return RbacProviders.Directory;
        if (action.StartsWith("microsoft.intune_", StringComparison.OrdinalIgnoreCase))
            return RbacProviders.Intune;
        if (action.StartsWith("microsoft.cloudpc/", StringComparison.OrdinalIgnoreCase))
            return RbacProviders.CloudPc;
        if (action.StartsWith("microsoft.entitlementmanagement/", StringComparison.OrdinalIgnoreCase))
            return RbacProviders.EntitlementManagement;
        return null;
    }

    /// <summary>Roles belonging to one provider.</summary>
    public IEnumerable<RoleDefinitionRecord> RolesFor(string provider) =>
        _byId.Values.Where(r => string.Equals(r.Provider, provider, StringComparison.OrdinalIgnoreCase));

    public IReadOnlyList<string> Providers =>
        _byId.Values.Select(r => r.Provider).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(p => p).ToList();

    public RoleDefinitionRecord? Find(string roleId) =>
        _byId.TryGetValue(roleId, out var r) ? r : null;

    public bool ActionExists(string resourceAction) => _allActions.Contains(resourceAction);

    public int ActionCount => _allActions.Count;

    /// <summary>Every distinct action across every provider. Read-only view.</summary>
    public IReadOnlyCollection<string> AllActions => _allActions;

    /// <summary>
    /// Marks AccessCheck's own bookkeeping records. These carry real permissions but are
    /// NOT roles that exist in the tenant — they have no assignable id, so they must never
    /// be offered as something to grant.
    /// </summary>
    public const string SyntheticIdPrefix = "accesscheck:proven:";

    public static bool IsSynthetic(string roleId) =>
        roleId.StartsWith(SyntheticIdPrefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Records permissions the TENANT ITSELF accepted during a successful grant.
    ///
    /// This is the strongest evidence available — stronger than a sync, which is a
    /// snapshot, and stronger than documentation, which describes the product rather than
    /// this tenant. A permission that was refused by the catalog, attempted anyway, and
    /// then read back from a role the tenant created is PROVEN to exist here.
    ///
    /// Kept in its own synthetic role so it is visible as learned rather than synced, and
    /// so a later full sync overwrites the real providers without erasing what was proven.
    /// </summary>
    public int RecordProvenActions(string provider, IEnumerable<string> actions)
    {
        var incoming = actions
            .Where(a => !string.IsNullOrWhiteSpace(a))
            .Select(a => a.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (incoming.Count == 0) return 0;

        const string provenIdPrefix = SyntheticIdPrefix;
        var id = provenIdPrefix + provider;
        var existing = Roles.FirstOrDefault(r =>
            r.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

        var merged = new List<string>(existing?.AllowedResourceActions ?? Array.Empty<string>());
        var added = 0;
        foreach (var action in incoming)
        {
            if (merged.Contains(action, StringComparer.OrdinalIgnoreCase)) continue;
            merged.Add(action);
            added++;
        }
        if (added == 0) return 0;

        var record = new RoleDefinitionRecord
        {
            Id = id,
            DisplayName = "(proven by successful grant)",
            Provider = provider,
            IsBuiltIn = false,
            Description = "Permissions this tenant ACCEPTED during a real grant. Recorded "
                        + "because the tenant's acceptance is stronger evidence than a "
                        + "catalog snapshot or documentation.",
            AllowedResourceActions = merged
        };

        // Add() is an UPSERT (_byId[role.Id] = role), so re-adding under the same id
        // replaces the previous record. Roles is a read-only view over that dictionary and
        // cannot be mutated directly — .Remove() on it bound to the IDictionary extension
        // method, which is what the compiler was objecting to.
        Add(record);
        return added;
    }

    // ---- persistence (local JSON snapshot; SQLite can replace later without touching callers) ----

    private sealed record Snapshot(DateTimeOffset? LastSyncedUtc, List<RoleDefinitionRecord> Roles);

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public string ToJson() =>
        JsonSerializer.Serialize(new Snapshot(LastSyncedUtc, _byId.Values.ToList()), JsonOpts);

    public static RoleCatalog FromJson(string json)
    {
        var snap = JsonSerializer.Deserialize<Snapshot>(json, JsonOpts)
                   ?? throw new InvalidDataException("Catalog JSON was empty or invalid.");
        var cat = new RoleCatalog();
        cat.ReplaceAll(snap.Roles, snap.LastSyncedUtc ?? DateTimeOffset.UtcNow);
        return cat;
    }

    public void Save(string path) => File.WriteAllText(path, ToJson());

    public static RoleCatalog Load(string path) => FromJson(File.ReadAllText(path));
}
