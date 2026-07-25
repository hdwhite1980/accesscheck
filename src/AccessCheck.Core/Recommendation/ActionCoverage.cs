namespace AccessCheck.Core.Recommendation;

/// <summary>
/// Does a granted action COVER a required one?
///
/// Set containment was the whole test, and Entra's rollup actions break it. Global Reader
/// carries microsoft.directory/allEntities/standard/read — one action that grants read on
/// every object type in the directory. It does not literally contain
/// conditionalAccessPolicies/standard/read, so a role that plainly covers a read-only audit
/// request was reported as not covering it, and the model naming that role was called
/// unreliable for being right.
///
/// THE WEIGHTING MATTERS AS MUCH AS THE COVERAGE. Making this rollup-aware without also
/// pricing rollups correctly would rank Global Reader FIRST on read requests: its excess is
/// a handful of actions, each ending in /read and therefore weighted 1, against twenty
/// specific reads weighted 20. See ActionRisk.RollupWeight — a rollup is not one permission,
/// it is a category, and it is priced as one.
/// </summary>
public static class ActionCoverage
{
    private const string AllEntities = "allentities";
    private const string AllTasks = "alltasks";
    private const string AllProperties = "allproperties";

    private static readonly string[] PropertyScopes = { "standard", "basic", "allproperties" };

    /// <summary>True when any action in <paramref name="granted"/> covers <paramref name="required"/>.</summary>
    public static bool CoveredBy(string required, IEnumerable<string> granted) =>
        granted.Any(g => Covers(g, required));

    /// <summary>True when every required action is covered.</summary>
    public static bool CoversAll(IEnumerable<string> granted, IEnumerable<string> required)
    {
        var list = granted as IReadOnlyList<string> ?? granted.ToList();
        return required.All(r => CoveredBy(r, list));
    }

    /// <summary>
    /// Does <paramref name="granted"/> grant <paramref name="required"/>?
    ///
    /// Conservative by construction: anything that does not parse as a slash-delimited
    /// resource action falls back to exact equality, so Intune's underscored names and
    /// Exchange cmdlets behave exactly as before.
    /// </summary>
    public static bool Covers(string? granted, string? required)
    {
        if (string.IsNullOrWhiteSpace(granted) || string.IsNullOrWhiteSpace(required))
            return false;
        if (string.Equals(granted, required, StringComparison.OrdinalIgnoreCase)) return true;

        var g = Parse(granted);
        var r = Parse(required);
        if (g is null || r is null) return false;

        if (!string.Equals(g.Value.Namespace, r.Value.Namespace, StringComparison.OrdinalIgnoreCase))
            return false;

        // ENTITY. allEntities dominates any single entity path. Otherwise the paths must be
        // identical — users/allProperties/read is NOT assumed to cover a sub-resource such as
        // users/authenticationMethods, because Microsoft treats that as a separate resource
        // and over-claiming here would silently mark a role as covering something it cannot.
        var entityOk =
            g.Value.Entity.Length == 1
            && string.Equals(g.Value.Entity[0], AllEntities, StringComparison.OrdinalIgnoreCase)
            || g.Value.Entity.SequenceEqual(r.Value.Entity, StringComparer.OrdinalIgnoreCase);
        if (!entityOk) return false;

        // OPERATION. allTasks means every operation, which subsumes every property scope too,
        // so the scope check is skipped in that case.
        if (string.Equals(g.Value.Operation, AllTasks, StringComparison.OrdinalIgnoreCase))
            return true;

        if (!string.Equals(g.Value.Operation, r.Value.Operation, StringComparison.OrdinalIgnoreCase))
            return false;

        // SCOPE. allProperties dominates standard, basic and no scope at all. Anything else
        // must match — standard/read does NOT grant allProperties/read, which is the whole
        // point of the distinction.
        if (string.Equals(g.Value.Scope, r.Value.Scope, StringComparison.OrdinalIgnoreCase))
            return true;
        return string.Equals(g.Value.Scope, AllProperties, StringComparison.OrdinalIgnoreCase);
    }

    private readonly record struct Parsed(string Namespace, string[] Entity, string Scope, string Operation);

    private static Parsed? Parse(string action)
    {
        var parts = action.Trim().Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3) return null;
        if (!parts[0].Contains('.', StringComparison.Ordinal)) return null;

        var segments = parts.Skip(1).ToArray();
        var operation = segments[^1];

        var hasScope = segments.Length >= 3
            && PropertyScopes.Contains(segments[^2], StringComparer.OrdinalIgnoreCase);

        var scope = hasScope ? segments[^2] : "";
        var entity = segments.Take(segments.Length - (hasScope ? 2 : 1)).ToArray();
        if (entity.Length == 0) return null;

        return new Parsed(parts[0], entity, scope, operation);
    }
}
