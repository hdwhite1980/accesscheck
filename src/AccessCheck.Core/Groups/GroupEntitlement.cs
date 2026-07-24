using System.Text.Json;
using System.Text.Json.Serialization;
using AccessCheck.Core.Recommendation;

namespace AccessCheck.Core.Groups;

/// <summary>One role a group carries, and how.</summary>
public sealed record GroupRoleHolding
{
    public required string Provider { get; init; }
    public required string RoleId { get; init; }
    public required string RoleName { get; init; }
    /// <summary>True when the group holds the role as a PIM eligibility rather than actively.</summary>
    public bool Eligible { get; init; }

    public string Label => RoleName + (Eligible ? " (eligible)" : "");
}

/// <summary>
/// A group that carries at least one role, with the union of permissions its roles
/// grant. This is what makes "can they just join an existing group?" answerable
/// deterministically instead of by memory.
/// </summary>
public sealed record GroupEntitlement
{
    public required string GroupId { get; init; }
    public required string DisplayName { get; init; }
    public string Description { get; init; } = "";
    /// <summary>Role-assignable groups can carry Entra directory roles; set at creation, immutable.</summary>
    public bool IsRoleAssignable { get; init; }
    public required IReadOnlyList<GroupRoleHolding> Holdings { get; init; }
    /// <summary>Union of every action granted by the roles this group holds.</summary>
    public required IReadOnlyList<string> GrantedActions { get; init; }

    public string RolesLabel => string.Join(", ", Holdings.Select(h => h.Label));
    public IReadOnlyList<string> Providers =>
        Holdings.Select(h => h.Provider).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
}

/// <summary>How well an existing group matches what a request needs.</summary>
public sealed record GroupFit
{
    public required GroupEntitlement Group { get; init; }
    /// <summary>Required actions this group already grants.</summary>
    public required IReadOnlyList<string> CoveredActions { get; init; }
    /// <summary>Required actions it does NOT grant (empty means a full match).</summary>
    public required IReadOnlyList<string> MissingActions { get; init; }
    /// <summary>Actions the group grants beyond the request — the over-privilege cost of joining.</summary>
    public required IReadOnlyList<string> ExcessActions { get; init; }

    public bool FullyCovers => MissingActions.Count == 0 && CoveredActions.Count > 0;
    public int ExcessCount => ExcessActions.Count;
    public int ExcessPrivilegedCount => ActionRisk.CountPrivileged(ExcessActions);
    public int ExcessRiskScore => ActionRisk.Score(ExcessActions);
    public int CoveragePercent { get; init; }

    /// <summary>Writes that cannot escalate — still real blast radius.</summary>
    public int ExcessWriteCount => ActionRisk.CountWrites(ExcessActions) - ExcessPrivilegedCount;

    public string ExcessLabel =>
        "+" + ExcessCount + " excess" +
        (ExcessCount == 0
            ? ""
            : ", " + ExcessWriteCount + " write, " + ExcessPrivilegedCount + " escalation-capable");

    public string Summary => FullyCovers
        ? "covers all " + CoveredActions.Count + " needed action(s), " + ExcessLabel
        : "covers " + CoveredActions.Count + " of " +
          (CoveredActions.Count + MissingActions.Count) + " (" + CoveragePercent + "%), " +
          MissingActions.Count + " still missing";
}

/// <summary>
/// Deterministic matching of a request against existing groups. Full matches are ranked
/// by risk-weighted excess — the same measure used for roles, so joining a group with a
/// few extra ADMIN permissions ranks worse than one with more extra read permissions.
/// </summary>
public static class GroupMatcher
{
    public static IReadOnlyList<GroupFit> Rank(
        IEnumerable<GroupEntitlement> groups,
        IReadOnlyList<string> requiredActions,
        bool includePartial = true)
    {
        var required = new HashSet<string>(requiredActions, StringComparer.OrdinalIgnoreCase);
        if (required.Count == 0) return Array.Empty<GroupFit>();

        var fits = new List<GroupFit>();
        foreach (var g in groups)
        {
            var granted = new HashSet<string>(g.GrantedActions, StringComparer.OrdinalIgnoreCase);
            var covered = required.Where(granted.Contains)
                .OrderBy(a => a, StringComparer.OrdinalIgnoreCase).ToList();
            if (covered.Count == 0) continue;

            var missing = required.Where(a => !granted.Contains(a))
                .OrderBy(a => a, StringComparer.OrdinalIgnoreCase).ToList();
            if (missing.Count > 0 && !includePartial) continue;

            var excess = g.GrantedActions
                .Where(a => !required.Contains(a))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(a => a, StringComparer.OrdinalIgnoreCase).ToList();

            fits.Add(new GroupFit
            {
                Group = g,
                CoveredActions = covered,
                MissingActions = missing,
                ExcessActions = excess,
                CoveragePercent = (int)Math.Round(100.0 * covered.Count / required.Count)
            });
        }

        return fits
            .OrderByDescending(f => f.FullyCovers)      // complete answers first
            .ThenBy(f => f.ExcessRiskScore)             // then least risky over-grant
            .ThenBy(f => f.ExcessCount)
            .ThenByDescending(f => f.CoveragePercent)   // among partials, closest first
            .ThenBy(f => f.Group.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}

/// <summary>Persisted snapshot of the group entitlement catalog.</summary>
public sealed class GroupCatalog
{
    public List<GroupEntitlement> Groups { get; set; } = new();
    public DateTimeOffset? LastSyncedUtc { get; set; }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public void Save(string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(this, JsonOpts));

    public static GroupCatalog Load(string path) =>
        JsonSerializer.Deserialize<GroupCatalog>(File.ReadAllText(path), JsonOpts)
        ?? new GroupCatalog();
}
