using AccessCheck.Core.Catalog;

namespace AccessCheck.Core.Review;

/// <summary>How a role reached the user.</summary>
public enum GrantPath
{
    /// <summary>Active/permanent assignment — the user has it right now.</summary>
    Active,
    /// <summary>PIM eligible — the user can activate it on demand.</summary>
    Eligible,
    /// <summary>Inherited through group membership.</summary>
    ViaGroup
}

/// <summary>One role the user currently holds, with the actions it grants.</summary>
public sealed record HeldRole
{
    public required string Provider { get; init; }
    public required string RoleId { get; init; }
    public required string DisplayName { get; init; }
    public required GrantPath Path { get; init; }
    /// <summary>Group display name when Path is ViaGroup.</summary>
    public string? ViaGroupName { get; init; }
    public string DirectoryScope { get; init; } = "/";
    /// <summary>Expanded from the synced catalog; empty if the role wasn't in the catalog.</summary>
    public required IReadOnlyList<string> GrantedActions { get; init; }

    public string PathLabel => Path switch
    {
        GrantPath.Active => "Active",
        GrantPath.Eligible => "Eligible (PIM)",
        GrantPath.ViaGroup => "Via group" + (ViaGroupName is null ? "" : " '" + ViaGroupName + "'"),
        _ => Path.ToString()
    };
}

/// <summary>Deterministic verdict for one held role against what the person actually does.</summary>
public enum RoleVerdict
{
    /// <summary>Every action this role grants is needed for the stated function.</summary>
    FullyJustified,
    /// <summary>Some actions are needed; the rest are excess.</summary>
    PartiallyJustified,
    /// <summary>None of this role's actions are needed for the stated function.</summary>
    NotJustified,
    /// <summary>Role isn't in the synced catalog, so its actions couldn't be evaluated.</summary>
    Unknown
}

public sealed record RoleAssessment
{
    public required HeldRole Role { get; init; }
    public required RoleVerdict Verdict { get; init; }
    /// <summary>Actions this role grants that the stated function needs.</summary>
    public required IReadOnlyList<string> JustifiedActions { get; init; }
    /// <summary>Actions this role grants beyond the stated function.</summary>
    public required IReadOnlyList<string> ExcessActions { get; init; }

    public string VerdictLabel => Verdict switch
    {
        RoleVerdict.FullyJustified => "Fully justified",
        RoleVerdict.PartiallyJustified =>
            "Partially justified (" + JustifiedActions.Count + " needed, " +
            ExcessActions.Count + " excess)",
        RoleVerdict.NotJustified => "Not justified — none of its " +
            Role.GrantedActions.Count + " action(s) are needed",
        _ => "Unknown — role not in synced catalog"
    };
}

/// <summary>Full comparison of held access against required access.</summary>
public sealed record AccessReviewResult
{
    public required IReadOnlyList<RoleAssessment> RoleAssessments { get; init; }
    /// <summary>Union of everything the user can do today.</summary>
    public required IReadOnlyList<string> GrantedActions { get; init; }
    /// <summary>Validated actions the stated function requires.</summary>
    public required IReadOnlyList<string> RequiredActions { get; init; }
    /// <summary>Granted but not required — the over-privilege set.</summary>
    public required IReadOnlyList<string> ExcessActions { get; init; }
    /// <summary>Required but not granted — the user can't actually do part of their job.</summary>
    public required IReadOnlyList<string> MissingActions { get; init; }

    public int GrantedCount => GrantedActions.Count;
    public int ExcessCount => ExcessActions.Count;

    /// <summary>Share of granted actions that the stated function does not need (0-100).</summary>
    public int ExcessPercent => GrantedActions.Count == 0
        ? 0
        : (int)Math.Round(100.0 * ExcessActions.Count / GrantedActions.Count);

    public bool OverPrivileged => ExcessActions.Count > 0;
    public bool UnderPrivileged => MissingActions.Count > 0;

    public string Headline =>
        GrantedActions.Count == 0
            ? "No catalog-resolvable permissions are assigned to this user."
            : OverPrivileged
                ? ExcessActions.Count + " of " + GrantedActions.Count + " granted action(s) (" +
                  ExcessPercent + "%) are not needed for the stated function." +
                  (UnderPrivileged ? " " + MissingActions.Count + " needed action(s) are missing." : "")
                : "No excess: every granted action maps to the stated function." +
                  (UnderPrivileged ? " But " + MissingActions.Count + " needed action(s) are missing." : "");
}

/// <summary>
/// Deterministic comparator. The over-privilege verdict is computed here from set
/// arithmetic on the synced catalog — the AI only narrates risk afterwards, it never
/// decides whether a role is excessive.
/// </summary>
public static class AccessReviewer
{
    public static AccessReviewResult Compare(
        IReadOnlyList<HeldRole> heldRoles,
        IReadOnlyList<string> requiredActions)
    {
        var required = new HashSet<string>(requiredActions, StringComparer.OrdinalIgnoreCase);
        var grantedAll = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var assessments = new List<RoleAssessment>();

        foreach (var role in heldRoles)
        {
            foreach (var a in role.GrantedActions) grantedAll.Add(a);

            var justified = role.GrantedActions
                .Where(required.Contains)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var excess = role.GrantedActions
                .Where(a => !required.Contains(a))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var verdict =
                role.GrantedActions.Count == 0 ? RoleVerdict.Unknown
                : excess.Count == 0 ? RoleVerdict.FullyJustified
                : justified.Count == 0 ? RoleVerdict.NotJustified
                : RoleVerdict.PartiallyJustified;

            assessments.Add(new RoleAssessment
            {
                Role = role,
                Verdict = verdict,
                JustifiedActions = justified,
                ExcessActions = excess
            });
        }

        var excessAll = grantedAll
            .Where(a => !required.Contains(a))
            .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var missing = required
            .Where(a => !grantedAll.Contains(a))
            .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new AccessReviewResult
        {
            RoleAssessments = assessments
                .OrderByDescending(a => a.ExcessActions.Count)
                .ToList(),
            GrantedActions = grantedAll.OrderBy(a => a, StringComparer.OrdinalIgnoreCase).ToList(),
            RequiredActions = required.OrderBy(a => a, StringComparer.OrdinalIgnoreCase).ToList(),
            ExcessActions = excessAll,
            MissingActions = missing
        };
    }

    /// <summary>Expands a role id to its catalog actions (empty when not in the catalog).</summary>
    public static IReadOnlyList<string> ActionsFor(RoleCatalog catalog, string roleId) =>
        catalog.Find(roleId)?.AllowedResourceActions ?? Array.Empty<string>();
}
