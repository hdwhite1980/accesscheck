using AccessCheck.Core.Catalog;

namespace AccessCheck.Core.Recommendation;

/// <summary>One role in a composed plan, with the cmdlets it contributes and its excess.</summary>
public sealed record PlannedRole
{
    public required string RoleId { get; init; }
    public required string RoleName { get; init; }
    /// <summary>Required cmdlets this role supplies.</summary>
    public required IReadOnlyList<string> Covers { get; init; }
    /// <summary>Cmdlets it grants beyond the requirement — stripped when derived.</summary>
    public required IReadOnlyList<string> Excess { get; init; }

    /// <summary>
    /// Whether this role would be trimmed. Only meaningful where the service can actually
    /// create custom roles — Purview cannot, so its excess is unavoidable rather than
    /// something to strip.
    /// </summary>
    public bool NeedsDerivation => Excess.Count > 0 && CanDerive;

    /// <summary>Set by the planner from the provider's capability.</summary>
    public bool CanDerive { get; init; } = true;
    public int ExcessRiskScore => ActionRisk.Score(Excess);

    public string Summary => NeedsDerivation
        ? $"derive from '{RoleName}' (supplies {Covers.Count}, strips {Excess.Count} excess)"
        : Excess.Count == 0
            ? $"use '{RoleName}' as-is (supplies {Covers.Count}, no excess)"
            // Excess that cannot be stripped is still excess — name it rather than implying
            // the role is a clean fit.
            : $"use '{RoleName}' as-is (supplies {Covers.Count}, carries {Excess.Count} "
              + "unavoidable extra cmdlet(s) — this service cannot create custom roles)";
}

/// <summary>
/// A least-privilege plan for the Exchange-model services, where a custom role must be
/// DERIVED from a parent and cannot be composed from scratch.
///
/// The single-parent assumption breaks on real tasks. Search-and-purge needs
/// New-ComplianceSearch (the Compliance Search role) AND New-ComplianceSearchAction -Purge
/// (the Search And Purge role) — no single role holds both, so a one-parent derivation
/// finds no covering role and recommends nothing at all.
///
/// The correct answer is a ROLE GROUP carrying the minimal set of roles, each derived down
/// to only what is needed. That is genuinely least privilege: the alternative Microsoft
/// documents is Organization Management or Data Investigator, which grant vastly more.
/// </summary>
public sealed record RoleGroupPlan
{
    public required string Provider { get; init; }
    public required string RoleGroupName { get; init; }

    /// <summary>
    /// A name that encodes the ROLE SET, so a plan needing different roles never collides
    /// with a group created for an earlier one. Role groups cannot have roles added after
    /// creation, so a name collision with the wrong contents is unfixable in place.
    /// </summary>
    public string DistinctGroupName
    {
        get
        {
            if (Roles.Count == 0) return RoleGroupName;
            var stamp = string.Join("+", Roles
                .Select(r => new string(r.RoleName.Where(char.IsLetterOrDigit).Take(10).ToArray()))
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase));
            var suffix = " [" + stamp + "]";

            // RESERVE ROOM FOR THE STAMP. Appending it and then truncating to 64 removed the
            // only distinguishing part, so a plan with different roles produced the SAME name
            // as an older group — the exact collision the stamp exists to prevent.
            const int max = 64;
            if (suffix.Length >= max) return RoleGroupName.Length <= max
                ? RoleGroupName : RoleGroupName[..max];

            var room = max - suffix.Length;
            var head = RoleGroupName.Length <= room ? RoleGroupName : RoleGroupName[..room];
            return head + suffix;
        }
    }
    public required IReadOnlyList<PlannedRole> Roles { get; init; }
    /// <summary>Required cmdlets no role in this service supplies.</summary>
    public required IReadOnlyList<string> Uncovered { get; init; }

    public bool IsComplete => Uncovered.Count == 0;
    public int TotalExcess => Roles.Sum(r => r.Excess.Count);
    public int TotalExcessRisk => Roles.Sum(r => r.ExcessRiskScore);

    /// <summary>True when every role is used as-is because the service forbids derivation.</summary>
    public bool CompositionOnly => Roles.Count > 0 && Roles.All(r => !r.CanDerive);

    public string Headline => IsComplete
        ? (Roles.Count == 1
            ? $"role group '{RoleGroupName}' carrying 1 role"
            : $"role group '{RoleGroupName}' carrying {Roles.Count} roles")
          + (TotalExcess == 0
             ? ", exactly the needed cmdlets"
             : CompositionOnly
                 // Claiming "stripped by derivation" where derivation is impossible
                 // described a grant that could not happen.
                 ? $", carrying {TotalExcess} unavoidable extra cmdlet(s) — this service "
                   + "cannot create custom roles, so composing the minimal set of built-in "
                   + "roles IS the least-privilege answer"
                 : $", {TotalExcess} excess cmdlet(s) stripped by derivation")
        : $"INCOMPLETE — {Uncovered.Count} cmdlet(s) are not in any role this service defines";

    /// <summary>
    /// Minimal set cover over the provider's roles: repeatedly take the role covering the
    /// most still-uncovered cmdlets, breaking ties by least risk-weighted excess so a
    /// narrow role beats a broad one that happens to cover the same amount.
    /// </summary>
    public static RoleGroupPlan Build(
        RoleCatalog catalog,
        string provider,
        IReadOnlyCollection<string> requiredActions,
        string roleGroupName)
    {
        // Purview cannot create custom management roles, so a plan that proposes deriving
        // one is a plan that cannot execute — it failed with "This endpoint does not
        // support creating custom management roles."
        var canDerive = RbacProviders.DerivationCapable.Contains(provider);
        var remaining = new HashSet<string>(requiredActions, StringComparer.OrdinalIgnoreCase);
        var candidates = catalog.RolesFor(provider).ToList();
        var chosen = new List<PlannedRole>();

        while (remaining.Count > 0)
        {
            RoleDefinitionRecord? best = null;
            List<string>? bestCovers = null;

            foreach (var role in candidates)
            {
                if (chosen.Any(c => c.RoleId == role.Id)) continue;

                var covers = role.AllowedResourceActions
                    .Where(a => remaining.Contains(a))
                    .ToList();
                if (covers.Count == 0) continue;

                if (best is null || covers.Count > bestCovers!.Count)
                {
                    best = role;
                    bestCovers = covers;
                    continue;
                }

                // Same coverage: prefer the role that over-grants least, weighted by risk.
                if (covers.Count == bestCovers!.Count)
                {
                    var thisExcess = ActionRisk.Score(
                        role.AllowedResourceActions.Where(a => !remaining.Contains(a)).ToList());
                    var bestExcess = ActionRisk.Score(
                        best.AllowedResourceActions.Where(a => !remaining.Contains(a)).ToList());
                    if (thisExcess < bestExcess)
                    {
                        best = role;
                        bestCovers = covers;
                    }
                }
            }

            if (best is null || bestCovers is null) break;   // nothing else can help

            var required = new HashSet<string>(requiredActions, StringComparer.OrdinalIgnoreCase);
            chosen.Add(new PlannedRole
            {
                CanDerive = canDerive,
                RoleId = best.Id,
                RoleName = best.DisplayName,
                Covers = bestCovers.OrderBy(a => a, StringComparer.OrdinalIgnoreCase).ToList(),
                Excess = best.AllowedResourceActions
                    .Where(a => !required.Contains(a))
                    .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
                    .ToList()
            });

            foreach (var covered in bestCovers) remaining.Remove(covered);
        }

        return new RoleGroupPlan
        {
            Provider = provider,
            RoleGroupName = roleGroupName,
            Roles = chosen,
            Uncovered = remaining.OrderBy(a => a, StringComparer.OrdinalIgnoreCase).ToList()
        };
    }

    /// <summary>Human-readable plan for the approval screen and the audit record.</summary>
    public string Describe()
    {
        var lines = new List<string>
        {
            $"{RbacProviders.DisplayName(Provider)} — {Headline}",
            ""
        };

        foreach (var role in Roles)
        {
            lines.Add("  " + role.Summary);
            foreach (var cmdlet in role.Covers.Take(10))
                lines.Add("      supplies: " + ActionDisplay.Short(cmdlet));
            if (role.Excess.Count > 0)
            {
                foreach (var cmdlet in role.Excess.Take(8))
                    lines.Add("      strips:   " + ActionDisplay.Short(cmdlet));
                if (role.Excess.Count > 8)
                    lines.Add($"      strips:   (+{role.Excess.Count - 8} more)");
            }
            lines.Add("");
        }

        if (!IsComplete)
        {
            lines.Add("NOT COVERED by any role in this service:");
            foreach (var cmdlet in Uncovered) lines.Add("  " + ActionDisplay.Short(cmdlet));
            lines.Add("");
            lines.Add("Granting this plan would leave the task partly undone. Check the "
                    + "service is correct before proceeding.");
        }

        return string.Join(Environment.NewLine, lines);
    }
}
