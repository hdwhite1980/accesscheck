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

    /// <summary>
    /// True when this entry IS a role rather than a bundle of cmdlets.
    ///
    /// Purview exposes role names and nothing inside them — Get-ManagementRoleEntry does
    /// not exist in that session and Get-ManagementRole returns an empty RoleEntries. So
    /// the granular unit there is the ROLE, and Covers holds the role's own name. Excess
    /// is always empty: a role cannot over-grant relative to itself, and the real
    /// over-privilege question is which built-in role GROUP you would otherwise have used.
    /// </summary>
    public bool IsRoleLevel { get; init; }

    /// <summary>Microsoft's description of the role, where the vocabulary is role-level.</summary>
    public string Description { get; init; } = "";

    // Scoring cmdlet names is meaningful; scoring role names is not — ActionRisk reads
    // action shapes, and "Search And Purge" is not one.
    public int ExcessRiskScore => IsRoleLevel ? 0 : ActionRisk.Score(Excess);

    public string Summary => IsRoleLevel
        ? $"include role '{RoleName}'"
          + (Description.Length == 0 ? "" : " — " + Description)
        : NeedsDerivation
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

    /// <summary>
    /// True when this plan grants ROLES rather than cmdlets. Purview only.
    /// </summary>
    public bool RoleLevel { get; init; }

    /// <summary>
    /// The narrowest built-in role group that already carries everything this plan needs,
    /// and how many EXTRA roles it would also hand over.
    ///
    /// This is the over-privilege figure for a role-level service, and it is a different
    /// measurement from the cmdlet-level one — extra ROLES, not extra actions. Without it
    /// a Purview verdict had no delta at all and read as "zero excess", which is exactly
    /// the reassurance PermissionBreadth exists to stop the app giving.
    ///
    /// Null means NO single built-in group covers the set. That is not "no excess": it
    /// means the alternative is granting two groups, which is the strongest case for
    /// composing one.
    /// </summary>
    public string? NarrowestAlternative { get; init; }
    public int? AlternativeExcessRoles { get; init; }

    public bool IsComplete => Uncovered.Count == 0;
    public int TotalExcess => Roles.Sum(r => r.Excess.Count);
    public int TotalExcessRisk => Roles.Sum(r => r.ExcessRiskScore);

    /// <summary>True when every role is used as-is because the service forbids derivation.</summary>
    public bool CompositionOnly => Roles.Count > 0 && Roles.All(r => !r.CanDerive);

    public string Headline => RoleLevel ? RoleLevelHeadline : CmdletLevelHeadline;

    private string RoleLevelHeadline => IsComplete
        ? $"role group '{RoleGroupName}' carrying " +
          (Roles.Count == 1 ? "1 role" : Roles.Count + " roles") +
          (AlternativeExcessRoles is { } extra
              ? extra == 0
                  // The built-in already is the minimum. Composing adds an object to govern
                  // and grants nothing less, so say so rather than manufacture a difference.
                  ? $" — the same as built-in '{NarrowestAlternative}', which is already minimal"
                  : $" — the narrowest built-in alternative is '{NarrowestAlternative}', which " +
                    $"would also grant {extra} role(s) nobody asked for"
              : " — NO single built-in role group carries this combination, so the " +
                "alternative is granting two")
        : $"INCOMPLETE — {Uncovered.Count} role(s) are not defined in this tenant";

    private string CmdletLevelHeadline => IsComplete
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

    /// <summary>
    /// A plan for a service whose vocabulary is ROLES, not cmdlets. Purview only.
    ///
    /// Build() cannot work here and never could: it set-covers over
    /// AllowedResourceActions, and Purview roles carry none. The tenant reports 120 roles
    /// and nothing about their contents, because the Security and Compliance session has
    /// no Get-ManagementRoleEntry and Get-ManagementRole returns an empty RoleEntries. Set
    /// cover over empty sets covers nothing, so every Purview request fell through to
    /// another service — a phishing purge came back with Remove-Mailbox, which deletes the
    /// mailbox rather than the message.
    ///
    /// Chasing those cmdlets was the wrong goal anyway. Purview cannot create custom
    /// management roles, so nothing is ever derived or stripped and a cmdlet list could
    /// not be acted on even if it existed. The unit of granting IS the role.
    ///
    /// VALIDATION STILL HOLDS. A proposed role must appear in the tenant's own role list
    /// or it is Uncovered — the same rule as an unknown action, applied to the only
    /// vocabulary this service publishes. A model cannot invent a role here any more than
    /// it can invent an action elsewhere.
    ///
    /// OVER-PRIVILEGE IS MEASURED IN ROLES. Microsoft publishes which built-in role groups
    /// carry each role, so the narrowest of those is the alternative an operator would
    /// otherwise use, and its surplus roles are the saving. That is a real delta from a
    /// documented source, in place of the "unknown" this service used to report.
    /// </summary>
    public static RoleGroupPlan BuildFromRoles(
        PurviewRoleCatalog docs,
        IReadOnlyCollection<string> tenantRoleNames,
        IReadOnlyCollection<string> wantedRoles,
        string roleGroupName)
    {
        var tenant = new HashSet<string>(tenantRoleNames, StringComparer.OrdinalIgnoreCase);

        var known = wantedRoles
            .Where(r => tenant.Contains(r))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(r => r, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var unknown = wantedRoles
            .Where(r => !tenant.Contains(r))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(r => r, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var planned = known.Select(name => new PlannedRole
        {
            RoleId = name,
            RoleName = name,
            IsRoleLevel = true,
            CanDerive = false,
            Description = docs.Find(name)?.Description ?? "",
            Covers = new[] { name },
            // A role cannot over-grant relative to itself. The real question is which
            // built-in group you would otherwise have used, answered below.
            Excess = Array.Empty<string>()
        }).ToList();

        var narrowest = known.Count == 0
            ? null
            : docs.RoleGroups
                .Where(g => known.All(k =>
                    g.Roles.Any(r => r.Equals(k, StringComparison.OrdinalIgnoreCase))))
                .OrderBy(g => g.Roles.Count)
                .FirstOrDefault();

        return new RoleGroupPlan
        {
            Provider = RbacProviders.Purview,
            RoleGroupName = roleGroupName,
            RoleLevel = true,
            Roles = planned,
            Uncovered = unknown,
            NarrowestAlternative = narrowest?.Name,
            AlternativeExcessRoles = narrowest is null
                ? null : narrowest.Roles.Count - known.Count
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
            // A role-level entry's Covers is its own name, already shown in the summary.
            // Repeating it as "supplies:" reads as though the role contained one cmdlet.
            if (role.IsRoleLevel) { lines.Add(""); continue; }
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

        if (RoleLevel && AlternativeExcessRoles is { } surplus && surplus > 0
            && NarrowestAlternative is not null)
        {
            lines.Add("Narrowest built-in alternative: '" + NarrowestAlternative + "', which "
                    + "would also grant " + surplus + " role(s) this plan does not.");
            lines.Add("");
        }

        if (!IsComplete)
        {
            lines.Add(RoleLevel
                ? "NOT DEFINED in this tenant:"
                : "NOT COVERED by any role in this service:");
            foreach (var cmdlet in Uncovered) lines.Add("  " + ActionDisplay.Short(cmdlet));
            lines.Add("");
            lines.Add(RoleLevel
                ? "These role names are not in your tenant's synced Purview role list and "
                + "were rejected. Nothing was substituted."
                : "Granting this plan would leave the task partly undone. Check the "
                + "service is correct before proceeding.");
        }

        return string.Join(Environment.NewLine, lines);
    }
}
