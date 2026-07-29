using AccessCheck.Core.Catalog;

namespace AccessCheck.Core.Recommendation;

/// <summary>How long a grant should live. Not every duty deserves the same answer.</summary>
public enum GrantLifetime
{
    /// <summary>Read-only, no escalation potential. Safe to hold continuously.</summary>
    Standing = 0,
    /// <summary>Changes state but cannot escalate. Grant for a period, let it expire.</summary>
    TimeBoxed = 1,
    /// <summary>Escalation-capable. Should be requested per incident, not held.</summary>
    OnRequest = 2
}

/// <summary>One duty after the ordinary pipeline has run over it.</summary>
public sealed record DutyAnalysis
{
    public required string Duty { get; init; }
    public required string Provider { get; init; }
    public required IReadOnlyList<string> Actions { get; init; }
    /// <summary>Role the verdict settled on — built-in name or custom draft name. Null when none.</summary>
    public string? RoleLabel { get; init; }
    public bool CustomRole { get; init; }
    /// <summary>The decomposer's read that this duty only looks at things.</summary>
    public bool DeclaredReadOnly { get; init; }
}

/// <summary>One grant in the finished plan, possibly covering several duties.</summary>
public sealed record PortfolioGrant
{
    public required string Provider { get; init; }
    public required string RoleLabel { get; init; }
    public bool CustomRole { get; init; }
    public required IReadOnlyList<string> Duties { get; init; }
    public required IReadOnlyList<string> Actions { get; init; }
    public required GrantLifetime Lifetime { get; init; }
    public required string Rationale { get; init; }
    /// <summary>Role labels this grant absorbed because it already contains everything they did.</summary>
    public IReadOnlyList<string> Supersedes { get; init; } = Array.Empty<string>();
    public int RiskScore => ActionRisk.Score(Actions);

    public string Headline =>
        RbacProviders.DisplayName(Provider) + ": " + RoleLabel +
        " — " + LifetimeLabel(Lifetime) +
        (Duties.Count == 1 ? "" : "  (covers " + Duties.Count + " duties)") +
        (Supersedes.Count == 0 ? ""
            : "  [replaces " + string.Join(", ", Supersedes) + "]");

    public static string LifetimeLabel(GrantLifetime l) => l switch
    {
        GrantLifetime.Standing => "STANDING",
        GrantLifetime.TimeBoxed => "TIME-BOXED",
        _ => "ON REQUEST"
    };
}

/// <summary>Something about the portfolio AS A WHOLE that no single duty reveals.</summary>
public sealed record PortfolioConcern
{
    public required string Title { get; init; }
    public required string Detail { get; init; }
    /// <summary>True when this should block sign-off rather than merely inform it.</summary>
    public bool Blocking { get; init; }
}

/// <summary>
/// Turns a pile of per-duty verdicts into a plan someone can actually approve.
///
/// The pipeline answers one question well: what does THIS duty need? A job description
/// asks a different one, and answering it duty-by-duty produces two failures that are
/// invisible from inside any single answer:
///
///   DUPLICATION. Six duties in Entra frequently resolve to the same covering role.
///   Presented separately that reads as six grants to review and six things to govern.
///
///   AGGREGATION. Each grant can be individually defensible while the UNION is an
///   escalation path. Password reset is reasonable. Group management is reasonable.
///   Held together they let someone add themselves to a privileged group and then take
///   over an account in it — and nothing examining one duty at a time can see that.
///
/// Everything here is deterministic and computed from the actions. No model involvement:
/// the model split the prose, and that job is finished.
/// </summary>
public static class PortfolioComposer
{
    /// <summary>
    /// Lifetime from what the permissions DO, not from how the duty was worded.
    ///
    /// The decomposer's readOnly flag is a reading of English and is not trusted on its
    /// own — a duty described as "reviews group membership" can still resolve to a write
    /// permission, and the actions are the thing that will actually be granted.
    /// </summary>
    public static GrantLifetime LifetimeFor(IReadOnlyCollection<string> actions)
    {
        if (actions.Count == 0) return GrantLifetime.Standing;

        // Escalation-capable means holding it continuously is a standing takeover risk,
        // however routine the duty sounds.
        if (actions.Any(ActionRisk.IsCriticalExcess)) return GrantLifetime.OnRequest;
        if (actions.Any(ActionRisk.IsPrivileged)) return GrantLifetime.OnRequest;

        // Writes are recoverable and auditable but still real blast radius.
        if (actions.Any(ActionRisk.IsWrite)) return GrantLifetime.TimeBoxed;

        return GrantLifetime.Standing;
    }

    /// <summary>
    /// Actions that reach every property, entity or task of their resource. ActionRisk
    /// prices these far above a plain read for a reason: they are a category, not a
    /// permission.
    /// </summary>
    private static List<string> Rollups(IEnumerable<string> actions) =>
        actions.Where(a => ActionRisk.RollupWeight(a) > 0).ToList();

    private static string RationaleFor(GrantLifetime lifetime, IReadOnlyCollection<string> actions)
    {
        var escalating = actions.Where(ActionRisk.IsPrivileged).Take(3).ToList();
        var rollups = Rollups(actions);

        // "NO BLAST RADIUS" NEXT TO A SCORE OF 9 READS AS NONSENSE, and an approver who
        // notices stops trusting both numbers. The score was right — allProperties/read is
        // priced at 8 because it reaches every property of its resource, not because
        // anything changes state. Read-only and NARROW are different claims, and the
        // rationale was making the second while the score measured the first.
        var breadth = rollups.Count == 0
            ? ""
            : "  BUT BROAD: " + rollups.Count + " of these reach every property or entity of "
              + "their resource (" + string.Join(", ", rollups.Take(2)) +
              (rollups.Count > 2 ? ", ..." : "") + "), which is why the score is higher than "
              + "the permission count suggests. Nothing changes state; the holder can "
              + "nonetheless see everything in scope.";

        return lifetime switch
        {
            GrantLifetime.Standing =>
                "Read-only. Nothing here changes state, so holding it continuously adds no "
                + "blast radius and removes a request cycle from routine work." + breadth,
            GrantLifetime.TimeBoxed =>
                "Changes state but cannot escalate privilege. Grant for a defined period and "
                + "let it expire — the duty is real, the standing access is not." + breadth,
            _ =>
                "Escalation-capable" +
                (escalating.Count == 0 ? "" : " (" + string.Join(", ", escalating) + ")") +
                ". Held continuously this is a standing route to privilege. Grant per "
                + "incident, with an expiry, and expect it to be used rarely." + breadth
        };
    }

    public sealed record Portfolio
    {
        public required IReadOnlyList<PortfolioGrant> Grants { get; init; }
        /// <summary>Duties that produced no grantable permission at all.</summary>
        public required IReadOnlyList<string> Unresolved { get; init; }
        public required IReadOnlyList<PortfolioConcern> Concerns { get; init; }

        public int TotalActions => Grants.SelectMany(g => g.Actions)
            .Distinct(StringComparer.OrdinalIgnoreCase).Count();
        public int TotalRisk => ActionRisk.Score(
            Grants.SelectMany(g => g.Actions)
                  .Distinct(StringComparer.OrdinalIgnoreCase).ToList());
        public bool HasBlockingConcern => Concerns.Any(c => c.Blocking);

        public string Summary =>
            Grants.Count + " grant(s) covering " +
            Grants.Sum(g => g.Duties.Count) + " duty(ies), " +
            TotalActions + " distinct permission(s). " +
            Grants.Count(g => g.Lifetime == GrantLifetime.Standing) + " standing, " +
            Grants.Count(g => g.Lifetime == GrantLifetime.TimeBoxed) + " time-boxed, " +
            Grants.Count(g => g.Lifetime == GrantLifetime.OnRequest) + " on request." +
            (Unresolved.Count == 0 ? "" : "  " + Unresolved.Count + " duty(ies) unresolved.");
    }

    public static Portfolio Compose(IReadOnlyCollection<DutyAnalysis> analyses)
    {
        // A DUTY IS UNRESOLVED ONLY IF IT RESOLVED NOWHERE.
        //
        // One duty produces one analysis PER PROVIDER, so a cross-service request lands in
        // several — and a duty answered in Exchange while Purview returned nothing was
        // listed as a grant AND under "no permission found" at the same time. Reading that,
        // an operator cannot tell whether the duty is covered.
        var resolvedDuties = analyses
            .Where(a => a.Actions.Count > 0 && !string.IsNullOrWhiteSpace(a.RoleLabel))
            .Select(a => a.Duty)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var unresolved = analyses
            .Where(a => a.Actions.Count == 0 || string.IsNullOrWhiteSpace(a.RoleLabel))
            .Select(a => a.Duty)
            .Where(d => !resolvedDuties.Contains(d))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // COLLAPSE BY PROVIDER + ROLE. Two duties landing on the same role are one grant.
        var grants = analyses
            .Where(a => a.Actions.Count > 0 && !string.IsNullOrWhiteSpace(a.RoleLabel))
            // CUSTOM ROLES GROUP BY WHAT THEY GRANT, NOT BY THE NAME THEY WERE GIVEN.
            //
            // BuildCustomRoleName derives its name from the RESOURCE, so every duty
            // touching users drafts something called "AC - Entra ID manage users" —
            // account creation, MFA re-registration and licence REPORTING all collided
            // under one label and merged into a single eight-permission role rated
            // escalation-capable. Bundling a read-only reporting duty into a role that can
            // delete accounts is precisely the over-grant this application exists to
            // prevent, and grouping by a generated name produced it.
            //
            // Built-in roles still group by name: there the name identifies a real object
            // with fixed contents, so two duties naming it genuinely are one grant.
            .GroupBy(a => a.Provider + "\u0000" + (a.CustomRole
                    ? "custom:" + string.Join(",",
                        a.Actions.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
                    : a.RoleLabel),
                StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var actions = g.SelectMany(a => a.Actions)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                // THE UNION DECIDES THE LIFETIME. A role shared by a read duty and a write
                // duty grants both sets, so the stricter answer is the only honest one —
                // taking the gentler would describe a grant narrower than the one made.
                var lifetime = LifetimeFor(actions);

                return new PortfolioGrant
                {
                    Provider = g.First().Provider,
                    RoleLabel = g.First().RoleLabel!,
                    CustomRole = g.Any(a => a.CustomRole),
                    Duties = g.Select(a => a.Duty)
                        .Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                    Actions = actions,
                    Lifetime = lifetime,
                    Rationale = RationaleFor(lifetime, actions)
                };
            })
            .ToList();

        grants = FoldSubsets(grants)
            .OrderByDescending(g => g.Lifetime)
            .ThenByDescending(g => g.RiskScore)
            .ThenBy(g => g.Provider, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new Portfolio
        {
            Grants = grants,
            Unresolved = unresolved,
            Concerns = Concerns(grants, analyses)
        };
    }

    /// <summary>
    /// Drops a grant whose permissions are ALREADY CONTAINED in another grant for the same
    /// provider, moving its duties across.
    ///
    /// Grouping by role label alone is not enough. Two duties can produce two differently
    /// NAMED custom roles where one is a strict superset of the other — "read
    /// signInReports" and "read users + signInReports" are two grants, two approvals and
    /// two objects in the tenant to govern, and the first grants nothing the second does
    /// not already give.
    ///
    /// Folding cannot increase privilege: the surviving grant was going to be made anyway,
    /// and the dropped one added nothing to it. It only removes redundancy — which matters
    /// because every extra grant is another thing to review, expire and eventually explain.
    ///
    /// Ties (identical action sets under different names) collapse to the grant covering
    /// more duties, then to the alphabetically first label, so the result does not depend
    /// on input order.
    /// </summary>
    private static List<PortfolioGrant> FoldSubsets(List<PortfolioGrant> grants)
    {
        var ordered = grants
            .OrderByDescending(g => g.Actions.Count)
            .ThenByDescending(g => g.Duties.Count)
            .ThenBy(g => g.RoleLabel, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var kept = new List<PortfolioGrant>();
        var absorbedInto = new Dictionary<int, List<PortfolioGrant>>();

        foreach (var candidate in ordered)
        {
            var host = -1;
            for (var i = 0; i < kept.Count; i++)
            {
                if (!kept[i].Provider.Equals(candidate.Provider, StringComparison.OrdinalIgnoreCase))
                    continue;

                var hostActions = kept[i].Actions.ToHashSet(StringComparer.OrdinalIgnoreCase);
                if (candidate.Actions.All(hostActions.Contains)) { host = i; break; }
            }

            if (host < 0) { kept.Add(candidate); continue; }

            if (!absorbedInto.TryGetValue(host, out var list))
                absorbedInto[host] = list = new List<PortfolioGrant>();
            list.Add(candidate);
        }

        for (var i = 0; i < kept.Count; i++)
        {
            if (!absorbedInto.TryGetValue(i, out var absorbed)) continue;

            kept[i] = kept[i] with
            {
                Duties = kept[i].Duties
                    .Concat(absorbed.SelectMany(a => a.Duties))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList(),
                // ONLY NAMES THAT DIFFER. Two custom roles drafted for the same resource
                // carry the same generated name, so folding one into the other printed
                // "[replaces AC - Intune manage DeviceCompliancePolices]" on a grant of
                // exactly that name — which reads as a bug and tells the reader nothing.
                Supersedes = absorbed.Select(a => a.RoleLabel)
                    .Where(label => !label.Equals(kept[i].RoleLabel, StringComparison.OrdinalIgnoreCase))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                    .ToList()
            };
        }

        return kept;
    }

    // ---------- aggregate findings ----------

    private static readonly string[] CredentialMarkers =
    {
        "password", "authenticationmethod", "credential", "invalidateallrefreshtokens"
    };

    private static readonly string[] RoleManagementMarkers =
    {
        "rolemanagement", "roledefinitions", "roleassignments", "directoryroles"
    };

    // ENTRA QUALIFIES THE RESOURCE. The real action is
    // microsoft.directory/groups.security/members/update — never "groups/members" — so a
    // literal marker for the unqualified form matched nothing, and the escalation pair
    // went unreported on a portfolio that contained it. Match the members segment itself.
    private static readonly string[] GroupMembershipMarkers =
    {
        "/members/update", "/members/allproperties", "/owners/update",
        "groupmember", "add-rolegroupmember", "groups/allproperties"
    };

    private static bool AnyMatches(IEnumerable<string> actions, string[] markers) =>
        actions.Any(a =>
        {
            var lower = a.ToLowerInvariant();
            return markers.Any(m => lower.Contains(m, StringComparison.Ordinal));
        });

    private static IReadOnlyList<PortfolioConcern> Concerns(
        IReadOnlyList<PortfolioGrant> grants, IReadOnlyCollection<DutyAnalysis> analyses)
    {
        var concerns = new List<PortfolioConcern>();
        var all = grants.SelectMany(g => g.Actions)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        // THE CLASSIC ESCALATION PAIR, and the reason this class exists. Each half is an
        // ordinary service-desk duty. Together they are a route to any account in a
        // privileged group: add yourself, then take over an account inside it.
        var canManageMembership = AnyMatches(all, GroupMembershipMarkers);
        var canTakeCredentials = AnyMatches(all, CredentialMarkers);
        if (canManageMembership && canTakeCredentials)
        {
            concerns.Add(new PortfolioConcern
            {
                Blocking = true,
                Title = "Combined escalation path: group membership + credential control",
                Detail =
                    "Separately these are routine. Together they let the holder add a "
                    + "principal to a privileged group and then take over an account in it, "
                    + "without needing any administrator role by name. Split them between "
                    + "two people, scope the group permission to specific groups, or make "
                    + "the credential half on-request only."
            });
        }

        if (AnyMatches(all, RoleManagementMarkers))
        {
            concerns.Add(new PortfolioConcern
            {
                Blocking = true,
                Title = "Role management is in scope",
                Detail =
                    "One or more duties resolved to permissions that manage role definitions "
                    + "or assignments. That is the permission to grant permissions, and it "
                    + "makes every other limit in this plan advisory — the holder can lift "
                    + "them. Very few job descriptions genuinely require it."
            });
        }

        // A PORTFOLIO OF INDIVIDUALLY-FINE GRANTS CAN STILL BE TOO MUCH.
        var escalating = all.Count(ActionRisk.IsPrivileged);
        if (escalating >= 8)
        {
            concerns.Add(new PortfolioConcern
            {
                Title = escalating + " escalation-capable permissions across the plan",
                Detail =
                    "No single grant here looks alarming; the total does. Consider whether "
                    + "this job is really one person, or whether the duties belong to two "
                    + "roles that happen to be written on one page."
            });
        }

        var standingWrites = grants
            .Where(g => g.Lifetime != GrantLifetime.Standing)
            .Sum(g => g.Duties.Count);
        if (standingWrites > 0 && grants.All(g => g.Lifetime != GrantLifetime.Standing))
        {
            concerns.Add(new PortfolioConcern
            {
                Title = "Nothing here is safe to hold continuously",
                Detail =
                    "Every grant in this plan changes state or can escalate. That is "
                    + "workable but operationally heavy — check the read-only duties in the "
                    + "document were not lost in the split, since a job with no standing "
                    + "access is unusual."
            });
        }

        // BREADTH ACCUMULATES ACROSS STANDING GRANTS, and no single verdict can see it.
        // Each duty here was individually judged narrower than Global Reader — one of them
        // rejected it at +101 excess — yet three standing whole-resource reads held
        // together approach the same visibility by a different route. Read-only is not the
        // same as harmless when the subject is sign-in logs, policy configuration and guest
        // accounts at once.
        var standingRollups = grants
            .Where(g => g.Lifetime == GrantLifetime.Standing)
            .SelectMany(g => g.Actions)
            .Where(a => ActionRisk.RollupWeight(a) > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (standingRollups.Count >= 2)
        {
            concerns.Add(new PortfolioConcern
            {
                Title = standingRollups.Count + " whole-resource reads held continuously",
                Detail =
                    "These grant every property or entity of their resource and are proposed "
                    + "as standing access: " + string.Join(", ", standingRollups.Take(4)) +
                    (standingRollups.Count > 4 ? ", ..." : "") + ". Individually each was "
                    + "ranked narrower than a broad built-in reader role. Together they "
                    + "approach the same visibility without ever being called that. Consider "
                    + "whether the reading needs to be continuous or only at review time."
            });
        }

        // Cross-service breadth is worth naming even when each part is minimal.
        var providers = grants.Select(g => g.Provider)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (providers.Count >= 4)
        {
            concerns.Add(new PortfolioConcern
            {
                Title = "Spans " + providers.Count + " services",
                Detail =
                    string.Join(", ", providers.Select(RbacProviders.DisplayName)) +
                    ". Each grant may be minimal within its service while the combination "
                    + "reaches most of the tenant. Worth confirming the breadth is intended "
                    + "rather than inherited from a job description that was never scoped."
            });
        }

        var unresolvedCount = analyses.Count(a => a.Actions.Count == 0);
        if (unresolvedCount > 0 && unresolvedCount >= analyses.Count / 2)
        {
            concerns.Add(new PortfolioConcern
            {
                Title = "Half or more of the duties produced nothing",
                Detail =
                    unresolvedCount + " of " + analyses.Count + " duties resolved to no "
                    + "permission. That usually means a service is missing from the synced "
                    + "catalog rather than that the duties need no access. Check the Catalog "
                    + "tab before treating this plan as complete."
            });
        }

        return concerns;
    }

    /// <summary>Plain-text plan for the console, an email, or the audit record.</summary>
    public static string Describe(Portfolio portfolio)
    {
        var lines = new List<string> { portfolio.Summary, "" };

        foreach (var grant in portfolio.Grants)
        {
            lines.Add(grant.Headline);
            foreach (var duty in grant.Duties) lines.Add("    duty: " + duty);
            lines.Add("    " + grant.Actions.Count + " permission(s), risk score " +
                      grant.RiskScore);
            lines.Add("    " + grant.Rationale);
            lines.Add("");
        }

        if (portfolio.Unresolved.Count > 0)
        {
            lines.Add("NO PERMISSION FOUND:");
            foreach (var duty in portfolio.Unresolved) lines.Add("    " + duty);
            lines.Add("");
        }

        if (portfolio.Concerns.Count > 0)
        {
            lines.Add("CONCERNS ABOUT THE PLAN AS A WHOLE:");
            foreach (var concern in portfolio.Concerns)
            {
                lines.Add("  " + (concern.Blocking ? "[BLOCKING] " : "") + concern.Title);
                lines.Add("    " + concern.Detail);
            }
        }

        return string.Join(Environment.NewLine, lines);
    }
}
