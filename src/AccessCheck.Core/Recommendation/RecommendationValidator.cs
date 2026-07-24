using AccessCheck.Core.Catalog;

namespace AccessCheck.Core.Recommendation;

/// <summary>
/// The deterministic authority. Takes the AI's untrusted suggestion and produces
/// the verdict that actually drives the approval screen:
///   1. rejects any action not present in the synced catalog,
///   2. finds every role whose action set covers the validated actions (set-cover),
///   3. ranks them by least excess privilege and computes the exact delta,
///   4. drafts a custom role when the best built-in overshoots beyond threshold.
/// </summary>
public sealed class RecommendationValidator
{
    /// <summary>
    /// Max number of excess actions tolerated before a custom role is recommended
    /// instead of the smallest covering built-in role.
    /// </summary>
    public int MaxAcceptableExcessActions { get; init; } = 5;

    /// <summary>
    /// Risk-weighted excess a built-in role may carry before a custom role is preferred.
    /// Read=1, Write=3, Escalation=6 — so this is roughly "five writes, or two escalations,
    /// or fifteen reads", which is a far better rule than five of anything.
    /// </summary>
    public int MaxAcceptableExcessRisk { get; init; } = 15;

    /// <summary>
    /// Provider-aware entry point. Actions are partitioned by the provider that owns
    /// them in the catalog (a single role can never span providers), and set-cover
    /// runs per provider. Unknown actions are rejected once, globally.
    /// </summary>
    public IReadOnlyList<ProviderOutcome> ValidateMulti(
        RoleCatalog catalog,
        AiSuggestion suggestion,
        string functionDescription)
    {
        // Global known/unknown split first
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unknown = new List<string>();
        var byProvider = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in suggestion.RequiredActions)
        {
            var action = raw.Trim();
            if (action.Length == 0 || !seen.Add(action)) continue;
            var provider = catalog.ProviderOf(action);
            if (provider is null) { unknown.Add(action); continue; }
            if (!byProvider.TryGetValue(provider, out var list))
                byProvider[provider] = list = new List<string>();
            list.Add(action);
        }

        var results = new List<ProviderOutcome>();
        bool first = true;
        foreach (var (provider, actions) in byProvider.OrderBy(kv => kv.Key))
        {
            var sub = new RoleCatalog();
            sub.ReplaceAll(catalog.RolesFor(provider), catalog.LastSyncedUtc ?? DateTimeOffset.UtcNow);
            var outcome = Validate(sub, new AiSuggestion
            {
                RequiredActions = actions,
                RecommendedRoleId = suggestion.RecommendedRoleId,
                Reasoning = suggestion.Reasoning
            }, functionDescription);

            // Custom-role capability differs per provider:
            // - Graph providers: draft as-is (exact action list -> POST roleDefinitions)
            // - Exchange/Purview: DERIVED model — needs a covering parent role; the draft
            //   becomes "copy parent, strip excess entries" so the result is exact anyway.
            // - anything else: no custom role possible.
            if (outcome.CustomRoleRecommended)
            {
                if (RbacProviders.DerivedRoleCapable.Contains(provider))
                {
                    var parent = outcome.BestFit;
                    outcome = parent is null
                        ? outcome with { CustomRoleRecommended = false, CustomRole = null }
                        : outcome with
                        {
                            CustomRole = outcome.CustomRole! with
                            {
                                ParentRoleName = parent.DisplayName,
                                EntriesToRemove = parent.ExcessActions
                            }
                        };
                }
                else if (!RbacProviders.CustomRoleCapable.Contains(provider))
                {
                    outcome = outcome with { CustomRoleRecommended = false, CustomRole = null };
                }
            }

            // attach globally-unknown actions to the first outcome only (report once)
            if (first && unknown.Count > 0)
                outcome = outcome with
                {
                    UnknownActionsRejected =
                        outcome.UnknownActionsRejected.Concat(unknown).ToList()
                };
            first = false;

            results.Add(new ProviderOutcome { Provider = provider, Outcome = outcome });
        }

        if (results.Count == 0 && unknown.Count > 0)
        {
            results.Add(new ProviderOutcome
            {
                Provider = RbacProviders.Directory,
                Outcome = new ValidationOutcome
                {
                    ValidActions = Array.Empty<string>(),
                    UnknownActionsRejected = unknown,
                    RankedFits = Array.Empty<RoleFit>(),
                    CustomRoleRecommended = false
                }
            });
        }
        return results;
    }

    /// <summary>
    /// Microsoft's authoritative permission list, when it has been synced. Permissions
    /// present here are REAL even if no role in this tenant grants them — which is exactly
    /// the case where a custom role is the only way to grant one.
    /// </summary>
    public IReadOnlySet<string>? ReferenceActions { get; set; }

    /// <summary>
    /// Actions this tenant has already refused to put in a custom role. Learned from real
    /// refusals, because nothing in the reference marks which actions are eligible.
    /// </summary>
    public CustomRoleEligibility? Ineligibility { get; set; }

    public ValidationOutcome Validate(
        RoleCatalog catalog,
        AiSuggestion suggestion,
        string functionDescription)
    {
        var valid = new List<string>();
        var unknown = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var referenceOnly = new List<string>();
        var provenance = new Dictionary<string, ActionProvenance>(StringComparer.OrdinalIgnoreCase);
        var resolver = new PermissionResolver(ReferenceActions, catalog);

        foreach (var raw in suggestion.RequiredActions)
        {
            var action = raw.Trim();
            if (action.Length == 0 || !seen.Add(action)) continue;

            // Documentation says whether it is REAL; the tenant says whether it is
            // AVAILABLE HERE. Both are recorded, because they answer different questions
            // and the operator needs to know which one is missing.
            var where = resolver.Resolve(action);
            provenance[action] = where;

            if (where == ActionProvenance.TenantVerified || where == ActionProvenance.TenantOnly)
            {
                valid.Add(action);
                continue;
            }

            // NOT in the catalog is not the same as NOT REAL. The catalog is DERIVED from
            // the roles this tenant defines, so a permission Microsoft supports that no
            // role happens to bundle is invisible to it — and rejecting those was wrong.
            // Microsoft's own reference is authoritative: if it is in there, it exists and
            // a custom role can be built from it.
            if (where == ActionProvenance.DocumentedOnly)
            {
                // Real, but nothing here grants it. Valid — a custom role is the route —
                // and flagged so the operator knows the tenant has not confirmed it.
                valid.Add(action);
                referenceOnly.Add(action);
                continue;
            }

            unknown.Add(action);
        }

        var fits = RankFits(catalog, valid);

        // Never DRAFT a custom role for a service that cannot create one. Purview has no
        // New-ManagementRole, so proposing a derivation there is proposing something that
        // fails at execution — the plan must be role-group composition instead.
        var providerForRoles = catalog.ProviderOf(valid.FirstOrDefault() ?? "")
                               ?? RbacProviders.Directory;
        // Graph providers create roles through role definitions; PowerShell providers need
        // New-ManagementRole, which only Exchange has. Reusing the Graph set here would
        // have read Exchange as unable to create custom roles — exactly backwards.
        var serviceCanCreateCustomRoles =
            !RbacProviders.DerivedRoleCapable.Contains(providerForRoles)
            || RbacProviders.DerivationCapable.Contains(providerForRoles);

        // Some directory actions are real, documented, granted by built-in roles, and STILL
        // refused by custom role creation. Once the tenant has said so, never propose it
        // again — a built-in role is the only route for those.
        // THREE STATES, not two. "Not on the refused list" is not proof of eligibility —
        // only a prior tenant acceptance is. Recommending a custom role on Unknown is how
        // a grant reaches approval and then fails at Microsoft, leaving a real role behind.
        var blockedByEligibility = Ineligibility is null
            ? new List<string>()
            : valid.Where(a => Ineligibility.Eligibility(a) != CustomRoleEligibility.Status.Supported)
                   .ToList();
        var hasIneligible = blockedByEligibility.Count > 0;

        // DECIDE ON RISK, NOT RAW COUNT. Ranking already scores risk-weighted excess and
        // the threshold then threw it away: five extra DELETE actions passed while six
        // harmless reads triggered a custom role. Count is kept as a secondary bound so a
        // very wide but low-risk role still gets questioned.
        var best = fits.FirstOrDefault();
        var excessTooRisky = best is not null &&
            (best.ExcessRiskScore > MaxAcceptableExcessRisk
             || best.ExcessActions.Any(ActionRisk.IsCriticalExcess)
             || best.ExcessCount > MaxAcceptableExcessActions * 4);

        // CONFIDENCE IS AN ENFORCEMENT BOUNDARY, not a label. A low-confidence suggestion
        // can still contain real permission strings and pass every existence check — so it
        // must not silently become a NEW PRIVILEGED ROLE. A built-in role is reviewable;
        // a freshly minted custom role from an uncertain reading is not.
        var confidentEnough = suggestion.Confidence == SuggestionConfidence.High;

        bool customNeeded = valid.Count > 0 && serviceCanCreateCustomRoles && !hasIneligible &&
            confidentEnough && (best is null || excessTooRisky);

        CustomRoleDraft? draft = customNeeded
            ? new CustomRoleDraft
            {
                DisplayName = BuildCustomRoleName(
                    functionDescription,
                    catalog.ProviderOf(valid.FirstOrDefault() ?? "") ?? RbacProviders.Directory,
                    valid),
                Description =
                    "AccessCheck least-privilege role. Function: " + Truncate(functionDescription, 240) +
                    ". Grants exactly " + valid.Count + " action(s).",
                AllowedResourceActions = valid
            }
            : null;

        // Exchange and Purview custom roles are DERIVED from a parent, so a requirement
        // spanning two roles cannot be met by one. Compose the minimal set instead — with
        // no plan, a search-and-purge request finds no covering role and yields nothing.
        var provider = catalog.ProviderOf(valid.FirstOrDefault() ?? "") ?? RbacProviders.Directory;
        RoleGroupPlan? groupPlan = null;
        if (valid.Count > 0 && RbacProviders.DerivedRoleCapable.Contains(provider))
        {
            groupPlan = RoleGroupPlan.Build(
                catalog, provider, valid,
                "ACG - " + Truncate(BuildCustomRoleName(functionDescription, provider, valid)
                    .Replace("AC - ", ""), 80));
        }

        return new ValidationOutcome
        {
            RoleGroupPlan = groupPlan,
            SuggestionConfidence = suggestion.Confidence,
            CustomRoleBlockedActions = blockedByEligibility,
            CustomRoleRefusedActions = Ineligibility is null
                ? Array.Empty<string>()
                : valid.Where(a => Ineligibility.IsIneligible(a)).ToList(),
            TaskCoverage = TaskCoverage.EvaluateAll(
                functionDescription,
                valid.Select(a => (a, DescriptionFor(catalog, a)))).ToList(),
            ReferenceOnlyActions = referenceOnly,
            Provenance = provenance,
            ValidActions = valid,
            UnknownActionsRejected = unknown,
            RankedFits = fits,
            CustomRoleRecommended = customNeeded,
            CustomRole = draft
        };
    }

    /// <summary>
    /// Microsoft's description for an action, when the reference has been synced. Falls
    /// back to empty rather than a role description — a role's text describes the ROLE.
    /// </summary>
    private string DescriptionFor(RoleCatalog catalog, string action) =>
        ReferenceDescriptions is not null
        && ReferenceDescriptions.TryGetValue(action, out var d) ? d : "";

    /// <summary>Microsoft's descriptions, keyed by action. Supplied by the caller.</summary>
    public IReadOnlyDictionary<string, string>? ReferenceDescriptions { get; set; }

    private static List<RoleFit> RankFits(RoleCatalog catalog, IReadOnlyList<string> required)
    {
        var fits = new List<RoleFit>();
        if (required.Count == 0) return fits;

        foreach (var role in catalog.Roles)
        {
            // Skip AccessCheck's own learning record. It holds permissions the tenant has
            // proven, but it is not a role in the tenant and has no assignable id — offering
            // it produced "RECOMMENDED — custom role '(proven by successful grant)'", which
            // could never have been granted.
            if (RoleCatalog.IsSynthetic(role.Id)) continue;

            var granted = new HashSet<string>(role.AllowedResourceActions, StringComparer.OrdinalIgnoreCase);
            var missing = required.Where(a => !granted.Contains(a)).ToList();

            // A role covering NONE of what is needed is noise. A role covering SOME is a
            // real option when nothing covers everything — which is common once a request
            // spans two resources, and used to leave the card with no choices at all.
            if (missing.Count == required.Count) continue;

            var excess = role.AllowedResourceActions
                .Where(a => !required.Contains(a, StringComparer.OrdinalIgnoreCase))
                .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
                .ToList();

            fits.Add(new RoleFit
            {
                RoleId = role.Id,
                DisplayName = role.DisplayName,
                IsBuiltIn = role.IsBuiltIn,
                // Microsoft's ROLE-level flag: this role is an escalation path. Different
                // from excess risk — a role can carry little excess and still be one.
                IsPrivilegedRole = role.IsPrivilegedRole,
                ExcessActions = excess,
                MissingActions = missing
            });
        }

        // FULL covers always rank above partial ones, however much excess they carry —
        // a role that does the whole job is categorically better than one that does half.
        var full = fits.Where(f => !f.IsPartial).ToList();
        var partial = fits.Where(f => f.IsPartial).ToList();
        if (full.Count > 0) fits = full;
        else
        {
            fits = partial
                .OrderBy(f => f.MissingActions.Count)
                .ThenBy(f => f.ExcessRiskScore)
                .Take(6)
                .ToList();
        }

        // Rank by RISK-WEIGHTED excess, not raw count: a role granting 5 extra admin
        // actions is worse than one granting 6 extra read-only actions, even though the
        // raw count says otherwise.
        return fits
            .OrderBy(f => f.ExcessRiskScore)
            // A role Microsoft itself marks PRIVILEGED is an escalation path regardless of
            // how little excess it carries. Between two otherwise equal fits, take the one
            // that is not.
            .ThenBy(f => f.IsPrivilegedRole == true ? 1 : 0)
            .ThenBy(f => f.ExcessCount)
            .ThenByDescending(f => f.IsBuiltIn) // prefer built-in on ties: less churn to govern
            .ThenBy(f => f.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Names the role after WHAT IT GRANTS, not after the sentence someone typed.
    /// Truncating the request produced tenant objects called "AC - I need access to use",
    /// which is meaningless in an audit six months later.
    /// </summary>
    private static string BuildCustomRoleName(
        string functionDescription, string provider, IReadOnlyList<string> actions)
    {
        var subjects = new List<string>();
        foreach (var action in actions.Take(3))
        {
            var subject = ActionDisplay.Subject(action);
            if (subject.Length > 0 && !subjects.Contains(subject)) subjects.Add(subject);
        }

        // "read" vs "manage" is a WRITE question, not an escalation one. Microsoft does not
        // flag devices/delete as privileged — it cannot make you an admin — but naming that
        // role "read devices" is plainly wrong, and the name is what an auditor sees.
        var verb = actions.All(a => !ActionRisk.IsWrite(a)) ? "read" : "manage";
        var what = subjects.Count == 0
            ? actions.Count + " permission(s)"
            : string.Join(" + ", subjects);
        var service = RbacProviders.DisplayName(provider).Split(" (")[0];

        return Truncate($"AC - {service} {verb} {what}", 120);
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max];
}
