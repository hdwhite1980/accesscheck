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
        // RIGHT OPERATION, WRONG RESOURCE — CORRECTED HERE, BEFORE ANYTHING IS PARTITIONED.
        //
        // This ran only at render time, so a permission the app had already identified as
        // acting on the wrong resource still entered the requirement set, still drove role
        // selection, and still produced "covers part only" against a requirement nothing
        // could satisfy. Detecting it and then ranking against it anyway is not a guard.
        //
        // It must happen HERE rather than inside Validate(): Validate runs per provider, and
        // a resource family owned by one service reads as uncovered from inside another
        // service's slice — the Intune verdict would report that the wipe permission does
        // not revoke sessions, which is true and useless.
        var correction = ResourceFamily.Correct(
            functionDescription, suggestion.RequiredActions, catalog.AllActions);

        // Global known/unknown split first
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unknown = new List<string>();
        var byProvider = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in correction.Actions)
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
                Reasoning = suggestion.Reasoning,
                // Citations must survive the split, or the per-provider validator has
                // nothing to check the model's quoted meanings against.
                Evidence = suggestion.Evidence,
                DocumentedRole = suggestion.DocumentedRole,
                CustomRoleEligible = suggestion.CustomRoleEligible,
                Confidence = suggestion.Confidence
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
                    // THE PARENT MUST COVER THE TASK. Derivation copies a parent and strips
                    // entries OUT of it, so a parent missing an action can never produce a
                    // role that has it. RankFits returns PARTIAL covers as well as full ones
                    // — deliberately, since the best partial beats nothing — so BestFit is
                    // often a role that grants only some of what was asked.
                    //
                    // This used to be unreachable: Exchange cmdlets are never proven
                    // custom-role eligible, so Unknown eligibility blocked the whole branch.
                    // Removing that block (Unknown no longer withholds a custom role) made
                    // the path live, and it would have offered "derive from Mail Recipients"
                    // for a request Mail Recipients cannot satisfy.
                    var parent = outcome.BestFit;
                    outcome = parent is null || parent.IsPartial
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

            // Corrections are a property of the REQUEST, not of any one service, so they
            // ride on the first outcome and are shown once above the verdicts.
            if (first && correction.Changed)
                outcome = outcome with
                {
                    ResourceSubstitutions = correction.Substituted,
                    WrongResourceRemoved = correction.Removed
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
        var rejectedForCoverage = new List<TaskCoverage.Result>();
        var rejectedCitations = new List<CitationCheck.Result>();
        var verifiedCitations = new List<CitationCheck.Result>();
        var uncited = new List<string>();
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

            // TASK COVERAGE DECIDES ADMISSION, NOT JUST DISPLAY.
            // "A permission should not move to role comparison unless its documented
            // description supports the requested operation." Adding it to `valid` and then
            // flagging it meant it still drove role selection, still shaped the excess
            // calculation, and still appeared as a recommendation.
            // The whole proposed set, so a read can be recognised as a companion to a write
            // on the same resource rather than judged alone.
            var coverage = TaskCoverage.Evaluate(
                functionDescription, action, DescriptionFor(catalog, action),
                suggestion.RequiredActions);

            if (coverage.Status == TaskCoverage.Status.Contradicted)
            {
                rejectedForCoverage.Add(coverage);
                continue;
            }

            // DID THE MODEL TELL THE TRUTH ABOUT WHAT MICROSOFT SAYS?
            //
            // Every other guard checks the action STRING, which is cheap to verify. Nothing
            // checked the JUSTIFICATION, so "users/basic/update ... typically includes
            // resetting authentication methods" passed everything: real action, documented,
            // present, a write, custom-role eligible. Only the sentence was invented.
            // A permission whose cited meaning is not Microsoft's does not get to justify a
            // grant, so it is excluded here rather than displayed and believed.
            var citation = suggestion.Evidence
                .FirstOrDefault(c => string.Equals(c.Action, action, StringComparison.OrdinalIgnoreCase));
            var cited = CitationCheck.Evaluate(
                action, citation, DescriptionFor(catalog, action),
                enforce: suggestion.Evidence.Count > 0);

            // ONLY A FABRICATION IS DISQUALIFYING. An action can be uncited for reasons
            // that are nobody's fault: ResourceFamily SUBSTITUTES the correct permission,
            // and the model never saw it to cite it. Rejecting on Uncited meant this guard
            // deleted the corrections made by the guard before it, and a real run came back
            // with zero validated actions and "nothing actionable for this service".
            if (cited.Status == CitationCheck.Status.Fabricated)
            {
                rejectedCitations.Add(cited);
                continue;
            }
            if (cited.Status == CitationCheck.Status.Uncited) uncited.Add(action);
            if (cited.Status == CitationCheck.Status.Verified) verifiedCitations.Add(cited);

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

        // THE ROLE MICROSOFT DOCUMENTS FOR THIS TASK, verified against the catalog rather
        // than taken on trust. Excess arithmetic answers "which role grants least beyond
        // what is needed"; it cannot answer "which role is Microsoft's intended answer for
        // this job", because that judgement includes things the action list does not encode
        // — Authentication Administrator is documented as unable to act on administrators
        // or members of role-assignable groups, and no count of excess actions expresses
        // that. So when the suggester names a role, we CHECK it: does it exist here, and
        // does it grant everything required? Only then is it preferred.
        string? documentedRoleName = null;
        var documentedRoleCovers = false;
        var documentedRoleMismatch = false;
        var documentedRolePromoted = false;

        if (!string.IsNullOrWhiteSpace(suggestion.DocumentedRole))
        {
            var wanted = suggestion.DocumentedRole!.Trim();
            var match = catalog.Roles.FirstOrDefault(r =>
                !RoleCatalog.IsSynthetic(r.Id) &&
                string.Equals(r.DisplayName, wanted, StringComparison.OrdinalIgnoreCase));

            // Not found is NOT reported: Validate runs per provider, so a directory role
            // name is legitimately absent from the Intune slice. Silence beats a false
            // "that role does not exist".
            if (match is not null)
            {
                documentedRoleName = match.DisplayName;
                documentedRoleCovers = valid.Count > 0
                    && ActionCoverage.CoversAll(match.AllowedResourceActions, valid);

                // Named as the answer but does not grant what is needed — the claim is
                // wrong, and saying so is worth more than quietly ignoring it.
                //
                // NOT when nothing survived validation, though: with an empty required set
                // every role "fails to cover", and the card then blamed the model for a
                // cascade that started somewhere else entirely.
                // NOT WHEN NO SINGLE ROLE CAN COVER IT. For search-and-purge the answer is a
                // role GROUP carrying two roles, so 'Search And Purge' correctly grants only
                // half — and the card called the model's answer unreliable for naming one of
                // the two roles the plan itself then used. Where a RoleGroupPlan exists, a
                // partial single role is the expected shape, not a wrong claim.
                documentedRoleMismatch = valid.Count > 0 && !documentedRoleCovers;

                if (documentedRoleCovers)
                {
                    var idx = fits.FindIndex(fit =>
                        string.Equals(fit.RoleId, match.Id, StringComparison.OrdinalIgnoreCase));

                    // A TIE-BREAKER, NOT AN OVERRIDE.
                    //
                    // Promoting unconditionally put Authentication Administrator top for a
                    // password reset — 18 excess actions including users/delete and the whole
                    // authenticationMethods family — while Password Administrator sat below it
                    // carrying almost nothing. The documented role is evidence about INTENT,
                    // which excess arithmetic cannot supply; it is not evidence that the role
                    // is narrow, which excess arithmetic measures directly and better.
                    //
                    // So it wins ties and near-ties, and loses to a materially narrower role.
                    // Either way the operator is told which is which.
                    if (idx > 0
                        && fits[idx].ExcessRiskScore <= fits[0].ExcessRiskScore)
                    {
                        var promoted = fits[idx];
                        fits.RemoveAt(idx);
                        fits.Insert(0, promoted);
                        documentedRolePromoted = true;
                    }
                    else if (idx == 0)
                    {
                        documentedRolePromoted = true;
                    }
                }
            }
        }

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
        //
        // RULE CHANGE, 24 Jul, DELIBERATELY OVERRIDING root cause 4 of the original bug
        // report: a custom role is withheld for exactly two reasons — Microsoft has REFUSED
        // a required action, or a built-in role already covers the task with NO excess.
        // UNKNOWN NO LONGER BLOCKS. Blocking on Unknown weighed an uncertain custom role
        // against nothing, when the real alternative was a built-in role carrying 94 excess
        // actions, 58 of them escalation-capable. A refused creation leaves nothing behind
        // once GrantLedger reads it back; a built-in grant leaves every action it carries.
        var refusedByMicrosoft = Ineligibility is null
            ? new List<string>()
            : valid.Where(a => Ineligibility.Eligibility(a) == CustomRoleEligibility.Status.Unsupported)
                   .ToList();

        // CAVEATS the custom role rather than withholding it. The operator is told the
        // tenant has not yet proven these, and approving one proves it for next time.
        var eligibilityUnproven = Ineligibility is null
            ? new List<string>()
            : valid.Where(a => Ineligibility.Eligibility(a) == CustomRoleEligibility.Status.Unknown)
                   .ToList();

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
        // NOTE: confidence NO LONGER GATES the custom role. Under the rule above the only
        // grounds for withholding it are a refusal and a zero-excess built-in. Confidence
        // is still carried on the outcome so the card can caveat it, and approval remains
        // a human step. Restore `&& suggestion.Confidence == SuggestionConfidence.High`
        // here to put the old enforcement boundary back.
        var confidentEnough = suggestion.Confidence == SuggestionConfidence.High;
        _ = confidentEnough;

        // THE ONLY BUILT-IN ROLE THAT CANNOT BE IMPROVED ON is one that covers the whole
        // task and grants nothing beyond it. Any excess at all means an exact custom role
        // is strictly narrower, so it gets offered and the operator decides — the old
        // threshold silently accepted 94 excess actions because none tripped its limits.
        var builtInIsExact = best is not null && !best.IsPartial && best.ExcessCount == 0;

        // THE MODEL LOOKED IT UP AND SAID NO. Honour that, because it can only ever REDUCE
        // privilege: the fallback is a built-in role, which over-grants but works. A "yes"
        // is deliberately NOT honoured — an unverified assertion must not mint a privileged
        // role. On a real run the model reported "this action is not eligible for custom
        // roles", correctly, and the app proposed one anyway because nothing read the field.
        var modelSaysIneligible = suggestion.CustomRoleEligible == false;

        bool customNeeded = valid.Count > 0
                            && serviceCanCreateCustomRoles
                            && refusedByMicrosoft.Count == 0
                            && !modelSaysIneligible
                            && !builtInIsExact;

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

        // A PARTIAL SINGLE ROLE IS THE EXPECTED SHAPE WHEN A GROUP PLAN EXISTS. For
        // search-and-purge the answer is a role GROUP carrying two roles, so 'Search And
        // Purge' correctly grants only half — and the card called the model's answer
        // unreliable for naming one of the two roles the plan then used. Suppressed here
        // rather than at the check itself, because the plan is not built until now.
        if (groupPlan is not null) documentedRoleMismatch = false;

        return new ValidationOutcome
        {
            RoleGroupPlan = groupPlan,
            SuggestionConfidence = suggestion.Confidence,
            CustomRoleBlockedActions = refusedByMicrosoft,
            EligibilityUnproven = eligibilityUnproven,
            CustomRoleRefusedActions = Ineligibility is null
                ? Array.Empty<string>()
                : valid.Where(a => Ineligibility.IsIneligible(a)).ToList(),
            // Evaluated for what SURVIVED, plus the ones excluded for contradicting the
            // task — the operator needs to see what was dropped and why.
            TaskCoverage = TaskCoverage.EvaluateAll(
                functionDescription,
                valid.Select(a => (a, DescriptionFor(catalog, a))))
                .Concat(rejectedForCoverage).ToList(),
            FabricatedCitations = rejectedCitations,
            VerifiedCitations = verifiedCitations,
            UncitedActions = uncited,
            // Whatever meaning we have per action, so downstream guards can read MEANINGS
            // rather than names. Microsoft's reference first; the model's quoted description
            // only as a fallback, which is acceptable here because a description can only
            // ever SUPPRESS a warning — it authorises nothing.
            ActionDescriptions = valid.ToDictionary(
                a => a,
                a =>
                {
                    var fromReference = DescriptionFor(catalog, a);
                    if (!string.IsNullOrWhiteSpace(fromReference)) return fromReference;
                    var quoted = suggestion.Evidence.FirstOrDefault(c =>
                        string.Equals(c.Action, a, StringComparison.OrdinalIgnoreCase));
                    return quoted is null
                        || quoted.Description.TrimStart().StartsWith("[no Microsoft description",
                                                                     StringComparison.OrdinalIgnoreCase)
                        ? ""
                        : quoted.Description;
                },
                StringComparer.OrdinalIgnoreCase),
            CustomRoleRuledOutByDocumentation = modelSaysIneligible,
            DocumentedRoleName = documentedRoleName,
            DocumentedRoleCovers = documentedRoleCovers,
            DocumentedRoleMismatch = documentedRoleMismatch,
            DocumentedRolePromoted = documentedRolePromoted,
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
    /// <summary>
    /// Microsoft's description for a CATALOG action name. Resolved rather than looked up
    /// directly: the reference is keyed by Microsoft's resourceOperations spelling, and the
    /// catalog carries the role-definition spelling, which for Intune differ by a letter.
    /// An exact lookup returned nothing for a whole service.
    /// </summary>
    private string DescriptionFor(RoleCatalog catalog, string action)
    {
        if (ReferenceDescriptions is null) return "";
        _descriptionNames ??= new ActionNameMatch.NameResolver(ReferenceDescriptions.Keys);
        var key = _descriptionNames.Resolve(action);
        return key is not null && ReferenceDescriptions.TryGetValue(key, out var d) ? d : "";
    }

    private ActionNameMatch.NameResolver? _descriptionNames;

    /// <summary>Microsoft's descriptions, keyed by action. Supplied by the caller.</summary>
    public IReadOnlyDictionary<string, string>? ReferenceDescriptions { get; set; }

    /// <summary>
    /// Roles that exist in the catalog but are NEVER a grant.
    ///
    /// User, Guest User and Restricted Guest User are Entra's IMPLICIT roles — every
    /// principal already holds one, and the permissions they carry are scoped to SELF. They
    /// list microsoft.directory/users/authenticationMethods/basic/update because you may
    /// change your OWN authentication methods, not anyone else's.
    ///
    /// Left in the ranking they win constantly, because they carry almost no excess: on an
    /// MFA-reset request 'Restricted Guest User' was recommended over Authentication
    /// Administrator. Assigning it grants the recipient nothing they did not already have
    /// and lets them reset nobody. The deprecated partner and device-join roles are here for
    /// the same reason — Microsoft documents them as not for customer assignment.
    /// </summary>
    private static readonly HashSet<string> NeverGrantableRoles = new(StringComparer.OrdinalIgnoreCase)
    {
        "User", "Guest User", "Restricted Guest User",
        "Directory Synchronization Accounts",
        "Partner Tier1 Support", "Partner Tier2 Support",
        "Device Join", "Workplace Device Join"
    };

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

            // ROLLUP-AWARE. Global Reader's microsoft.directory/allEntities/standard/read
            // grants every read in the directory without literally containing any of them,
            // so literal containment reported a role that plainly covers a read-only request
            // as not covering it. ActionRisk prices rollups as categories, so a role covering
            // this way still ranks below an exact one.
            // Implicit and deprecated roles are not grants, however well they score.
            if (NeverGrantableRoles.Contains(role.DisplayName)) continue;

            var missing = required
                .Where(a => !ActionCoverage.CoveredBy(a, role.AllowedResourceActions))
                .ToList();

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
