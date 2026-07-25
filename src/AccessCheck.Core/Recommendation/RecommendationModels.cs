using AccessCheck.Core.Catalog;
namespace AccessCheck.Core.Recommendation;

/// <summary>
/// What the AI provider returns. This is UNTRUSTED input until it passes
/// RecommendationValidator against the synced catalog.
/// </summary>
public sealed record AiSuggestion
{
    /// <summary>Resource actions the AI believes the function requires.</summary>
    public required IReadOnlyList<string> RequiredActions { get; init; }
    /// <summary>Role the AI proposes, if it thinks a built-in role fits. May be null or wrong.</summary>
    public string? RecommendedRoleId { get; init; }
    public string Reasoning { get; init; } = "";

    /// <summary>
    /// How much weight the verdict deserves. A tool that grants access must be able to say
    /// "I do not know" — a confident wrong answer gets acted on, which is worse than none.
    /// </summary>
    public SuggestionConfidence Confidence { get; init; } = SuggestionConfidence.High;
    /// <summary>Services the model said own this feature, for display and the audit record.</summary>
    public IReadOnlyList<string> IdentifiedServices { get; init; } = Array.Empty<string>();
    /// <summary>Set when nothing plausible was found, explaining what was searched.</summary>
    public string? NoMatchExplanation { get; init; }
    /// <summary>How many candidates were put in front of the model.</summary>
    public int CandidatesConsidered { get; init; }

    /// <summary>
    /// One citation per returned action. An action with no citation was not justified, and
    /// the validator may reject it on that basis alone.
    /// </summary>
    public IReadOnlyList<ActionCitation> Evidence { get; init; } = Array.Empty<ActionCitation>();

    /// <summary>
    /// The model's documented answer on whether these actions can go in a custom role.
    ///
    /// HONOURED ONLY WHEN IT SAYS NO. A restrictive claim is safe to act on: the worst case
    /// is a built-in role instead of a custom one, which over-grants but cannot fail. A
    /// permissive claim is not — treating "yes" as proof would let an unverified assertion
    /// mint a privileged role, which is exactly what three-state eligibility exists to stop.
    /// null when the model did not answer.
    /// </summary>
    public bool? CustomRoleEligible { get; init; }

    /// <summary>
    /// The built-in role the model found DOCUMENTED as least-privileged for this task.
    /// Microsoft documents tasks at the role level, not the permission level, so this is
    /// often the only place the human-readable answer exists.
    /// </summary>
    public string? DocumentedRole { get; init; }
}

/// <summary>
/// The description the model claims Microsoft gives for an action, and where it got it.
///
/// WHY THIS EXISTS. The model's action strings were already checkable — they either exist
/// in the catalog or they do not. Its REASONING was not: "users/basic/update allows updates
/// to user information, which typically includes resetting authentication methods" passed
/// every check the app had, because nothing checked a prose claim. Requiring the model to
/// quote the description it relied on, and name where that came from, turns the claim into
/// something the deterministic layer can compare against ReferenceStore.
/// </summary>
public sealed record ActionCitation
{
    public required string Action { get; init; }
    /// <summary>The description the model says it relied on, verbatim.</summary>
    public required string Description { get; init; }
    /// <summary>A documentation URL, or the literal "candidate list".</summary>
    public required string Source { get; init; }

    /// <summary>True when the model looked it up rather than reading the supplied list.</summary>
    public bool FromDocumentation =>
        Source.StartsWith("http", StringComparison.OrdinalIgnoreCase);
}

public enum SuggestionConfidence
{
    /// <summary>The owning service was identified and the permissions came from it.</summary>
    High,
    /// <summary>Permissions found, but the service was uncertain or they sit outside it.</summary>
    Low,
    /// <summary>Nothing plausible found. The app says so rather than inventing something.</summary>
    None
}

/// <summary>How well one catalog role covers the validated required actions.</summary>
public sealed record RoleFit
{
    public required string RoleId { get; init; }
    public required string DisplayName { get; init; }
    public bool IsBuiltIn { get; init; }
    /// <summary>
    /// Carried through from the catalog role: Microsoft flags this role as an escalation
    /// path. Ranking prefers a non-privileged role between two otherwise equal fits.
    /// null when the beta enrichment has not run — null is NOT "not privileged".
    /// </summary>
    public bool? IsPrivilegedRole { get; init; }
    /// <summary>Actions the role grants BEYOND what the function needs — the over-privilege delta.</summary>
    public required IReadOnlyList<string> ExcessActions { get; init; }
    public int ExcessCount => ExcessActions.Count;

    /// <summary>
    /// Required actions this role does NOT grant. Empty for a full fit.
    ///
    /// When no single role covers everything, offering the best PARTIAL covers beats
    /// offering nothing — the operator can take one and handle the remainder separately.
    /// Silence just left the card with no options at all.
    /// </summary>
    public IReadOnlyList<string> MissingActions { get; init; } = Array.Empty<string>();
    public bool IsPartial => MissingActions.Count > 0;
    /// <summary>Excess actions Microsoft flags as able to ESCALATE PRIVILEGE — not the same as "writes".</summary>
    public int ExcessPrivilegedCount => ActionRisk.CountPrivileged(ExcessActions);
    /// <summary>Risk-weighted excess: privileged actions cost far more than read-only ones.</summary>
    public int ExcessRiskScore => ActionRisk.Score(ExcessActions);
    /// <summary>Short label for the UI, separating writes from escalation-capable actions.</summary>
    /// <summary>Writes that cannot escalate — still real blast radius.</summary>
    public int ExcessWriteCount => ActionRisk.CountWrites(ExcessActions) - ExcessPrivilegedCount;

    public string ExcessLabel =>
        (IsPartial ? "covers part only, " : "") +
        "+" + ExcessCount + " excess" +
        (ExcessCount == 0
            ? ""
            : ", " + ExcessWriteCount + " write, " + ExcessPrivilegedCount + " escalation-capable");
}

/// <summary>
/// Draft custom role. For Graph providers this is the POST /roleDefinitions body.
/// For Exchange/Purview (derived model) ParentRoleName + EntriesToRemove drive
/// New-ManagementRole -Parent followed by Remove-ManagementRoleEntry per excess cmdlet.
/// </summary>
public sealed record CustomRoleDraft
{
    public required string DisplayName { get; init; }
    public required string Description { get; init; }
    public required IReadOnlyList<string> AllowedResourceActions { get; init; }
    /// <summary>Exchange/Purview only: the covering management role the custom role derives from.</summary>
    public string? ParentRoleName { get; init; }
    /// <summary>Exchange/Purview only: parent role entries (cmdlets) to strip after derivation.</summary>
    public IReadOnlyList<string>? EntriesToRemove { get; init; }
}

/// <summary>
/// Deterministic verdict shown on the approval screen. Everything here is
/// computed locally from the catalog — never taken from the AI on faith.
/// </summary>
public sealed record ValidationOutcome
{
    /// <summary>AI-suggested actions that exist in the tenant catalog.</summary>
    public required IReadOnlyList<string> ValidActions { get; init; }
    /// <summary>AI-suggested actions REJECTED because they do not exist in the catalog.</summary>
    public required IReadOnlyList<string> UnknownActionsRejected { get; init; }
    /// <summary>Catalog roles that fully cover ValidActions, ranked by least excess privilege.</summary>
    public required IReadOnlyList<RoleFit> RankedFits { get; init; }
    /// <summary>
    /// For Exchange-model services, the minimal SET of roles that together cover the
    /// requirement. A single derived role cannot span two parents — search-and-purge needs
    /// Compliance Search AND Search And Purge — so the least-privilege answer there is a
    /// role group carrying both, each derived down to only what is needed.
    /// </summary>
    public RoleGroupPlan? RoleGroupPlan { get; init; }
    /// <summary>
    /// Validated because MICROSOFT defines them, not because any role in this tenant
    /// grants them. No existing role can cover these, so a custom role is the only route —
    /// and the operator should know the difference.
    /// </summary>
    public IReadOnlyList<string> ReferenceOnlyActions { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Actions Microsoft refuses to put in a custom role, so a built-in role is the only
    /// route. Learned from a real refusal — nothing in the reference marks these.
    /// </summary>
    /// <summary>
    /// Actions blocking a custom-role recommendation — either REFUSED by Microsoft or of
    /// UNKNOWN eligibility. Unknown blocks too, because silence is not permission.
    /// </summary>
    /// <summary>
    /// The AI's confidence, carried INTO the deterministic outcome so approval logic can
    /// use it. Previously it was displayed and then discarded, so a low-confidence reading
    /// could still mint a privileged custom role.
    /// </summary>
    public SuggestionConfidence SuggestionConfidence { get; init; } = SuggestionConfidence.High;

    public IReadOnlyList<string> CustomRoleBlockedActions { get; init; } = Array.Empty<string>();

    /// <summary>The subset Microsoft has actually refused, as opposed to merely unproven.</summary>
    public IReadOnlyList<string> CustomRoleRefusedActions { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Required actions whose custom-role eligibility this tenant has not yet proven either
    /// way. These CAVEAT the custom role; they do not withhold it. Withholding on Unknown
    /// meant falling back to a built-in role carrying far more privilege than the uncertain
    /// custom role would have — the rule weighed uncertainty against nothing instead of
    /// against the alternative that actually gets granted.
    /// </summary>
    public IReadOnlyList<string> EligibilityUnproven { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Whether each permission actually performs the requested operation. Existence and
    /// task coverage are different questions and were being reported as one.
    /// </summary>
    public IReadOnlyList<TaskCoverage.Result> TaskCoverage { get; init; }
        = Array.Empty<TaskCoverage.Result>();

    /// <summary>
    /// Wrong-resource picks the app CORRECTED before role comparison: right operation, wrong
    /// object, and the catalog held the right one. Reported because a silent substitution is
    /// not reviewable — the operator must see that the requirement set was changed.
    /// </summary>
    public IReadOnlyList<ResourceFamily.Swap> ResourceSubstitutions { get; init; }
        = Array.Empty<ResourceFamily.Swap>();

    /// <summary>
    /// Wrong for the requested resource with NO replacement in the catalog, so dropped
    /// rather than allowed to shape the recommendation.
    /// </summary>
    public IReadOnlyList<string> WrongResourceRemoved { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Permissions excluded because the meaning the model quoted is NOT what Microsoft
    /// publishes — an invented justification for a real permission. The action existed and
    /// passed every string-level check; only the reasoning was false.
    /// </summary>
    public IReadOnlyList<CitationCheck.Result> FabricatedCitations { get; init; }
        = Array.Empty<CitationCheck.Result>();

    /// <summary>Permissions whose quoted meaning was confirmed against Microsoft's reference.</summary>
    public IReadOnlyList<CitationCheck.Result> VerifiedCitations { get; init; }
        = Array.Empty<CitationCheck.Result>();

    /// <summary>
    /// A built-in role Microsoft documents as least-privileged for this task, FOUND in this
    /// tenant's catalog. Null when none was named or none matched here.
    /// </summary>
    public string? DocumentedRoleName { get; init; }

    /// <summary>True when that role grants every validated action — checked, not trusted.</summary>
    public bool DocumentedRoleCovers { get; init; }

    /// <summary>
    /// True when the documented role was actually put top. False when it covers the task but
    /// a narrower role beat it on risk-weighted excess — documentation says which role is
    /// INTENDED for a job, not which is smallest, and the second question has a better
    /// answer already.
    /// </summary>
    public bool DocumentedRolePromoted { get; init; }

    /// <summary>
    /// The named role exists here but does NOT grant what the task needs, so the claim is
    /// wrong. Reported rather than silently dropped.
    /// </summary>
    public bool DocumentedRoleMismatch { get; init; }

    /// <summary>
    /// Per validated action, the best description available — Microsoft's where synced,
    /// otherwise the one the model quoted. Lets guards reason about what a permission DOES
    /// instead of what it is called.
    /// </summary>
    public IReadOnlyDictionary<string, string> ActionDescriptions { get; init; }
        = new Dictionary<string, string>();

    /// <summary>
    /// The suggester reported, from documentation, that a required action cannot go in a
    /// custom role — so a built-in role is the route and no custom role was drafted.
    /// </summary>
    public bool CustomRoleRuledOutByDocumentation { get; init; }

    /// <summary>
    /// Kept, but with no quoted meaning behind them — usually because AccessCheck itself
    /// added the permission (a ResourceFamily substitution) so the model never saw it.
    /// Worth showing; never grounds for exclusion.
    /// </summary>
    public IReadOnlyList<string> UncitedActions { get; init; } = Array.Empty<string>();

    /// <summary>Permissions that CANNOT do what was asked — a read action for a delete task.</summary>
    public IReadOnlyList<TaskCoverage.Result> Contradicted =>
        TaskCoverage.Where(t => t.Status == Recommendation.TaskCoverage.Status.Contradicted).ToList();

    /// <summary>
    /// Per action: does Microsoft document it, does this tenant grant it, or neither.
    /// Two different questions, and the operator needs to know WHICH one failed.
    /// </summary>
    public IReadOnlyDictionary<string, ActionProvenance> Provenance { get; init; }
        = new Dictionary<string, ActionProvenance>();
    /// <summary>True when the best fit overshoots beyond the configured threshold (or nothing covers).</summary>
    public bool CustomRoleRecommended { get; init; }
    public CustomRoleDraft? CustomRole { get; init; }
    public RoleFit? BestFit => RankedFits.Count > 0 ? RankedFits[0] : null;
}

/// <summary>One provider's validation result within a multi-service request.</summary>
public sealed record ProviderOutcome
{
    public required string Provider { get; init; }
    public required ValidationOutcome Outcome { get; init; }
}
