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
    /// Microsoft's ROLE-level privileged flag — the role contains at least one sensitive
    /// action, i.e. it is an escalation path. Null when the beta metadata has not been
    /// read. Distinct from excess risk: a role can carry almost no excess and still be one.
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
    /// Whether each permission actually performs the requested operation. Existence and
    /// task coverage are different questions and were being reported as one.
    /// </summary>
    public IReadOnlyList<TaskCoverage.Result> TaskCoverage { get; init; }
        = Array.Empty<TaskCoverage.Result>();

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
