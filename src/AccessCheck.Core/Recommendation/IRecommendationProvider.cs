using AccessCheck.Core.Catalog;

namespace AccessCheck.Core.Recommendation;

/// <summary>
/// Inference abstraction. Implementations may call a remote GenAI endpoint.
/// DELIBERATE CONSTRAINT: the signature accepts ONLY the function description and
/// role catalog data — no principal, UPN, tenant ID, or assignment history can be
/// passed, so identity data provably never reaches the model.
/// </summary>
public interface IRecommendationProvider
{
    /// <summary>
    /// Takes the whole catalog rather than a role list, because the recommendation now
    /// reasons over the PERMISSION vocabulary: a permission whose containing roles are
    /// named after something else is otherwise unreachable.
    /// `forcedProviders` lets the operator name the owning service directly, removing the
    /// one judgement the model gets wrong most often.
    /// </summary>
    Task<AiSuggestion> SuggestAsync(
        string functionDescription,
        RoleCatalog catalog,
        IReadOnlyCollection<string>? forcedProviders = null,
        CancellationToken ct = default,
        // Microsoft's descriptions and reference-only permissions; optional so callers that
        // have not synced the reference still work.
        ReferenceStore? reference = null);
}
