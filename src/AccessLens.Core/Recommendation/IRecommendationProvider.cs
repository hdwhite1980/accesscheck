using AccessLens.Core.Catalog;

namespace AccessLens.Core.Recommendation;

/// <summary>
/// Inference abstraction. Implementations may call a remote GenAI endpoint.
/// DELIBERATE CONSTRAINT: the signature accepts ONLY the function description and
/// role catalog data — no principal, UPN, tenant ID, or assignment history can be
/// passed, so identity data provably never reaches the model.
/// </summary>
public interface IRecommendationProvider
{
    Task<AiSuggestion> SuggestAsync(
        string functionDescription,
        IReadOnlyCollection<RoleDefinitionRecord> catalogRoles,
        CancellationToken ct = default);
}
