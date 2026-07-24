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
    ///
    /// `reference` is MICROSOFT'S published permission reference, and passing it is what
    /// makes the candidate list correct: without it the vocabulary is built from tenant
    /// roles alone, which hides every permission no local role bundles — exactly the set a
    /// custom role exists to grant — and leaves each candidate with no documented meaning.
    /// It carries no tenant data, so the constraint above is untouched: it is a published
    /// catalogue of what permissions MEAN, not a record of who holds them.
    /// Null is legitimate and means the reference has not been synced yet.
    /// </summary>
    Task<AiSuggestion> SuggestAsync(
        string functionDescription,
        RoleCatalog catalog,
        IReadOnlyCollection<string>? forcedProviders = null,
        CancellationToken ct = default,
        ReferenceStore? reference = null);
}
