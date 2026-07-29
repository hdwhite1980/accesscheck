using AccessCheck.Core.Catalog;
using AccessCheck.Core.Recommendation;

namespace AccessCheck.Cli;

/// <summary>
/// Offline stand-in for the AI endpoint so the full pipeline
/// (suggest -> validate -> approve -> plan) can be exercised with no network.
/// Naive keyword matching against catalog action strings — deliberately dumb,
/// because the validator is what makes the pipeline safe, not the suggester.
/// </summary>
public sealed class DemoProvider : IRecommendationProvider
{
    public Task<AiSuggestion> SuggestAsync(
        string functionDescription,
        RoleCatalog catalog,
        IReadOnlyCollection<string>? forcedProviders = null,
        CancellationToken ct = default,
        ReferenceStore? reference = null)
    {
        var catalogRoles = catalog.Roles;
        var words = functionDescription
            .ToLowerInvariant()
            .Split(new[] { ' ', ',', '.', ';' }, StringSplitOptions.RemoveEmptyEntries)
            .Where(w => w.Length > 3)
            .ToHashSet();

        var matched = catalogRoles
            .SelectMany(r => r.AllowedResourceActions)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(action => words.Any(w =>
                action.Contains(w, StringComparison.OrdinalIgnoreCase)))
            .Take(6)
            .ToList();

        return Task.FromResult(new AiSuggestion
        {
            RequiredActions = matched,
            Reasoning = "DEMO provider: keyword match on '" + functionDescription +
                        "'. Replace with the AI endpoint for real analysis."
        });
    }
}
