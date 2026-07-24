using AccessLens.Core.Catalog;
using AccessLens.Core.Recommendation;

namespace AccessLens.Cli;

/// <summary>
/// Offline stand-in for the GenAI endpoint so the full pipeline
/// (suggest -> validate -> approve -> plan) can be exercised with no network.
/// Naive keyword matching against catalog action strings — deliberately dumb,
/// because the validator is what makes the pipeline safe, not the suggester.
/// </summary>
public sealed class DemoProvider : IRecommendationProvider
{
    public Task<AiSuggestion> SuggestAsync(
        string functionDescription,
        IReadOnlyCollection<RoleDefinitionRecord> catalogRoles,
        CancellationToken ct = default)
    {
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
                        "'. Replace with the GenAI endpoint for real analysis."
        });
    }
}
