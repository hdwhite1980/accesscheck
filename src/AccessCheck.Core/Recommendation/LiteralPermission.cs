namespace AccessCheck.Core.Recommendation;

/// <summary>
/// When the request NAMES a permission, use that permission.
///
/// A request like "let someone manage microsoft.directory/users/authenticationMethods.password/delete"
/// contains no ambiguity to resolve — the operator has already said exactly what they
/// want. Sending it through the model anyway invites substitution: asked for
/// authenticationMethods.password/delete it returned agentUsers/delete, a different
/// resource, with a confident justification attached.
///
/// So: detect literal permission strings, resolve them against the catalog and Microsoft's
/// reference, and short-circuit. If a named permission does NOT exist, say so plainly
/// rather than letting a plausible substitute through — being told "that permission does
/// not exist" is useful; being handed a different one silently is not.
/// </summary>
public static class LiteralPermission
{
    public sealed record Detection
    {
        /// <summary>Named in the request AND real.</summary>
        public required IReadOnlyList<string> Resolved { get; init; }
        /// <summary>Looks like a permission, but exists in neither the catalog nor the reference.</summary>
        public required IReadOnlyList<string> NotFound { get; init; }
        /// <summary>Close matches for a NotFound token — usually a typo or a guess.</summary>
        public required IReadOnlyDictionary<string, IReadOnlyList<string>> Suggestions { get; init; }

        public bool HasAny => Resolved.Count > 0 || NotFound.Count > 0;
    }

    /// <summary>
    /// Tokens shaped like a permission: a dotted namespace with slashes
    /// (microsoft.directory/users/...), Intune's underscored form
    /// (Microsoft.Intune_ManagedApps_Read), or a Verb-Noun cmdlet.
    /// </summary>
    private static IEnumerable<string> CandidateTokens(string text)
    {
        foreach (var raw in text.Split(new[] { ' ', '\t', '\n', '\r', ',', ';', '"', '\'', '(', ')' },
                                       StringSplitOptions.RemoveEmptyEntries))
        {
            var token = raw.Trim().TrimEnd('.', ':');
            if (token.Length < 6) continue;

            var looksLikeResourceAction = token.Contains('/') && token.Contains('.');
            var looksLikeIntune = token.StartsWith("Microsoft.Intune_", StringComparison.OrdinalIgnoreCase);
            var looksLikeCmdlet = ActionDisplay.CmdletName(token) is not null;

            if (looksLikeResourceAction || looksLikeIntune || looksLikeCmdlet)
                yield return token;
        }
    }

    public static Detection Detect(
        string functionDescription,
        Catalog.RoleCatalog catalog,
        IReadOnlySet<string>? referenceActions)
    {
        var resolved = new List<string>();
        var notFound = new List<string>();
        var suggestions = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var token in CandidateTokens(functionDescription).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (catalog.ActionExists(token))
            {
                if (!resolved.Contains(token, StringComparer.OrdinalIgnoreCase)) resolved.Add(token);
                continue;
            }

            var fromReference = referenceActions?
                .FirstOrDefault(a => a.Equals(token, StringComparison.OrdinalIgnoreCase));
            if (fromReference is not null)
            {
                if (!resolved.Contains(fromReference, StringComparer.OrdinalIgnoreCase))
                    resolved.Add(fromReference);
                continue;
            }

            notFound.Add(token);
            suggestions[token] = NearMatches(token, catalog, referenceActions);
        }

        return new Detection
        {
            Resolved = resolved,
            NotFound = notFound,
            Suggestions = suggestions
        };
    }

    /// <summary>
    /// Permissions sharing the token's resource path. A named permission that does not
    /// exist is usually a near-miss — the right resource with the wrong verb, or a
    /// property that was renamed — so showing siblings is more useful than a bare "no".
    /// </summary>
    private static IReadOnlyList<string> NearMatches(
        string token, Catalog.RoleCatalog catalog, IReadOnlySet<string>? referenceActions)
    {
        var universe = catalog.AllActions.ToList();
        if (referenceActions is not null) universe.AddRange(referenceActions);

        var parts = token.Split('/');
        var prefix = parts.Length >= 2 ? parts[0] + "/" + parts[1] : token;

        var byPrefix = universe
            .Where(a => a.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToList();
        if (byPrefix.Count > 0) return byPrefix;

        // Nothing on that resource: fall back to the namespace so there is still a lead.
        var ns = parts.Length >= 1 ? parts[0] : token;
        return universe
            .Where(a => a.StartsWith(ns, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToList();
    }
}
