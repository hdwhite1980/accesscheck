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

    /// <summary>
    /// True when the token could only be a permission string — not merely something with a
    /// hyphen in it. Used to decide whether a token that FAILED to resolve is worth
    /// reporting as missing.
    /// </summary>
    private static bool IsUnambiguousPermissionShape(string token) =>
        (token.Contains('/') && token.Contains('.'))
        || token.StartsWith("Microsoft.Intune_", StringComparison.OrdinalIgnoreCase);

    public static Detection Detect(
        string functionDescription,
        Catalog.RoleCatalog catalog,
        IReadOnlySet<string>? referenceActions)
    {
        var resolved = new List<string>();
        var notFound = new List<string>();
        var suggestions = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);

        // A permission named in a PROHIBITION is not a request for it, and this detector
        // short-circuits the model entirely — a token picked up here reaches the proposal
        // without passing through the candidate list.
        var asked = RequestNegation.Positive(functionDescription);

        // Built ONCE. It canonicalises the whole reference — roughly 1,200 entries — so
        // constructing it per token would redo that work for every candidate string in the
        // request.
        var referenceNames = referenceActions is null
            ? null
            : new ActionNameMatch.NameResolver(referenceActions);

        foreach (var token in CandidateTokens(asked).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (catalog.ActionExists(token))
            {
                if (!resolved.Contains(token, StringComparer.OrdinalIgnoreCase)) resolved.Add(token);
                continue;
            }

            // Resolver, not exact match: the reference and the catalog spell the same Intune
            // permission differently ("Devicecompliancepolicies" against Microsoft's own
            // misspelled "DeviceCompliancePolices"), so an operator naming either form must
            // resolve to the other.
            var fromReference = referenceNames?.Resolve(token);
            if (fromReference is not null)
            {
                if (!resolved.Contains(fromReference, StringComparer.OrdinalIgnoreCase))
                    resolved.Add(fromReference);
                continue;
            }

            // UNRESOLVED CMDLET SHAPES ARE JUST ENGLISH. "factory-reset the laptop" and
            // "Read-only is fine" both parse as Verb-Noun, and reporting them as permissions
            // that do not exist abandoned the whole request with "No confident match" before
            // the model's correct answer was even looked at. Hyphens are everywhere in
            // prose: sign-in, read-only, e-mail, factory-reset.
            //
            // A slash-and-dot resource action or an Intune underscored name is distinctive
            // enough that naming one and getting it wrong is worth reporting. A bare
            // hyphenated word is not, so it is dropped silently and the request proceeds
            // normally.
            if (!IsUnambiguousPermissionShape(token)) continue;

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
