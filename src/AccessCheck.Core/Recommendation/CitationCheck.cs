namespace AccessCheck.Core.Recommendation;

/// <summary>
/// Checks the description the model CLAIMED it relied on against the description Microsoft
/// actually publishes.
///
/// WHY THIS EXISTS. Every other guard checks the model's action STRINGS, which are cheap to
/// verify because they either exist in the catalog or they do not. Nothing checked its
/// REASONING. On a real run the model returned:
///
///   "'microsoft.directory/users/basic/update' allows updates to user information, which
///    typically includes resetting authentication methods"
///
/// The action was real, documented, present in the tenant, custom-role eligible, and a
/// write — it passed every check the app had. The justification was invented. Microsoft's
/// actual description is "Update basic properties on users", which says nothing about
/// authentication methods, and `basic` explicitly EXCLUDES the properties used for
/// multifactor authentication.
///
/// Requiring a verbatim quote turns that invented sentence into something comparable
/// against a synced authority. This does NOT check whether the permission was the right
/// CHOICE — ResourceFamily and TaskCoverage answer that. It checks only whether the model
/// told the truth about what Microsoft says.
/// </summary>
public static class CitationCheck
{
    public enum Status
    {
        /// <summary>The quote matches Microsoft's published description.</summary>
        Verified,
        /// <summary>The quote does not resemble Microsoft's description. Treated as invented.</summary>
        Fabricated,
        /// <summary>The model returned no citation for an action it nonetheless chose.</summary>
        Uncited,
        /// <summary>No synced description exists to compare against — not a failure.</summary>
        Uncheckable
    }

    public sealed record Result
    {
        public required string Action { get; init; }
        public required Status Status { get; init; }
        /// <summary>What the model said Microsoft says.</summary>
        public string Claimed { get; init; } = "";
        /// <summary>What Microsoft actually says, where the reference has been synced.</summary>
        public string Actual { get; init; } = "";
        public string Source { get; init; } = "";
        public required string Message { get; init; }
    }

    /// <summary>
    /// Below this share of Microsoft's own significant words, the quote is not a quote.
    ///
    /// Tuned against a real leak: quoting "Update basic properties on users" for
    /// users/authenticationMethods/basic/update scores 0.67 against that action's actual
    /// description, because the two differ by exactly the segment that matters. A citation
    /// is supposed to be verbatim, so the bar is set where a near-miss fails.
    /// </summary>
    public const double MinimumOverlap = 0.8;

    /// <summary>
    /// A substring of the truth is not a lie, but it has to be substantial enough to BE a
    /// quote — "for users" appears in half of Microsoft's descriptions and cites nothing.
    /// </summary>
    private const int MinimumQuotedTokens = 3;

    /// <summary>
    /// <paramref name="enforce"/> is false when the model returned no evidence at all — an
    /// endpoint that ignores the schema, or an older deployment. Rejecting every action in
    /// that case would break the app rather than protect it, so an absent evidence block is
    /// Uncheckable while a WRONG one inside a populated block is Fabricated.
    /// </summary>
    public static Result Evaluate(
        string action,
        ActionCitation? citation,
        string? referenceDescription,
        bool enforce)
    {
        if (!enforce)
            return new Result
            {
                Action = action,
                Status = Status.Uncheckable,
                Message = "This endpoint returned no citations, so nothing was verified."
            };

        // THE APP'S OWN PLACEHOLDER IS NOT A LIE. PromptBuilder.Describe emits
        // "[no Microsoft description; granted by X]" when the candidate list has no meaning
        // to offer. A model that quotes that back is reporting accurately that it was given
        // nothing — treating it as a fabrication punished the model for the app's gap and
        // excluded every correct permission on a real run.
        if (citation is not null
            && citation.Description.TrimStart().StartsWith("[no Microsoft description",
                                                           StringComparison.OrdinalIgnoreCase))
            return new Result
            {
                Action = action,
                Status = Status.Uncheckable,
                Claimed = citation.Description,
                Source = citation.Source,
                Message = "The candidate list gave the model no description for this "
                        + "permission, so it had nothing to quote. The gap is in the app's "
                        + "reference data, not in the model's answer."
            };

        if (citation is null || string.IsNullOrWhiteSpace(citation.Description))
            return new Result
            {
                Action = action,
                Status = Status.Uncited,
                Message = "The model chose this permission but quoted no description for it. "
                        + "An action it cannot cite a meaning for was not justified."
            };

        if (string.IsNullOrWhiteSpace(referenceDescription))
            return new Result
            {
                Action = action,
                Status = Status.Uncheckable,
                Claimed = citation.Description,
                Source = citation.Source,
                Message = "Microsoft's description for this permission has not been synced, "
                        + "so the quoted meaning could not be checked against it."
            };

        var matches = Resembles(citation.Description, referenceDescription!);

        return new Result
        {
            Action = action,
            Status = matches ? Status.Verified : Status.Fabricated,
            Claimed = citation.Description,
            Actual = referenceDescription!,
            Source = citation.Source,
            Message = matches
                ? "Quoted description matches Microsoft's."
                : "The description the model relied on is NOT what Microsoft publishes for "
                + "this permission. It was excluded rather than allowed to justify a grant."
        };
    }

    // ---- comparison ------------------------------------------------------------------

    private static readonly HashSet<string> Noise = new(StringComparer.OrdinalIgnoreCase)
    {
        "the", "and", "for", "that", "with", "from", "are", "all", "any", "its", "this",
        "which", "when", "who", "can", "not", "such", "also", "only", "including", "include",
        "these", "those", "their", "them", "has", "have", "was", "were", "been", "being"
    };

    /// <summary>
    /// Tolerant of whitespace, case, punctuation and a trailing plural, because the model is
    /// quoting rather than transcribing. Intolerant of a different sentence, which is the
    /// whole point.
    /// </summary>
    public static bool Resembles(string claimed, string actual)
    {
        var a = Normalize(claimed);
        var b = Normalize(actual);
        if (a.Length == 0 || b.Length == 0) return false;

        if (string.Equals(a, b, StringComparison.Ordinal)) return true;
        if (a.Contains(b, StringComparison.Ordinal)) return true;
        // A PARTIAL QUOTE IS STILL A QUOTE, and the app itself causes partial quotes:
        // PromptBuilder.Describe truncates to the FIRST SENTENCE and caps at 160 characters
        // before the model ever sees a description. So the model was shown "Initiates a
        // wipe of the device" and quoted it faithfully, while this check compared it against
        // Microsoft's full paragraph about factory resets and ChromeOS Powerwash — and
        // called an honest quote a fabrication. Requiring the substring to be most of the
        // full text got that exactly backwards.
        if (b.Contains(a, StringComparison.Ordinal)
            && Tokens(a).Count >= MinimumQuotedTokens) return true;

        var claimedTokens = Tokens(a);
        var actualTokens = Tokens(b);
        if (actualTokens.Count == 0) return false;

        // Very short descriptions cannot support a ratio, so require containment, which the
        // checks above already tested for.
        if (actualTokens.Count < 3) return false;

        var shared = actualTokens.Count(t => claimedTokens.Contains(t));
        return (double)shared / actualTokens.Count >= MinimumOverlap;
    }

    private static string Normalize(string s)
    {
        var chars = s.Trim().ToLowerInvariant()
            .Select(c => char.IsLetterOrDigit(c) ? c : ' ')
            .ToArray();
        return string.Join(" ", new string(chars)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries));
    }

    private static HashSet<string> Tokens(string normalized)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (var w in normalized.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (w.Length <= 2 || Noise.Contains(w)) continue;
            // Strip a trailing plural so "users" and "user" compare equal — the model is
            // quoting prose, not a schema.
            set.Add(w.Length > 3 && w.EndsWith('s') ? w[..^1] : w);
        }
        return set;
    }
}
