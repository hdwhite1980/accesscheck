namespace AccessCheck.Core.Recommendation;

/// <summary>
/// Removes the parts of a request that say what someone must NOT be able to do, before any
/// guard goes looking for verbs in it.
///
/// WHY THIS EXISTS. A read-only request was answered correctly with two Intune read
/// permissions, and then both were excluded as unable to perform a DELETE — because the
/// request ended:
///
///   "...they should not be able to change any policy, wipe anything, or touch a device."
///
/// "change" and "wipe" were matched as requested operations. The clause forbidding them was
/// read as requiring them. Every verb-matching guard shares this flaw, and the effect is
/// exactly inverted: the more carefully an operator writes down what the grant must NOT do,
/// the more the app demands it.
///
/// RequestConstraints already reads these clauses correctly — as limits — so the same text
/// was being interpreted two opposite ways on one screen.
///
/// Deliberately conservative: it drops from a negation marker to the end of that sentence
/// and no further, so "They must not delete anything. They do need to export reports."
/// keeps the export.
/// </summary>
public static class RequestNegation
{
    private static readonly string[] Markers =
    {
        "should not", "shouldn't", "should never",
        "must not", "mustn't", "may not",
        "cannot", "can not", "can't", "could not", "couldn't",
        "not be able", "unable to", "no ability", "without the ability",
        "do not", "don't", "does not", "doesn't", "did not",
        "never ", "no need to", "not allowed", "not permitted",
        "but not", "rather than", "instead of", "as opposed to"
    };

    /// <summary>
    /// End of the sentence containing <paramref name="from"/>, or the end of the text.
    ///
    /// A bare IndexOfAny on '.' was wrong, and permission strings are exactly where it
    /// showed: "They must not have microsoft.directory/users/delete" stopped cutting at the
    /// period inside "microsoft.directory", leaving ".directory/users/delete" behind for
    /// LiteralPermission to resolve and grant. A terminator only ends a sentence when
    /// whitespace or the end of the text follows it.
    /// </summary>
    private static int SentenceEndFrom(string text, int from)
    {
        for (var i = from; i < text.Length; i++)
        {
            var c = text[i];
            if (c != '.' && c != '!' && c != '?' && c != ';') continue;
            if (i + 1 >= text.Length) return i;
            if (char.IsWhiteSpace(text[i + 1])) return i;
        }
        return text.Length;
    }

    /// <summary>
    /// The request with negated clauses removed. Returns the original when nothing is
    /// negated, so the common case costs nothing.
    /// </summary>
    public static string Positive(string? functionDescription)
    {
        var text = functionDescription ?? "";
        if (text.Length == 0) return text;

        var lower = text.ToLowerInvariant();
        var cuts = new List<(int Start, int End)>();

        foreach (var marker in Markers)
        {
            var i = 0;
            while ((i = lower.IndexOf(marker, i, StringComparison.Ordinal)) >= 0)
            {
                // Stop at the end of the sentence containing the marker, not the end of the
                // text — a later sentence may state a genuine requirement.
                var end = SentenceEndFrom(text, i);
                cuts.Add((i, end));
                i += marker.Length;
            }
        }

        if (cuts.Count == 0) return text;

        // Merge overlaps so two markers in one clause do not produce tangled ranges.
        cuts.Sort((a, b) => a.Start.CompareTo(b.Start));
        var merged = new List<(int Start, int End)>();
        foreach (var cut in cuts)
        {
            if (merged.Count > 0 && cut.Start <= merged[^1].End)
            {
                if (cut.End > merged[^1].End) merged[^1] = (merged[^1].Start, cut.End);
            }
            else merged.Add(cut);
        }

        var sb = new System.Text.StringBuilder();
        var pos = 0;
        foreach (var (start, end) in merged)
        {
            if (start > pos) sb.Append(text, pos, start - pos);
            sb.Append(' ');   // keep word boundaries intact for whole-word matchers
            pos = end;
        }
        if (pos < text.Length) sb.Append(text, pos, text.Length - pos);

        var result = sb.ToString().Trim();

        // If negation swallowed everything, the caller is better off with the original than
        // with nothing — an empty request would make every guard silent.
        return result.Length == 0 ? text : result;
    }

    /// <summary>True when the request forbids something, i.e. a limit is being stated.</summary>
    public static bool ContainsProhibition(string? functionDescription)
    {
        var lower = (functionDescription ?? "").ToLowerInvariant();
        return Markers.Any(m => lower.Contains(m, StringComparison.Ordinal));
    }
}
