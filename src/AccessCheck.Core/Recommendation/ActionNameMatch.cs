namespace AccessCheck.Core.Recommendation;

/// <summary>
/// Joins an action name in the CATALOG to the same action in Microsoft's REFERENCE, when
/// the two sources spell it differently.
///
/// WHY THIS EXISTS. Both of these are the same Intune permission:
///
///   catalog     Microsoft.Intune_DeviceCompliancePolices_Read      (Microsoft's misspelling)
///   reference   Microsoft.Intune_Devicecompliancepolicies_Read     (spelled correctly)
///
/// One letter apart, so an exact — even case-insensitive — join fails and the permission
/// arrives at the model with no description at all. That is not cosmetic: description-less
/// candidates are what made the model pattern-match on names, which is the root cause behind
/// every wrong recommendation this app has produced.
///
/// The fallback is deliberately narrow, because a WRONG description is far worse than a
/// missing one. A near match is accepted only when it is unique, same provider, same trailing
/// operation, long enough not to collide, and within two edits. Anything ambiguous is left
/// unmatched.
/// </summary>
public static class ActionNameMatch
{
    /// <summary>Two edits covers a dropped letter, a doubled letter, and a transposition.</summary>
    public const int MaxEdits = 2;

    /// <summary>Short names collide too easily to risk approximate matching.</summary>
    public const int MinLengthForFuzzy = 12;

    /// <summary>
    /// Case, spaces and punctuation removed. Handles the other half of the problem: the
    /// reference builds names from resourceOperations, where an action is literally called
    /// "View reports" — with a space the catalog's "ViewReports" does not have.
    /// </summary>
    public static string Canonical(string? action)
    {
        if (string.IsNullOrWhiteSpace(action)) return "";
        var chars = action.ToLowerInvariant()
            .Where(char.IsLetterOrDigit)
            .ToArray();
        return new string(chars);
    }

    /// <summary>The trailing operation — read, update, delete — used to constrain a near match.</summary>
    public static string Operation(string? action)
    {
        if (string.IsNullOrWhiteSpace(action)) return "";
        var parts = action.Split(new[] { '_', '/' }, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 0 ? "" : Canonical(parts[^1]);
    }

    /// <summary>
    /// The reference entry matching <paramref name="catalogAction"/>, or null.
    /// <paramref name="exact"/> is checked first; the approximate pass only runs when the
    /// canonical form is absent entirely.
    /// </summary>
    public static string? Resolve(
        string catalogAction,
        IReadOnlyDictionary<string, string> canonicalToReferenceName)
    {
        var key = Canonical(catalogAction);
        if (key.Length == 0) return null;

        if (canonicalToReferenceName.TryGetValue(key, out var exact)) return exact;
        if (key.Length < MinLengthForFuzzy) return null;

        var operation = Operation(catalogAction);
        string? best = null;
        var bestDistance = int.MaxValue;
        var ties = 0;

        foreach (var (candidateKey, candidateName) in canonicalToReferenceName)
        {
            if (Math.Abs(candidateKey.Length - key.Length) > MaxEdits) continue;

            // The OPERATION must agree exactly. Without this, "..._Read" could be matched to
            // "..._Update" on two edits, which would attach a write description to a read.
            if (operation.Length > 0 && Operation(candidateName) != operation) continue;

            var distance = BoundedDistance(key, candidateKey, MaxEdits);
            if (distance > MaxEdits) continue;

            if (distance < bestDistance)
            {
                bestDistance = distance;
                best = candidateName;
                ties = 1;
            }
            else if (distance == bestDistance) ties++;
        }

        // Ambiguity means we do not know, and guessing here reintroduces the exact failure
        // this whole guard layer exists to prevent.
        return ties == 1 ? best : null;
    }

    /// <summary>
    /// A reusable, cached resolver from a CATALOG action name to the matching REFERENCE
    /// name. Build it once per reference load.
    ///
    /// Every consumer of reference data needs this, not just the index build. Descriptions
    /// and Microsoft's privilege flags were both keyed by the reference spelling and looked
    /// up by the catalog spelling, so for Intune they never resolved — which silently
    /// disabled the description-based risk correction and left provenance reporting
    /// "in your tenant only" for permissions Microsoft documents in full.
    /// </summary>
    public sealed class NameResolver
    {
        private readonly HashSet<string> _names;
        private readonly Dictionary<string, string> _canonicalToName;

        public NameResolver(IEnumerable<string> referenceNames)
        {
            _names = new HashSet<string>(referenceNames, StringComparer.OrdinalIgnoreCase);
            _canonicalToName = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var name in _names)
            {
                var canonical = Canonical(name);
                if (canonical.Length > 0 && !_canonicalToName.ContainsKey(canonical))
                    _canonicalToName[canonical] = name;
            }
        }

        public int Count => _names.Count;

        /// <summary>Exact, then canonical, then a narrow near match. Null when unresolved.</summary>
        public string? Resolve(string? catalogAction)
        {
            if (string.IsNullOrWhiteSpace(catalogAction)) return null;
            var trimmed = catalogAction.Trim();
            if (_names.TryGetValue(trimmed, out var exact)) return exact;
            return ActionNameMatch.Resolve(trimmed, _canonicalToName);
        }
    }

    /// <summary>Levenshtein distance, abandoning early once it cannot come in under the bound.</summary>
    public static int BoundedDistance(string a, string b, int max)
    {
        if (a == b) return 0;
        if (Math.Abs(a.Length - b.Length) > max) return max + 1;
        if (a.Length == 0 || b.Length == 0) return Math.Max(a.Length, b.Length);

        var previous = new int[b.Length + 1];
        var current = new int[b.Length + 1];
        for (var j = 0; j <= b.Length; j++) previous[j] = j;

        for (var i = 1; i <= a.Length; i++)
        {
            current[0] = i;
            var rowBest = current[0];

            for (var j = 1; j <= b.Length; j++)
            {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                current[j] = Math.Min(
                    Math.Min(current[j - 1] + 1, previous[j] + 1),
                    previous[j - 1] + cost);
                if (current[j] < rowBest) rowBest = current[j];
            }

            if (rowBest > max) return max + 1;
            (previous, current) = (current, previous);
        }

        return previous[b.Length];
    }
}
