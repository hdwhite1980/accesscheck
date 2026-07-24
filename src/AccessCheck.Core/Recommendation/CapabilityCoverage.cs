namespace AccessCheck.Core.Recommendation;

/// <summary>
/// Does the proposal actually DO what the request asked?
///
/// Every other guard in this app looks for too MUCH — excess, scope creep, service-wide
/// grants. None of them notice when the answer does too LITTLE, and that failure is
/// silent: a request to "search all mailboxes and permanently delete it" came back with
/// ExecuteSearch and GetSearchResults, which search and view but cannot delete anything.
/// Zero excess, clean verdict, and the person still cannot do their job.
///
/// Under-granting is not a safety problem, so it is reported as a gap rather than a
/// danger — but it wastes a grant cycle and erodes trust in the verdict.
/// </summary>
public static class CapabilityCoverage
{
    /// <summary>A capability the request asked for, and the words that signal it.</summary>
    private static readonly (string Capability, string[] RequestWords, string[] ActionWords)[] Verbs =
    {
        ("delete or purge",
         new[] { "delete", "purge", "remove", "destroy", "erase", "wipe", "expunge" },
         new[] { "delete", "purge", "remove", "wipe", "destroy", "expunge", "alltasks", "manage" }),

        ("create",
         new[] { "create", "add", "provision", "new ", "set up", "onboard" },
         new[] { "create", "add", "new", "provision", "alltasks", "manage" }),

        ("update or change",
         new[] { "update", "change", "modify", "edit", "configure", "set ", "reset" },
         new[] { "update", "write", "set", "modify", "configure", "patch", "alltasks", "manage" }),

        ("export",
         new[] { "export", "download", "extract", "pst" },
         new[] { "export", "download", "alltasks", "manage" }),

        ("assign or grant",
         new[] { "assign", "grant", "give access", "add to group", "membership" },
         new[] { "assign", "grant", "membership", "alltasks", "manage" })
    };

    public sealed record Gap
    {
        public required string Capability { get; init; }
        public required string RequestPhrase { get; init; }
        public required string Message { get; init; }
    }

    /// <summary>
    /// Capabilities the request asked for that NOTHING in the proposal provides.
    /// Deliberately conservative: it only fires when the request clearly asked and the
    /// proposal clearly cannot, because a false "you are missing something" is worse than
    /// silence on a judgement call.
    /// </summary>
    public static IReadOnlyList<Gap> Gaps(
        string functionDescription, IReadOnlyCollection<string> validatedActions)
    {
        if (validatedActions.Count == 0) return Array.Empty<Gap>();

        var text = functionDescription.ToLowerInvariant();
        var actions = validatedActions.Select(a => a.ToLowerInvariant()).ToList();
        var gaps = new List<Gap>();

        foreach (var (capability, requestWords, actionWords) in Verbs)
        {
            var asked = requestWords.FirstOrDefault(w => text.Contains(w, StringComparison.Ordinal));
            if (asked is null) continue;

            var provided = actions.Any(a =>
                actionWords.Any(w => a.Contains(w, StringComparison.Ordinal)));
            if (provided) continue;

            gaps.Add(new Gap
            {
                Capability = capability,
                RequestPhrase = asked.Trim(),
                Message =
                    $"The request asks to {capability} (\"{asked.Trim()}\"), but NOTHING in the "
                    + "proposed permissions can do that. They may let the person find or view "
                    + "what they need, and then stop.\n\n"
                    + "This is UNDER-granting, not over-granting — it is safe, but the grant "
                    + "will not achieve the task. Check whether the capability needs a "
                    + "separate permission or a different role, and add it before approving."
            });
        }

        return gaps;
    }
}
