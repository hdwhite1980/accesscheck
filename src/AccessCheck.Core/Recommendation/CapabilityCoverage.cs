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

        // "new" is NOT a request word. It is an adjective at least as often as a verb, and
        // in access requests it is almost always attached to a person: "new starters",
        // "new hires", "new joiners". A password-reset request opening "New starters on the
        // service desk need to..." was reported as asking to CREATE something. A genuine
        // creation request says create, add, provision, onboard, set up or spin up — and
        // "new" then rides along with one of those anyway.
        ("create",
         new[] { "create", "add", "provision", "onboard", "set up", "spin up", "stand up" },
         // "update" IS a create shape when the thing being created is a member of a
         // collection. Adding a client secret is applications/credentials/UPDATE; adding a
         // member is members/update; adding an owner is owners/update. A request to "add a
         // client secret" answered correctly with credentials/update was reported as unable
         // to create anything — the same verb-shape assumption that made "reset" demand an
         // update action.
         new[] { "create", "add", "new", "provision", "update", "alltasks", "manage" }),

        ("update or change",
         new[] { "update", "change", "modify", "edit", "configure", "set " },
         new[] { "update", "write", "set", "modify", "configure", "patch", "alltasks", "manage" }),

        // VERBS WHOSE SHAPE DEPENDS ON THE OBJECT. This entry exists because the table
        // above assumes a request verb implies an action verb, and for these it does not.
        //
        // Resetting a PASSWORD is an update. Resetting MFA is DELETING the registered
        // methods so the user enrols again. Both are "reset". Listing reset under "update
        // or change" meant a correct answer — users/authenticationMethods/delete — was
        // reported as "NOTHING in the proposed permissions can do that", which is the
        // deterministic layer making exactly the mistake the prompt forbids the model.
        //
        // Revoke and disable have the same problem: sessions are revoked with
        // invalidateAllRefreshTokens, an account is disabled with users/disable, and
        // neither carries a delete or update marker.
        //
        // So these are satisfied by ANY state-changing action. The guard keeps its real
        // job — a read-only proposal for a write request still matches nothing here and
        // still fires — without asserting a shape it cannot know.
        ("reset, revoke or disable",
         new[] { "reset", "revoke", "disable", "suspend", "block", "deactivate" },
         new[] { "update", "write", "set", "modify", "configure", "patch",
                 "delete", "remove", "purge", "wipe", "destroy", "expunge",
                 "revoke", "invalidate", "disable", "block", "suspend", "retire",
                 "create", "add", "new", "provision", "alltasks", "manage" }),

        ("export",
         new[] { "export", "download", "extract", "pst" },
         new[] { "export", "download", "alltasks", "manage" }),

        // MEMBER IS THE WORD THE PERMISSIONS ACTUALLY USE. Nothing in Microsoft's
        // vocabulary for managing membership says "assign" or "grant" — it says
        // Add-DistributionGroupMember, Add-RoleGroupMember, groups/members/update, and the
        // descriptions say "add a single recipient to distribution groups". So a request to
        // manage membership, answered with precisely the three cmdlets that manage it, was
        // reported as unable to do it.
        //
        // This only became a confident finding once the cmdlet descriptions were imported:
        // before, the same mismatch surfaced as an UNCONFIRMED note, which was wrong but
        // said so. A guard that is certain and wrong is worse than one that is uncertain
        // and wrong, because the uncertain one invites the check that would correct it.
        ("assign or grant",
         new[] { "assign", "grant", "give access", "add to group", "membership" },
         new[] { "assign", "grant", "membership", "member", "members",
                 "alltasks", "manage" })
    };

    /// <summary>
    /// Whole-word (plus ordinary inflections) match against the request text.
    ///
    /// A plain Contains was matching "set " INSIDE "re-set", so "reset MFA methods" was read
    /// as an update request and a correct delete-shaped answer was reported as doing
    /// nothing. The same flaw has "add" matching "address". Request words are words, so
    /// they have to be matched as words.
    ///
    /// Inflections are allowed because these are English sentences, not identifiers:
    /// "disabling", "revoked", "resetting" all mean the verb was asked for.
    /// </summary>
    internal static bool WordAppears(string paddedLowerText, string word)
    {
        var w = word.Trim();
        if (w.Length == 0) return false;

        if (Matches(paddedLowerText, w, EndingsFor(w))) return true;
        // (the 'e'-dropping variant is handled below)

        // Verbs ending in 'e' drop it before -ing/-ed: revoke -> revoking, disable -> disabling.
        if (w.EndsWith('e') && w.Length > 2)
        {
            var stem = w[..^1];
            if (Matches(paddedLowerText, stem, new[] { "ing", "ed", "es" })) return true;
        }

        return false;
    }

    private static string[] EndingsFor(string w)
    {
        var endings = new List<string> { "", "s", "es", "ed", "d", "ing" };

        // Consonant-final verbs double it: reset -> resetting/resetted, block -> blocking.
        var last = w[^1];
        if (char.IsLetter(last) && !"aeiou".Contains(last))
        {
            endings.Add(last + "ing");
            endings.Add(last + "ed");
        }
        return endings.ToArray();
    }

    /// <summary>
    /// Words that turn the verb after them into a DESCRIPTION of existing state rather than
    /// a request. "every Conditional Access policy we have configured" is not asking anyone
    /// to configure anything — but "configured" matched, the request read as an update, and
    /// two correct read-only permissions were excluded as unable to perform it. A read-only
    /// engagement, refused for not being able to write.
    /// </summary>
    private static readonly string[] Auxiliaries =
    {
        "have", "has", "had", "was", "were", "been", "being", "is", "are",
        "already", "previously", "currently", "existing"
    };

    private static bool Matches(string padded, string stem, string[] endings)
    {
        var needle = " " + stem;
        var i = 0;
        while ((i = padded.IndexOf(needle, i, StringComparison.Ordinal)) >= 0)
        {
            var after = i + needle.Length;
            var rest = padded[after..];
            foreach (var e in endings)
            {
                if (!rest.StartsWith(e, StringComparison.Ordinal)) continue;
                if (rest.Length != e.Length && char.IsLetter(rest[e.Length])) continue;
                if (PrecededByAuxiliary(padded, i)) break;   // descriptive, not requested
                return true;
            }
            i = after;
        }
        return false;
    }

    private static bool PrecededByAuxiliary(string padded, int spaceIndex)
    {
        if (spaceIndex <= 0) return false;
        var before = padded[..spaceIndex].TrimEnd();
        var start = before.LastIndexOf(' ');
        var previous = start < 0 ? before : before[(start + 1)..];
        return Auxiliaries.Contains(previous, StringComparer.Ordinal);
    }

    public sealed record Gap
    {
        public required string Capability { get; init; }
        public required string RequestPhrase { get; init; }
        public required string Message { get; init; }

        /// <summary>
        /// True when the verdict was reached from action NAMES alone, because no
        /// description was available for anything in the proposal. The finding is a
        /// suspicion, not a conclusion, and is worded as one.
        /// </summary>
        public bool NamesOnly { get; init; }
    }

    /// <summary>
    /// Capabilities the request asked for that NOTHING in the proposal provides.
    /// Deliberately conservative: it only fires when the request clearly asked and the
    /// proposal clearly cannot, because a false "you are missing something" is worse than
    /// silence on a judgement call.
    /// </summary>
    public static IReadOnlyList<Gap> Gaps(
        string functionDescription, IReadOnlyCollection<string> validatedActions) =>
        Gaps(functionDescription, validatedActions.Select(a => (a, "")).ToList());

    /// <summary>
    /// MATCHES THE DESCRIPTION AS WELL AS THE NAME.
    ///
    /// Names are not meanings, and this guard was reading only names. A correct answer to a
    /// read-and-export request — Intune's ViewReports permission, whose description covers
    /// viewing, generating AND exporting reports — was reported as unable to export, purely
    /// because the word "export" is absent from the action string. Every capability listed
    /// above is something a permission DOES, so the description is the better evidence and
    /// the name is the fallback.
    ///
    /// Descriptions are negation-filtered too: "Read policies. Does not allow deleting."
    /// must not satisfy a delete capability.
    /// </summary>
    public static IReadOnlyList<Gap> Gaps(
        string functionDescription,
        IReadOnlyCollection<(string Action, string Description)> validatedActions)
    {
        if (validatedActions.Count == 0) return Array.Empty<Gap>();

        // A capability the request FORBIDS is not a capability it asked for.
        var text = RequestNegation.Positive(functionDescription).ToLowerInvariant();
        var actions = validatedActions
            .Select(a => (a.Action + " " + RequestNegation.Positive(a.Description))
                         .ToLowerInvariant())
            .ToList();
        // CAN THIS GUARD SEE MEANINGS AT ALL? With no descriptions it is matching capability
        // words against action NAMES, which is exactly the reasoning this app tells the model
        // not to do. Intune's ViewReports permission covers exporting and says so in its
        // description; its name does not. Asserting "NOTHING can do that" from the name is a
        // claim the evidence does not support, so when nothing is described the finding is
        // reported as unconfirmed rather than as a fact.
        var anyDescribed = validatedActions.Any(a => !string.IsNullOrWhiteSpace(a.Description));

        var gaps = new List<Gap>();

        var padded = " " + new string(text.Select(c => char.IsLetterOrDigit(c) ? c : ' ').ToArray()) + " ";

        foreach (var (capability, requestWords, actionWords) in Verbs)
        {
            var asked = requestWords.FirstOrDefault(w => WordAppears(padded, w));
            if (asked is null) continue;

            var provided = actions.Any(a =>
                actionWords.Any(w => a.Contains(w, StringComparison.Ordinal)));
            if (provided) continue;

            gaps.Add(new Gap
            {
                Capability = capability,
                RequestPhrase = asked.Trim(),
                NamesOnly = !anyDescribed,
                Message = anyDescribed
                    ? $"The request asks to {capability} (\"{asked.Trim()}\"), but NOTHING in the "
                      + "proposed permissions can do that. They may let the person find or view "
                      + "what they need, and then stop.\n\n"
                      + "This is UNDER-granting, not over-granting — it is safe, but the grant "
                      + "will not achieve the task. Check whether the capability needs a "
                      + "separate permission or a different role, and add it before approving."
                    : $"The request asks to {capability} (\"{asked.Trim()}\"), and NOTHING IN THE "
                      + "NAMES of the proposed permissions says they can. This could not be "
                      + "confirmed: Microsoft's descriptions for these permissions have not been "
                      + "synced, so there is nothing to check the names against.\n\n"
                      + "A permission often does more than its name suggests — a reports "
                      + "permission may well cover exporting them. Treat this as worth checking, "
                      + "not as a finding. Syncing the permission reference for this service "
                      + "would settle it."
            });
        }

        return gaps;
    }
}
