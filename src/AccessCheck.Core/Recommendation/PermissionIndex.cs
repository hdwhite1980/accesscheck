using AccessCheck.Core.Catalog;

namespace AccessCheck.Core.Recommendation;

/// <summary>One permission in the tenant, independent of any role that contains it.</summary>
public sealed record PermissionEntry
{
    public required string Action { get; init; }
    public required string Provider { get; init; }
    /// <summary>Display names of the roles that grant it.</summary>
    public required IReadOnlyList<string> GrantedByRoles { get; init; }

    /// <summary>
    /// What this permission DOES, in words. Without it the model is choosing between bare
    /// strings and pattern-matching on names: "ExecuteSearch" reads like it executes a
    /// compliance search, and it does not — it is Exchange mailbox search. Names are not
    /// meanings, and a list of names is not enough information to choose correctly.
    /// </summary>
    public string Description { get; init; } = "";

    /// <summary>
    /// Where the description came from. A role-derived description describes the ROLE, not
    /// this permission, and the model must be told which it is looking at.
    /// </summary>
    public string DescriptionSource { get; init; } = "granting role";

    /// <summary>Microsoft's stated privilege flag, when the reference supplies one.</summary>
    public bool? IsPrivilegedStated { get; init; }

    /// <summary>False for a permission Microsoft documents that no local role grants.</summary>
    public bool PresentInTenant { get; init; } = true;

    public bool IsPrivileged => ActionRisk.IsPrivileged(Action);
    public string RiskLabel => IsPrivileged ? "privileged" : "read";
    public int RoleCount => GrantedByRoles.Count;
}

/// <summary>
/// A flat, searchable view of every permission the tenant defines.
///
/// The role catalog answers "what does this role grant?". This answers the question a
/// least-privilege decision actually starts from: "what permissions exist for the thing
/// this person needs to do, and which is narrowest?" Without it, the only permissions
/// ever considered are those inside whichever roles happened to be shortlisted BY NAME —
/// which is how a request for Intune's GPO analyzer produced
/// microsoft.intune/allEntities/allTasks, the whole service.
/// </summary>
public sealed class PermissionIndex
{
    private readonly Dictionary<string, PermissionEntry> _byAction = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<PermissionEntry> Entries { get; private set; } = Array.Empty<PermissionEntry>();

    /// <summary>
    /// Builds the permission vocabulary from BOTH sources.
    ///
    /// Two corrections over the earlier role-only build:
    ///
    /// 1. A permission's DESCRIPTION now comes from Microsoft's reference, never from a
    ///    role that happens to contain it. A built-in role holds dozens of unrelated
    ///    actions and its description explains the ROLE's purpose — attaching it to every
    ///    action inside told the model that an unrelated permission performs the role's
    ///    primary function. Role membership is context ("granted by X"), not meaning.
    ///
    /// 2. The candidate set is the UNION of Microsoft's reference and the tenant's roles.
    ///    Building from roles alone hid every permission Microsoft supports that no local
    ///    role happens to bundle — which is exactly the set a custom role exists to grant.
    /// </summary>
    public static PermissionIndex Build(RoleCatalog catalog, ReferenceStore? reference)
    {
        var index = Build(catalog);
        if (reference is null || reference.Entries.Count == 0) return index;

        var byName = index.Entries.ToDictionary(e => e.Action, StringComparer.OrdinalIgnoreCase);
        var merged = new List<PermissionEntry>();

        // JOIN ON A CANONICAL FORM, NOT THE RAW STRING. The two sources disagree about
        // spelling and spacing for the same permission — the catalog carries Microsoft's
        // "DeviceCompliancePolices" misspelling while resourceOperations spells it
        // correctly, and resourceOperations names actions like "View reports" with a space.
        // Exact matching therefore left a whole service description-less, and a candidate
        // with no description is one the model can only guess about.
        var byCanonical = new Dictionary<string, string>(StringComparer.Ordinal);
        var referenceByName = new Dictionary<string, ReferenceStore.ReferenceEntry>(
            StringComparer.OrdinalIgnoreCase);

        foreach (var r in reference.Entries)
        {
            referenceByName[r.Name] = r;
            var canonical = ActionNameMatch.Canonical(r.Name);
            // First writer wins: a later duplicate canonical form is ambiguous, and Resolve
            // already refuses ambiguity rather than picking.
            if (canonical.Length > 0 && !byCanonical.ContainsKey(canonical))
                byCanonical[canonical] = r.Name;
        }

        foreach (var entry in index.Entries)
        {
            // MICROSOFT'S DESCRIPTION WINS. The role-derived one is a fallback only.
            var doc = reference.Entries.FirstOrDefault(r =>
                r.Name.Equals(entry.Action, StringComparison.OrdinalIgnoreCase));

            if (doc is null)
            {
                var resolved = ActionNameMatch.Resolve(entry.Action, byCanonical);
                if (resolved is not null) referenceByName.TryGetValue(resolved, out doc);
            }

            merged.Add(doc is null || string.IsNullOrWhiteSpace(doc.Description)
                ? entry with { DescriptionSource = "granting role (no Microsoft description)" }
                : entry with
                  {
                      Description = doc.Description,
                      DescriptionSource = "Microsoft reference",
                      IsPrivilegedStated = doc.IsPrivileged
                  });
        }

        // Reference-only permissions: real, documented, and absent from every local role.
        foreach (var doc in reference.Entries)
        {
            if (byName.ContainsKey(doc.Name)) continue;
            merged.Add(new PermissionEntry
            {
                Action = doc.Name,
                Provider = doc.Provider,
                Description = doc.Description,
                DescriptionSource = "Microsoft reference",
                IsPrivilegedStated = doc.IsPrivileged,
                GrantedByRoles = Array.Empty<string>(),
                PresentInTenant = false
            });
        }

        return new PermissionIndex
        {
            Entries = merged
                .OrderBy(e => e.Action, StringComparer.OrdinalIgnoreCase)
                .ToList()
        };
    }

    public static PermissionIndex Build(RoleCatalog catalog)
    {
        var rolesByAction = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var providerByAction = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var describedByAction = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var role in catalog.Roles)
        {
            foreach (var action in role.AllowedResourceActions)
            {
                if (!rolesByAction.TryGetValue(action, out var names))
                    rolesByAction[action] = names = new List<string>();
                if (!names.Contains(role.DisplayName)) names.Add(role.DisplayName);
                if (!providerByAction.ContainsKey(action)) providerByAction[action] = role.Provider;

                // The granting role's description is the best meaning available for a bare
                // cmdlet. For documented Purview roles it IS the capability summary.
                if (!describedByAction.ContainsKey(action) && role.Description.Length > 0)
                    describedByAction[action] = role.Description;
            }
        }

        var index = new PermissionIndex();
        index.Entries = rolesByAction
            .Select(kv => new PermissionEntry
            {
                Action = kv.Key,
                Provider = providerByAction.TryGetValue(kv.Key, out var p) ? p : RbacProviders.Directory,
                Description = describedByAction.TryGetValue(kv.Key, out var d) ? d : "",
                GrantedByRoles = kv.Value.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList()
            })
            .OrderBy(e => e.Provider, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Action, StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var entry in index.Entries) index._byAction[entry.Action] = entry;
        return index;
    }

    public PermissionEntry? Find(string action) =>
        _byAction.TryGetValue(action, out var entry) ? entry : null;

    public IReadOnlyList<string> Providers =>
        Entries.Select(e => e.Provider).Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();

    public IReadOnlyList<PermissionEntry> Search(string query, string? provider = null)
    {
        var q = query.Trim();
        return Entries.Where(entry =>
        {
            if (provider is not null &&
                !entry.Provider.Equals(provider, StringComparison.OrdinalIgnoreCase)) return false;
            if (q.Length == 0) return true;
            return entry.Action.Contains(q, StringComparison.OrdinalIgnoreCase)
                || RbacProviders.DisplayName(entry.Provider).Contains(q, StringComparison.OrdinalIgnoreCase)
                || entry.GrantedByRoles.Any(r => r.Contains(q, StringComparison.OrdinalIgnoreCase));
        }).ToList();
    }

    private static readonly HashSet<string> StopWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "need", "access", "user", "users", "the", "and", "for", "with", "that", "this",
        "have", "from", "into", "able", "would", "like", "want", "please", "help", "team"
    };

    /// <summary>
    /// Candidate permissions drawn from the WHOLE tenant vocabulary rather than from a
    /// handful of roles. Keyword-matched from the function text, and CAPPED PER PROVIDER
    /// so a verbose service cannot crowd out a terse one.
    /// </summary>
    /// <summary>
    /// Does the request ask for a state change? Deliberately generous on the verbs —
    /// missing one costs a wrongly-offered read permission, which is the failure this
    /// exists to prevent.
    /// </summary>
    public static bool RequestWantsStateChange(string functionDescription)
    {
        // NEGATED CLAUSES ARE NOT REQUIREMENTS. "they should not be able to change any
        // policy, wipe anything" made this return true for a read-only request, which then
        // stripped every read permission out of the candidate list.
        var text = RequestNegation.Positive(functionDescription).ToLowerInvariant();
        string[] verbs =
        {
            "create", "add", "provision", "onboard", "register", "new ",
            "update", "change", "modify", "edit", "configure", "set ",
            "reset", "rotate", "revoke", "disable", "enable", "assign", "approve",
            "delete", "remove", "purge", "wipe", "destroy", "erase", "retire",
            "execute", "run ", "start", "restore", "export", "block", "unblock"
        };
        return verbs.Any(v => text.Contains(v, StringComparison.Ordinal));
    }

    /// <summary>
    /// A read-only action, judged from its NAME — which is structured and reliable, unlike
    /// prose. Anything carrying a write verb is not read-only even if "read" appears
    /// somewhere in the path.
    /// </summary>
    public static bool IsReadOnlyAction(string action)
    {
        var a = (action ?? "").ToLowerInvariant();
        if (a.Length == 0) return false;

        string[] writeMarkers =
        {
            "create", "update", "delete", "write", "manage", "alltasks", "allproperties/allTasks",
            "remove", "reset", "/set", "add", "wipe", "revoke", "purge", "enable", "disable",
            "retire", "assign", "execute", "start", "invoke", "restore", "new-", "set-",
            "remove-", "add-", "import", "export"
        };
        if (writeMarkers.Any(m => a.Contains(m, StringComparison.Ordinal))) return false;

        string[] readMarkers = { "/read", "read", "getslist", "_read", "/view", "list" };
        return readMarkers.Any(m => a.Contains(m, StringComparison.Ordinal));
    }

    /// <summary>
    /// Whether a request word appears in an action name or its prose.
    ///
    /// A plain Contains is DIRECTIONAL, and the direction is wrong for English. A request
    /// says "mailboxes", "messages", "policies"; Microsoft names resources in the
    /// singular — Remove-Mailbox, conditionalAccessPolicies. "remove-mailbox" does not
    /// contain "mailboxes", so the single most relevant word in a mailbox request scored
    /// nothing at all against the mailbox permissions.
    ///
    /// Only regular plural endings are stripped, and only down to three characters, so
    /// this cannot turn a short word into a prefix that matches everything.
    /// </summary>
    /// <summary>
    /// True when the word IS one of the action's path segments, rather than merely
    /// appearing inside one.
    ///
    /// Resource names are segments — microsoft.directory/USERS/password/update,
    /// Microsoft.Intune_DEVICECOMPLIANCEPOLICES_Read — and a request naming a resource
    /// means that resource, not every longer name containing it. Without this, "users"
    /// matched agentUsers and guestUsers as strongly as users, and "groups" matched
    /// groups.security, groups.unified and accessReviews/definitions.groups alike.
    /// </summary>
    /// <summary>
    /// Whether the request is actually about agent or workload identities. Shared so the
    /// scoring filter and the needs stage cannot disagree about when the gate opens.
    /// </summary>
    public static bool RequestMentionsSpecialisedIdentity(string functionDescription)
    {
        var lower = functionDescription.ToLowerInvariant();
        return lower.Contains("agent", StringComparison.Ordinal)
            || lower.Contains("service principal", StringComparison.Ordinal)
            || lower.Contains("workload identit", StringComparison.Ordinal);
    }

    /// <summary>
    /// Identity types that are NOT ordinary user accounts, however similar their action
    /// names look. Kept deliberately short — this suppresses candidates, so anything listed
    /// here becomes unreachable for a request that does not name it.
    /// </summary>
    private static readonly string[] SpecialisedIdentitySegments =
    {
        "agentusers"
    };

    /// <summary>
    /// True when this action belongs to a specialised identity type rather than to ordinary
    /// user accounts. Public because CANDIDATE SCORING IS NOT THE ONLY DOOR — the
    /// open-ended needs stage looks permissions up by name against the whole index, so a
    /// filter applied only to scoring let the model name agentUsers/disable and have it
    /// seeded straight back in.
    /// </summary>
    public static bool IsSpecialisedIdentity(string action)
    {
        var segments = action.ToLowerInvariant()
            .Split(new[] { '/', '_', '.' }, StringSplitOptions.RemoveEmptyEntries);
        return segments.Any(seg => SpecialisedIdentitySegments.Contains(seg, StringComparer.Ordinal));
    }

    internal static bool SegmentMatches(string action, string word)
    {
        var segments = action.Split(new[] { '/', '_', '.', '-', ' ' },
            StringSplitOptions.RemoveEmptyEntries);

        foreach (var segment in segments)
        {
            if (segment.Equals(word, StringComparison.OrdinalIgnoreCase)) return true;

            // NUMBER HAS TO MATCH IN BOTH DIRECTIONS.
            //
            // Request plural against a singular segment — "mailboxes" reaching "mailbox" —
            // is the case I wrote first. The commoner one is the reverse: Microsoft names
            // resources in the PLURAL, and requests describe them in the singular. "create
            // user accounts" carries the word "user"; the segment is "users". Handling only
            // one direction left the most natural phrasing scoring nothing at all against
            // the resource it named.
            if (word.EndsWith("ies", StringComparison.Ordinal) && word.Length > 4
                && segment.Equals(word[..^3] + "y", StringComparison.OrdinalIgnoreCase)) return true;
            if (word.EndsWith("es", StringComparison.Ordinal) && word.Length > 4
                && segment.Equals(word[..^2], StringComparison.OrdinalIgnoreCase)) return true;
            if (word.EndsWith('s') && word.Length > 3
                && segment.Equals(word[..^1], StringComparison.OrdinalIgnoreCase)) return true;

            // Singular request word, plural segment.
            if (word.Length > 2)
            {
                if (segment.Equals(word + "s", StringComparison.OrdinalIgnoreCase)) return true;
                if (segment.Equals(word + "es", StringComparison.OrdinalIgnoreCase)) return true;
                if (word.EndsWith('y')
                    && segment.Equals(word[..^1] + "ies", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }

    internal static bool NameMatches(string haystack, string word)
    {
        if (haystack.Contains(word, StringComparison.Ordinal)) return true;

        // policies -> policy, and the -ies form is why this is not just trimming an s.
        if (word.EndsWith("ies", StringComparison.Ordinal) && word.Length > 4
            && haystack.Contains(word[..^3] + "y", StringComparison.Ordinal)) return true;

        if (word.EndsWith("es", StringComparison.Ordinal) && word.Length > 4
            && haystack.Contains(word[..^2], StringComparison.Ordinal)) return true;

        if (word.EndsWith('s') && word.Length > 3
            && haystack.Contains(word[..^1], StringComparison.Ordinal)) return true;

        // AND THE OTHER DIRECTION. The same asymmetry as SegmentMatches, and it bites
        // harder here because this is the fallback: a singular request word scored NOTHING
        // against a plural resource name. "review every Conditional Access policy" carries
        // "policy"; the action is conditionalAccessPolicies, a compound segment where the
        // segment rule correctly does not apply — so this substring path was the only one
        // left, and it was failing too.
        if (word.Length > 2)
        {
            if (haystack.Contains(word + "s", StringComparison.Ordinal)) return true;
            if (haystack.Contains(word + "es", StringComparison.Ordinal)) return true;
            if (word.EndsWith('y')
                && haystack.Contains(word[..^1] + "ies", StringComparison.Ordinal)) return true;
        }

        return false;
    }

    public static IReadOnlyList<PermissionEntry> CandidateActions(
        string functionDescription, RoleCatalog catalog, int perProviderLimit = 60,
        ReferenceStore? reference = null)
    {
        // Build with the reference when we have it, so candidates carry Microsoft's
        // descriptions and reference-only permissions are offered too.
        var index = Build(catalog, reference);
        // Keywords come from what the request ASKS FOR, never from what it forbids. A word
        // that appears only in a prohibition — "or manage anyone's licences" — was scoring
        // licence permissions to the top of the very list the model chooses from.
        var words = RequestNegation.Positive(functionDescription).ToLowerInvariant()
            .Split(new[] { ' ', '\t', '\n', '\r', ',', '.', ';', ':', '(', ')', '/', '\\', '-', '"', '\'' },
                   StringSplitOptions.RemoveEmptyEntries)
            .Where(w => w.Length > 2 && !StopWords.Contains(w))
            .ToList();

        // STEP 6 OF THE SEQUENCE: reject read-only permissions for write/delete/reset
        // tasks — and do it HERE, before the model sees the list, not after it chooses.
        //
        // Catching a read permission downstream and blocking approval still let it be
        // proposed, still let it reach role comparison, and still put it on screen. The
        // model cannot pick what it is not shown.
        var wantsChange = RequestWantsStateChange(functionDescription);

        // Whether the request is about agent identities at all. Checked once per request
        // rather than per candidate.
        var mentionsSpecialisedIdentity = RequestMentionsSpecialisedIdentity(functionDescription);

        var scored = new List<(PermissionEntry Entry, int Score)>();
        foreach (var entry in index.Entries)
        {
            // A read action cannot perform a write task. Excluded from the candidate set
            // entirely rather than offered and later rejected.
            if (wantsChange && IsReadOnlyAction(entry.Action)) continue;

            // SEARCH THE MEANING, NOT JUST THE NAME. Matching on the action string alone
            // required the request to use Microsoft's resource-action vocabulary — "reset
            // MFA methods" shares no words with authenticationMethods/standard/read. The
            // description is where the task's own language lives.
            var name = entry.Action.ToLowerInvariant();
            var haystack = (entry.Action + " " + entry.Description + " " +
                            string.Join(" ", entry.GrantedByRoles)).ToLowerInvariant();

            // A SPECIALISED OBJECT TYPE THE REQUEST DID NOT ASK FOR IS NOISE.
            //
            // agentUsers are identities for AI agents, not staff, and their action list
            // mirrors the real one almost exactly — create, delete, disable, manager/update,
            // photo/update. The model conflates them relentlessly: one duty to AMEND user
            // accounts came back proposing eight agentUsers permissions, all of which the
            // verifier then had to strip, and a duty to DISABLE user accounts was left with
            // nothing at all once its single agentUsers proposal was removed.
            //
            // Segment scoring does not solve this — users/* already outranks agentUsers/*,
            // and the model picked the latter regardless with both in front of it. So the
            // fix is to stop offering them unless the request is actually about agents.
            //
            // Gated on the request rather than removed outright: a genuine request to manage
            // agent identities must still be answerable.
            if (IsSpecialisedIdentity(entry.Action) && !mentionsSpecialisedIdentity) continue;

            var score = 0;
            foreach (var word in words)
            {
                // A WHOLE SEGMENT BEATS A SUBSTRING INSIDE ONE.
                //
                // "microsoft.directory/agentUsers/disable" contains "users", so a request
                // about user accounts scored agent-user permissions exactly as highly as
                // real ones — and agentUsers has more actions, so it crowded the candidate
                // list. Three duties in one run came back proposing agentUsers, and only
                // the verifier stopped them; two then had nothing left and produced no
                // answer at all. Agent users are a different object type entirely.
                if (SegmentMatches(name, word)) score += 5;
                else if (NameMatches(name, word)) score += 3;
                else if (NameMatches(haystack, word)) score += 2;
                else continue;

                // A read permission answering a read-shaped request is the better fit.
                if (!entry.IsPrivileged) score += 1;
            }
            if (score > 0) scored.Add((entry, score));
        }

        // TIES DECIDED BY NARROWNESS, NOT BY CATALOG ORDER.
        //
        // Sorting on score alone leaves ties in whatever order Build happened to produce,
        // and ties are the common case: one shared word scores 3, so dozens of Purview
        // cmdlets containing "compliance" score identically. Which of them survived the
        // per-provider cap was therefore decided by catalog order — the same request
        // returned different permissions on different runs, and New-ComplianceSearch lost
        // its place to cmdlets that merely shared a word.
        //
        // Breaking ties by breadth then by name length puts the specific permission ahead
        // of the sweeping one, and makes the same request produce the same candidates
        // every time. A recommendation that changes between identical runs cannot be
        // reviewed, and cannot be defended afterwards.
        var byProvider = new Dictionary<string, List<PermissionEntry>>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in scored
            .OrderByDescending(s => s.Score)
            .ThenBy(s => (int)PermissionBreadth.Classify(s.Entry.Action))
            .ThenBy(s => s.Entry.Action.Length)
            .ThenBy(s => s.Entry.Action, StringComparer.OrdinalIgnoreCase))
        {
            if (!byProvider.TryGetValue(item.Entry.Provider, out var list))
                byProvider[item.Entry.Provider] = list = new List<PermissionEntry>();
            if (list.Count < perProviderLimit) list.Add(item.Entry);
        }

        return byProvider.Values.SelectMany(v => v)
            .OrderBy(e => e.Provider, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Action, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// A service's FULL vocabulary, ordered narrowest-first. The right permission's name
    /// may share no words with how the task was described — "GPO analytics" contains
    /// nothing matching DeviceConfigurations — so the service, not the wording, finds it.
    /// Order matters: a model weights what it sees first, so service-wide actions go last.
    /// </summary>
    /// <remarks>
    /// TAKES THE REFERENCE, and this is not optional. Building from the catalog alone gave
    /// every candidate a role-derived description, so the prompt showed
    /// "[no Microsoft description; granted by X]" for permissions the app could describe
    /// perfectly well — users/disable was offered with no meaning while ReferenceStore held
    /// "Disable users" the whole time. CandidateActions was threaded with the reference and
    /// this method was not, and THIS is the path that runs whenever the service is
    /// identified: the caller replaces the reference-backed list with this one. So the fix
    /// applied to the fallback path and missed the common one.
    /// </remarks>
    public static IReadOnlyList<PermissionEntry> PermissionsInProviders(
        IReadOnlyCollection<string> providers, RoleCatalog catalog,
        string functionDescription, int limitPerProvider = 220,
        ReferenceStore? reference = null)
    {
        var index = Build(catalog, reference);
        // Same rule as CandidateActions: ordering must not be driven by a forbidden word.
        var words = RequestNegation.Positive(functionDescription).ToLowerInvariant()
            .Split(new[] { ' ', '\t', '\n', '\r', ',', '.', ';', ':', '(', ')', '/', '\\', '-' },
                   StringSplitOptions.RemoveEmptyEntries)
            .Where(w => w.Length > 2)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // THE SAME GATE AS CandidateActions, AND THIS IS THE PATH THAT MATTERS MORE.
        //
        // The filter was added to CandidateActions only, but once a service has been
        // identified the pipeline comes through HERE — so a duty to disable user accounts
        // took the ungated path, agentUsers/disable was offered, and the model took it.
        //
        // Worse than being offered: agentUsers sorts BEFORE users alphabetically, so on
        // equal keyword hits and equal breadth it wins the tie and takes the slot. The
        // correct permission, microsoft.directory/users/disable, sat in the catalog and
        // never appeared in a single prompt.
        //
        // One rule, three doors: scoring, service-scoped listing, and the needs stage.
        var mentionsSpecialisedIdentity = RequestMentionsSpecialisedIdentity(functionDescription);

        var result = new List<PermissionEntry>();
        foreach (var provider in providers)
        {
            var forProvider = index.Entries
                .Where(e => e.Provider.Equals(provider, StringComparison.OrdinalIgnoreCase))
                .Where(e => mentionsSpecialisedIdentity || !IsSpecialisedIdentity(e.Action))
                // HOW MANY WORDS MATCH, AND HOW WELL — NOT WHETHER ANY DOES.
                //
                // This was a boolean: one match ranked identically to five. Every
                // microsoft.directory/users/* action contains "user", so on a request about
                // user accounts thousands of actions tied at true and the real ordering
                // fell through to breadth, privilege, then ALPHABETICAL. In a provider with
                // 145 roles that exhausts 220 slots long before the letter d.
                //
                // microsoft.directory/users/disable therefore never appeared in a single
                // prompt, across every run in the log, while users/basic/update survived
                // purely because "basic" sorts early. The model kept answering a disable
                // request with a property update because that was the only one of the two
                // it was ever shown — and every fix aimed at helping it CHOOSE better was
                // aimed at a stage that had nothing correct to choose.
                //
                // A whole-segment match is the strong signal: "disable" IS a segment of
                // users/disable, whereas "user" merely appears inside hundreds of others.
                .OrderByDescending(e => words.Count(w => SegmentMatches(e.Action, w)) * 3
                                      + words.Count(w =>
                                          e.Action.Contains(w, StringComparison.OrdinalIgnoreCase)))
                .ThenBy(e => PermissionBreadth.Classify(e.Action))               // narrowest first
                .ThenBy(e => e.IsPrivileged)                                     // reads before writes
                .ThenBy(e => e.Action, StringComparer.OrdinalIgnoreCase)
                .Take(limitPerProvider);
            result.AddRange(forProvider);
        }
        return result;
    }
}
