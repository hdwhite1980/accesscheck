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

        foreach (var entry in index.Entries)
        {
            // MICROSOFT'S DESCRIPTION WINS. The role-derived one is a fallback only.
            var doc = reference.Entries.FirstOrDefault(r =>
                r.Name.Equals(entry.Action, StringComparison.OrdinalIgnoreCase));

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
        var text = (functionDescription ?? "").ToLowerInvariant();
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

    public static IReadOnlyList<PermissionEntry> CandidateActions(
        string functionDescription, RoleCatalog catalog, int perProviderLimit = 60,
        ReferenceStore? reference = null)
    {
        // Build with the reference when we have it, so candidates carry Microsoft's
        // descriptions and reference-only permissions are offered too.
        var index = Build(catalog, reference);
        var words = functionDescription.ToLowerInvariant()
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

            var score = 0;
            foreach (var word in words)
            {
                // A hit in the ACTION NAME is stronger evidence than one in prose.
                if (name.Contains(word, StringComparison.Ordinal)) score += 3;
                else if (haystack.Contains(word, StringComparison.Ordinal)) score += 2;
                else continue;

                // A read permission answering a read-shaped request is the better fit.
                if (!entry.IsPrivileged) score += 1;
            }
            if (score > 0) scored.Add((entry, score));
        }

        var byProvider = new Dictionary<string, List<PermissionEntry>>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in scored.OrderByDescending(s => s.Score))
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
    public static IReadOnlyList<PermissionEntry> PermissionsInProviders(
        IReadOnlyCollection<string> providers, RoleCatalog catalog,
        string functionDescription, int limitPerProvider = 220)
    {
        var index = Build(catalog);
        var words = functionDescription.ToLowerInvariant()
            .Split(new[] { ' ', '\t', '\n', '\r', ',', '.', ';', ':', '(', ')', '/', '\\', '-' },
                   StringSplitOptions.RemoveEmptyEntries)
            .Where(w => w.Length > 2)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var result = new List<PermissionEntry>();
        foreach (var provider in providers)
        {
            var forProvider = index.Entries
                .Where(e => e.Provider.Equals(provider, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(e => words.Any(w =>
                    e.Action.Contains(w, StringComparison.OrdinalIgnoreCase)))   // keyword hits first
                .ThenBy(e => PermissionBreadth.Classify(e.Action))               // narrowest first
                .ThenBy(e => e.IsPrivileged)                                     // reads before writes
                .ThenBy(e => e.Action, StringComparer.OrdinalIgnoreCase)
                .Take(limitPerProvider);
            result.AddRange(forProvider);
        }
        return result;
    }
}
