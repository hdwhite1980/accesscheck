namespace AccessCheck.Core.Recommendation;

/// <summary>
/// Classifies a resource action as read-only or write/administrative, so ranking can
/// weigh excess permissions by what they'd actually let someone DO rather than just
/// counting them. Without this, a role granting 5 extra admin actions outranks one
/// granting 6 extra read actions — which is backwards for least privilege.
/// Heuristics cover the action vocabularies AccessCheck syncs:
///   Entra   microsoft.directory/users/password/update, .../allEntities/allTasks
///   Intune  Microsoft.Intune_ManagedDevices_Read, Microsoft.Intune_RemoteTasks_RebootNow
///   EXO/SCC Get-Mailbox, Set-Mailbox, New-RoleGroup
/// </summary>
public static class ActionRisk
{
    /// <summary>
    /// Weights, and WHY there are three.
    ///
    /// Microsoft's isPrivileged does NOT mean "write". It marks permissions that can
    /// ELEVATE PRIVILEGE if misused — microsoft.directory/devices/delete is a genuine
    /// destructive write that Microsoft does NOT flag, because deleting a device cannot
    /// make you an administrator. The heuristic answers "does this change state"; the
    /// Microsoft flag answers "can this escalate". They are different questions, and
    /// collapsing them named a delete "read" on a real grant.
    /// </summary>
    public const int EscalationWeight = 6;   // Microsoft says it can elevate privilege
    public const int WriteWeight = 3;        // changes state, but cannot escalate
    public const int ReadWeight = 1;

    /// <summary>Kept for callers that still speak the old two-level language.</summary>
    public const int PrivilegedWeight = EscalationWeight;

    /// <summary>
    /// Microsoft's OWN privilege classification, keyed by action name. When the Reference
    /// has been synced, this REPLACES the heuristic below for every action it covers.
    ///
    /// This is not a refinement, it is a correction. On one real tenant the heuristic
    /// disagreed with Microsoft on 568 of 939 directory actions — around 60% — and that
    /// classification drives risk-weighted ranking everywhere, so the ordering of "least
    /// over-privileged role" was being decided by a guess most of the time. An
    /// authoritative answer exists; guessing where one exists is indefensible.
    /// </summary>
    private static IReadOnlyDictionary<string, bool>? _authoritative;

    /// <summary>Number of actions Microsoft has classified for us. Zero until synced.</summary>
    public static int AuthoritativeCount => _authoritative?.Count ?? 0;

    /// <summary>
    /// Install Microsoft's classifications. Pass only entries where Microsoft actually
    /// STATED a value — PowerShell-sourced entries have none, and a missing flag must fall
    /// through to the heuristic rather than being read as "read".
    /// </summary>
    public static void UseAuthoritative(IReadOnlyDictionary<string, bool>? stated)
    {
        _authoritative = stated is null || stated.Count == 0
            ? null
            : new Dictionary<string, bool>(stated, StringComparer.OrdinalIgnoreCase);
        _authoritativeNames = _authoritative is null
            ? null
            : new ActionNameMatch.NameResolver(_authoritative.Keys);
    }

    // Reference data is keyed by the REFERENCE spelling and looked up by the CATALOG
    // spelling, and for Intune those differ — "Devicecompliancepolicies" against Microsoft's
    // own misspelled "DeviceCompliancePolices". Exact lookups therefore missed every one,
    // which quietly disabled the description-based correction below.
    private static ActionNameMatch.NameResolver? _authoritativeNames;
    private static ActionNameMatch.NameResolver? _descriptionNames;

    /// <summary>How a given action was classified — for showing provenance in the UI.</summary>
    public static bool IsAuthoritative(string action) =>
        _authoritativeNames is not null && _authoritativeNames.Resolve(action) is not null;

    /// <summary>
    /// Microsoft's DESCRIPTIONS, used to correct the heuristic where it over-reaches.
    ///
    /// The heuristic's last line is "unknown shape: treat as privileged", which is the right
    /// default with nothing else to go on — but Intune states no privilege flag for ANY
    /// action, so on that service the guess decides everything. It rated
    /// Microsoft.Intune_Devicecompliancepolicies_View_reports as escalation-capable purely
    /// because the name ends in neither a read nor a write marker. Its description reads
    /// "View, generate, and export device compliance reports." That is a read, and
    /// escalation costs six times what a read costs in every ranking decision.
    ///
    /// ONE-DIRECTIONAL BY DESIGN: a description can only DOWNGRADE a heuristic guess of
    /// privileged to read, never upgrade. It applies only when Microsoft's own words carry a
    /// read verb and no write verb at all, so caution is lost only where the documentation
    /// is explicit. Everything ambiguous keeps the over-cautious default.
    /// </summary>
    private static IReadOnlyDictionary<string, string>? _descriptions;

    public static void UseDescriptions(IReadOnlyDictionary<string, string>? descriptions)
    {
        _descriptions = descriptions is null || descriptions.Count == 0
            ? null
            : new Dictionary<string, string>(descriptions, StringComparer.OrdinalIgnoreCase);
        _descriptionNames = _descriptions is null
            ? null
            : new ActionNameMatch.NameResolver(_descriptions.Keys);
    }

    /// <summary>Actions whose meaning we can read rather than guess. Zero until synced.</summary>
    public static int DescribedCount => _descriptions?.Count ?? 0;

    private static readonly string[] ReadVerbs =
    {
        "read", "view", "list", "see", "display", "monitor", "report", "reports",
        "export", "download", "audit", "inspect", "query", "search", "browse"
    };

    private static readonly string[] WriteVerbs =
    {
        "create", "add", "delete", "remove", "update", "change", "modify", "edit",
        "set", "configure", "manage", "assign", "unassign", "revoke", "reset", "wipe",
        "retire", "enable", "disable", "install", "uninstall", "deploy", "provision",
        "approve", "grant", "restore", "purge", "execute", "run", "start", "stop",
        "lock", "unlock", "block", "unblock", "initiate", "trigger", "invoke", "send",
        "write", "rotate", "move", "rename", "upload", "import"
        // "sync" and "issue" are DELIBERATELY ABSENT. They appear inside product names and
        // nouns rather than as verbs — "Exchange ActiveSync Connectors", "view compliance
        // issues" — and a false write here silently keeps an over-cautious rating that this
        // list exists to correct.
    };

    /// <summary>
    /// True when Microsoft's description says this action only looks at things.
    /// Negation-filtered first, so "Read policies. Does not allow deleting." is not read as
    /// granting a delete.
    /// </summary>
    public static bool DescriptionSaysReadOnly(string action)
    {
        if (_descriptions is null || _descriptionNames is null) return false;
        var key = _descriptionNames.Resolve(action);
        if (key is null || !_descriptions.TryGetValue(key, out var description)) return false;
        if (string.IsNullOrWhiteSpace(description)) return false;

        var cleaned = RequestNegation.Positive(description).ToLowerInvariant();
        var padded = " " + new string(cleaned.Select(c => char.IsLetterOrDigit(c) ? c : ' ').ToArray()) + " ";

        if (WriteVerbs.Any(v => CapabilityCoverage.WordAppears(padded, v))) return false;
        return ReadVerbs.Any(v => CapabilityCoverage.WordAppears(padded, v));
    }

    private static readonly string[] PrivilegedMarkers =
    {
        "alltasks", "/update", "/create", "/delete", "/manage", "/write",
        "/reset", "/restore", "/enable", "/disable", "/assign", "/impersonate",
        "/invalidate", "/execute", "/run", "/wipe", "/retire", "/lock",
        "_create", "_update", "_delete", "_assign", "_manage", "_write",
        "_remotetasks", "_wipe", "_retire"
    };

    private static readonly string[] ReadPrefixes =
    {
        "get-", "search-", "test-", "export-", "measure-"
    };

    private static readonly string[] WritePrefixes =
    {
        "set-", "new-", "remove-", "add-", "enable-", "disable-", "update-",
        "start-", "stop-", "restore-", "reset-", "import-", "install-", "invoke-"
    };

    /// <summary>True when the action can change state or perform an administrative task.</summary>
    public static bool IsPrivileged(string action)
    {
        if (string.IsNullOrWhiteSpace(action)) return false;

        // Microsoft's stated answer wins wherever it exists. Everything below is a guess
        // for the actions it does not cover.
        if (_authoritative is not null && _authoritativeNames is not null
            && _authoritativeNames.Resolve(action) is { } statedKey
            && _authoritative.TryGetValue(statedKey, out var stated))
            return stated;

        // The guess, then Microsoft's words as a one-way correction to it.
        if (!IsPrivilegedHeuristic(action)) return false;
        return !DescriptionSaysReadOnly(action);
    }

    /// <summary>
    /// The inference ALONE, ignoring Microsoft's answer.
    ///
    /// Needed because comparing IsPrivileged against Microsoft's flag became
    /// self-referential the moment the override was installed: the disagreement count
    /// dropped from 568 to 0 not because the heuristic improved but because it was no
    /// longer being consulted. Measuring a guess requires the guess.
    /// </summary>
    public static bool IsPrivilegedHeuristic(string action)
    {
        if (string.IsNullOrWhiteSpace(action)) return false;
        var a = action.Trim().ToLowerInvariant();

        // Exchange / Purview cmdlets: the verb decides.
        if (a.Contains('-') && !a.Contains('/'))
        {
            foreach (var p in ReadPrefixes) if (a.StartsWith(p, StringComparison.Ordinal)) return false;
            foreach (var p in WritePrefixes) if (a.StartsWith(p, StringComparison.Ordinal)) return true;
        }

        // Explicit read endings are the strongest read signal.
        if (a.EndsWith("/read", StringComparison.Ordinal) ||
            a.EndsWith("_read", StringComparison.Ordinal) ||
            a.EndsWith("/standard/read", StringComparison.Ordinal) ||
            a.EndsWith("/basic/read", StringComparison.Ordinal) ||
            a.EndsWith("/allproperties/read", StringComparison.Ordinal))
            return false;

        foreach (var marker in PrivilegedMarkers)
            if (a.Contains(marker, StringComparison.Ordinal)) return true;

        // Unknown shape: treat as privileged. Over-caution is the safe default here.
        return true;
    }

    /// <summary>
    /// True when the action CHANGES STATE, regardless of whether Microsoft considers it
    /// escalation-capable. This is the question role naming and blast radius care about.
    /// </summary>
    public static bool IsWrite(string action)
    {
        // Same correction as IsPrivileged: an action Microsoft describes as only viewing
        // things does not change state, whatever its name looks like. IsPrivilegedHeuristic
        // itself stays untouched so the disagreement metric still measures the raw guess.
        if (!IsPrivilegedHeuristic(action)) return false;
        return !DescriptionSaysReadOnly(action);
    }

    /// <summary>
    /// Excess that should never be waved through on a count threshold, however small.
    ///
    /// Credential, authentication-method and role-management actions are how an ordinary
    /// grant becomes an escalation path — five of these as "acceptable excess" is not the
    /// same as five extra read actions, and the raw count treated them identically.
    /// </summary>
    private static readonly string[] CriticalMarkers =
    {
        "credential", "authenticationmethod", "password", "rolemanagement",
        // LOWERCASE, because IsCriticalExcess lowercases the action and compares Ordinal.
        // "allTasks" and "allproperties/allTasks" carried a capital T and could therefore
        // NEVER match — the two markers most obviously meant to catch a whole-service grant
        // were dead. roleManagement/allProperties/allTasks only passed its test by matching
        // "rolemanagement" instead.
        "rolemember", "alltasks", "allproperties/alltasks", "impersonat",
        // allEntities joins allTasks here: an action spanning every object type in a service
        // is never "a small amount of extra", however few actions the role lists.
        "allentities",
        "applicationpolicies", "serviceprincipal", "owners", "delete", "disable",
        "revoke", "approve", "consent"
    };

    public static bool IsCriticalExcess(string action)
    {
        if (string.IsNullOrWhiteSpace(action)) return false;
        var a = action.ToLowerInvariant();

        // A read of a sensitive object is not itself an escalation path.
        if (a.EndsWith("/read", StringComparison.Ordinal)
            || a.Contains("/standard/read", StringComparison.Ordinal)) return false;

        return CriticalMarkers.Any(m => a.Contains(m, StringComparison.Ordinal));
    }

    /// <summary>
    /// Three-level cost: a read is cheap, a write has blast radius, and an action
    /// Microsoft flags as escalation-capable is in a category of its own.
    /// </summary>
    /// <summary>A rollup is not one permission, it is a category, and it is priced as one.</summary>
    public const int AllTasksWeight = 50;
    public const int AllEntitiesWeight = 25;
    public const int AllPropertiesWeight = 8;

    /// <summary>
    /// What an action costs when it grants across ALL entities or ALL tasks.
    ///
    /// Without this, making coverage rollup-aware ranks Global Reader FIRST on any read
    /// request: it covers everything through a handful of allEntities actions, each ending
    /// in /read and therefore weighted 1, so its excess scores about 8 against a narrow
    /// role's 20. Counting a category as one permission is how the broadest role in the
    /// tenant comes out looking like the tightest.
    /// </summary>
    public static int RollupWeight(string action)
    {
        if (string.IsNullOrWhiteSpace(action)) return 0;
        var a = action.ToLowerInvariant();
        if (a.Contains("alltasks", StringComparison.Ordinal)) return AllTasksWeight;
        if (a.Contains("allentities", StringComparison.Ordinal)) return AllEntitiesWeight;
        if (a.Contains("allproperties", StringComparison.Ordinal)) return AllPropertiesWeight;
        return 0;
    }

    public static int Weight(string action)
    {
        var baseline = IsPrivileged(action)
            ? EscalationWeight
            : IsWrite(action) ? WriteWeight : ReadWeight;
        return Math.Max(baseline, RollupWeight(action));
    }

    /// <summary>Actions that change state — not the same as CountPrivileged.</summary>
    public static int CountWrites(IEnumerable<string> actions) => actions.Count(IsWrite);

    /// <summary>Total risk-weighted cost of a set of excess actions.</summary>
    public static int Score(IEnumerable<string> actions) =>
        actions.Sum(Weight);

    public static int CountPrivileged(IEnumerable<string> actions) =>
        actions.Count(IsPrivileged);
}
