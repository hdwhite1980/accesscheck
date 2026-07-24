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
    }

    /// <summary>How a given action was classified — for showing provenance in the UI.</summary>
    public static bool IsAuthoritative(string action) =>
        _authoritative is not null && _authoritative.ContainsKey(action);

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
        if (_authoritative is not null && _authoritative.TryGetValue(action.Trim(), out var stated))
            return stated;

        return IsPrivilegedHeuristic(action);
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
    public static bool IsWrite(string action) => IsPrivilegedHeuristic(action);

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
        "rolemember", "allTasks", "allproperties/allTasks", "impersonat",
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
    public static int Weight(string action)
    {
        if (IsPrivileged(action)) return EscalationWeight;
        return IsWrite(action) ? WriteWeight : ReadWeight;
    }

    /// <summary>Actions that change state — not the same as CountPrivileged.</summary>
    public static int CountWrites(IEnumerable<string> actions) => actions.Count(IsWrite);

    /// <summary>Total risk-weighted cost of a set of excess actions.</summary>
    public static int Score(IEnumerable<string> actions) =>
        actions.Sum(Weight);

    public static int CountPrivileged(IEnumerable<string> actions) =>
        actions.Count(IsPrivileged);
}
