namespace AccessCheck.Core.Catalog;

/// <summary>
/// Not every failed read is a problem. A 403 on a service the tenant isn't licensed for
/// is normal and permanent; a missing consent scope is something the operator must fix.
/// Only the second kind belongs in the operator's face — the rest belongs in Details.
/// </summary>
public enum IssueSeverity
{
    /// <summary>Expected: unlicensed service, provider absent from this cloud, nothing to read.</summary>
    Informational,
    /// <summary>Needs action: missing consent, a malformed request, an unexpected failure.</summary>
    Actionable
}

public sealed record SyncIssue(string Source, string Message, IssueSeverity Severity)
{
    public bool IsActionable => Severity == IssueSeverity.Actionable;

    public string Line => (Severity == IssueSeverity.Actionable ? "[ACTION] " : "[info]   ") +
                          Source + ": " + Message;

    /// <summary>
    /// Classifies a failure from its message. Consent problems and malformed requests are
    /// actionable; licensing and absent providers are not.
    /// </summary>
    public static SyncIssue FromError(string source, string message)
    {
        var m = message ?? "";

        bool consent =
            m.Contains("PermissionScopeNotGranted", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("Authorization_RequestDenied", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("InvalidAuthenticationToken", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("401", StringComparison.Ordinal);

        bool malformed =
            m.Contains("400", StringComparison.Ordinal) ||
            m.Contains("BadRequest", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("not valid", StringComparison.OrdinalIgnoreCase);

        // A licensing/entitlement 403, or a provider that simply isn't in this cloud.
        bool expected =
            (m.Contains("403", StringComparison.Ordinal) && !consent) ||
            m.Contains("accessDenied", StringComparison.OrdinalIgnoreCase) ||
            m.Contains("404", StringComparison.Ordinal) ||
            m.Contains("NotFound", StringComparison.OrdinalIgnoreCase);

        var severity = (consent || malformed) ? IssueSeverity.Actionable
            : expected ? IssueSeverity.Informational
            : IssueSeverity.Actionable;   // unknown shapes get attention

        var friendly = consent
            ? "consent is missing for this read — add the scope and re-sign-in. (" + Trim(m) + ")"
            : expected && !consent
                ? "not available in this tenant (unlicensed service or provider absent). (" +
                  Trim(m) + ")"
                : Trim(m);

        return new SyncIssue(source, friendly, severity);
    }

    private static string Trim(string s) => s.Length <= 220 ? s : s[..220];
}

/// <summary>Collects issues and answers the only two questions the UI has.</summary>
public sealed class IssueLog
{
    private readonly List<SyncIssue> _issues = new();

    public IReadOnlyList<SyncIssue> All => _issues;
    public IReadOnlyList<SyncIssue> Actionable => _issues.Where(i => i.IsActionable).ToList();

    public void Add(SyncIssue issue) => _issues.Add(issue);
    public void AddError(string source, string message) => Add(SyncIssue.FromError(source, message));
    public void AddInfo(string source, string message) =>
        Add(new SyncIssue(source, message, IssueSeverity.Informational));
    public void Clear() => _issues.Clear();

    /// <summary>Banner text — empty when nothing needs the operator's attention.</summary>
    public string BannerText
    {
        get
        {
            var act = Actionable;
            if (act.Count == 0) return "";
            return "Needs attention — " + string.Join("  ", act.Select(a => a.Source + ": " + a.Message));
        }
    }

    /// <summary>One line per issue for the Details window, actionable ones first.</summary>
    public string DetailText => _issues.Count == 0
        ? "No issues recorded."
        : string.Join(Environment.NewLine,
            _issues.OrderByDescending(i => i.IsActionable).Select(i => i.Line));

    public string QuietSummary
    {
        get
        {
            var info = _issues.Count - Actionable.Count;
            if (_issues.Count == 0) return "";
            if (Actionable.Count == 0)
                return info + " expected condition(s) logged — see Details.";
            return Actionable.Count + " needing attention, " + info + " expected — see Details.";
        }
    }
}
