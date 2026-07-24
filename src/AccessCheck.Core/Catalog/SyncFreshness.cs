namespace AccessCheck.Core.Catalog;

/// <summary>
/// When each source was last read, and whether that is still good enough.
///
/// The two halves of the catalog have very different costs. Graph providers return every
/// role in one paged call — cheap enough to re-run whenever. Exchange and Purview have no
/// bulk API: entries need a round trip PER ROLE, and the inverse lookup one PER CMDLET,
/// so a full read is ~500 calls and several minutes. Treating both the same forced a
/// choice between a slow app and a stale catalog.
///
/// So they are tracked separately: Graph on demand, PowerShell on a weekly cadence with a
/// visible reminder. Permission vocabularies change when Microsoft ships, not hourly.
/// </summary>
public sealed class SyncFreshness
{
    public DateTimeOffset? GraphLastSync { get; set; }
    public DateTimeOffset? PowerShellLastSync { get; set; }
    public DateTimeOffset? ReferenceLastSync { get; set; }

    /// <summary>Graph is cheap, so it goes stale sooner before anyone should care.</summary>
    public TimeSpan GraphMaxAge { get; set; } = TimeSpan.FromDays(7);
    /// <summary>PowerShell is expensive; weekly is the intended cadence.</summary>
    public TimeSpan PowerShellMaxAge { get; set; } = TimeSpan.FromDays(7);
    /// <summary>Microsoft's own list changes only when Microsoft ships.</summary>
    public TimeSpan ReferenceMaxAge { get; set; } = TimeSpan.FromDays(30);

    public sealed record Status
    {
        public required string Source { get; init; }
        public required DateTimeOffset? LastSync { get; init; }
        public required TimeSpan MaxAge { get; init; }

        public bool NeverSynced => LastSync is null;
        public TimeSpan? Age => LastSync is null ? null : DateTimeOffset.UtcNow - LastSync.Value;
        public bool IsStale => NeverSynced || Age! > MaxAge;

        public string Describe()
        {
            if (NeverSynced) return Source + ": never synced";
            var days = (int)Age!.Value.TotalDays;
            var text = Source + ": " + (days == 0
                ? "synced today"
                : days == 1 ? "synced yesterday" : "synced " + days + " days ago");
            return IsStale ? text + " — DUE" : text;
        }
    }

    public IReadOnlyList<Status> All() => new[]
    {
        new Status { Source = "Graph providers", LastSync = GraphLastSync, MaxAge = GraphMaxAge },
        new Status { Source = "Exchange & Purview (PowerShell)", LastSync = PowerShellLastSync,
                     MaxAge = PowerShellMaxAge },
        new Status { Source = "Microsoft permission reference", LastSync = ReferenceLastSync,
                     MaxAge = ReferenceMaxAge }
    };

    public IReadOnlyList<Status> Due() => All().Where(s => s.IsStale).ToList();

    /// <summary>One line for the home page. Empty when nothing is due.</summary>
    public string? DueBanner()
    {
        var due = Due();
        if (due.Count == 0) return null;

        var never = due.Where(d => d.NeverSynced).Select(d => d.Source).ToList();
        var aged = due.Where(d => !d.NeverSynced).ToList();

        var parts = new List<string>();
        if (never.Count > 0) parts.Add("never synced: " + string.Join(", ", never));
        foreach (var s in aged)
            parts.Add(s.Source + " last synced " + (int)s.Age!.Value.TotalDays + " days ago");

        return "Catalog refresh due — " + string.Join("; ", parts)
            + ".  Recommendations are validated against this data, so a stale catalog "
            + "produces stale answers.";
    }
}
