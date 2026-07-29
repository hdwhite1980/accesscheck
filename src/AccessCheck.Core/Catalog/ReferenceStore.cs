using System.Text.Json;

namespace AccessCheck.Core.Catalog;

/// <summary>
/// Microsoft's permission vocabulary, cached on disk.
///
/// Kept separate from the role catalog because it answers a different question: the
/// catalog says what this tenant's roles grant, the reference says what Microsoft
/// supports at all. Validation needs both — a permission can be real without any local
/// role bundling it, and that is precisely when a custom role is the only way to grant it.
/// </summary>
public sealed class ReferenceStore
{
    public List<ReferenceEntry> Entries { get; set; } = new();
    public DateTimeOffset? LastSyncedUtc { get; set; }

    public sealed class ReferenceEntry
    {
        public string Name { get; set; } = "";
        public string Provider { get; set; } = "";
        public string Description { get; set; } = "";
        public bool? IsPrivileged { get; set; }
        public string Source { get; set; } = "";
    }

    public HashSet<string> ActionNames() =>
        Entries.Select(e => e.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Only the entries where Microsoft actually STATED a privilege level. PowerShell
    /// entries carry none, and treating a missing flag as "read" would be worse than the
    /// heuristic it replaces.
    /// </summary>
    public Dictionary<string, bool> StatedPrivilege() =>
        Entries.Where(e => e.IsPrivileged is not null)
            .GroupBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().IsPrivileged!.Value,
                          StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Microsoft's DESCRIPTIONS, keyed by action name — the input to
    /// ActionRisk.UseDescriptions.
    ///
    /// Deliberately a sibling of <see cref="StatedPrivilege"/> rather than something the
    /// caller assembles inline: both feed ActionRisk, both must skip empty values, and both
    /// must survive duplicate names. Having only one of them here is why the description
    /// correction was easy to wire up and easy to forget.
    ///
    /// Empty descriptions are dropped rather than stored blank. ActionRisk treats a blank
    /// description as "no opinion" anyway, and carrying them inflates DescribedCount into
    /// claiming coverage the app does not have.
    /// </summary>
    public Dictionary<string, string> Descriptions() =>
        Entries.Where(e => !string.IsNullOrWhiteSpace(e.Description))
            .GroupBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Description,
                          StringComparer.OrdinalIgnoreCase);

    public static ReferenceStore Load(string path)
    {
        if (!File.Exists(path)) return new ReferenceStore();
        try
        {
            var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            return JsonSerializer.Deserialize<ReferenceStore>(File.ReadAllText(path), opts)
                   ?? new ReferenceStore();
        }
        catch (Exception)
        {
            // A corrupt cache must never block the app — it is a cache, not a record.
            return new ReferenceStore();
        }
    }

    public void Save(string path)
    {
        var opts = new JsonSerializerOptions { WriteIndented = true };
        File.WriteAllText(path, JsonSerializer.Serialize(this, opts));
    }
}
