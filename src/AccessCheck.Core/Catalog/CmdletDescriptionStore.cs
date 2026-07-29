using System.Text.Json;
using System.Text.Json.Serialization;

namespace AccessCheck.Core.Catalog;

/// <summary>
/// Microsoft's published descriptions for Exchange and Purview cmdlets.
///
/// WHY THIS EXISTS. These are the only two services whose permissions reach the model with
/// NO description at all, and every recommendation failure in them traces back to that.
/// Asked to remove malicious MESSAGES, the model proposed Remove-Mailbox — which deletes
/// the mailbox and the user account with it. Asked to delegate a mailbox it declined
/// entirely, stating that the candidate list held no described permission for the task,
/// while Add-MailboxFolderPermission sat in that list with an empty description. The
/// app's own rule is that a permission's meaning comes from its description and never from
/// its name; for these two services there was no description, so only the name was left.
///
/// WHY NOT Get-Help. Exchange Online's REST mode generates proxy cmdlets at connection
/// time and they carry no help content — Get-Help returns the syntax block and an empty
/// synopsis for every one of them. The data is simply not in the session.
///
/// WHAT IT ALSO FIXES. These descriptions flow into ActionRisk.UseDescriptions, which can
/// downgrade an over-cautious privileged guess to a read. Exchange and Purview cmdlets
/// currently fall through to the heuristic's "unknown shape, treat as privileged" default,
/// which is why almost every grant in those services comes back rated escalation-capable
/// whatever it actually does.
/// </summary>
public sealed class CmdletDescriptionStore
{
    [JsonPropertyName("source")]
    public string Source { get; set; } = "";

    [JsonPropertyName("importedUtc")]
    public DateTimeOffset? ImportedUtc { get; set; }

    [JsonPropertyName("descriptions")]
    public Dictionary<string, string> Descriptions { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    public bool IsEmpty => Descriptions.Count == 0;
    public int Count => Descriptions.Count;

    public string? Find(string cmdlet) =>
        Descriptions.TryGetValue(cmdlet, out var d) && !string.IsNullOrWhiteSpace(d) ? d : null;

    /// <summary>
    /// Merges these into a ReferenceStore so the rest of the app needs no new plumbing.
    ///
    /// ReferenceStore is already the single place a permission's meaning comes from —
    /// PermissionIndex joins against it, ActionRisk.UseDescriptions reads it, the guards
    /// check against it, and Stage D grounds its verdicts on it. Adding a parallel source
    /// would mean teaching all four about a second one, and they would have to agree
    /// forever. Feeding the same store means every one of them improves at once.
    ///
    /// EXISTING ENTRIES ARE NEVER OVERWRITTEN. A description that came from Graph's
    /// resourceActions is authoritative for this tenant; these are documentation, and
    /// documentation describes the product rather than the deployment.
    ///
    /// IsPrivileged is deliberately left null. Microsoft states that flag for Graph
    /// actions and does not state it for cmdlets, and inventing one here would put a guess
    /// where the app is careful to keep an authoritative answer or nothing.
    ///
    /// Returns how many entries were added.
    /// </summary>
    public int MergeInto(ReferenceStore reference, string provider)
    {
        if (IsEmpty) return 0;

        var known = reference.Entries
            .Select(e => e.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var added = 0;
        foreach (var (cmdlet, description) in Descriptions)
        {
            if (string.IsNullOrWhiteSpace(description)) continue;
            if (known.Contains(cmdlet)) continue;

            reference.Entries.Add(new ReferenceStore.ReferenceEntry
            {
                Name = cmdlet,
                Provider = provider,
                Description = description,
                IsPrivileged = null,
                Source = "learn.microsoft.com (cmdlet reference)"
            });
            added++;
        }

        return added;
    }

    // ---------- persistence ----------

    public static CmdletDescriptionStore Load(string path)
    {
        if (!File.Exists(path)) return new CmdletDescriptionStore();
        try
        {
            var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            var loaded = JsonSerializer.Deserialize<CmdletDescriptionStore>(
                File.ReadAllText(path), opts) ?? new CmdletDescriptionStore();

            // The importer writes a plain JSON object, so the dictionary comes back with the
            // default comparer. Cmdlet casing varies between the docs and the tenant —
            // "Add-MailboxFolderPermission" against "add-mailboxfolderpermission" — and a
            // case-sensitive lookup would miss most of them.
            loaded.Descriptions = new Dictionary<string, string>(
                loaded.Descriptions, StringComparer.OrdinalIgnoreCase);
            return loaded;
        }
        catch (Exception)
        {
            // A corrupt cache must never block the app — it is a cache, not a record.
            return new CmdletDescriptionStore();
        }
    }

    public void Save(string path)
    {
        var opts = new JsonSerializerOptions { WriteIndented = true };
        File.WriteAllText(path, JsonSerializer.Serialize(this, opts));
    }
}
