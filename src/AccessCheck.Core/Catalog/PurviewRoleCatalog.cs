using System.Text.Json;

namespace AccessCheck.Core.Catalog;

/// <summary>
/// Microsoft's published Purview role vocabulary: what each role does, and which built-in
/// role groups already carry it.
///
/// WHY THIS EXISTS AT ALL. The Security and Compliance session does not expose
/// Get-ManagementRoleEntry — it is an Exchange cmdlet — and Get-ManagementRole returns
/// names with an empty RoleEntries collection. So a tenant will tell you that 120 Purview
/// roles exist and nothing whatsoever about what they contain. Synced that way, every
/// Purview recommendation is made against an empty dictionary: a request to purge phishing
/// mail found no Purview vocabulary, fell through to Exchange, and came back with
/// Remove-Mailbox — which deletes the mailbox rather than the message.
///
/// WHY CMDLETS ARE THE WRONG TARGET ANYWAY. Purview cannot create custom management roles.
/// Nothing can be derived, nothing stripped. The unit of granting IS the role, placed in a
/// role group. Cmdlets are an Exchange concept — they matter there because a role can be
/// derived from a parent and trimmed — and chasing them for Purview was chasing a number
/// that could never be acted on.
///
/// WHAT REPLACES THEM. Microsoft publishes, for every role, a description of what it does
/// and the list of built-in role groups that already carry it. That second column is the
/// least-privilege argument stated outright: if Search And Purge is only available inside
/// Data Investigator and Organization Management, then a role group carrying that one role
/// is narrower than either, and the size difference is the evidence.
/// </summary>
public sealed class PurviewRoleCatalog
{
    public sealed record PurviewRole
    {
        public string Name { get; init; } = "";
        /// <summary>Microsoft's description of what the role permits.</summary>
        public string Description { get; init; } = "";
        /// <summary>Built-in role groups that carry this role by default.</summary>
        public IReadOnlyList<string> InRoleGroups { get; init; } = Array.Empty<string>();
    }

    public sealed record PurviewRoleGroup
    {
        public string Name { get; init; } = "";
        public string Description { get; init; } = "";
        public IReadOnlyList<string> Roles { get; init; } = Array.Empty<string>();
    }

    public List<PurviewRole> Roles { get; set; } = new();
    public List<PurviewRoleGroup> RoleGroups { get; set; } = new();
    public DateTimeOffset? LastUpdatedUtc { get; set; }
    /// <summary>Where this came from, so a stale or hand-edited file is identifiable.</summary>
    public string Source { get; set; } = "";

    public bool IsEmpty => Roles.Count == 0;

    // ---------- least-privilege questions ----------

    public PurviewRole? Find(string roleName) =>
        Roles.FirstOrDefault(r => r.Name.Equals(roleName, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The built-in role groups an operator would otherwise have to use to grant this role.
    ///
    /// This is the comparison that makes a custom role group defensible. Granting Search
    /// And Purge through Organization Management hands over forty-odd other roles; a group
    /// carrying only that one is the same capability without them. Naming the alternative
    /// is what turns "we made a custom group" into an argument.
    /// </summary>
    public IReadOnlyList<PurviewRoleGroup> GroupsCarrying(string roleName) =>
        RoleGroups
            .Where(g => g.Roles.Any(r => r.Equals(roleName, StringComparison.OrdinalIgnoreCase)))
            .OrderBy(g => g.Roles.Count)
            .ToList();

    /// <summary>
    /// How much a plan of these roles saves against the narrowest built-in group that
    /// covers them all. Null when no single built-in group covers the set — which is itself
    /// the strongest case for composing one, since the alternative is granting two.
    /// </summary>
    public int? ExcessRolesInNarrowestAlternative(IReadOnlyCollection<string> wanted)
    {
        if (wanted.Count == 0) return null;

        var covering = RoleGroups
            .Where(g => wanted.All(w =>
                g.Roles.Any(r => r.Equals(w, StringComparison.OrdinalIgnoreCase))))
            .OrderBy(g => g.Roles.Count)
            .FirstOrDefault();

        return covering is null ? null : covering.Roles.Count - wanted.Count;
    }

    // ---------- parsing ----------

    /// <summary>
    /// Reads Microsoft's own tables rather than a hand-typed copy of them.
    ///
    /// The page is available as markdown by appending ?accept=text/markdown, so the app can
    /// parse the source instead of carrying a transcription that silently goes out of date
    /// every time Microsoft adds a role — and they add them constantly.
    ///
    /// Two tables are recognised by their header row:
    ///   "Role group | Description | Default roles assigned"
    ///   "Role | Description | Default role group assignments"
    /// Anything else in the document is ignored, so the parser survives the surrounding
    /// prose being rewritten.
    /// </summary>
    public static PurviewRoleCatalog ParseLearnMarkdown(string markdown, string source = "")
    {
        var catalog = new PurviewRoleCatalog
        {
            LastUpdatedUtc = DateTimeOffset.UtcNow,
            Source = source
        };
        if (string.IsNullOrWhiteSpace(markdown)) return catalog;

        var lines = markdown.Replace("\r\n", "\n").Split('\n');
        var mode = 0;   // 0 none, 1 role groups, 2 roles

        foreach (var raw in lines)
        {
            var line = raw.Trim();

            if (!line.StartsWith('|'))
            {
                // A non-table line ends whichever table was being read. Without this, prose
                // between the two tables would be parsed as rows of the first.
                mode = 0;
                continue;
            }

            var cells = SplitRow(line);
            if (cells.Count < 3) continue;

            var first = Clean(cells[0]);

            // Header rows switch mode. Separator rows (---) are skipped by the emptiness
            // check below.
            if (first.Equals("Role group", StringComparison.OrdinalIgnoreCase)) { mode = 1; continue; }
            if (first.Equals("Role", StringComparison.OrdinalIgnoreCase)) { mode = 2; continue; }
            if (mode == 0) continue;
            if (first.Length == 0 || first.All(c => c is '-' or ':')) continue;

            var description = Clean(cells[1]);
            var listed = SplitList(cells[2]);

            if (mode == 1)
            {
                catalog.RoleGroups.Add(new PurviewRoleGroup
                {
                    Name = first, Description = description, Roles = listed
                });
            }
            else
            {
                catalog.Roles.Add(new PurviewRole
                {
                    Name = first, Description = description, InRoleGroups = listed
                });
            }
        }

        return catalog;
    }

    private static List<string> SplitRow(string line)
    {
        var trimmed = line.Trim('|');
        return trimmed.Split('|').Select(c => c.Trim()).ToList();
    }

    /// <summary>
    /// Strips markdown emphasis, links and the asterisk Microsoft uses to mark roles that
    /// are not in Organization Management by default. A role named "**Search And Purge**"
    /// must match the plain string the tenant reports.
    /// </summary>
    private static string Clean(string cell)
    {
        var s = cell.Trim();

        // [text](url) -> text. Done before asterisk stripping so a link inside emphasis
        // does not leave a stray bracket.
        while (true)
        {
            var open = s.IndexOf('[');
            if (open < 0) break;
            var close = s.IndexOf(']', open);
            if (close < 0) break;
            var paren = close + 1 < s.Length && s[close + 1] == '(' ? s.IndexOf(')', close) : -1;
            var text = s[(open + 1)..close];
            s = paren > 0 ? s[..open] + text + s[(paren + 1)..] : s[..open] + text + s[(close + 1)..];
        }

        s = s.Replace("\\*", "*");
        s = s.Trim().Trim('*').Trim();
        s = s.Replace("<br>", " ").Replace("**", "");
        // Microsoft footnotes some role groups with a superscript one.
        s = s.TrimEnd('¹', '*', ' ');
        return string.Join(" ", s.Split(' ', StringSplitOptions.RemoveEmptyEntries));
    }

    /// <summary>
    /// Splits the "roles assigned" cell. Entries are run together separated by runs of
    /// whitespace, so a single-space split would shred "Case Management" into two roles.
    /// Two or more spaces is the separator.
    /// </summary>
    private static List<string> SplitList(string cell)
    {
        var s = Clean(cell).Replace("<br>", "  ");
        if (s.Length == 0) return new List<string>();

        // Re-split on the original cell rather than the collapsed one, since Clean
        // normalises runs of spaces away.
        var source = cell.Replace("<br>", "   ");
        var parts = System.Text.RegularExpressions.Regex
            .Split(source, @"\s{2,}")
            .Select(Clean)
            .Where(p => p.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return parts;
    }

    // ---------- catalog enrichment ----------

    /// <summary>
    /// Fills in the vocabulary of every Purview role the tenant reports but cannot describe,
    /// by giving each role ITS OWN NAME as its single grantable action.
    ///
    /// That is not a workaround, it is the accurate model. Purview cannot create custom
    /// management roles, so nothing below the role can ever be granted, derived or
    /// stripped. The role IS the atomic unit. Storing it as a one-action role makes the
    /// catalog say exactly that, and every existing stage then works unmodified: the
    /// resolver validates the name as real vocabulary, PermissionIndex offers it as a
    /// candidate carrying Microsoft's description, and set cover treats each role as
    /// covering precisely itself with zero excess.
    ///
    /// The alternative — teaching the validator, the resolver, the index and the planner
    /// each to special-case one provider — spreads a single fact about Purview across four
    /// files that would then have to agree forever.
    ///
    /// Only roles the TENANT reports are touched. A role Microsoft documents that this
    /// tenant does not have cannot be granted here, because there is no custom-role path to
    /// create it, so offering it as a candidate would propose something unexecutable.
    ///
    /// Returns how many roles were filled in.
    /// </summary>
    public int EnrichCatalog(RoleCatalog catalog)
    {
        if (IsEmpty) return 0;

        var byName = new Dictionary<string, PurviewRole>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in Roles) byName[r.Name] = r;

        var all = catalog.Roles.ToList();
        var rebuilt = new List<RoleDefinitionRecord>(all.Count);
        var filled = 0;

        foreach (var role in all)
        {
            var isPurview = role.Provider.Equals(RbacProviders.Purview,
                StringComparison.OrdinalIgnoreCase);

            // Never overwrite real data. If a future API does start returning entries, the
            // live answer must win over the documented one.
            if (!isPurview || role.AllowedResourceActions.Count > 0)
            {
                rebuilt.Add(role);
                continue;
            }

            byName.TryGetValue(role.DisplayName, out var doc);

            rebuilt.Add(role with
            {
                AllowedResourceActions = new List<string> { role.DisplayName },
                // Microsoft's description of the role, where the tenant supplied none.
                // A candidate with no description is one the model can only guess about.
                Description = string.IsNullOrWhiteSpace(role.Description) && doc is not null
                    ? doc.Description
                    : role.Description
            });
            filled++;
        }

        if (filled > 0) catalog.ReplaceAll(rebuilt, catalog.LastSyncedUtc ?? DateTimeOffset.UtcNow);
        return filled;
    }

    // ---------- persistence ----------

    public static PurviewRoleCatalog Load(string path)
    {
        if (!File.Exists(path)) return new PurviewRoleCatalog();
        try
        {
            var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            return JsonSerializer.Deserialize<PurviewRoleCatalog>(File.ReadAllText(path), opts)
                   ?? new PurviewRoleCatalog();
        }
        catch (Exception)
        {
            // A corrupt cache must never block the app — it is a cache, not a record.
            return new PurviewRoleCatalog();
        }
    }

    public void Save(string path)
    {
        var opts = new JsonSerializerOptions { WriteIndented = true };
        File.WriteAllText(path, JsonSerializer.Serialize(this, opts));
    }
}
