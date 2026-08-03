namespace AccessCheck.Core.Config;

/// <summary>
/// Copies the reference data shipped inside the package into the user's data folder on
/// first run.
///
/// WHY THIS EXISTS. Two files carry knowledge no tenant can produce for itself:
///
///   purview-roles.json — the Security and Compliance session cannot report what a Purview
///   role contains, so without this a tenant reporting 120 roles holds vocabulary for 8 of
///   them and most Purview requests return nothing at all.
///
///   exchange-descriptions.json — no API supplies Exchange or Purview cmdlet descriptions,
///   and Exchange Online's REST mode generates proxy cmdlets with no help content, so even
///   Get-Help returns an empty synopsis. Without them the model reads names only, which is
///   how a request to remove MESSAGES came back with Remove-Mailbox — a cmdlet that deletes
///   the mailbox and the user account with it.
///
/// Both are identical for every tenant, so they belong in the package rather than being
/// something each new user has to know to import. Shipping without them means every fresh
/// install silently reproduces failures that were already fixed.
///
/// NEVER OVERWRITES. A user who has re-imported has data newer than this build, and a
/// version bump must not quietly roll it back to whatever was current when the package was
/// made.
/// </summary>
public static class SeedData
{
    /// <summary>Files copied on first run. Anything here must be tenant-independent.</summary>
    private static readonly string[] Seeded =
    {
        // The MARKDOWN, not a parsed cache. It is what Microsoft actually publishes, it is
        // diffable when they revise it, and parsing it in the app keeps the parser and the
        // data from drifting apart inside the package. PurviewRoleCatalog.LoadOrImport
        // converts it once on first use.
        "purview-roles.md",
        "exchange-descriptions.json"
    };

    /// <summary>
    /// Copies any missing seed file from the install directory into <paramref name="dataDir"/>.
    /// Returns the names copied, so the caller can say what happened rather than doing it
    /// silently — a first run that quietly installs a thousand descriptions is harder to
    /// diagnose later than one that mentions it.
    /// </summary>
    public static IReadOnlyList<string> EnsureSeeded(string dataDir)
    {
        var copied = new List<string>();

        // The package's own folder. Under MSIX this is read-only, which is exactly why the
        // data has to be copied out rather than used in place — the app rewrites these
        // files when the operator re-imports.
        var source = Path.Combine(AppContext.BaseDirectory, "data");
        if (!Directory.Exists(source)) return copied;

        try { Directory.CreateDirectory(dataDir); }
        catch (Exception) { return copied; }

        foreach (var name in Seeded)
        {
            var from = Path.Combine(source, name);
            var to = Path.Combine(dataDir, name);

            if (!File.Exists(from)) continue;
            if (File.Exists(to)) continue;   // the user's copy always wins

            try
            {
                File.Copy(from, to);
                copied.Add(name);
            }
            catch (Exception)
            {
                // A failed seed must never stop the app starting. The consequence is a
                // degraded catalog, which the Purview coverage message already reports.
            }
        }

        return copied;
    }
}
