using System.Text.Json;

namespace AccessCheck.Core.Catalog;

/// <summary>
/// Short notes that distinguish a permission from the one it is repeatedly mistaken for.
///
/// WHY THESE EXIST. Microsoft's descriptions are accurate and sometimes uninformative next
/// to a near neighbour. "Disable users" against "Update basic properties on users" reads as
/// though the second is broader and therefore covers the first — so a duty to disable
/// accounts was answered with a property update, repeatedly, across many runs. The choosing
/// stage was not wrong about what either permission says; it was wrong about which one the
/// task needed, and nothing in front of it said so.
///
/// WHY THEY ARE KEPT SEPARATE FROM THE REFERENCE. This application's rule is that a
/// permission's meaning comes from Microsoft, never from an inference — PermissionIndex
/// says so, and MergeInto refuses to overwrite a Graph-sourced description for the same
/// reason. A note here is a human judgement, and a wrong one would be wrong persuasively
/// and permanently. So notes are APPENDED, never substituted, and rendered with their own
/// prefix: Microsoft still says what a permission is, the note says which similar thing it
/// is not.
///
/// WHAT BELONGS HERE. Only disambiguation between confusable actions, and only where the
/// confusion has actually been observed. Not commentary, not policy, not "be careful with
/// this one" — those belong in the guards, which are deterministic and testable.
/// </summary>
public sealed class ActionNoteStore
{
    public Dictionary<string, string> Notes { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    public bool IsEmpty => Notes.Count == 0;
    public int Count => Notes.Count;

    public string? Find(string action) =>
        Notes.TryGetValue(action, out var note) && !string.IsNullOrWhiteSpace(note) ? note : null;

    /// <summary>
    /// Microsoft's description with the note appended, or the description unchanged where
    /// there is no note. The prefix matters: an approver reading a card should be able to
    /// tell which half came from Microsoft.
    /// </summary>
    public string Describe(string action, string microsoftDescription)
    {
        var note = Find(action);
        if (note is null) return microsoftDescription;

        return string.IsNullOrWhiteSpace(microsoftDescription)
            ? "AccessCheck note: " + note
            : microsoftDescription.TrimEnd() + "  AccessCheck note: " + note;
    }

    // ---------- installation ----------

    /// <summary>
    /// The notes in force for this process. Consulted by PromptBuilder when it renders a
    /// candidate line, and by nothing else.
    /// </summary>
    private static ActionNoteStore _installed = new();

    /// <summary>
    /// Installs the notes for rendering. Follows the same ambient pattern as
    /// ActionRisk.UseDescriptions, which this application already uses for reference data
    /// that every stage needs and nothing should have to thread through.
    /// </summary>
    public static void Install(ActionNoteStore store) => _installed = store;

    /// <summary>The note for an action, or empty. Safe before Install is ever called.</summary>
    public static string NoteFor(string action) => _installed.Find(action) ?? "";

    /// <summary>
    /// WHY NOTES ARE NEVER WRITTEN INTO A DESCRIPTION.
    ///
    /// The first version appended them to ReferenceStore.Description, which reached the
    /// prompt correctly and broke CitationCheck: that guard compares the description the
    /// model QUOTED against the one this application holds, so a model faithfully quoting
    /// an annotated description was judged to have invented it. Four correct permissions
    /// were excluded in one run — users/disable, users/enable, RemoteTasks_Retire and
    /// assignLicense — and every one of them was an action carrying a note. Nothing
    /// unannotated failed.
    ///
    /// The lesson is not that CitationCheck needed a special case. It is that a description
    /// has more consumers than are obvious, and any of them may compare it verbatim against
    /// something. So Microsoft's description stays exactly Microsoft's everywhere, and the
    /// note is added at RENDER time by the one component whose job is presentation.
    /// </summary>
    /// <summary>
    /// Applies every note to a descriptions dictionary, in place. Returns how many were
    /// applied, so a caller can report it rather than changing behaviour silently.
    /// </summary>
    public int ApplyTo(Dictionary<string, string> descriptions)
    {
        if (IsEmpty) return 0;

        var applied = 0;
        foreach (var (action, note) in Notes)
        {
            if (string.IsNullOrWhiteSpace(note)) continue;

            descriptions.TryGetValue(action, out var existing);
            descriptions[action] = Describe(action, existing ?? "");
            applied++;
        }
        return applied;
    }

    // ---------- persistence ----------

    public static ActionNoteStore Load(string path)
    {
        if (!File.Exists(path)) return Builtin();
        try
        {
            var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            var loaded = JsonSerializer.Deserialize<ActionNoteStore>(File.ReadAllText(path), opts);
            if (loaded is null) return Builtin();

            loaded.Notes = new Dictionary<string, string>(loaded.Notes, StringComparer.OrdinalIgnoreCase);
            return loaded;
        }
        catch (Exception)
        {
            return Builtin();
        }
    }

    public void Save(string path)
    {
        var opts = new JsonSerializerOptions { WriteIndented = true };
        File.WriteAllText(path, JsonSerializer.Serialize(this, opts));
    }

    /// <summary>
    /// The notes shipped with the application. Every one of these corrects a confusion that
    /// was OBSERVED producing a wrong recommendation, not one that seemed likely.
    /// </summary>
    public static ActionNoteStore Builtin()
    {
        var store = new ActionNoteStore();

        // OBSERVED: a duty to disable accounts answered with basic/update across many runs,
        // and once endorsed by the verifier as "can update user properties, which includes
        // disabling accounts". It cannot.
        store.Notes["microsoft.directory/users/disable"] =
            "This is the ONLY action that disables a user account. A basic or standard "
            + "property update does not disable anything.";
        store.Notes["microsoft.directory/users/basic/update"] =
            "Properties only — display name, job title, department. It does NOT disable, "
            + "enable, delete or reset the password of an account; each of those is a "
            + "separate action.";
        store.Notes["microsoft.directory/users/enable"] =
            "This is the ONLY action that re-enables a disabled account.";

        // OBSERVED: agentUsers proposed for staff-account duties on almost every run until
        // they were withheld from the candidate list entirely.
        store.Notes["microsoft.directory/agentUsers/disable"] =
            "AGENT identities, not staff accounts. A request about user accounts means "
            + "microsoft.directory/users/disable.";
        store.Notes["microsoft.directory/agentUsers/create"] =
            "AGENT identities, not staff accounts. A request about user accounts means "
            + "microsoft.directory/users/create.";

        // OBSERVED: proposed for a request to delete MESSAGES. It would have destroyed the
        // mailbox and the user account with it.
        store.Notes["Remove-Mailbox"] =
            "Deletes the ENTIRE MAILBOX and its user account. To delete individual messages "
            + "use New-ComplianceSearchAction -Purge in Purview.";
        store.Notes["Search-Mailbox"] =
            "Deprecated in Exchange Online. Content search and purge is "
            + "New-ComplianceSearch plus New-ComplianceSearchAction in Purview.";

        // OBSERVED: access reviews proposed for a duty to manage group membership.
        store.Notes["microsoft.directory/accessReviews/definitions.groups/create"] =
            "Creates a review CAMPAIGN over group membership. It does not add or remove "
            + "members — that is microsoft.directory/groups/members/update.";
        store.Notes["microsoft.directory/groups/members/update"] =
            "Adds and removes group MEMBERS. Not the group itself, and not an access review.";

        // OBSERVED: assignLicense proposed for a duty that only needed to REPORT on licence
        // consumption, which then folded into an account-management grant.
        store.Notes["microsoft.directory/users/assignLicense"] =
            "ASSIGNS licences — a write. Reporting on licence allocation needs a read, not "
            + "this.";

        // OBSERVED: enrollment-manager permissions proposed for a duty to enrol devices.
        store.Notes["Microsoft.Intune_DeviceEnrollmentManagers_Update"] =
            "Manages the enrollment MANAGER accounts, not the devices they enrol.";

        // OBSERVED: a duty to retire devices answered with ManagedDevices_Delete. Retiring
        // removes company data and leaves the device; deleting removes the record.
        store.Notes["Microsoft.Intune_RemoteTasks_Retire"] =
            "Removes company data from a device and leaves the device itself. Deleting the "
            + "device RECORD is Microsoft.Intune_ManagedDevices_Delete.";
        store.Notes["Microsoft.Intune_ManagedDevices_Delete"] =
            "Deletes the device RECORD from Intune. It does not remove company data from the "
            + "device — that is Microsoft.Intune_RemoteTasks_Retire.";

        // OBSERVED: mailbox delegation answered with the folder-level permission, and folder
        // delegation answered with the full-access one. They are different grants.
        store.Notes["Add-MailboxPermission"] =
            "FULL access to the whole mailbox. Access to specific folders only is "
            + "Add-MailboxFolderPermission.";
        store.Notes["Add-MailboxFolderPermission"] =
            "Access to named FOLDERS within a mailbox. Full mailbox access is "
            + "Add-MailboxPermission.";

        // OBSERVED: search-and-purge duties answered with the compliance search removal
        // cmdlet, which deletes the search rather than the messages it found.
        store.Notes["Remove-ComplianceSearch"] =
            "Deletes the SEARCH, not the messages it found. Deleting messages is "
            + "New-ComplianceSearchAction -Purge.";

        return store;
    }
}
