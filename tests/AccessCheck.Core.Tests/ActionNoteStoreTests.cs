using AccessCheck.Core.Catalog;
using Xunit;

namespace AccessCheck.Core.Tests;

/// <summary>
/// Notes are a human judgement sitting beside Microsoft's. That is a deliberate exception
/// to this application's rule that a permission's meaning comes from Microsoft alone, so
/// the constraints on it matter as much as the content: appended, never substituted, and
/// visibly attributed.
/// </summary>
public class ActionNoteStoreTests
{
    [Fact]
    public void MicrosoftsDescriptionIsKeptAndTheNoteIsAppended()
    {
        // If a note could REPLACE a description, a wrong note would be wrong permanently and
        // invisibly. Appending keeps the authoritative text in front of the reader.
        var store = ActionNoteStore.Builtin();

        var text = store.Describe("microsoft.directory/users/disable", "Disable users.");

        Assert.Contains("Disable users.", text);
        Assert.Contains("AccessCheck note:", text);
    }

    [Fact]
    public void AnActionWithNoNoteIsReturnedUnchanged()
    {
        var store = ActionNoteStore.Builtin();

        Assert.Equal("Read basic properties on groups.",
            store.Describe("microsoft.directory/groups/standard/read",
                           "Read basic properties on groups."));
    }

    [Fact]
    public void ANoteSurvivesAnEmptyMicrosoftDescription()
    {
        // Exchange cmdlets carried no description at all until the docs import, and some
        // still will. A note is better than nothing, and must still be attributed.
        var store = ActionNoteStore.Builtin();

        var text = store.Describe("Remove-Mailbox", "");

        Assert.StartsWith("AccessCheck note:", text);
        Assert.Contains("ENTIRE MAILBOX", text);
    }

    [Fact]
    public void TheConfusionThatCostTheMostIsCovered()
    {
        // A duty to disable accounts was answered with basic/update across many runs, and
        // once endorsed by the verifier as "includes disabling accounts". Both sides of that
        // confusion carry a note, because correcting only one leaves the other persuasive.
        var store = ActionNoteStore.Builtin();

        Assert.NotNull(store.Find("microsoft.directory/users/disable"));
        Assert.NotNull(store.Find("microsoft.directory/users/basic/update"));
    }

    [Fact]
    public void ApplyToAnnotatesInPlaceAndReportsHowMany()
    {
        var store = ActionNoteStore.Builtin();
        var descriptions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["microsoft.directory/users/disable"] = "Disable users.",
            ["microsoft.directory/groups/standard/read"] = "Read basic properties on groups."
        };

        var applied = store.ApplyTo(descriptions);

        Assert.True(applied > 0);
        Assert.Contains("AccessCheck note:", descriptions["microsoft.directory/users/disable"]);
        Assert.DoesNotContain("AccessCheck note:",
            descriptions["microsoft.directory/groups/standard/read"]);
    }

    [Fact]
    public void MicrosoftsDescriptionIsNeverModified()
    {
        // THE FAILURE THIS DESIGN EXISTS TO PREVENT. Written into the description, the note
        // reached the prompt correctly and broke CitationCheck — that guard compares the
        // description the model QUOTED against the one held here, so a model quoting an
        // annotated description faithfully was judged to have invented it. Four correct
        // permissions were excluded in one run, and every one carried a note.
        var reference = new ReferenceStore();
        reference.Entries.Add(new ReferenceStore.ReferenceEntry
        {
            Name = "microsoft.directory/users/disable",
            Description = "Disable users."
        });

        ActionNoteStore.Install(ActionNoteStore.Builtin());

        Assert.Equal("Disable users.", reference.Entries[0].Description);
        Assert.DoesNotContain("AccessCheck note",
            reference.Descriptions()["microsoft.directory/users/disable"]);
    }

    [Fact]
    public void AnInstalledNoteIsAvailableForRendering()
    {
        ActionNoteStore.Install(ActionNoteStore.Builtin());

        Assert.Contains("ONLY action that disables",
            ActionNoteStore.NoteFor("microsoft.directory/users/disable"));
        Assert.Equal("", ActionNoteStore.NoteFor("microsoft.directory/groups/standard/read"));
    }

    [Fact]
    public void ANoteIsFoundRegardlessOfCasing()
    {
        // Cmdlet casing varies between the docs, the tenant and the model's recall.
        var store = ActionNoteStore.Builtin();

        Assert.NotNull(store.Find("remove-mailbox"));
        Assert.NotNull(store.Find("REMOVE-MAILBOX"));
    }

    [Fact]
    public void EveryNoteNamesTheAlternativeRatherThanJustWarning()
    {
        // A note that only says "be careful" belongs in a guard. These exist to point at the
        // permission the request actually needed, so each should name something concrete.
        var store = ActionNoteStore.Builtin();

        foreach (var (action, note) in store.Notes)
        {
            Assert.False(string.IsNullOrWhiteSpace(note), action);
            Assert.True(note.Length > 40, action + ": note too short to disambiguate");
        }
    }
}
