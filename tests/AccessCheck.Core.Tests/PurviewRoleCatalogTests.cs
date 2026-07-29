using AccessCheck.Core.Catalog;
using Xunit;

namespace AccessCheck.Core.Tests;

public class PurviewRoleCatalogTests
{
    // A cut-down version of the two tables Microsoft publishes, in the shape the real page
    // uses: pipe-delimited, emphasis on names, roles run together in one cell separated by
    // runs of whitespace.
    private const string Sample = """
        # Roles and role groups

        Some prose that must not be parsed as a row.

        | Role group | Description | Default roles assigned |
        | --- | --- | --- |
        | **Data Investigator** | Perform searches on mailboxes. | Compliance Search      Custodian      Export      Search And Purge |
        | **Organization Management**¹ | Members can control permissions. | Audit Logs      Case Management      Compliance Search      Role Management      Search And Purge |
        | **Audit Reader** | Search, View, and Export Audit logs. | View-Only Audit Logs |

        More prose between the tables.

        | Role | Description | Default role group assignments |
        | --- | --- | --- |
        | **Search And Purge** | Lets people bulk-remove data. | Data Investigator      Organization Management |
        | **Compliance Search** | Perform searches across mailboxes. | Data Investigator      Organization Management |
        | \***Custodian** | Identify and manage custodians. | Data Investigator |
        | **Audit Logs** | Turn on and configure auditing. | Organization Management |
        """;

    private static PurviewRoleCatalog Parsed() =>
        PurviewRoleCatalog.ParseLearnMarkdown(Sample, "test");

    [Fact]
    public void BothTablesAreRecognisedSeparately()
    {
        var c = Parsed();

        Assert.Equal(3, c.RoleGroups.Count);
        Assert.Equal(4, c.Roles.Count);
    }

    [Fact]
    public void ProseBetweenTablesIsNotParsedAsRows()
    {
        // Without ending the table on a non-pipe line, the prose separating the two tables
        // would be read as continuation rows of the first.
        Assert.DoesNotContain(Parsed().RoleGroups, g => g.Name.Contains("prose"));
    }

    [Fact]
    public void EmphasisAndFootnoteMarkersAreStrippedFromNames()
    {
        var c = Parsed();

        // Must match the plain string the tenant reports, not the markdown around it.
        Assert.Contains(c.RoleGroups, g => g.Name == "Organization Management");
        Assert.Contains(c.Roles, r => r.Name == "Custodian");
    }

    [Fact]
    public void RunTogetherRoleListsSplitOnRunsOfWhitespaceNotSingleSpaces()
    {
        // A single-space split shreds "Compliance Search" into two roles that exist nowhere.
        var group = Parsed().RoleGroups.Single(g => g.Name == "Data Investigator");

        Assert.Equal(4, group.Roles.Count);
        Assert.Contains("Compliance Search", group.Roles);
        Assert.Contains("Search And Purge", group.Roles);
        Assert.DoesNotContain("Compliance", group.Roles);
    }

    [Fact]
    public void ARoleCanBeLookedUpByTheNameTheTenantUses()
    {
        var role = Parsed().Find("search and purge");

        Assert.NotNull(role);
        Assert.NotEmpty(role!.Description);
    }

    // ---------- the least-privilege comparison ----------

    [Fact]
    public void GroupsCarryingARoleAreListedNarrowestFirst()
    {
        // The narrowest built-in alternative is the one worth naming: it is the smallest
        // over-grant an operator avoids by composing a group instead.
        var groups = Parsed().GroupsCarrying("Search And Purge");

        Assert.Equal(2, groups.Count);
        Assert.Equal("Data Investigator", groups[0].Name);
    }

    [Fact]
    public void TheExcessOfTheNarrowestAlternativeIsQuantified()
    {
        // Data Investigator carries 4 roles; the plan needs 1. Granting it hands over 3
        // roles nobody asked for, and that number is the argument for a custom group.
        var excess = Parsed().ExcessRolesInNarrowestAlternative(new[] { "Search And Purge" });

        Assert.Equal(3, excess);
    }

    [Fact]
    public void NoSingleBuiltInGroupCoveringTheSetReturnsNull()
    {
        // Null is not "no excess" — it means the alternative is granting TWO built-in
        // groups, which is the strongest case for composing one.
        var excess = Parsed().ExcessRolesInNarrowestAlternative(
            new[] { "Search And Purge", "View-Only Audit Logs" });

        Assert.Null(excess);
    }

    [Fact]
    public void AnEmptyOrCorruptSourceProducesAnEmptyCatalogNotAnError()
    {
        Assert.True(PurviewRoleCatalog.ParseLearnMarkdown("").IsEmpty);
        Assert.True(PurviewRoleCatalog.ParseLearnMarkdown("not a table at all").IsEmpty);
    }
}
