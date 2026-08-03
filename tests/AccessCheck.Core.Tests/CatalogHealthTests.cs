using AccessCheck.Core.Catalog;
using AccessCheck.Core.Recommendation;
using Xunit;

namespace AccessCheck.Core.Tests;

/// <summary>
/// Each of these reproduces a catalog state that actually occurred, produced wrong
/// recommendations, and raised nothing at the time.
/// </summary>
public class CatalogHealthTests
{
    private static RoleDefinitionRecord Role(
        string id, string provider, params string[] actions) =>
        new()
        {
            Id = id,
            DisplayName = id,
            Provider = provider,
            IsBuiltIn = true,
            Description = "",
            AllowedResourceActions = actions.ToList()
        };

    private static RoleCatalog CatalogOf(params RoleDefinitionRecord[] roles)
    {
        var c = new RoleCatalog();
        c.ReplaceAll(roles, new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        return c;
    }

    [Fact]
    public void AProviderWithRolesAndNoPermissionsIsBroken()
    {
        // THE PURVIEW CASE. 120 roles, zero permissions between them, reported as a healthy
        // sync. Every Purview request fell through to another service, and a request to
        // purge phishing mail came back with Remove-Mailbox — which deletes the mailbox.
        var catalog = CatalogOf(
            Role("Search And Purge", RbacProviders.Purview),
            Role("Compliance Search", RbacProviders.Purview),
            Role("Case Management", RbacProviders.Purview));

        var findings = CatalogHealth.Check(catalog);

        Assert.Contains(findings, f =>
            f.Severity == CatalogHealth.Severity.Broken &&
            f.Provider == RbacProviders.Purview);
    }

    [Fact]
    public void TwoActionFormatsInOneProviderIsBroken()
    {
        // THE EXCHANGE CASE. One of three entry paths did not strip the module qualifier, so
        // the catalog held 2,734 fully-qualified strings beside 466 bare cmdlet names.
        // Nothing could match the first kind, and whether a request worked depended on which
        // path had supplied that role.
        var catalog = CatalogOf(
            Role("Mail Recipients", RbacProviders.Exchange,
                 "(Microsoft.Exchange.Management.PowerShell.E2010) Add-MailboxPermission -AccessRights",
                 "(Microsoft.Exchange.Management.PowerShell.E2010) Get-Mailbox -Identity"),
            Role("MyBaseOptions", RbacProviders.Exchange,
                 "Add-MailboxFolderPermission",
                 "Get-MailboxFolderPermission"));

        var findings = CatalogHealth.Check(catalog);

        Assert.Contains(findings, f =>
            f.Severity == CatalogHealth.Severity.Broken &&
            f.Title.Contains("two action formats", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void OneConsistentFormatIsNotFlagged()
    {
        var catalog = CatalogOf(
            Role("Mail Recipients", RbacProviders.Exchange,
                 "Add-MailboxPermission", "Get-Mailbox"),
            Role("MyBaseOptions", RbacProviders.Exchange,
                 "Add-MailboxFolderPermission"));

        Assert.DoesNotContain(CatalogHealth.Check(catalog), f =>
            f.Title.Contains("two action formats", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ARoleThatCollapsedSinceTheLastSyncIsFlagged()
    {
        // THE MAIL RECIPIENTS CASE. A transient error during the entry fetch, swallowed by
        // the per-role try/catch, stored 1 cmdlet where the tenant reports 178 — and
        // Add-MailboxPermission was then reported as an action Microsoft does not define.
        var before = CatalogOf(Role("Mail Recipients", RbacProviders.Exchange,
            Enumerable.Range(1, 178).Select(i => "Cmdlet-" + i).ToArray()));

        var after = CatalogOf(Role("Mail Recipients", RbacProviders.Exchange, "Cmdlet-1"));

        var findings = CatalogHealth.Check(after, before);

        Assert.Contains(findings, f =>
            f.Title.Contains("collapsed", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void AnOrdinarySmallRoleIsNotMistakenForACollapse()
    {
        // Plenty of roles legitimately hold one or two cmdlets — Application Mail.Read,
        // MyDisplayName. Flagging those would make the check noise, and a noisy check is one
        // people learn to scroll past.
        var before = CatalogOf(Role("MyDisplayName", RbacProviders.Exchange, "Set-User"));
        var after = CatalogOf(Role("MyDisplayName", RbacProviders.Exchange, "Set-User"));

        Assert.DoesNotContain(CatalogHealth.Check(after, before), f =>
            f.Title.Contains("collapsed", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ADeliberatelyTrimmedRoleIsNotACollapse()
    {
        // An administrator removing a few entries is normal. Only a ten-fold drop looks like
        // a fetch that failed halfway.
        var before = CatalogOf(Role("Custom", RbacProviders.Exchange,
            Enumerable.Range(1, 20).Select(i => "Cmdlet-" + i).ToArray()));
        var after = CatalogOf(Role("Custom", RbacProviders.Exchange,
            Enumerable.Range(1, 15).Select(i => "Cmdlet-" + i).ToArray()));

        Assert.DoesNotContain(CatalogHealth.Check(after, before), f =>
            f.Title.Contains("collapsed", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void AMostlyEmptyProviderWarnsWithoutClaimingItIsBroken()
    {
        // Purview after the documented role list is imported: some roles have vocabulary,
        // most do not, and that is the best the service allows. The operator should know how
        // much is unreachable without being told the service does not work.
        var roles = new List<RoleDefinitionRecord>
        {
            Role("Search And Purge", RbacProviders.Purview, "New-ComplianceSearchAction")
        };
        for (var i = 0; i < 10; i++)
            roles.Add(Role("Empty-" + i, RbacProviders.Purview));

        var findings = CatalogHealth.Check(CatalogOf(roles.ToArray()));

        Assert.Contains(findings, f => f.Severity == CatalogHealth.Severity.Warning);
        Assert.DoesNotContain(findings, f => f.Severity == CatalogHealth.Severity.Broken);
    }

    [Fact]
    public void AHealthyCatalogProducesNothing()
    {
        // Silence has to mean something, or the check is decoration.
        var catalog = CatalogOf(
            Role("User Administrator", RbacProviders.Directory,
                 "microsoft.directory/users/create",
                 "microsoft.directory/users/disable"),
            Role("Helpdesk Administrator", RbacProviders.Directory,
                 "microsoft.directory/users/password/update"));

        Assert.Empty(CatalogHealth.Check(catalog));
    }
}
