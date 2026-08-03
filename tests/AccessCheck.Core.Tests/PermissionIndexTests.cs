using AccessCheck.Core.Catalog;
using AccessCheck.Core.Recommendation;
using Xunit;

namespace AccessCheck.Core.Tests;

/// <summary>
/// Candidate selection decides what the model is ever ALLOWED to pick. Nothing downstream
/// can recover a permission that was never shown — the validator, the guards and the
/// verifier all operate on what came back, not on what was available. So a fault here is
/// invisible everywhere else, and shows up only as a plausible wrong answer.
/// </summary>
public class PermissionIndexTests
{
    // ---------- plural matching ----------

    [Theory]
    // The request's English plural against Microsoft's singular resource name. A plain
    // Contains fails every one of these, and they are the most relevant word in the request.
    [InlineData("remove-mailbox", "mailboxes")]
    [InlineData("microsoft.directory/conditionalaccesspolicies/allproperties/read", "policies")]
    [InlineData("new-compliancesearch", "compliance")]
    [InlineData("microsoft.directory/users/password/update", "passwords")]
    [InlineData("microsoft.directory/groups.security/members/update", "groups")]
    public void ARequestPluralMatchesASingularResourceName(string haystack, string word)
    {
        Assert.True(PermissionIndex.NameMatches(haystack, word));
    }

    [Theory]
    [InlineData("remove-mailbox", "devices")]
    [InlineData("microsoft.directory/users/password/update", "mailboxes")]
    public void UnrelatedWordsStillDoNotMatch(string haystack, string word)
    {
        Assert.False(PermissionIndex.NameMatches(haystack, word));
    }

    [Fact]
    public void StrippingDoesNotShortenAWordIntoAPrefixThatMatchesAnything()
    {
        // "as" must not become "a". A three-character floor keeps a plural rule from
        // turning into a wildcard that scores every permission in the tenant.
        Assert.False(PermissionIndex.NameMatches("microsoft.directory/users/create", "as"));
        Assert.False(PermissionIndex.NameMatches("microsoft.directory/users/create", "es"));
    }

    // ---------- segment vs substring ----------

    [Theory]
    [InlineData("microsoft.directory/users/password/update", "users")]
    // Singular request word, plural resource segment — the commonest shape, since requests
    // say "create user accounts" while Microsoft names the resource "users".
    [InlineData("microsoft.directory/users/create", "user")]
    [InlineData("Microsoft.Intune_DeviceConfigurations_Create", "deviceconfigurations")]
    // Plural request word, singular segment.
    [InlineData("microsoft.directory/groups/members/update", "groups")]
    public void AWordThatIsAWholeSegmentMatchesIt(string action, string word)
    {
        Assert.True(PermissionIndex.SegmentMatches(action, word));
    }

    [Theory]
    // The bug this exists for: agentUsers and guestUsers are different object types, and a
    // request about user accounts scored them exactly as highly as the real thing.
    [InlineData("microsoft.directory/agentUsers/disable", "users")]
    [InlineData("microsoft.directory/users/guestBasicProfile/limitedRead", "guests")]
    // COMPOUND SEGMENTS ARE THE SAME CASE. "policy" sits inside conditionalAccessPolicies
    // and "mailboxes" inside MailboxFolderPermission — related, but not the segment itself,
    // so they rank as substrings rather than winning the segment bonus outright.
    [InlineData("microsoft.directory/conditionalAccessPolicies/allProperties/read", "policy")]
    [InlineData("Add-MailboxFolderPermission", "mailboxes")]
    public void AWordBuriedInsideALongerSegmentIsNotASegmentMatch(string action, string word)
    {
        Assert.False(PermissionIndex.SegmentMatches(action, word));
    }

    [Theory]
    // ...but they must still MATCH, or the most relevant word in the request scores nothing
    // at all against the permission it names.
    [InlineData("microsoft.directory/conditionalaccesspolicies/allproperties/read", "policy")]
    [InlineData("add-mailboxfolderpermission", "mailboxes")]
    [InlineData("microsoft.directory/agentusers/disable", "users")]
    public void AWordInsideACompoundSegmentStillScoresAsASubstring(string action, string word)
    {
        Assert.True(PermissionIndex.NameMatches(action, word));
    }

    [Fact]
    public void TheRealResourceOutranksALongerNameContainingIt()
    {
        var catalog = CatalogWith(
            Role("r1", RbacProviders.Directory,
                 "microsoft.directory/agentUsers/disable",
                 "microsoft.directory/agentUsers/enable",
                 "microsoft.directory/agentUsers/delete",
                 "microsoft.directory/users/disable"));

        var top = PermissionIndex.CandidateActions(
            "disable user accounts for leavers", catalog, perProviderLimit: 1);

        Assert.Equal("microsoft.directory/users/disable", Assert.Single(top).Action);
    }

    // ---------- specialised identity types ----------

    [Fact]
    public void AgentIdentityPermissionsAreNotOfferedToAStaffAccountRequest()
    {
        // agentUsers are identities for AI agents, and their action list mirrors the real
        // one almost exactly. A duty to AMEND user accounts came back proposing eight of
        // them; a duty to DISABLE user accounts was left with nothing once its single
        // agentUsers proposal was stripped by the verifier.
        var catalog = CatalogWith(
            Role("r1", RbacProviders.Directory,
                 "microsoft.directory/agentUsers/disable",
                 "microsoft.directory/agentUsers/enable",
                 "microsoft.directory/agentUsers/delete",
                 "microsoft.directory/users/disable"));

        var candidates = PermissionIndex.CandidateActions(
            "disable user accounts for leavers", catalog);

        Assert.DoesNotContain(candidates,
            c => c.Action.Contains("agentUsers", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(candidates,
            c => c.Action.Equals("microsoft.directory/users/disable",
                                 StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ARequestAboutAgentsCanStillReachAgentPermissions()
    {
        // Suppressing a candidate makes it unreachable, so the gate has to open for a
        // request that genuinely means agent identities.
        var catalog = CatalogWith(
            Role("r1", RbacProviders.Directory,
                 "microsoft.directory/agentUsers/disable",
                 "microsoft.directory/users/disable"));

        var candidates = PermissionIndex.CandidateActions(
            "disable agent identities that are no longer in use", catalog);

        Assert.Contains(candidates,
            c => c.Action.Contains("agentUsers", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void TheServiceScopedListingAlsoWithholdsAgentIdentities()
    {
        // THE PATH THAT ACTUALLY MATTERS. Once a service is identified the pipeline uses
        // PermissionsInProviders, not CandidateActions — so gating only the latter left
        // the real door open. agentUsers also sorts BEFORE users alphabetically, so it won
        // the tie and took the slot: microsoft.directory/users/disable sat in the catalog
        // and never appeared in a single prompt.
        var catalog = CatalogWith(
            Role("r1", RbacProviders.Directory,
                 "microsoft.directory/agentUsers/disable",
                 "microsoft.directory/users/disable"));

        var offered = PermissionIndex.PermissionsInProviders(
            new[] { RbacProviders.Directory }, catalog, "disable user accounts for leavers");

        Assert.DoesNotContain(offered,
            e => e.Action.Contains("agentUsers", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(offered,
            e => e.Action.Equals("microsoft.directory/users/disable",
                                 StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void TheServiceScopedListingStillOffersAgentsWhenAsked()
    {
        var catalog = CatalogWith(
            Role("r1", RbacProviders.Directory,
                 "microsoft.directory/agentUsers/disable",
                 "microsoft.directory/users/disable"));

        var offered = PermissionIndex.PermissionsInProviders(
            new[] { RbacProviders.Directory }, catalog, "disable unused agent identities");

        Assert.Contains(offered,
            e => e.Action.Contains("agentUsers", StringComparison.OrdinalIgnoreCase));
    }

    // ---------- determinism ----------

    private static RoleCatalog CatalogWith(params RoleDefinitionRecord[] roles)
    {
        var c = new RoleCatalog();
        c.ReplaceAll(roles, new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        return c;
    }

    private static RoleDefinitionRecord Role(string id, string provider, params string[] actions) =>
        new()
        {
            Id = id,
            DisplayName = id,
            Provider = provider,
            IsBuiltIn = true,
            Description = "",
            AllowedResourceActions = actions.ToList()
        };

    [Fact]
    public void TheSameRequestProducesTheSameCandidatesEveryTime()
    {
        // Ties were left in catalog order, so identical runs returned different candidate
        // sets and therefore different recommendations. A recommendation that changes
        // between identical runs cannot be reviewed or defended afterwards.
        var catalog = CatalogWith(
            Role("r1", RbacProviders.Purview,
                 "New-ComplianceSearch", "Get-ComplianceCase", "Set-ComplianceTag",
                 "New-ComplianceSearchAction", "Get-ComplianceSearch"));

        var first = PermissionIndex.CandidateActions("run a compliance search", catalog)
            .Select(e => e.Action).ToList();
        var second = PermissionIndex.CandidateActions("run a compliance search", catalog)
            .Select(e => e.Action).ToList();

        Assert.Equal(first, second);
        Assert.NotEmpty(first);
    }

    [Fact]
    public void AMailboxRequestReachesMailboxPermissions()
    {
        // The end-to-end version of the plural bug: the request says "mailboxes" and every
        // relevant permission is named for a "Mailbox".
        var catalog = CatalogWith(
            Role("r1", RbacProviders.Exchange,
                 "Add-MailboxFolderPermission", "Get-MailboxFolderPermission"));

        var candidates = PermissionIndex.CandidateActions(
            "delegate access to mailboxes while staff are on leave", catalog);

        Assert.Contains(candidates, c =>
            c.Action.Equals("Add-MailboxFolderPermission", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ANarrowPermissionOutranksASweepingOneOnAnEqualScore()
    {
        // Both contain the request word. The specific one must survive the per-provider cap
        // ahead of the one that grants the whole service.
        var catalog = CatalogWith(
            Role("r1", RbacProviders.Intune,
                 "microsoft.intune/allEntities/allTasks",
                 "microsoft.intune/deviceConfigurations/create"));

        var candidates = PermissionIndex.CandidateActions(
            "create device configurations in intune", catalog, perProviderLimit: 1);

        Assert.Equal("microsoft.intune/deviceConfigurations/create",
                     Assert.Single(candidates).Action);
    }
}
