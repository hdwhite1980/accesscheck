using AccessCheck.Core.Catalog;
using AccessCheck.Core.Recommendation;
using Xunit;

namespace AccessCheck.Core.Tests;

/// <summary>
/// The GUARDS — the layer between a plausible-looking suggestion and an approved grant.
///
/// These had no tests. That mattered more than it looks: a guard that stops firing does
/// not fail loudly, it just goes quiet, and a quiet guard is indistinguishable from a
/// clean request. Every assertion here is a failure mode that has already happened once.
/// </summary>
public class GuardTests
{
    private static RoleCatalog CatalogWith(params RoleDefinitionRecord[] roles)
    {
        var c = new RoleCatalog();
        c.ReplaceAll(roles, new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        return c;
    }

    private static RoleDefinitionRecord Role(
        string id, string name, string provider, params string[] actions) =>
        new()
        {
            Id = id,
            DisplayName = name,
            Provider = provider,
            IsBuiltIn = true,
            Description = "test role",
            AllowedResourceActions = actions.ToList()
        };

    // ================= PermissionBreadth =================

    [Theory]
    [InlineData("microsoft.intune/allEntities/allTasks", BreadthLevel.ServiceWide)]
    [InlineData("microsoft.directory/administrativeUnits/allProperties/allTasks", BreadthLevel.ServiceWide)]
    [InlineData("microsoft.directory/groups/allProperties/read", BreadthLevel.Broad)]
    [InlineData("microsoft.directory/users/password/update", BreadthLevel.Specific)]
    [InlineData("microsoft.directory/users/standard/read", BreadthLevel.Specific)]
    public void Breadth_IsClassifiedFromTheActionShape(string action, BreadthLevel expected)
    {
        Assert.Equal(expected, PermissionBreadth.Classify(action));
    }

    [Fact]
    public void ServiceWideGrantIsFlaggedWhenSomethingNarrowerExists()
    {
        var catalog = CatalogWith(Role(
            "r1", "Intune Administrator", RbacProviders.Intune,
            "microsoft.intune/allEntities/allTasks",
            "microsoft.intune/deviceConfigurations/read"));

        var findings = PermissionBreadth.Findings(
            new[] { "microsoft.intune/allEntities/allTasks" }, catalog);

        var finding = Assert.Single(findings);
        Assert.Equal(BreadthLevel.ServiceWide, finding.Level);
        Assert.NotEmpty(finding.Examples);
    }

    [Fact]
    public void SpecificGrantIsNotFlagged()
    {
        var catalog = CatalogWith(Role(
            "r1", "Helpdesk", RbacProviders.Directory,
            "microsoft.directory/users/password/update",
            "microsoft.directory/users/standard/read"));

        var findings = PermissionBreadth.Findings(
            new[] { "microsoft.directory/users/password/update" }, catalog);

        Assert.Empty(findings);
    }

    [Fact]
    public void ServiceWideGrantIsNotFlaggedWhenTheServiceOffersNothingNarrower()
    {
        // Silence here is CORRECT, not a missed finding. Telling an operator a grant is
        // too broad while offering no alternative is advice they cannot act on.
        var catalog = CatalogWith(Role(
            "r1", "Blunt", RbacProviders.Defender,
            "microsoft.defender/allEntities/allTasks"));

        var findings = PermissionBreadth.Findings(
            new[] { "microsoft.defender/allEntities/allTasks" }, catalog);

        Assert.Empty(findings);
    }

    [Fact]
    public void WholeServiceAndWholeResourceAreDescribedDifferently()
    {
        // These are different breadths and were once worded identically. Overstating
        // "every task on administrativeUnits" as "every entity in Entra ID" is the kind of
        // exaggeration an operator checks once and then stops trusting the card.
        var catalog = CatalogWith(Role(
            "r1", "Directory", RbacProviders.Directory,
            "microsoft.directory/allEntities/allTasks",
            "microsoft.directory/administrativeUnits/allProperties/allTasks",
            "microsoft.directory/administrativeUnits/standard/read",
            "microsoft.directory/users/standard/read"));

        var whole = PermissionBreadth.Findings(
            new[] { "microsoft.directory/allEntities/allTasks" }, catalog);
        var resource = PermissionBreadth.Findings(
            new[] { "microsoft.directory/administrativeUnits/allProperties/allTasks" }, catalog);

        Assert.Contains("EVERY entity", Assert.Single(whole).Message);
        Assert.DoesNotContain("EVERY entity", Assert.Single(resource).Message);
    }

    // ================= RoleGroupPlan =================
    //
    // Purview's ONLY least-privilege path. It cannot create custom management roles, so a
    // minimal set cover over built-in roles is the answer — there is no fallback if this
    // is wrong.

    [Fact]
    public void SetCover_SpansTwoRolesWhenNoSingleRoleHoldsEverything()
    {
        // The motivating case: search-and-purge needs cmdlets that live in two different
        // roles, so a single-parent derivation finds nothing and recommends nothing.
        var catalog = CatalogWith(
            Role("p1", "Compliance Search", RbacProviders.Purview, "New-ComplianceSearch"),
            Role("p2", "Search And Purge", RbacProviders.Purview, "New-ComplianceSearchAction"));

        var plan = RoleGroupPlan.Build(
            catalog, RbacProviders.Purview,
            new[] { "New-ComplianceSearch", "New-ComplianceSearchAction" },
            "ACG - purge");

        Assert.True(plan.IsComplete);
        Assert.Equal(2, plan.Roles.Count);
        Assert.Empty(plan.Uncovered);
    }

    [Fact]
    public void SetCover_PrefersOneRoleThatCoversEverythingOverTwoThatDo()
    {
        var catalog = CatalogWith(
            Role("p1", "Does Both", RbacProviders.Purview, "A-Cmdlet", "B-Cmdlet"),
            Role("p2", "Does A", RbacProviders.Purview, "A-Cmdlet"),
            Role("p3", "Does B", RbacProviders.Purview, "B-Cmdlet"));

        var plan = RoleGroupPlan.Build(
            catalog, RbacProviders.Purview, new[] { "A-Cmdlet", "B-Cmdlet" }, "ACG - both");

        Assert.True(plan.IsComplete);
        var role = Assert.Single(plan.Roles);
        Assert.Equal("Does Both", role.RoleName);
    }

    [Fact]
    public void SetCover_BreaksTiesOnRiskWeightedExcessNotRawCount()
    {
        // Equal coverage, and the narrow role must win. Raw excess COUNT would prefer the
        // dangerous one here (1 extra vs 3), which is backwards.
        var catalog = CatalogWith(
            Role("p1", "Few But Dangerous", RbacProviders.Purview,
                 "Get-Thing", "New-RoleGroup"),
            Role("p2", "Many But Harmless", RbacProviders.Purview,
                 "Get-Thing", "Get-Other", "Get-Third", "Get-Fourth"));

        var plan = RoleGroupPlan.Build(
            catalog, RbacProviders.Purview, new[] { "Get-Thing" }, "ACG - read");

        var role = Assert.Single(plan.Roles);
        Assert.Equal("Many But Harmless", role.RoleName);
    }

    [Fact]
    public void SetCover_ReportsUncoveredRatherThanClaimingSuccess()
    {
        var catalog = CatalogWith(
            Role("p1", "Partial", RbacProviders.Purview, "A-Cmdlet"));

        var plan = RoleGroupPlan.Build(
            catalog, RbacProviders.Purview, new[] { "A-Cmdlet", "Z-Cmdlet" }, "ACG - x");

        Assert.False(plan.IsComplete);
        Assert.Equal("Z-Cmdlet", Assert.Single(plan.Uncovered));
        Assert.Contains("INCOMPLETE", plan.Headline);
    }

    [Fact]
    public void PurviewExcessIsUnavoidable_ExchangeExcessIsStripped()
    {
        // Purview has no New-ManagementRole. A plan that says "stripped by derivation"
        // there describes a grant that cannot execute.
        var purview = CatalogWith(
            Role("p1", "Broad", RbacProviders.Purview, "Get-Thing", "Set-Thing"));
        var exchange = CatalogWith(
            Role("e1", "Broad", RbacProviders.Exchange, "Get-Thing", "Set-Thing"));

        var purviewPlan = RoleGroupPlan.Build(
            purview, RbacProviders.Purview, new[] { "Get-Thing" }, "ACG - p");
        var exchangePlan = RoleGroupPlan.Build(
            exchange, RbacProviders.Exchange, new[] { "Get-Thing" }, "ACG - e");

        Assert.True(purviewPlan.CompositionOnly);
        Assert.Contains("unavoidable", purviewPlan.Headline);

        Assert.False(exchangePlan.CompositionOnly);
        Assert.True(exchangePlan.Roles.Single().NeedsDerivation);
    }

    [Fact]
    public void DistinctGroupName_DiffersByRoleSetAndStaysWithinTheLimit()
    {
        // Role groups cannot have roles added after creation, so reusing a name whose
        // contents differ is unfixable in place. The stamp must survive truncation.
        var longName = "ACG - " + new string('x', 200);

        var catalog = CatalogWith(
            Role("p1", "Alpha", RbacProviders.Purview, "A-Cmdlet"),
            Role("p2", "Beta", RbacProviders.Purview, "B-Cmdlet"));

        var planA = RoleGroupPlan.Build(catalog, RbacProviders.Purview,
            new[] { "A-Cmdlet" }, longName);
        var planB = RoleGroupPlan.Build(catalog, RbacProviders.Purview,
            new[] { "B-Cmdlet" }, longName);

        Assert.True(planA.DistinctGroupName.Length <= 64);
        Assert.True(planB.DistinctGroupName.Length <= 64);
        Assert.NotEqual(planA.DistinctGroupName, planB.DistinctGroupName);
    }

    // ================= CapabilityCoverage =================
    //
    // The only guard that looks for too LITTLE. Everything else checks for excess.

    [Fact]
    public void SearchOnlyPermissionsDoNotSatisfyAPurgeRequest()
    {
        var gaps = CapabilityCoverage.Gaps(
            "search all mailboxes and permanently delete the message",
            new[]
            {
                ("ExecuteSearch", "Run a compliance search."),
                ("GetSearchResults", "View the results of a compliance search.")
            });

        var gap = Assert.Single(gaps);
        Assert.Equal("delete or purge", gap.Capability);
        Assert.False(gap.NamesOnly);
    }

    [Fact]
    public void APermissionThatCanDeleteClosesTheGap()
    {
        var gaps = CapabilityCoverage.Gaps(
            "search all mailboxes and permanently delete the message",
            new[]
            {
                ("ExecuteSearch", "Run a compliance search."),
                ("New-ComplianceSearchAction", "Purge items returned by a compliance search.")
            });

        Assert.Empty(gaps);
    }

    [Fact]
    public void DescriptionSatisfiesACapabilityTheNameDoesNotMention()
    {
        // Intune's ViewReports covers exporting and says so — but the word "export" is
        // absent from the action string. Reading names only reported a false gap.
        var gaps = CapabilityCoverage.Gaps(
            "export device compliance reports",
            new[]
            {
                ("Microsoft.Intune_Devicecompliancepolicies_View_reports",
                 "View, generate, and export device compliance reports.")
            });

        Assert.Empty(gaps);
    }

    [Fact]
    public void WithNoDescriptionsAtAll_TheFindingIsMarkedUnconfirmed()
    {
        // Asserting "NOTHING can do that" from names alone is the exact reasoning this app
        // forbids the model. It must report a suspicion, not a fact.
        var gaps = CapabilityCoverage.Gaps(
            "export device compliance reports",
            new[] { "Microsoft.Intune_Devicecompliancepolicies_View_reports" });

        var gap = Assert.Single(gaps);
        Assert.True(gap.NamesOnly);
        Assert.Contains("could not be confirmed", gap.Message);
    }

    [Fact]
    public void ResetIsNotTreatedAsAnUpdateOnlyVerb()
    {
        // Resetting MFA DELETES the registered methods. Listing reset under "update or
        // change" reported the correct answer as unable to do the job.
        var gaps = CapabilityCoverage.Gaps(
            "reset MFA methods for a user",
            new[]
            {
                ("microsoft.directory/users/authenticationMethods/delete",
                 "Delete authentication methods for users.")
            });

        Assert.Empty(gaps);
    }

    [Fact]
    public void NewStartersIsNotACreateRequest()
    {
        // "new" is an adjective at least as often as a verb, and in access requests it is
        // almost always attached to a person.
        var gaps = CapabilityCoverage.Gaps(
            "new starters on the service desk need to reset passwords",
            new[]
            {
                ("microsoft.directory/users/password/update", "Reset passwords for users.")
            });

        Assert.DoesNotContain(gaps, g => g.Capability == "create");
    }

    [Fact]
    public void AVerbDescribingExistingStateIsNotARequest()
    {
        // "every policy we have configured" asks nobody to configure anything. Matching it
        // turned a read-only audit into an update request and excluded both correct
        // read-only permissions.
        var gaps = CapabilityCoverage.Gaps(
            "review every Conditional Access policy we have configured",
            new[]
            {
                ("microsoft.directory/conditionalAccessPolicies/standard/read",
                 "Read Conditional Access policies.")
            });

        Assert.DoesNotContain(gaps, g => g.Capability == "update or change");
    }

    [Fact]
    public void ACapabilityTheRequestForbidsIsNotOneItAskedFor()
    {
        var gaps = CapabilityCoverage.Gaps(
            "read group membership, but they must not delete anything",
            new[]
            {
                ("microsoft.directory/groups/standard/read", "Read basic properties on groups.")
            });

        Assert.DoesNotContain(gaps, g => g.Capability == "delete or purge");
    }

    [Fact]
    public void MembershipCmdletsSatisfyAMembershipRequest()
    {
        // REGRESSION. Microsoft's vocabulary for membership never says "assign" or "grant"
        // — it says Add-DistributionGroupMember and "add a single recipient to distribution
        // groups". A request to manage membership, answered with the three cmdlets that
        // manage it, was reported as unable to do it.
        var gaps = CapabilityCoverage.Gaps(
            "manage membership of distribution lists",
            new[]
            {
                ("Add-DistributionGroupMember",
                 "Use the Add-DistributionGroupMember cmdlet to add a single recipient to "
                 + "distribution groups and mail-enabled security groups."),
                ("Remove-DistributionGroupMember",
                 "Use the Remove-DistributionGroupMember cmdlet to remove a single recipient "
                 + "from distribution groups.")
            });

        Assert.DoesNotContain(gaps, g => g.Capability == "assign or grant");
    }

    [Fact]
    public void AReadOnlyMembershipPermissionDoesNotSatisfyAManageRequest()
    {
        // The guard must keep its real job: viewing membership is not managing it.
        var gaps = CapabilityCoverage.Gaps(
            "add staff to distribution lists",
            new[]
            {
                ("Get-DistributionGroup",
                 "Use the Get-DistributionGroup cmdlet to view existing distribution groups.")
            });

        Assert.NotEmpty(gaps);
    }

    [Fact]
    public void NoValidatedActions_ProducesNoGaps()
    {
        // Nothing to assess is not the same as "cannot do it".
        Assert.Empty(CapabilityCoverage.Gaps("delete everything", Array.Empty<string>()));
    }
}
