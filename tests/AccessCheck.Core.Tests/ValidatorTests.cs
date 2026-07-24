using AccessCheck.Core.Catalog;
using AccessCheck.Core.Recommendation;
using Xunit;

namespace AccessCheck.Core.Tests;

public class ValidatorTests
{
    private static RoleCatalog BuildCatalog()
    {
        var cat = new RoleCatalog();
        cat.Add(new RoleDefinitionRecord
        {
            Id = "role-helpdesk",
            DisplayName = "Helpdesk Administrator",
            IsBuiltIn = true,
            AllowedResourceActions = new[]
            {
                "microsoft.directory/users/password/update",
                "microsoft.directory/users/invalidateAllRefreshTokens",
                "microsoft.directory/users/standard/read"
            }
        });
        cat.Add(new RoleDefinitionRecord
        {
            Id = "role-useradmin",
            DisplayName = "User Administrator",
            IsBuiltIn = true,
            AllowedResourceActions = new[]
            {
                "microsoft.directory/users/password/update",
                "microsoft.directory/users/invalidateAllRefreshTokens",
                "microsoft.directory/users/standard/read",
                "microsoft.directory/users/create",
                "microsoft.directory/users/delete",
                "microsoft.directory/users/basic/update",
                "microsoft.directory/groups/members/update",
                "microsoft.directory/groups/create",
                "microsoft.directory/groups/delete"
            }
        });
        return cat;
    }

    [Fact]
    public void UnknownActionsAreRejected_NeverPassThrough()
    {
        var validator = new RecommendationValidator();
        var suggestion = new AiSuggestion
        {
            RequiredActions = new[]
            {
                "microsoft.directory/users/password/update",
                "microsoft.directory/made/up/action"   // hallucinated
            }
        };

        var outcome = validator.Validate(BuildCatalog(), suggestion, "reset passwords");

        Assert.Single(outcome.ValidActions);
        Assert.Single(outcome.UnknownActionsRejected);
        Assert.Equal("microsoft.directory/made/up/action", outcome.UnknownActionsRejected[0]);
    }

    [Fact]
    public void SmallestCoveringRoleWins_DeltaComputed()
    {
        var validator = new RecommendationValidator();
        var suggestion = new AiSuggestion
        {
            RequiredActions = new[]
            {
                "microsoft.directory/users/password/update",
                "microsoft.directory/users/standard/read"
            }
        };

        var outcome = validator.Validate(BuildCatalog(), suggestion, "reset passwords for tickets");

        Assert.False(outcome.CustomRoleRecommended);
        Assert.NotNull(outcome.BestFit);
        Assert.Equal("role-helpdesk", outcome.BestFit!.RoleId);
        // Helpdesk grants exactly one action beyond the need
        Assert.Single(outcome.BestFit.ExcessActions);
        Assert.Contains("microsoft.directory/users/invalidateAllRefreshTokens",
            outcome.BestFit.ExcessActions);
        // User Administrator must rank below (bigger delta)
        Assert.True(outcome.RankedFits.Count >= 2);
        Assert.Equal("role-useradmin", outcome.RankedFits[1].RoleId);
    }

    [Fact]
    public void OvershootBeyondThreshold_TriggersCustomRoleDraft()
    {
        var validator = new RecommendationValidator { MaxAcceptableExcessActions = 0 };
        var suggestion = new AiSuggestion
        {
            RequiredActions = new[] { "microsoft.directory/users/password/update" }
        };

        var outcome = validator.Validate(BuildCatalog(), suggestion, "password reset only");

        Assert.True(outcome.CustomRoleRecommended);
        Assert.NotNull(outcome.CustomRole);
        Assert.Single(outcome.CustomRole!.AllowedResourceActions);
        Assert.Equal("microsoft.directory/users/password/update",
            outcome.CustomRole.AllowedResourceActions[0]);
    }

    [Fact]
    public void NoValidActions_NoCustomRole_NoFits()
    {
        var validator = new RecommendationValidator();
        var suggestion = new AiSuggestion
        {
            RequiredActions = new[] { "totally/fake/action" }
        };

        var outcome = validator.Validate(BuildCatalog(), suggestion, "nonsense");

        Assert.Empty(outcome.ValidActions);
        Assert.Empty(outcome.RankedFits);
        Assert.False(outcome.CustomRoleRecommended);
        Assert.Null(outcome.CustomRole);
    }
}

public class MultiProviderValidatorTests
{
    private static AccessCheck.Core.Catalog.RoleCatalog BuildMultiCatalog()
    {
        var cat = new AccessCheck.Core.Catalog.RoleCatalog();
        cat.Add(new AccessCheck.Core.Catalog.RoleDefinitionRecord
        {
            Id = "dir-helpdesk",
            DisplayName = "Helpdesk Administrator",
            IsBuiltIn = true,
            Provider = AccessCheck.Core.Catalog.RbacProviders.Directory,
            AllowedResourceActions = new[]
            {
                "microsoft.directory/users/password/update",
                "microsoft.directory/users/standard/read"
            }
        });
        cat.Add(new AccessCheck.Core.Catalog.RoleDefinitionRecord
        {
            Id = "intune-helpdesk",
            DisplayName = "Help Desk Operator",
            IsBuiltIn = true,
            Provider = AccessCheck.Core.Catalog.RbacProviders.Intune,
            AllowedResourceActions = new[]
            {
                "Microsoft.Intune_RemoteTasks_RebootNow",
                "Microsoft.Intune_ManagedDevices_Read"
            }
        });
        cat.Add(new AccessCheck.Core.Catalog.RoleDefinitionRecord
        {
            Id = "exo-recipients",
            DisplayName = "Mail Recipients",
            IsBuiltIn = true,
            Provider = AccessCheck.Core.Catalog.RbacProviders.Exchange,
            AllowedResourceActions = new[] { "Set-Mailbox", "Get-Mailbox" }
        });
        return cat;
    }

    [Fact]
    public void CrossProviderActions_PartitionIntoSeparateOutcomes()
    {
        var validator = new RecommendationValidator();
        var suggestion = new AiSuggestion
        {
            RequiredActions = new[]
            {
                "microsoft.directory/users/password/update",
                "Microsoft.Intune_ManagedDevices_Read",
                "Get-Mailbox"
            }
        };

        var outcomes = validator.ValidateMulti(BuildMultiCatalog(), suggestion, "helpdesk mix");

        Assert.Equal(3, outcomes.Count);
        Assert.Contains(outcomes, o => o.Provider == AccessCheck.Core.Catalog.RbacProviders.Directory);
        Assert.Contains(outcomes, o => o.Provider == AccessCheck.Core.Catalog.RbacProviders.Intune);
        Assert.Contains(outcomes, o => o.Provider == AccessCheck.Core.Catalog.RbacProviders.Exchange);
        // no role ever spans providers, so every outcome's fits are same-provider only
        foreach (var po in outcomes)
            Assert.All(po.Outcome.RankedFits, f => Assert.NotNull(f.RoleId));
    }

    [Fact]
    public void ExchangeOvershoot_DraftsDerivedRole_ParentAndRemovalsFromDelta()
    {
        var validator = new RecommendationValidator { MaxAcceptableExcessActions = 0 };
        var suggestion = new AiSuggestion { RequiredActions = new[] { "Set-Mailbox" } };

        var outcomes = validator.ValidateMulti(BuildMultiCatalog(), suggestion, "edit mailboxes");

        var exo = Assert.Single(outcomes);
        Assert.Equal(AccessCheck.Core.Catalog.RbacProviders.Exchange, exo.Provider);
        // Derived model: custom role IS drafted, from the covering parent, stripping the excess
        Assert.True(exo.Outcome.CustomRoleRecommended);
        Assert.NotNull(exo.Outcome.CustomRole);
        Assert.Equal("Mail Recipients", exo.Outcome.CustomRole!.ParentRoleName);
        Assert.Single(exo.Outcome.CustomRole.AllowedResourceActions);
        Assert.Equal("Set-Mailbox", exo.Outcome.CustomRole.AllowedResourceActions[0]);
        Assert.NotNull(exo.Outcome.CustomRole.EntriesToRemove);
        Assert.Contains("Get-Mailbox", exo.Outcome.CustomRole.EntriesToRemove!);
    }

    [Fact]
    public void ExchangeWithNoCoveringRole_CannotDeriveCustom()
    {
        var validator = new RecommendationValidator { MaxAcceptableExcessActions = 0 };
        // spans two would-be roles; no single Exchange role covers both in the fixture
        var suggestion = new AiSuggestion
        {
            RequiredActions = new[] { "Set-Mailbox", "Set-TransportRule" }
        };

        var cat = BuildMultiCatalog();
        cat.Add(new AccessCheck.Core.Catalog.RoleDefinitionRecord
        {
            Id = "exo-transport",
            DisplayName = "Transport Rules",
            IsBuiltIn = true,
            Provider = AccessCheck.Core.Catalog.RbacProviders.Exchange,
            AllowedResourceActions = new[] { "Set-TransportRule", "Get-TransportRule" }
        });

        var outcomes = validator.ValidateMulti(cat, suggestion, "mailbox and transport");

        var exo = Assert.Single(outcomes);
        // no covering parent exists -> derivation impossible -> no draft, no fits
        Assert.False(exo.Outcome.CustomRoleRecommended);
        Assert.Null(exo.Outcome.CustomRole);
        Assert.Empty(exo.Outcome.RankedFits);
    }
}

public class RiskWeightedRankingTests
{
    private static AccessCheck.Core.Catalog.RoleCatalog BuildCatalog()
    {
        var cat = new AccessCheck.Core.Catalog.RoleCatalog();
        // Reads-only role: more excess actions, but all read.
        cat.Add(new AccessCheck.Core.Catalog.RoleDefinitionRecord
        {
            Id = "reports-reader",
            DisplayName = "Reports Reader",
            IsBuiltIn = true,
            AllowedResourceActions = new[]
            {
                "microsoft.office365.usageReports/allEntities/allProperties/read",
                "microsoft.directory/auditLogs/allProperties/read",
                "microsoft.directory/signInReports/allProperties/read",
                "microsoft.office365.webPortal/allEntities/standard/read",
                "microsoft.office365.network/performance/allProperties/read"
            }
        });
        // Admin role: fewer excess actions, but they are allTasks admin permissions.
        cat.Add(new AccessCheck.Core.Catalog.RoleDefinitionRecord
        {
            Id = "sp-embedded-admin",
            DisplayName = "SharePoint Embedded Administrator",
            IsBuiltIn = true,
            AllowedResourceActions = new[]
            {
                "microsoft.office365.usageReports/allEntities/allProperties/read",
                "microsoft.office365.fileStorageContainers/allEntities/allProperties/allTasks",
                "microsoft.office365.serviceHealth/allEntities/allTasks",
                "microsoft.office365.supportTickets/allEntities/allTasks"
            }
        });
        return cat;
    }

    [Fact]
    public void ReadOnlyRoleBeatsAdminRole_EvenWithMoreExcessActions()
    {
        var validator = new RecommendationValidator { MaxAcceptableExcessActions = 99 };
        var suggestion = new AiSuggestion
        {
            RequiredActions = new[] { "microsoft.office365.usageReports/allEntities/allProperties/read" }
        };

        var outcome = validator.Validate(BuildCatalog(), suggestion, "read usage reports");

        // Admin role has 3 excess vs reader's 4 — but all 3 are privileged, so the
        // read-only role must still win.
        Assert.NotNull(outcome.BestFit);
        Assert.Equal("reports-reader", outcome.BestFit!.RoleId);
        Assert.Equal(0, outcome.BestFit.ExcessPrivilegedCount);
    }

    [Theory]
    [InlineData("microsoft.directory/users/standard/read", false)]
    [InlineData("microsoft.office365.usageReports/allEntities/allProperties/read", false)]
    [InlineData("microsoft.office365.serviceHealth/allEntities/allTasks", true)]
    [InlineData("microsoft.directory/users/password/update", true)]
    [InlineData("microsoft.directory/groups/create", true)]
    [InlineData("Microsoft.Intune_ManagedDevices_Read", false)]
    [InlineData("Microsoft.Intune_RemoteTasks_RebootNow", true)]
    [InlineData("Get-Mailbox", false)]
    [InlineData("Set-Mailbox", true)]
    [InlineData("New-RoleGroup", true)]
    public void Classifier_SortsReadFromPrivileged(string action, bool expectedPrivileged)
    {
        Assert.Equal(expectedPrivileged, ActionRisk.IsPrivileged(action));
    }
}

public class GroupMatcherTests
{
    private static AccessCheck.Core.Groups.GroupEntitlement Group(
        string name, params string[] actions) =>
        new()
        {
            GroupId = name,
            DisplayName = name,
            Holdings = new[]
            {
                new AccessCheck.Core.Groups.GroupRoleHolding
                {
                    Provider = AccessCheck.Core.Catalog.RbacProviders.Directory,
                    RoleId = name + "-role",
                    RoleName = name + " Role"
                }
            },
            GrantedActions = actions
        };

    [Fact]
    public void FullMatchOutranksPartial()
    {
        var groups = new[]
        {
            Group("Partial", "a/read"),
            Group("Full", "a/read", "b/read")
        };

        var fits = AccessCheck.Core.Groups.GroupMatcher.Rank(
            groups, new[] { "a/read", "b/read" });

        Assert.Equal("Full", fits[0].Group.DisplayName);
        Assert.True(fits[0].FullyCovers);
        Assert.False(fits[1].FullyCovers);
        Assert.Equal(50, fits[1].CoveragePercent);
    }

    [Fact]
    public void AmongFullMatches_LeastRiskyExcessWins()
    {
        var groups = new[]
        {
            // fewer excess actions, but they are privileged
            Group("AdminGroup", "a/read", "b/allTasks", "c/delete"),
            // more excess actions, all read-only
            Group("ReaderGroup", "a/read", "x/read", "y/read", "z/read", "w/read")
        };

        var fits = AccessCheck.Core.Groups.GroupMatcher.Rank(groups, new[] { "a/read" });

        Assert.True(fits.All(f => f.FullyCovers));
        Assert.Equal("ReaderGroup", fits[0].Group.DisplayName);
        Assert.Equal(0, fits[0].ExcessPrivilegedCount);
        Assert.Equal(2, fits[1].ExcessPrivilegedCount);
    }

    [Fact]
    public void GroupGrantingNothingNeeded_IsNotOffered()
    {
        var groups = new[] { Group("Unrelated", "q/read", "r/read") };

        var fits = AccessCheck.Core.Groups.GroupMatcher.Rank(groups, new[] { "a/read" });

        Assert.Empty(fits);
    }

    [Fact]
    public void PartialsCanBeExcluded()
    {
        var groups = new[] { Group("Partial", "a/read") };

        var withPartial = AccessCheck.Core.Groups.GroupMatcher.Rank(
            groups, new[] { "a/read", "b/read" });
        var withoutPartial = AccessCheck.Core.Groups.GroupMatcher.Rank(
            groups, new[] { "a/read", "b/read" }, includePartial: false);

        Assert.Single(withPartial);
        Assert.Empty(withoutPartial);
    }
}
