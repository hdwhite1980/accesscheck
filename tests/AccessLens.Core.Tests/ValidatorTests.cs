using AccessLens.Core.Catalog;
using AccessLens.Core.Recommendation;
using Xunit;

namespace AccessLens.Core.Tests;

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
    private static AccessLens.Core.Catalog.RoleCatalog BuildMultiCatalog()
    {
        var cat = new AccessLens.Core.Catalog.RoleCatalog();
        cat.Add(new AccessLens.Core.Catalog.RoleDefinitionRecord
        {
            Id = "dir-helpdesk",
            DisplayName = "Helpdesk Administrator",
            IsBuiltIn = true,
            Provider = AccessLens.Core.Catalog.RbacProviders.Directory,
            AllowedResourceActions = new[]
            {
                "microsoft.directory/users/password/update",
                "microsoft.directory/users/standard/read"
            }
        });
        cat.Add(new AccessLens.Core.Catalog.RoleDefinitionRecord
        {
            Id = "intune-helpdesk",
            DisplayName = "Help Desk Operator",
            IsBuiltIn = true,
            Provider = AccessLens.Core.Catalog.RbacProviders.Intune,
            AllowedResourceActions = new[]
            {
                "Microsoft.Intune_RemoteTasks_RebootNow",
                "Microsoft.Intune_ManagedDevices_Read"
            }
        });
        cat.Add(new AccessLens.Core.Catalog.RoleDefinitionRecord
        {
            Id = "exo-recipients",
            DisplayName = "Mail Recipients",
            IsBuiltIn = true,
            Provider = AccessLens.Core.Catalog.RbacProviders.Exchange,
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
        Assert.Contains(outcomes, o => o.Provider == AccessLens.Core.Catalog.RbacProviders.Directory);
        Assert.Contains(outcomes, o => o.Provider == AccessLens.Core.Catalog.RbacProviders.Intune);
        Assert.Contains(outcomes, o => o.Provider == AccessLens.Core.Catalog.RbacProviders.Exchange);
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
        Assert.Equal(AccessLens.Core.Catalog.RbacProviders.Exchange, exo.Provider);
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
        cat.Add(new AccessLens.Core.Catalog.RoleDefinitionRecord
        {
            Id = "exo-transport",
            DisplayName = "Transport Rules",
            IsBuiltIn = true,
            Provider = AccessLens.Core.Catalog.RbacProviders.Exchange,
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
