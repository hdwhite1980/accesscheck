using AccessCheck.Core.Catalog;
using AccessCheck.Core.Recommendation;
using Xunit;

namespace AccessCheck.Core.Tests;

/// <summary>
/// Composition is where a job description stops being a list of answers and becomes a plan.
/// The properties that matter are the ones no single duty can reveal: duplication across
/// duties, and risk that only exists in the union.
/// </summary>
public class PortfolioComposerTests
{
    private static DutyAnalysis Duty(
        string duty, string provider, string role, params string[] actions) =>
        new()
        {
            Duty = duty,
            Provider = provider,
            RoleLabel = role,
            Actions = actions.ToList()
        };

    // ---------- lifetime ----------

    [Fact]
    public void ReadOnlyPermissionsAreSafeToHoldContinuously()
    {
        Assert.Equal(GrantLifetime.Standing, PortfolioComposer.LifetimeFor(
            new[] { "microsoft.directory/users/standard/read" }));
    }

    [Fact]
    public void EscalationCapablePermissionsAreOnRequest()
    {
        Assert.Equal(GrantLifetime.OnRequest, PortfolioComposer.LifetimeFor(
            new[] { "microsoft.directory/users/password/update" }));
    }

    [Fact]
    public void LifetimeComesFromTheActionsNotTheWording()
    {
        // The decomposer's readOnly flag is a reading of English. The actions are what
        // will actually be granted, so they decide.
        var analyses = new[]
        {
            Duty("reviews group membership", RbacProviders.Directory, "Group Writer",
                 "microsoft.directory/groups/members/update") with { DeclaredReadOnly = true }
        };

        var portfolio = PortfolioComposer.Compose(analyses);

        Assert.NotEqual(GrantLifetime.Standing, Assert.Single(portfolio.Grants).Lifetime);
    }

    // ---------- deduplication ----------

    [Fact]
    public void DutiesResolvingToTheSameRoleBecomeOneGrant()
    {
        var analyses = new[]
        {
            Duty("reset passwords", RbacProviders.Directory, "Helpdesk Administrator",
                 "microsoft.directory/users/password/update"),
            Duty("unlock accounts", RbacProviders.Directory, "Helpdesk Administrator",
                 "microsoft.directory/users/invalidateAllRefreshTokens")
        };

        var grant = Assert.Single(PortfolioComposer.Compose(analyses).Grants);

        Assert.Equal(2, grant.Duties.Count);
        Assert.Equal(2, grant.Actions.Count);
    }

    [Fact]
    public void TheSameRoleNameInDifferentServicesStaysTwoGrants()
    {
        var analyses = new[]
        {
            Duty("a", RbacProviders.Directory, "Reader", "microsoft.directory/users/standard/read"),
            Duty("b", RbacProviders.Intune, "Reader", "Microsoft.Intune_ManagedDevices_Read")
        };

        Assert.Equal(2, PortfolioComposer.Compose(analyses).Grants.Count);
    }

    [Fact]
    public void AMergedGrantTakesTheStricterLifetime()
    {
        // The role grants both sets to whoever holds it. Reporting the gentler answer would
        // describe a narrower grant than the one being made.
        var analyses = new[]
        {
            Duty("view users", RbacProviders.Directory, "User Administrator",
                 "microsoft.directory/users/standard/read"),
            Duty("reset passwords", RbacProviders.Directory, "User Administrator",
                 "microsoft.directory/users/password/update")
        };

        var grant = Assert.Single(PortfolioComposer.Compose(analyses).Grants);

        Assert.Equal(GrantLifetime.OnRequest, grant.Lifetime);
    }

    [Fact]
    public void AGrantWhoseActionsAreAlreadyInAnotherIsFoldedIn()
    {
        // Two differently-NAMED custom roles where one contains the other. Grouping by
        // label alone left both, so the plan asked for two approvals and two tenant
        // objects when the first granted nothing the second did not.
        var analyses = new[]
        {
            Duty("monitor sign-in logs", RbacProviders.Directory,
                 "AC - Entra ID read signInReports",
                 "microsoft.directory/signInReports/allProperties/read"),
            Duty("audit guest accounts", RbacProviders.Directory,
                 "AC - Entra ID read users + signInReports",
                 "microsoft.directory/signInReports/allProperties/read",
                 "microsoft.directory/users/guestBasicProfile/limitedRead")
        };

        var grant = Assert.Single(PortfolioComposer.Compose(analyses).Grants);

        Assert.Equal("AC - Entra ID read users + signInReports", grant.RoleLabel);
        Assert.Equal(2, grant.Duties.Count);
        Assert.Equal("AC - Entra ID read signInReports", Assert.Single(grant.Supersedes));
    }

    [Fact]
    public void AReadOnlyDutyDoesNotFoldIntoAGrantThatWrites()
    {
        // THE OVER-GRANT THIS APPLICATION EXISTS TO PREVENT, produced by the application.
        // Licence REPORTING resolved to assignLicense, whose action was contained in the
        // account-amendment grant, so containment merged them — and approving "monthly
        // licence reporting" also granted the ability to change licences and edit users.
        var analyses = new[]
        {
            Duty("amend user accounts", RbacProviders.Directory, "AC - manage users",
                 "microsoft.directory/users/basic/update",
                 "microsoft.directory/users/assignLicense"),
            Duty("produce monthly licence reporting", RbacProviders.Directory,
                 "AC - assignLicense users",
                 "microsoft.directory/users/assignLicense") with { DeclaredReadOnly = true }
        };

        var portfolio = PortfolioComposer.Compose(analyses);

        Assert.Equal(2, portfolio.Grants.Count);
        Assert.DoesNotContain(portfolio.Grants,
            g => g.Duties.Count > 1 && g.Duties.Any(d => d.Contains("reporting")));
    }

    [Fact]
    public void TwoReadOnlyDutiesStillFoldTogether()
    {
        // The barrier is about crossing read into write, not about refusing to merge reads.
        var analyses = new[]
        {
            Duty("audit guests", RbacProviders.Directory, "AC - read users + signIns",
                 "microsoft.directory/users/standard/read",
                 "microsoft.directory/signInReports/allProperties/read")
                 with { DeclaredReadOnly = true },
            Duty("read users", RbacProviders.Directory, "AC - read users",
                 "microsoft.directory/users/standard/read") with { DeclaredReadOnly = true }
        };

        Assert.Single(PortfolioComposer.Compose(analyses).Grants);
    }

    [Fact]
    public void AWriteDutyStillFoldsIntoALargerWriteGrant()
    {
        // Nothing about the barrier should stop ordinary deduplication.
        var analyses = new[]
        {
            Duty("amend users", RbacProviders.Directory, "AC - manage users",
                 "microsoft.directory/users/basic/update",
                 "microsoft.directory/users/assignLicense"),
            Duty("assign licences", RbacProviders.Directory, "AC - assignLicense",
                 "microsoft.directory/users/assignLicense")
        };

        Assert.Single(PortfolioComposer.Compose(analyses).Grants);
    }

    [Fact]
    public void OverlappingButNotContainedGrantsBothSurvive()
    {
        // Sharing a permission is not the same as being contained. Folding these would
        // silently drop a permission the other duty needs.
        var analyses = new[]
        {
            Duty("a", RbacProviders.Directory, "Role A",
                 "microsoft.directory/users/standard/read",
                 "microsoft.directory/groups/standard/read"),
            Duty("b", RbacProviders.Directory, "Role B",
                 "microsoft.directory/users/standard/read",
                 "microsoft.directory/devices/standard/read")
        };

        Assert.Equal(2, PortfolioComposer.Compose(analyses).Grants.Count);
    }

    [Fact]
    public void ContainmentDoesNotCrossServices()
    {
        // An Intune role cannot carry an Entra permission, however the action sets compare.
        var analyses = new[]
        {
            Duty("a", RbacProviders.Directory, "Entra role", "shared/action"),
            Duty("b", RbacProviders.Intune, "Intune role", "shared/action", "extra/action")
        };

        Assert.Equal(2, PortfolioComposer.Compose(analyses).Grants.Count);
    }

    [Fact]
    public void FoldingIsIndependentOfInputOrder()
    {
        var small = Duty("small", RbacProviders.Directory, "Small",
                         "microsoft.directory/users/standard/read");
        var big = Duty("big", RbacProviders.Directory, "Big",
                       "microsoft.directory/users/standard/read",
                       "microsoft.directory/groups/standard/read");

        var forward = PortfolioComposer.Compose(new[] { small, big }).Grants;
        var reverse = PortfolioComposer.Compose(new[] { big, small }).Grants;

        Assert.Equal("Big", Assert.Single(forward).RoleLabel);
        Assert.Equal("Big", Assert.Single(reverse).RoleLabel);
    }

    // ---------- aggregate risk ----------

    [Fact]
    public void GroupMembershipPlusCredentialControlIsFlaggedAsAnEscalationPath()
    {
        // Each half is a routine service-desk duty. Together they are a route to any
        // account in a privileged group, with no admin role named anywhere.
        var analyses = new[]
        {
            Duty("manage group membership", RbacProviders.Directory, "Group Writer",
                 "microsoft.directory/groups/members/update"),
            Duty("reset passwords", RbacProviders.Directory, "Helpdesk Administrator",
                 "microsoft.directory/users/password/update")
        };

        var portfolio = PortfolioComposer.Compose(analyses);

        Assert.True(portfolio.HasBlockingConcern);
        Assert.Contains(portfolio.Concerns,
            c => c.Title.Contains("escalation path", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void TheEscalationPairIsDetectedOnEntrasREALActionShape()
    {
        // REGRESSION. The marker was the literal "groups/members", but Entra qualifies the
        // resource — groups.security/members/update, groups.unified/members/update — so it
        // matched nothing and a portfolio containing the pair was reported clean.
        var analyses = new[]
        {
            Duty("manage security groups", RbacProviders.Directory, "AC - manage groups",
                 "microsoft.directory/groups.security/members/update",
                 "microsoft.directory/groups.unified/members/update"),
            Duty("reset passwords", RbacProviders.Directory, "AC - manage users",
                 "microsoft.directory/users/password/update")
        };

        var portfolio = PortfolioComposer.Compose(analyses);

        Assert.True(portfolio.HasBlockingConcern);
        Assert.Contains(portfolio.Concerns,
            c => c.Title.Contains("escalation path", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void AMailingListIsNotHalfOfAnEscalationPath()
    {
        // Add-DistributionGroupMember manages a MAIL list. It grants access to nothing, so
        // pairing it with password reset is not a route to privilege — and a blocking
        // concern that is wrong teaches operators to dismiss the ones that are right.
        var analyses = new[]
        {
            Duty("manage distribution lists", RbacProviders.Exchange, "AC - Exchange lists",
                 "Add-DistributionGroupMember", "Remove-DistributionGroupMember"),
            Duty("reset passwords", RbacProviders.Directory, "Helpdesk",
                 "microsoft.directory/users/password/update")
        };

        Assert.DoesNotContain(PortfolioComposer.Compose(analyses).Concerns,
            c => c.Title.Contains("escalation path", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ARoleGroupIsStillHalfOfAnEscalationPath()
    {
        // Exchange role groups DO carry permissions, so this pairing is real.
        var analyses = new[]
        {
            Duty("manage role groups", RbacProviders.Exchange, "AC - Exchange roles",
                 "Add-RoleGroupMember"),
            Duty("reset passwords", RbacProviders.Directory, "Helpdesk",
                 "microsoft.directory/users/password/update")
        };

        Assert.True(PortfolioComposer.Compose(analyses).HasBlockingConcern);
    }

    [Fact]
    public void EitherHalfAloneIsNotFlagged()
    {
        var groupsOnly = PortfolioComposer.Compose(new[]
        {
            Duty("manage group membership", RbacProviders.Directory, "Group Writer",
                 "microsoft.directory/groups/members/update")
        });

        Assert.DoesNotContain(groupsOnly.Concerns,
            c => c.Title.Contains("escalation path", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RoleManagementInScopeIsBlocking()
    {
        var portfolio = PortfolioComposer.Compose(new[]
        {
            Duty("manage admin roles", RbacProviders.Directory, "Privileged Role Administrator",
                 "microsoft.directory/roleManagement/allProperties/allTasks")
        });

        Assert.Contains(portfolio.Concerns, c => c.Blocking &&
            c.Title.Contains("Role management", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void BreadthAcrossManyServicesIsNamed()
    {
        var analyses = new[]
        {
            Duty("a", RbacProviders.Directory, "R1", "microsoft.directory/users/standard/read"),
            Duty("b", RbacProviders.Intune, "R2", "Microsoft.Intune_ManagedDevices_Read"),
            Duty("c", RbacProviders.Exchange, "R3", "Get-Mailbox"),
            Duty("d", RbacProviders.Defender, "R4", "microsoft.defender/incidents/read")
        };

        Assert.Contains(PortfolioComposer.Compose(analyses).Concerns,
            c => c.Title.Contains("Spans", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CustomRolesWithTheSameGeneratedNameButDifferentActionsStaySeparate()
    {
        // BuildCustomRoleName derives from the resource, so every user-touching duty drafts
        // "AC - Entra ID manage users". Grouping on that name merged account creation with
        // licence reporting into one escalation-capable role — the exact over-grant this
        // tool exists to prevent, produced by the composer rather than the model.
        var analyses = new[]
        {
            Duty("create accounts", RbacProviders.Directory, "AC - Entra ID manage users",
                 "microsoft.directory/users/create") with { CustomRole = true },
            Duty("re-register MFA", RbacProviders.Directory, "AC - Entra ID manage users",
                 "microsoft.directory/users/authenticationMethods/delete") with { CustomRole = true }
        };

        Assert.Equal(2, PortfolioComposer.Compose(analyses).Grants.Count);
    }

    [Fact]
    public void BuiltInRolesWithTheSameNameStillMerge()
    {
        // A built-in name identifies a real object with fixed contents, so two duties
        // naming it genuinely are one grant.
        var analyses = new[]
        {
            Duty("a", RbacProviders.Directory, "Helpdesk Administrator",
                 "microsoft.directory/users/password/update"),
            Duty("b", RbacProviders.Directory, "Helpdesk Administrator",
                 "microsoft.directory/users/invalidateAllRefreshTokens")
        };

        Assert.Single(PortfolioComposer.Compose(analyses).Grants);
    }

    [Fact]
    public void ADutyAnsweredInOneServiceIsNotAlsoReportedUnresolved()
    {
        // One duty produces one analysis per provider. Answered in Exchange while Purview
        // returned nothing, it appeared as a grant AND under "no permission found" — and an
        // operator reading that cannot tell whether the duty is covered.
        var analyses = new[]
        {
            Duty("purge phishing", RbacProviders.Exchange, "AC - Exchange", "Remove-Message"),
            new DutyAnalysis
            {
                Duty = "purge phishing",
                Provider = RbacProviders.Purview,
                Actions = Array.Empty<string>()
            }
        };

        var portfolio = PortfolioComposer.Compose(analyses);

        Assert.Single(portfolio.Grants);
        Assert.Empty(portfolio.Unresolved);
    }

    // ---------- breadth ----------

    [Fact]
    public void ABroadReadIsStillStandingButTheRationaleSaysItIsBroad()
    {
        // The score and the words must agree. "No blast radius" beside a score of 8 is not
        // wrong on either side — allProperties/read changes nothing and reaches everything —
        // but read together it reads as nonsense, and an approver who notices stops
        // trusting both.
        var grant = Assert.Single(PortfolioComposer.Compose(new[]
        {
            Duty("monitor sign-ins", RbacProviders.Directory, "AC - read signInReports",
                 "microsoft.directory/signInReports/allProperties/read")
        }).Grants);

        Assert.Equal(GrantLifetime.Standing, grant.Lifetime);
        Assert.Contains("BROAD", grant.Rationale);
        Assert.True(grant.RiskScore > 1);
    }

    [Fact]
    public void ANarrowReadSaysNothingAboutBreadth()
    {
        var grant = Assert.Single(PortfolioComposer.Compose(new[]
        {
            Duty("read users", RbacProviders.Directory, "AC - read users",
                 "microsoft.directory/users/standard/read")
        }).Grants);

        Assert.DoesNotContain("BROAD", grant.Rationale);
        Assert.Equal(1, grant.RiskScore);
    }

    [Fact]
    public void SeveralWholeResourceReadsHeldStandingAreFlaggedTogether()
    {
        // Each was individually ranked narrower than a broad built-in reader. Held
        // together they approach the same visibility by another route, and no single
        // verdict can see that.
        var analyses = new[]
        {
            Duty("a", RbacProviders.Directory, "R1",
                 "microsoft.directory/signInReports/allProperties/read"),
            Duty("b", RbacProviders.Directory, "R2",
                 "microsoft.directory/conditionalAccessPolicies/allProperties/read")
        };

        Assert.Contains(PortfolioComposer.Compose(analyses).Concerns,
            c => c.Title.Contains("whole-resource reads", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void OneWholeResourceReadIsNotYetAPattern()
    {
        var portfolio = PortfolioComposer.Compose(new[]
        {
            Duty("a", RbacProviders.Directory, "R1",
                 "microsoft.directory/signInReports/allProperties/read")
        });

        Assert.DoesNotContain(portfolio.Concerns,
            c => c.Title.Contains("whole-resource reads", StringComparison.OrdinalIgnoreCase));
    }

    // ---------- unresolved ----------

    [Fact]
    public void DutiesWithNoPermissionsAreReportedNotDropped()
    {
        var analyses = new[]
        {
            Duty("reset passwords", RbacProviders.Directory, "Helpdesk",
                 "microsoft.directory/users/password/update"),
            new DutyAnalysis
            {
                Duty = "liaises with vendors",
                Provider = RbacProviders.Directory,
                Actions = Array.Empty<string>()
            }
        };

        var portfolio = PortfolioComposer.Compose(analyses);

        Assert.Single(portfolio.Grants);
        Assert.Equal("liaises with vendors", Assert.Single(portfolio.Unresolved));
    }

    [Fact]
    public void MostlyUnresolvedSuggestsASyncGapRatherThanNoAccessNeeded()
    {
        var analyses = new[]
        {
            Duty("a", RbacProviders.Directory, "R1", "microsoft.directory/users/standard/read"),
            new DutyAnalysis { Duty = "b", Provider = RbacProviders.Exchange, Actions = Array.Empty<string>() },
            new DutyAnalysis { Duty = "c", Provider = RbacProviders.Exchange, Actions = Array.Empty<string>() }
        };

        Assert.Contains(PortfolioComposer.Compose(analyses).Concerns,
            c => c.Detail.Contains("synced catalog", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void EmptyInputProducesAnEmptyPlanNotAnError()
    {
        var portfolio = PortfolioComposer.Compose(Array.Empty<DutyAnalysis>());

        Assert.Empty(portfolio.Grants);
        Assert.Empty(portfolio.Unresolved);
        Assert.False(portfolio.HasBlockingConcern);
    }

    // ---------- ordering ----------

    [Fact]
    public void RiskiestGrantsAreListedFirst()
    {
        var analyses = new[]
        {
            Duty("read users", RbacProviders.Directory, "Reader",
                 "microsoft.directory/users/standard/read"),
            Duty("reset passwords", RbacProviders.Directory, "Helpdesk",
                 "microsoft.directory/users/password/update")
        };

        var grants = PortfolioComposer.Compose(analyses).Grants;

        Assert.Equal(GrantLifetime.OnRequest, grants[0].Lifetime);
        Assert.Equal(GrantLifetime.Standing, grants[^1].Lifetime);
    }
}
