using AccessCheck.Core.Catalog;
using AccessCheck.Core.Recommendation;
using Xunit;

namespace AccessCheck.Core.Tests;

/// <summary>
/// The guards decide whether a plausible-looking proposal reaches an approver. They have
/// never been testable, because the decision of which to run lived in the desktop app's
/// code-behind — so they also never ran anywhere else. That is how a request to remove
/// malicious MESSAGES was answered with Remove-Mailbox, which deletes the mailbox and the
/// user account, and passed without comment.
/// </summary>
public class GuardReportTests
{
    private static RoleCatalog CatalogWith(string provider, params string[] actions)
    {
        var c = new RoleCatalog();
        c.ReplaceAll(new[]
        {
            new RoleDefinitionRecord
            {
                Id = "r1",
                DisplayName = "Some Role",
                Provider = provider,
                IsBuiltIn = true,
                Description = "",
                AllowedResourceActions = actions.ToList()
            }
        }, new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        return c;
    }

    private static IReadOnlyList<ProviderOutcome> OutcomeWith(
        string provider, params string[] validActions)
    {
        var catalog = CatalogWith(provider, validActions);
        var validator = new RecommendationValidator { MaxAcceptableExcessActions = 5 };
        return validator.ValidateMulti(catalog, new AiSuggestion
        {
            RequiredActions = validActions,
            Reasoning = "",
            Confidence = SuggestionConfidence.High
        }, "test");
    }

    [Fact]
    public void ACleanProposalProducesNoFindings()
    {
        var catalog = CatalogWith(RbacProviders.Directory,
            "microsoft.directory/users/password/update");

        var findings = GuardReport.Build(
            "reset passwords for the service desk",
            OutcomeWith(RbacProviders.Directory, "microsoft.directory/users/password/update"),
            catalog);

        Assert.Empty(findings);
    }

    [Fact]
    public void ALimitPermissionsCannotExpressIsReported()
    {
        // "but not for administrators" is a reasonable request that RBAC cannot encode.
        // Approving the permissions without applying the limit elsewhere grants more than
        // was agreed — and this is the only finding that can be true of a CORRECT proposal.
        var catalog = CatalogWith(RbacProviders.Directory,
            "microsoft.directory/users/password/update");

        var findings = GuardReport.Build(
            "reset passwords for all staff except administrators",
            OutcomeWith(RbacProviders.Directory, "microsoft.directory/users/password/update"),
            catalog);

        Assert.NotEmpty(findings);
    }

    [Fact]
    public void LowConfidenceIsAFindingRatherThanAFootnote()
    {
        // "No confident match" is a real answer. Rendered as a verdict that looks like
        // every other verdict, it stops being read.
        var catalog = CatalogWith(RbacProviders.Directory,
            "microsoft.directory/users/standard/read");

        var findings = GuardReport.Build(
            "read users",
            OutcomeWith(RbacProviders.Directory, "microsoft.directory/users/standard/read"),
            catalog, null, SuggestionConfidence.Low);

        Assert.Contains(findings,
            f => f.Title.Contains("Low confidence", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void NothingProposedWithConfidenceIsSeriousNotAWarning()
    {
        var catalog = CatalogWith(RbacProviders.Directory,
            "microsoft.directory/users/standard/read");

        var findings = GuardReport.Build(
            "read users",
            OutcomeWith(RbacProviders.Directory, "microsoft.directory/users/standard/read"),
            catalog, null, SuggestionConfidence.None);

        Assert.Contains(findings,
            f => f.Severity == GuardSeverity.Serious &&
                 f.Title.Contains("Low confidence", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void AServiceWideGrantIsReportedWhenSomethingNarrowerExists()
    {
        var catalog = CatalogWith(RbacProviders.Intune,
            "microsoft.intune/allEntities/allTasks",
            "microsoft.intune/deviceConfigurations/read");

        var findings = GuardReport.Build(
            "manage everything in intune",
            OutcomeWith(RbacProviders.Intune, "microsoft.intune/allEntities/allTasks"),
            catalog);

        Assert.Contains(findings,
            f => f.Title.Contains("Too broad", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void FindingsAreOrderedMostSeriousFirst()
    {
        // An operator who reads only the first line should be reading the one most likely
        // to stop them.
        var catalog = CatalogWith(RbacProviders.Intune,
            "microsoft.intune/allEntities/allTasks",
            "microsoft.intune/deviceConfigurations/read");

        var findings = GuardReport.Build(
            "manage everything in intune except test devices",
            OutcomeWith(RbacProviders.Intune, "microsoft.intune/allEntities/allTasks"),
            catalog, null, SuggestionConfidence.Low);

        Assert.True(findings.Count > 1);
        for (var i = 1; i < findings.Count; i++)
            Assert.True(findings[i - 1].Severity >= findings[i].Severity);
    }

    [Theory]
    // Purview exposes no role CONTENTS, so the catalog stores each role as one action
    // carrying its own name. Those match no known action shape, so the
    // unknown-means-privileged default rated a READER role as an escalation route — which
    // made the lifetime tiers meaningless across the whole service.
    [InlineData("License Usage Reader", false)]
    [InlineData("Security Reader", false)]
    [InlineData("View-Only Audit Logs", false)]
    // Roles that genuinely write keep the cautious default. "Analyst" and "Investigator"
    // routinely carry write capability in Purview.
    [InlineData("DLP Compliance Management", true)]
    [InlineData("Search And Purge", true)]
    [InlineData("Insider Risk Management Analyst", true)]
    public void APurviewRoleNamedReaderIsAReadNotAnEscalationRoute(string role, bool privileged)
    {
        Assert.Equal(privileged, ActionRisk.IsPrivilegedHeuristic(role));
    }

    [Fact]
    public void OrdinaryActionShapesAreUnaffectedByTheRoleNameRule()
    {
        // The rule only reaches strings with a space and no path or cmdlet punctuation.
        Assert.True(ActionRisk.IsPrivilegedHeuristic("microsoft.directory/users/password/update"));
        Assert.False(ActionRisk.IsPrivilegedHeuristic("microsoft.directory/users/standard/read"));
        Assert.False(ActionRisk.IsPrivilegedHeuristic("Get-Mailbox"));
        // A hyphenated CMDLET has no space, so the role-name rule cannot reach it and the
        // verb still decides.
        Assert.True(ActionRisk.IsPrivilegedHeuristic("Remove-Mailbox"));
        Assert.True(ActionRisk.IsPrivilegedHeuristic("New-ComplianceSearchAction"));
    }

    [Fact]
    public void DescribeProducesNothingForACleanProposal()
    {
        Assert.Equal("", GuardReport.Describe(Array.Empty<GuardFinding>()));
    }

    [Fact]
    public void DescribeMarksSeriousFindingsDistinctly()
    {
        var findings = new[]
        {
            new GuardFinding
            {
                Severity = GuardSeverity.Serious,
                Title = "Possibly the wrong resource: Remove-Mailbox",
                Detail = "It deletes the mailbox, not messages within it.",
                Alternatives = new[] { "New-ComplianceSearchAction -Purge" }
            }
        };

        var text = GuardReport.Describe(findings);

        Assert.Contains("!!", text);
        Assert.Contains("consider instead", text);
    }
}
