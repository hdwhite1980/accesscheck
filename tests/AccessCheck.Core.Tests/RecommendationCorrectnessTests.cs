using AccessCheck.Core.Catalog;
using AccessCheck.Core.Recommendation;
using Xunit;

namespace AccessCheck.Core.Tests;

/// <summary>
/// Tests of RECOMMENDATION CORRECTNESS rather than mechanics.
///
/// The existing suite proves hallucinated strings are rejected and the smallest covering
/// role wins — real properties, but all of them about plumbing. None of them would fail if
/// the app recommended a read-only permission for a delete task, took a permission's
/// meaning from the role containing it, or minted a custom role from an action Microsoft
/// refuses. That is why the app could pass every test and still recommend the wrong thing.
/// </summary>
public class RecommendationCorrectnessTests
{
    private static RoleCatalog CatalogWith(params RoleDefinitionRecord[] roles)
    {
        var c = new RoleCatalog();
        c.ReplaceAll(roles);
        return c;
    }

    private static RoleDefinitionRecord Role(
        string id, string name, string provider, string description, params string[] actions) =>
        new()
        {
            Id = id,
            DisplayName = name,
            Provider = provider,
            IsBuiltIn = true,
            Description = description,
            AllowedResourceActions = actions.ToList()
        };

    // ---------- task coverage: operation must match ----------

    [Fact]
    public void ReadPermissionCannotSatisfyDeleteTask()
    {
        var r = TaskCoverage.Evaluate(
            "delete the user's authentication methods",
            "microsoft.directory/users/authenticationMethods/standard/restrictedRead",
            "Read standard properties of authentication methods.");

        Assert.Equal(TaskCoverage.Status.Contradicted, r.Status);
    }

    [Fact]
    public void ReadPermissionCannotSatisfyUpdateTask()
    {
        var r = TaskCoverage.Evaluate(
            "reset a user's password",
            "microsoft.directory/users/standard/read",
            "Read basic properties on users.");

        Assert.Equal(TaskCoverage.Status.Contradicted, r.Status);
    }

    [Fact]
    public void WritePermissionSatisfiesUpdateTask()
    {
        var r = TaskCoverage.Evaluate(
            "reset a user's password",
            "microsoft.directory/users/password/update",
            "Reset passwords for users.");

        Assert.Equal(TaskCoverage.Status.Verified, r.Status);
    }

    [Fact]
    public void UnclearOperationReturnsUnknownRatherThanGuessing()
    {
        // A confident wrong answer here is worse than silence.
        var r = TaskCoverage.Evaluate(
            "help the team with their mailboxes",
            "microsoft.directory/somethingOpaque",
            "");

        Assert.Equal(TaskCoverage.Status.Unknown, r.Status);
    }

    // ---------- a read permission must never be OFFERED for a write task ----------

    [Fact]
    public void ReadPermissionIsNotEvenOfferedForAWriteTask()
    {
        var catalog = CatalogWith(Role(
            "r1", "Authentication Administrator", RbacProviders.Directory, "d",
            "microsoft.directory/users/authenticationMethods/standard/restrictedRead",
            "microsoft.directory/users/authenticationMethods/basic/update"));

        var candidates = PermissionIndex.CandidateActions(
            "reset MFA methods for standard users", catalog);

        // The read permission must not be in the list the model sees at all.
        Assert.DoesNotContain(candidates,
            c => c.Action.Contains("restrictedRead", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ReadPermissionIsStillOfferedForAReadTask()
    {
        var catalog = CatalogWith(Role(
            "r1", "Reader", RbacProviders.Directory, "d",
            "microsoft.directory/users/standard/read"));

        var candidates = PermissionIndex.CandidateActions(
            "let the helpdesk view user properties", catalog);

        Assert.Contains(candidates,
            c => c.Action.Contains("/read", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ContradictedPermissionDoesNotReachRoleComparison()
    {
        var catalog = CatalogWith(Role(
            "r1", "Authentication Administrator", RbacProviders.Directory, "d",
            "microsoft.directory/users/authenticationMethods/standard/restrictedRead",
            "microsoft.directory/users/authenticationMethods/basic/update"));

        var validator = new RecommendationValidator();
        var outcome = validator.Validate(catalog, new AiSuggestion
        {
            // The model proposes both; only the write one may survive.
            RequiredActions = new[]
            {
                "microsoft.directory/users/authenticationMethods/standard/restrictedRead",
                "microsoft.directory/users/authenticationMethods/basic/update"
            },
            Confidence = SuggestionConfidence.High
        }, "reset MFA methods for standard users");

        Assert.DoesNotContain(outcome.ValidActions,
            a => a.Contains("restrictedRead", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(outcome.ValidActions,
            a => a.Contains("basic/update", StringComparison.OrdinalIgnoreCase));
    }

    // ---------- descriptions must come from the reference, not the role ----------

    [Fact]
    public void PermissionDescriptionComesFromReferenceNotRole()
    {
        var catalog = CatalogWith(Role(
            "r1", "Authentication Administrator", RbacProviders.Directory,
            "Manages authentication methods for users.",
            "microsoft.directory/users/authenticationMethods/update",
            "microsoft.directory/groups/basic/read"));

        var reference = new ReferenceStore
        {
            Entries =
            {
                new ReferenceStore.ReferenceEntry
                {
                    Name = "microsoft.directory/groups/basic/read",
                    Provider = RbacProviders.Directory,
                    Description = "Read basic properties on groups."
                }
            }
        };

        var index = PermissionIndex.Build(catalog, reference);
        var groups = index.Entries.First(e =>
            e.Action == "microsoft.directory/groups/basic/read");

        // The ROLE says "manages authentication methods". This permission reads groups.
        Assert.Equal("Read basic properties on groups.", groups.Description);
        Assert.DoesNotContain("authentication", groups.Description,
                              StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void UnrelatedPermissionFromSameRoleIsNotDescribedByTheRole()
    {
        var catalog = CatalogWith(Role(
            "r1", "Authentication Administrator", RbacProviders.Directory,
            "Manages authentication methods for users.",
            "microsoft.directory/groups/basic/read"));

        // No reference entry for it at all.
        var index = PermissionIndex.Build(catalog, new ReferenceStore());
        var entry = index.Entries.First();

        // Without a Microsoft description the source must SAY SO rather than borrowing
        // the role's text as though it described the permission.
        Assert.NotEqual("Microsoft reference", entry.DescriptionSource);
    }

    // ---------- the candidate set must include reference-only permissions ----------

    [Fact]
    public void ReferenceOnlyPermissionAppearsInCandidateSet()
    {
        var catalog = CatalogWith(Role(
            "r1", "Some Role", RbacProviders.Directory, "desc",
            "microsoft.directory/groups/basic/read"));

        var reference = new ReferenceStore
        {
            Entries =
            {
                new ReferenceStore.ReferenceEntry
                {
                    Name = "microsoft.directory/users/password/update",
                    Provider = RbacProviders.Directory,
                    Description = "Reset passwords for users."
                }
            }
        };

        var index = PermissionIndex.Build(catalog, reference);

        var referenceOnly = index.Entries.FirstOrDefault(e =>
            e.Action == "microsoft.directory/users/password/update");

        Assert.NotNull(referenceOnly);
        Assert.False(referenceOnly!.PresentInTenant);
    }

    // ---------- custom-role eligibility is three-state ----------

    [Fact]
    public void UnknownCustomRoleEligibilityDoesNotRecommendCustomRole()
    {
        var e = new CustomRoleEligibility();
        // Never refused, never proven — silence is not permission.
        Assert.Equal(CustomRoleEligibility.Status.Unknown,
                     e.Eligibility("microsoft.directory/users/disable"));
    }

    [Fact]
    public void RefusedActionIsUnsupported()
    {
        var e = new CustomRoleEligibility();
        e.RecordIneligible("microsoft.directory/users/disable");

        Assert.Equal(CustomRoleEligibility.Status.Unsupported,
                     e.Eligibility("microsoft.directory/users/disable"));
    }

    [Fact]
    public void ProvenActionIsSupportedAndRefusalOutranksProof()
    {
        var e = new CustomRoleEligibility();
        e.RecordEligible("microsoft.directory/groups/create");
        Assert.Equal(CustomRoleEligibility.Status.Supported,
                     e.Eligibility("microsoft.directory/groups/create"));

        // A later refusal must win over an earlier assumption.
        e.RecordIneligible("microsoft.directory/groups/create");
        Assert.Equal(CustomRoleEligibility.Status.Unsupported,
                     e.Eligibility("microsoft.directory/groups/create"));
    }

    [Fact]
    public void RefusedActionParsedFromMicrosoftError()
    {
        var parsed = CustomRoleEligibility.ParseRefusedAction(
            "Action 'microsoft.directory/users/disable' is not supported for Custom Role creation.");

        Assert.Equal("microsoft.directory/users/disable", parsed);
    }

    // ---------- risk, not raw count ----------

    [Fact]
    public void LeastRiskBuiltInRoleWinsOverRoleWithFewerButMoreDangerousExcessActions()
    {
        var required = new[] { "microsoft.directory/groups/basic/read" };

        var dangerous = Role("r1", "Few But Dangerous", RbacProviders.Directory, "d",
            "microsoft.directory/groups/basic/read",
            "microsoft.directory/users/password/update",
            "microsoft.directory/roleManagement/allProperties/allTasks");

        var wideButHarmless = Role("r2", "Many But Harmless", RbacProviders.Directory, "d",
            "microsoft.directory/groups/basic/read",
            "microsoft.directory/users/standard/read",
            "microsoft.directory/devices/standard/read",
            "microsoft.directory/applications/standard/read",
            "microsoft.directory/contacts/standard/read",
            "microsoft.directory/domains/standard/read");

        var catalog = CatalogWith(dangerous, wideButHarmless);
        var validator = new RecommendationValidator();
        var outcome = validator.Validate(catalog, new AiSuggestion
        {
            RequiredActions = required,
            Confidence = SuggestionConfidence.High
        }, "read group properties");

        // Five harmless reads must rank above two escalation-capable extras, even though
        // the raw count says the opposite.
        Assert.Equal("Many But Harmless", outcome.RankedFits.First().DisplayName);
    }

    [Fact]
    public void CriticalExcessIsFlaggedRegardlessOfCount()
    {
        Assert.True(ActionRisk.IsCriticalExcess("microsoft.directory/users/password/update"));
        Assert.True(ActionRisk.IsCriticalExcess("microsoft.directory/roleManagement/allProperties/allTasks"));
        Assert.False(ActionRisk.IsCriticalExcess("microsoft.directory/groups/standard/read"));
    }

    // ---------- provider ownership must not depend on sync order ----------

    [Fact]
    public void ActionInTwoServicesIsReportedAsAmbiguousNotArbitrary()
    {
        var exchange = Role("r1", "Mailbox Search", RbacProviders.Exchange, "d",
            "New-ComplianceSearch");
        var purview = Role("r2", "Compliance Search", RbacProviders.Purview, "d",
            "New-ComplianceSearch");

        var catalog = CatalogWith(exchange, purview);

        Assert.True(catalog.IsAmbiguous("New-ComplianceSearch"));
        Assert.Equal(2, catalog.ProvidersOf("New-ComplianceSearch").Count);
    }

    [Fact]
    public void DirectoryActionResolvesByShapeNotSyncOrder()
    {
        // Same action name granted by roles in two providers; its NAMESPACE settles it.
        var a = Role("r1", "A", RbacProviders.Intune, "d", "microsoft.directory/users/disable");
        var b = Role("r2", "B", RbacProviders.Directory, "d", "microsoft.directory/users/disable");

        var catalog = CatalogWith(a, b);
        Assert.Equal(RbacProviders.Directory, catalog.ProviderOf("microsoft.directory/users/disable"));
    }
}
