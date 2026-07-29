using AccessCheck.Core.Catalog;
using AccessCheck.Core.Recommendation;
using Xunit;

namespace AccessCheck.Core.Tests;

/// <summary>
/// The generated role name is what an auditor reads six months later, and it is also the
/// object's identity in the tenant. Two different grants sharing a name collide there — and
/// a role group's contents cannot be changed after creation, so that collision is unfixable
/// in place.
/// </summary>
public class CustomRoleNamingTests
{
    // Padding that makes every built-in a poor fit, so the custom-role path is the one under
    // test. A role covering the request EXACTLY wins on zero excess and no custom role is
    // ever drafted — which is correct behaviour and useless for testing naming.
    private static readonly string[] Noise =
    {
        "microsoft.directory/applications/allProperties/allTasks",
        "microsoft.directory/servicePrincipals/allProperties/allTasks",
        "microsoft.directory/devices/delete",
        "microsoft.directory/groups/allProperties/allTasks",
        "microsoft.directory/domains/allProperties/allTasks",
        "microsoft.directory/policies/allProperties/allTasks"
    };

    private static string DraftedNameFor(
        string provider, string function, params string[] wanted)
    {
        var catalog = new RoleCatalog();
        catalog.ReplaceAll(new[]
        {
            new RoleDefinitionRecord
            {
                Id = "broad",
                DisplayName = "Some Broad Built-In",
                Provider = provider,
                IsBuiltIn = true,
                Description = "",
                AllowedResourceActions = wanted.Concat(Noise).ToList()
            }
        }, new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));

        var validator = new RecommendationValidator { MaxAcceptableExcessActions = 0 };
        var outcome = validator.Validate(catalog, new AiSuggestion
        {
            RequiredActions = wanted,
            Reasoning = "",
            Confidence = SuggestionConfidence.High
        }, function);

        return outcome.CustomRole?.DisplayName ?? "";
    }

    [Fact]
    public void ThreeGrantsOnTheSameResourceGetThreeDifferentNames()
    {
        // All three act on "users" and were previously all called "AC - Entra ID manage
        // users": one creates accounts, one amends licence and location, one deletes and
        // re-creates authentication methods. Same name, three different grants, colliding
        // in the tenant.
        var create = DraftedNameFor(RbacProviders.Directory, "create user accounts",
            "microsoft.directory/users/create");

        var amend = DraftedNameFor(RbacProviders.Directory, "amend user accounts",
            "microsoft.directory/users/basic/update",
            "microsoft.directory/users/usageLocation/update");

        var mfa = DraftedNameFor(RbacProviders.Directory, "re-register MFA methods",
            "microsoft.directory/users/authenticationMethods/create",
            "microsoft.directory/users/authenticationMethods/delete");

        Assert.NotEmpty(create);
        Assert.NotEmpty(amend);
        Assert.NotEmpty(mfa);

        Assert.NotEqual(create, amend);
        Assert.NotEqual(create, mfa);
        Assert.NotEqual(amend, mfa);
    }

    [Fact]
    public void TheCapabilitySegmentAppearsInTheName()
    {
        // "manage users authenticationMethods" says what the role does in a way
        // "manage users" does not.
        var name = DraftedNameFor(RbacProviders.Directory, "re-register MFA methods",
            "microsoft.directory/users/authenticationMethods/delete");

        Assert.Contains("authenticationMethods", name, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BreadthQualifiersAreNotTreatedAsCapabilities()
    {
        // "basic" and "standard" qualify how MUCH of a resource is reached, not what is
        // done to it. Naming a role "manage users basic" would imply a capability that
        // does not exist.
        var name = DraftedNameFor(RbacProviders.Directory, "amend user accounts",
            "microsoft.directory/users/basic/update");

        Assert.NotEmpty(name);
        Assert.DoesNotContain(" basic", name, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ACmdletNameNeedsNoCapabilitySuffix()
    {
        // Add-MailboxFolderPermission has no path shape and is already specific — there is
        // no capability segment to extract, and appending one would invent a distinction.
        var name = DraftedNameFor(RbacProviders.Exchange, "delegate a mailbox",
            "Add-MailboxFolderPermission");

        Assert.NotEmpty(name);
        Assert.Contains("MailboxFolderPermission", name, StringComparison.OrdinalIgnoreCase);
    }
}
