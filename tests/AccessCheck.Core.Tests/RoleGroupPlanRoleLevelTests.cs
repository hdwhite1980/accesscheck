using AccessCheck.Core.Catalog;
using AccessCheck.Core.Recommendation;
using Xunit;

namespace AccessCheck.Core.Tests;

/// <summary>
/// Purview's plan is role-level because the service exposes nothing smaller. These pin the
/// two properties that matter: a role the tenant does not define is rejected rather than
/// substituted, and the over-privilege figure is real rather than absent.
/// </summary>
public class RoleGroupPlanRoleLevelTests
{
    private static PurviewRoleCatalog Docs()
    {
        var c = new PurviewRoleCatalog();
        c.Roles.Add(new PurviewRoleCatalog.PurviewRole
        {
            Name = "Search And Purge",
            Description = "Bulk-remove data matching a content search.",
            InRoleGroups = new[] { "Data Investigator", "Organization Management" }
        });
        c.Roles.Add(new PurviewRoleCatalog.PurviewRole
        {
            Name = "Compliance Search",
            Description = "Search across mailboxes and estimate results.",
            InRoleGroups = new[] { "Data Investigator", "Organization Management" }
        });
        c.Roles.Add(new PurviewRoleCatalog.PurviewRole
        {
            Name = "Audit Logs",
            Description = "Configure auditing and export audit reports.",
            InRoleGroups = new[] { "Organization Management" }
        });

        c.RoleGroups.Add(new PurviewRoleCatalog.PurviewRoleGroup
        {
            Name = "Data Investigator",
            Roles = new[] { "Compliance Search", "Custodian", "Export", "Search And Purge" }
        });
        c.RoleGroups.Add(new PurviewRoleCatalog.PurviewRoleGroup
        {
            Name = "Organization Management",
            Roles = new[] { "Audit Logs", "Compliance Search", "Role Management",
                            "Search And Purge", "Quarantine" }
        });
        return c;
    }

    private static readonly string[] Tenant =
    {
        "Search And Purge", "Compliance Search", "Audit Logs", "Custodian", "Export"
    };

    [Fact]
    public void ThePlanCarriesTheRolesAskedForAndNothingElse()
    {
        var plan = RoleGroupPlan.BuildFromRoles(
            Docs(), Tenant, new[] { "Search And Purge", "Compliance Search" }, "ACG - purge");

        Assert.True(plan.RoleLevel);
        Assert.True(plan.IsComplete);
        Assert.Equal(2, plan.Roles.Count);
        Assert.All(plan.Roles, r => Assert.True(r.IsRoleLevel));
        Assert.All(plan.Roles, r => Assert.Empty(r.Excess));
    }

    [Fact]
    public void OverPrivilegeIsMeasuredAgainstTheNarrowestBuiltInGroup()
    {
        // Data Investigator carries 4 roles; the plan needs 2. Composing avoids 2 roles.
        // Before this, a Purview verdict had no delta at all and read as "zero excess".
        var plan = RoleGroupPlan.BuildFromRoles(
            Docs(), Tenant, new[] { "Search And Purge", "Compliance Search" }, "ACG - purge");

        Assert.Equal("Data Investigator", plan.NarrowestAlternative);
        Assert.Equal(2, plan.AlternativeExcessRoles);
        Assert.Contains("Data Investigator", plan.Headline);
    }

    [Fact]
    public void NoSingleBuiltInGroupCoveringTheSetIsTheStrongestCaseNotTheWeakest()
    {
        // Custodian sits only in Data Investigator, Audit Logs only in Organization
        // Management. Null must not read as "no excess" — the alternative is granting both.
        var plan = RoleGroupPlan.BuildFromRoles(
            Docs(), Tenant, new[] { "Custodian", "Audit Logs" }, "ACG - mixed");

        Assert.Null(plan.AlternativeExcessRoles);
        Assert.Contains("NO single built-in role group", plan.Headline);
    }

    [Fact]
    public void ARoleTheTenantDoesNotDefineIsRejectedNotSubstituted()
    {
        // The same rule as an unknown action, applied to the only vocabulary this service
        // publishes. A model cannot invent a role here.
        var plan = RoleGroupPlan.BuildFromRoles(
            Docs(), Tenant, new[] { "Search And Purge", "Invented Role" }, "ACG - x");

        Assert.False(plan.IsComplete);
        Assert.Equal("Invented Role", Assert.Single(plan.Uncovered));
        Assert.Single(plan.Roles);
        Assert.Contains("not defined in this tenant", plan.Headline,
                        StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AnAlreadyMinimalBuiltInIsNotDressedUpAsASaving()
    {
        // Where the built-in carries exactly what is needed, composing a group adds an
        // object to govern and grants nothing less. Manufacturing a difference there would
        // be the same overstatement PermissionBreadth exists to stop.
        var docs = Docs();
        docs.RoleGroups.Add(new PurviewRoleCatalog.PurviewRoleGroup
        {
            Name = "Audit Reader", Roles = new[] { "Audit Logs" }
        });

        var plan = RoleGroupPlan.BuildFromRoles(
            docs, Tenant, new[] { "Audit Logs" }, "ACG - audit");

        Assert.Equal(0, plan.AlternativeExcessRoles);
        Assert.Contains("already minimal", plan.Headline);
    }

    [Fact]
    public void RoleDescriptionsReachThePlanForTheApprovalScreen()
    {
        var plan = RoleGroupPlan.BuildFromRoles(
            Docs(), Tenant, new[] { "Search And Purge" }, "ACG - purge");

        Assert.Contains("Bulk-remove", plan.Describe());
    }

    [Fact]
    public void RiskScoringIsNotAppliedToRoleNames()
    {
        // ActionRisk reads action SHAPES. "Search And Purge" is not one, and scoring it
        // would produce a number with no meaning behind it.
        var plan = RoleGroupPlan.BuildFromRoles(
            Docs(), Tenant, new[] { "Search And Purge" }, "ACG - purge");

        Assert.Equal(0, plan.TotalExcessRisk);
    }
}
