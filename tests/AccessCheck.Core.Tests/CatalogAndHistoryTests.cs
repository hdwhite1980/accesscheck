using AccessCheck.Core.Audit;
using AccessCheck.Core.Catalog;
using AccessCheck.Core.Recommendation;
using Xunit;

namespace AccessCheck.Core.Tests;

public class CatalogAndHistoryTests
{
    [Fact]
    public void CatalogJsonRoundTrip_PreservesRolesAndActions()
    {
        var cat = new RoleCatalog();
        cat.ReplaceAll(new[]
        {
            new RoleDefinitionRecord
            {
                Id = "r1",
                DisplayName = "Test Role",
                Description = "desc",
                IsBuiltIn = true,
                AllowedResourceActions = new[] { "a/b/c", "d/e/f" }
            }
        }, DateTimeOffset.UtcNow);

        var restored = RoleCatalog.FromJson(cat.ToJson());

        Assert.Single(restored.Roles);
        Assert.True(restored.ActionExists("a/b/c"));
        Assert.True(restored.ActionExists("A/B/C")); // case-insensitive
        Assert.False(restored.ActionExists("x/y/z"));
    }

    [Fact]
    public void HistoryStore_AppendAndReload_LatestWinsById()
    {
        var path = Path.Combine(Path.GetTempPath(), "al-test-" + Guid.NewGuid().ToString("N") + ".jsonl");
        try
        {
            var store = new RequestHistoryStore(path);
            var rec = new RequestRecord
            {
                Id = "req1",
                CreatedUtc = DateTimeOffset.UtcNow,
                FunctionDescription = "reset passwords"
            };
            store.Append(rec);
            store.Append(rec with { Approved = true, ApprovedBy = "admin" });

            var latest = store.LoadLatest();

            Assert.Single(latest);
            Assert.True(latest[0].Approved);
            Assert.Equal("admin", latest[0].ApprovedBy);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void RecordBuilder_CapturesDeltaFromOutcome()
    {
        var suggestion = new AiSuggestion
        {
            RequiredActions = new[] { "a/b/c" },
            Reasoning = "because"
        };
        var outcome = new ValidationOutcome
        {
            ValidActions = new[] { "a/b/c" },
            UnknownActionsRejected = Array.Empty<string>(),
            RankedFits = new[]
            {
                new RoleFit
                {
                    RoleId = "r1",
                    DisplayName = "Test Role",
                    IsBuiltIn = true,
                    ExcessActions = new[] { "d/e/f" }
                }
            },
            CustomRoleRecommended = false
        };

        var rec = RequestRecordBuilder.FromOutcome("do a thing", suggestion, outcome, "hash");

        Assert.Equal("r1", rec.ChosenRoleId);
        Assert.False(rec.CustomRoleCreated);
        Assert.Single(rec.ExcessActionsAccepted);
        Assert.Equal("hash", rec.PromptSha256);
    }
}

public class DurationParserTests
{
    [Theory]
    [InlineData("14 days", "P14D", 14 * 24)]
    [InlineData("30d", "P30D", 30 * 24)]
    [InlineData("2 weeks", "P14D", 14 * 24)]
    [InlineData("8 hours", "PT8H", 8)]
    [InlineData("45 min", "PT45M", 0)]
    [InlineData("1 month", "P1M", 30 * 24)]
    [InlineData("P7D", "P7D", 7 * 24)]
    [InlineData("pt8h", "PT8H", 8)]
    public void FriendlyAndIsoInputs_ProduceIso(string input, string expectedIso, int approxHours)
    {
        Assert.True(AccessCheck.Core.Execution.DurationParser.TryParse(input, out var iso, out var span));
        Assert.Equal(expectedIso, iso);
        if (approxHours > 0)
            Assert.Equal(approxHours, (int)span.TotalHours);
    }

    [Theory]
    [InlineData("")]
    [InlineData("soon")]
    [InlineData("0 days")]
    [InlineData("P")]
    [InlineData("14 parsecs")]
    public void Garbage_IsRejected(string input)
    {
        Assert.False(AccessCheck.Core.Execution.DurationParser.TryParse(input, out _, out _));
    }
}

public class AccessReviewerTests
{
    private static AccessCheck.Core.Review.HeldRole Role(
        string name, params string[] actions) =>
        new()
        {
            Provider = AccessCheck.Core.Catalog.RbacProviders.Directory,
            RoleId = name,
            DisplayName = name,
            Path = AccessCheck.Core.Review.GrantPath.Active,
            GrantedActions = actions
        };

    [Fact]
    public void OverPrivileged_ExcessComputedAcrossRoles()
    {
        var held = new[]
        {
            Role("Helpdesk", "a/read", "a/reset", "a/delete"),
            Role("Groups", "g/create", "g/delete")
        };

        var result = AccessCheck.Core.Review.AccessReviewer.Compare(
            held, new[] { "a/read", "a/reset" });

        Assert.True(result.OverPrivileged);
        Assert.Equal(5, result.GrantedCount);
        Assert.Equal(3, result.ExcessCount); // a/delete, g/create, g/delete
        Assert.Equal(60, result.ExcessPercent);
        Assert.Empty(result.MissingActions);
    }

    [Fact]
    public void PerRoleVerdicts_Classify()
    {
        var held = new[]
        {
            Role("Helpdesk", "a/read", "a/reset", "a/delete"), // partially
            Role("Groups", "g/create"),                        // not justified
            Role("Reader", "a/read")                           // fully
        };

        var result = AccessCheck.Core.Review.AccessReviewer.Compare(
            held, new[] { "a/read", "a/reset" });

        var byName = result.RoleAssessments.ToDictionary(r => r.Role.DisplayName);
        Assert.Equal(AccessCheck.Core.Review.RoleVerdict.PartiallyJustified, byName["Helpdesk"].Verdict);
        Assert.Equal(AccessCheck.Core.Review.RoleVerdict.NotJustified, byName["Groups"].Verdict);
        Assert.Equal(AccessCheck.Core.Review.RoleVerdict.FullyJustified, byName["Reader"].Verdict);
    }

    [Fact]
    public void MissingActions_FlagUnderPrivilege()
    {
        var held = new[] { Role("Reader", "a/read") };

        var result = AccessCheck.Core.Review.AccessReviewer.Compare(
            held, new[] { "a/read", "a/reset" });

        Assert.True(result.UnderPrivileged);
        Assert.Single(result.MissingActions);
        Assert.Equal("a/reset", result.MissingActions[0]);
        Assert.False(result.OverPrivileged);
    }

    [Fact]
    public void RoleNotInCatalog_IsUnknownNotExcess()
    {
        var held = new[] { Role("Mystery") }; // no actions resolved

        var result = AccessCheck.Core.Review.AccessReviewer.Compare(held, new[] { "a/read" });

        Assert.Equal(AccessCheck.Core.Review.RoleVerdict.Unknown,
            result.RoleAssessments[0].Verdict);
        Assert.Empty(result.ExcessActions);
    }
}

public class PermanentDurationTests
{
    [Theory]
    [InlineData("never")]
    [InlineData("Permanent")]
    [InlineData("no expiry")]
    [InlineData("NO EXPIRATION")]
    [InlineData("forever")]
    [InlineData("indefinite")]
    public void PermanentForms_ParseAsPermanent(string input)
    {
        Assert.True(AccessCheck.Core.Execution.DurationParser.TryParseSpec(input, out var spec));
        Assert.True(spec.Permanent);
        Assert.Equal("", spec.Iso);
    }

    [Fact]
    public void NormalDuration_IsNotPermanent()
    {
        Assert.True(AccessCheck.Core.Execution.DurationParser.TryParseSpec("14 days", out var spec));
        Assert.False(spec.Permanent);
        Assert.Equal("P14D", spec.Iso);
    }

    [Fact]
    public void Garbage_StillRejected()
    {
        Assert.False(AccessCheck.Core.Execution.DurationParser.TryParseSpec("whenever-ish", out _));
    }
}
