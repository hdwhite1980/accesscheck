using AccessLens.Core.Audit;
using AccessLens.Core.Catalog;
using AccessLens.Core.Recommendation;
using Xunit;

namespace AccessLens.Core.Tests;

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
        Assert.True(AccessLens.Core.Execution.DurationParser.TryParse(input, out var iso, out var span));
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
        Assert.False(AccessLens.Core.Execution.DurationParser.TryParse(input, out _, out _));
    }
}
