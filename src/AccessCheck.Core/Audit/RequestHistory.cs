using System.Text.Json;
using AccessCheck.Core.Recommendation;

namespace AccessCheck.Core.Audit;

/// <summary>
/// One access request end-to-end: what was asked, what the AI suggested, what the
/// validator ruled, what the human approved, and what Graph executed. This record
/// plus the prompt log is the exportable audit artifact.
/// </summary>
public sealed record RequestRecord
{
    public required string Id { get; init; }
    public required DateTimeOffset CreatedUtc { get; init; }
    public required string FunctionDescription { get; init; }
    public string? PrincipalId { get; init; }
    public string? PrincipalDisplay { get; init; }

    // AI stage (untrusted input, recorded verbatim for audit)
    public IReadOnlyList<string> AiSuggestedActions { get; init; } = Array.Empty<string>();
    /// <summary>Actions the APPROVER added by hand before execution — provenance kept separate from AI suggestions.</summary>
    public IReadOnlyList<string> HumanAddedActions { get; init; } = Array.Empty<string>();
    public string AiReasoning { get; init; } = "";
    /// <summary>SHA-256 of the exact outbound prompt; full text lives in the prompt log.</summary>
    public string? PromptSha256 { get; init; }

    // Deterministic stage
    public IReadOnlyList<string> ValidatedActions { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> RejectedUnknownActions { get; init; } = Array.Empty<string>();
    public string? ChosenRoleId { get; init; }
    public string? ChosenRoleDisplay { get; init; }
    public bool CustomRoleCreated { get; init; }
    /// <summary>The over-privilege delta of the chosen role vs the function's needs.</summary>
    public IReadOnlyList<string> ExcessActionsAccepted { get; init; } = Array.Empty<string>();

    // Human stage
    public bool Approved { get; init; }
    public string? ApprovedBy { get; init; }
    public DateTimeOffset? ApprovedUtc { get; init; }

    // Execution stage
    public string? AssignmentTypeUsed { get; init; }
    public string? Duration { get; init; }
    /// <summary>True when the approver deliberately granted access with no expiry.</summary>
    public bool PermanentGrant { get; init; }
    public string? GraphScheduleRequestId { get; init; }
    /// <summary>RBAC provider the grant targets (directory, deviceManagement, exchange, ...).</summary>
    public string? Provider { get; init; }
    /// <summary>Direct multi-provider assignment id (Intune/CloudPC/Defender) — app-tracked expiry.</summary>
    public string? MultiAssignmentId { get; init; }
    /// <summary>Group used for a PIM-for-Groups grant, when that path was chosen.</summary>
    public string? GroupIdUsed { get; init; }
    /// <summary>Exchange/Purview: the ACG- role group created to carry this grant.</summary>
    public string? ExoRoleGroup { get; init; }
    /// <summary>Exchange/Purview: the management role assigned (custom AC- role or built-in).</summary>
    public string? ExoRoleName { get; init; }
    /// <summary>When the app itself must remove access (non-PIM providers, direct path).</summary>
    public DateTimeOffset? TrackedExpiryUtc { get; init; }
    public bool RemovedByHousekeeping { get; init; }
    public DateTimeOffset? ExpiresUtc { get; init; }
    public string? Notes { get; init; }
}

/// <summary>Append-only JSON-lines store; one line per record revision (latest wins by Id).</summary>
public sealed class RequestHistoryStore
{
    private readonly string _path;
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public RequestHistoryStore(string path)
    {
        _path = path;
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    }

    public void Append(RequestRecord record) =>
        File.AppendAllText(_path, JsonSerializer.Serialize(record, JsonOpts) + Environment.NewLine);

    public IReadOnlyList<RequestRecord> LoadLatest()
    {
        if (!File.Exists(_path)) return Array.Empty<RequestRecord>();
        var byId = new Dictionary<string, RequestRecord>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in File.ReadLines(_path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var rec = JsonSerializer.Deserialize<RequestRecord>(line, JsonOpts);
            if (rec is not null) byId[rec.Id] = rec;
        }
        return byId.Values.OrderByDescending(r => r.CreatedUtc).ToList();
    }
}

/// <summary>Helper to build the audit record from a validated outcome.</summary>
public static class RequestRecordBuilder
{
    public static RequestRecord FromOutcome(
        string functionDescription,
        AiSuggestion suggestion,
        ValidationOutcome outcome,
        string? promptSha256,
        IReadOnlyList<string>? humanAddedActions = null)
    {
        var best = outcome.BestFit;
        return new RequestRecord
        {
            Id = Guid.NewGuid().ToString("N"),
            CreatedUtc = DateTimeOffset.UtcNow,
            FunctionDescription = functionDescription,
            AiSuggestedActions = suggestion.RequiredActions,
            HumanAddedActions = humanAddedActions ?? Array.Empty<string>(),
            AiReasoning = suggestion.Reasoning,
            PromptSha256 = promptSha256,
            ValidatedActions = outcome.ValidActions,
            RejectedUnknownActions = outcome.UnknownActionsRejected,
            ChosenRoleId = outcome.CustomRoleRecommended ? null : best?.RoleId,
            ChosenRoleDisplay = outcome.CustomRoleRecommended
                ? outcome.CustomRole?.DisplayName
                : best?.DisplayName,
            CustomRoleCreated = outcome.CustomRoleRecommended,
            ExcessActionsAccepted = outcome.CustomRoleRecommended
                ? Array.Empty<string>()
                : best?.ExcessActions ?? Array.Empty<string>()
        };
    }
}
