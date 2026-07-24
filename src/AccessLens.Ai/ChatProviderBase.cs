using System.Text.Json;
using AccessLens.Core.Catalog;
using AccessLens.Core.Recommendation;

namespace AccessLens.Ai;

/// <summary>
/// Transport-agnostic AI pipeline: two-stage suggestion (shortlist -> exact actions)
/// and single-turn completions (explanations). Subclasses supply only SendChatAsync —
/// the wire format for one provider. Prompt logging, hashing, JSON parsing, and the
/// identity-free prompt discipline live here so every provider behaves identically.
/// </summary>
public abstract class ChatProviderBase : IRecommendationProvider, IDisposable
{
    protected readonly AiProviderConfig Config;
    protected readonly HttpClient Http;
    protected readonly string ApiKey;

    /// <summary>(stage, promptText) — wire to the diagnostics log. Key is never included.</summary>
    public Action<string, string>? PromptLogger { get; set; }

    /// <summary>SHA-256 of the last stage-2 prompt, for the audit record.</summary>
    public string? LastPromptSha256 { get; private set; }

    protected ChatProviderBase(AiProviderConfig config, string apiKey, HttpClient? http = null)
    {
        Config = config;
        ApiKey = apiKey;
        Http = http ?? new HttpClient();
        Http.Timeout = TimeSpan.FromSeconds(config.TimeoutSeconds);
    }

    /// <summary>Send one system+user exchange to the provider and return the raw text reply.</summary>
    protected abstract Task<string> SendChatAsync(string system, string user, CancellationToken ct);

    public async Task<AiSuggestion> SuggestAsync(
        string functionDescription,
        IReadOnlyCollection<RoleDefinitionRecord> catalogRoles,
        CancellationToken ct = default)
    {
        // Stage 1: shortlist by name/description only (keeps token cost sane on big catalogs).
        var shortlistUser = PromptBuilder.BuildShortlistUser(
            functionDescription, catalogRoles, Config.ShortlistSize);
        PromptLogger?.Invoke("shortlist", shortlistUser);

        var shortlistRaw = StripFences(
            await SendChatAsync(PromptBuilder.ShortlistSystem, shortlistUser, ct));
        var shortlistIds = ParseShortlist(shortlistRaw);

        var byId = catalogRoles.ToDictionary(r => r.Id, StringComparer.OrdinalIgnoreCase);
        var shortlisted = shortlistIds
            .Where(byId.ContainsKey)
            .Select(id => byId[id])
            .Take(Config.ShortlistSize)
            .ToList();
        if (shortlisted.Count == 0)
            shortlisted = catalogRoles.Take(Config.ShortlistSize).ToList();

        // Stage 2: full action lists for the shortlist only.
        var suggestUser = PromptBuilder.BuildSuggestUser(functionDescription, shortlisted);
        PromptLogger?.Invoke("suggest", suggestUser);
        LastPromptSha256 = PromptBuilder.Sha256Hex(suggestUser);

        var suggestRaw = StripFences(
            await SendChatAsync(PromptBuilder.SuggestSystem, suggestUser, ct));
        return ParseSuggestion(suggestRaw);
    }

    /// <summary>
    /// Single-turn completion for auxiliary asks (e.g. explaining one permission).
    /// Same logging discipline; callers must keep prompts identity-free.
    /// </summary>
    public async Task<string> CompleteAsync(
        string stage, string system, string user, CancellationToken ct = default)
    {
        PromptLogger?.Invoke(stage, user);
        return StripFences(await SendChatAsync(system, user, ct));
    }

    // ---------- shared parsing ----------

    private static List<string> ParseShortlist(string raw)
    {
        try
        {
            using var doc = JsonDocument.Parse(raw);
            var list = new List<string>();
            foreach (var el in doc.RootElement.GetProperty("shortlist").EnumerateArray())
            {
                var s = el.GetString();
                if (!string.IsNullOrWhiteSpace(s)) list.Add(s);
            }
            return list;
        }
        catch (Exception)
        {
            return new List<string>();
        }
    }

    private static AiSuggestion ParseSuggestion(string raw)
    {
        try
        {
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;

            var actions = new List<string>();
            if (root.TryGetProperty("requiredActions", out var arr) &&
                arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in arr.EnumerateArray())
                {
                    var s = el.GetString();
                    if (!string.IsNullOrWhiteSpace(s)) actions.Add(s);
                }
            }

            string? roleId = null;
            if (root.TryGetProperty("recommendedRoleId", out var rid) &&
                rid.ValueKind == JsonValueKind.String)
            {
                var v = rid.GetString();
                if (!string.IsNullOrWhiteSpace(v) &&
                    !string.Equals(v, "null", StringComparison.OrdinalIgnoreCase))
                    roleId = v;
            }

            string reasoning = "";
            if (root.TryGetProperty("reasoning", out var rs) &&
                rs.ValueKind == JsonValueKind.String)
                reasoning = rs.GetString() ?? "";

            return new AiSuggestion
            {
                RequiredActions = actions,
                RecommendedRoleId = roleId,
                Reasoning = reasoning
            };
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException(
                "AI response was not the expected JSON shape: " + Truncate(raw, 300), ex);
        }
    }

    protected static string StripFences(string s)
    {
        var t = s.Trim();
        if (t.StartsWith("```", StringComparison.Ordinal))
        {
            var firstNewline = t.IndexOf('\n');
            if (firstNewline >= 0) t = t[(firstNewline + 1)..];
            var lastFence = t.LastIndexOf("```", StringComparison.Ordinal);
            if (lastFence >= 0) t = t[..lastFence];
        }
        return t.Trim();
    }

    protected static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max];

    public void Dispose() => Http.Dispose();
}
