using System.Text;
using System.Text.Json;

namespace AccessLens.Ai;

/// <summary>
/// Transport for the Anthropic Messages API (Claude). Headers: x-api-key +
/// anthropic-version. BaseUrl defaults to https://api.anthropic.com; the system
/// prompt goes in the top-level system field per the Messages API shape.
/// </summary>
public sealed class AnthropicProvider : ChatProviderBase
{
    public const string DefaultBaseUrl = "https://api.anthropic.com";
    public const string ApiVersionHeader = "2023-06-01";

    public AnthropicProvider(AiProviderConfig config, string apiKey, HttpClient? http = null)
        : base(config, apiKey, http) { }

    protected override async Task<string> SendChatAsync(
        string system, string user, CancellationToken ct)
    {
        var baseUrl = string.IsNullOrWhiteSpace(Config.BaseUrl)
            ? DefaultBaseUrl : Config.BaseUrl.TrimEnd('/');
        var url = baseUrl + "/v1/messages";

        var body = new
        {
            model = Config.Model,
            max_tokens = 2048,
            temperature = 0.1,
            system,
            messages = new object[]
            {
                new { role = "user", content = user }
            }
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
        };
        req.Headers.TryAddWithoutValidation("x-api-key", ApiKey);
        req.Headers.TryAddWithoutValidation("anthropic-version", ApiVersionHeader);

        using var resp = await Http.SendAsync(req, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException(
                "Anthropic endpoint returned " + (int)resp.StatusCode + ": " + Truncate(text, 400));

        using var doc = JsonDocument.Parse(text);
        var sb = new StringBuilder();
        if (doc.RootElement.TryGetProperty("content", out var content) &&
            content.ValueKind == JsonValueKind.Array)
        {
            foreach (var block in content.EnumerateArray())
            {
                if (block.TryGetProperty("type", out var t) && t.GetString() == "text" &&
                    block.TryGetProperty("text", out var txt))
                    sb.Append(txt.GetString());
            }
        }
        return sb.ToString();
    }
}
