using System.Text;
using System.Text.Json;

namespace AccessCheck.Ai;

/// <summary>
/// Transport for Azure OpenAI (commercial or Azure Government). BaseUrl is the
/// resource endpoint (https://YOUR-RESOURCE.openai.azure.com or the .us
/// equivalent), Model is the DEPLOYMENT NAME, auth is the api-key header, and the
/// api-version query parameter comes from config.
/// </summary>
public sealed class AzureOpenAiProvider : ChatProviderBase
{
    public const string DefaultApiVersion = "2024-06-01";

    public AzureOpenAiProvider(AiProviderConfig config, string apiKey, HttpClient? http = null)
        : base(config, apiKey, http) { }

    protected override async Task<string> SendChatAsync(
        string system, string user, CancellationToken ct)
    {
        var apiVersion = string.IsNullOrWhiteSpace(Config.ApiVersion)
            ? DefaultApiVersion : Config.ApiVersion.Trim();
        var url = Config.BaseUrl.TrimEnd('/') +
                  "/openai/deployments/" + Uri.EscapeDataString(Config.Model) +
                  "/chat/completions?api-version=" + Uri.EscapeDataString(apiVersion);

        var body = new
        {
            temperature = 0.1,
            messages = new object[]
            {
                new { role = "system", content = system },
                new { role = "user", content = user }
            }
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
        };
        req.Headers.TryAddWithoutValidation("api-key", ApiKey);

        using var resp = await Http.SendAsync(req, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException(
                "Azure OpenAI returned " + (int)resp.StatusCode + ": " + Truncate(text, 400));

        using var doc = JsonDocument.Parse(text);
        return doc.RootElement
            .GetProperty("choices")[0]
            .GetProperty("message")
            .GetProperty("content")
            .GetString() ?? "";
    }
}
