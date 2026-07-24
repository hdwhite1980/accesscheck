using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace AccessLens.Ai;

/// <summary>
/// Transport for any OpenAI-compatible /chat/completions endpoint: OpenAI itself,
/// the org GenAI gateway, Ollama's OpenAI mode, Groq, and similar. Auth header is
/// configurable (Authorization: Bearer by default; gateways with bare api-key
/// headers set AuthHeaderName/AuthValuePrefix accordingly).
/// </summary>
public sealed class OpenAiCompatibleProvider : ChatProviderBase
{
    public OpenAiCompatibleProvider(AiProviderConfig config, string apiKey, HttpClient? http = null)
        : base(config, apiKey, http) { }

    protected override async Task<string> SendChatAsync(
        string system, string user, CancellationToken ct)
    {
        var url = Config.BaseUrl.TrimEnd('/') + "/chat/completions";
        var body = new
        {
            model = Config.Model,
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

        if (string.Equals(Config.AuthHeaderName, "Authorization", StringComparison.OrdinalIgnoreCase))
        {
            var prefix = Config.AuthValuePrefix.Trim();
            req.Headers.Authorization = prefix.Length > 0
                ? new AuthenticationHeaderValue(prefix, ApiKey)
                : new AuthenticationHeaderValue("Bearer", ApiKey);
        }
        else
        {
            req.Headers.TryAddWithoutValidation(
                Config.AuthHeaderName, Config.AuthValuePrefix + ApiKey);
        }

        using var resp = await Http.SendAsync(req, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException(
                "AI endpoint returned " + (int)resp.StatusCode + ": " + Truncate(text, 400));

        using var doc = JsonDocument.Parse(text);
        return doc.RootElement
            .GetProperty("choices")[0]
            .GetProperty("message")
            .GetProperty("content")
            .GetString() ?? "";
    }
}
