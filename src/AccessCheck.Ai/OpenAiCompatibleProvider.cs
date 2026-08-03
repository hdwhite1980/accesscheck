using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace AccessCheck.Ai;

/// <summary>
/// Transport for any OpenAI-compatible /chat/completions endpoint: OpenAI itself,
/// the org AI gateway, Ollama's OpenAI mode, Groq, and similar. Auth header is
/// configurable (Authorization: Bearer by default; gateways with bare api-key
/// headers set AuthHeaderName/AuthValuePrefix accordingly).
/// </summary>
public sealed class OpenAiCompatibleProvider : ChatProviderBase
{
    public OpenAiCompatibleProvider(AiProviderConfig config, string apiKey, HttpClient? http = null)
        : base(config, apiKey, http) { }

    /// <summary>
    /// A FIXED SEED, not a random one. Determinism is the point: the same request must
    /// produce the same recommendation, or the answer cannot be reviewed and cannot be
    /// defended six months later when someone asks why an account holds what it holds.
    /// The value itself is arbitrary; only its constancy matters.
    /// </summary>
    private const int DeterministicSeed = 20260101;

    /// <summary>
    /// Set once an endpoint has rejected "seed". Gateways in front of a model vary in what
    /// they forward, and an org gateway that 400s on an unrecognised field would otherwise
    /// break every request rather than one.
    /// </summary>
    private bool _seedRejected;

    protected override async Task<string> SendChatAsync(
        string system, string user, CancellationToken ct)
    {
        try
        {
            return await PostAsync(system, user, includeSeed: !_seedRejected, ct);
        }
        catch (HttpRequestException ex) when (!_seedRejected && MentionsSeed(ex.Message))
        {
            // Remembered for the session, so this costs one wasted request rather than one
            // per call.
            _seedRejected = true;
            return await PostAsync(system, user, includeSeed: false, ct);
        }
    }

    /// <summary>
    /// Whether a rejection looks like it was about the seed field specifically. Deliberately
    /// narrow — retrying a genuine auth or model-name failure without the seed would just
    /// fail twice and bury the real message.
    /// </summary>
    private static bool MentionsSeed(string message) =>
        message.Contains("seed", StringComparison.OrdinalIgnoreCase)
        && (message.Contains("400") || message.Contains("unsupported", StringComparison.OrdinalIgnoreCase)
            || message.Contains("unrecognized", StringComparison.OrdinalIgnoreCase)
            || message.Contains("unknown", StringComparison.OrdinalIgnoreCase)
            || message.Contains("not supported", StringComparison.OrdinalIgnoreCase));

    private async Task<string> PostAsync(
        string system, string user, bool includeSeed, CancellationToken ct)
    {
        var url = Config.BaseUrl.TrimEnd('/') + "/chat/completions";

        // TEMPERATURE ZERO, NOT NEARLY ZERO.
        //
        // This was 0.1, which still samples. That is invisible on a question with one clear
        // answer and decisive on the question this application actually asks: sixty
        // similar-looking permissions, several of them plausible, differing by a token or
        // two. Identical runs of one job description resolved a duty to the correct Purview
        // role once and returned nothing the next; a licence-reporting duty found the right
        // read permission on one pass and a licence-ASSIGNMENT write on another.
        //
        // Weeks of work on candidate scoring were fighting this. Least privilege is not a
        // creative task — there is a narrowest correct answer, the same one every time, and
        // an auditor reading history.jsonl has to be able to reproduce it.
        //
        // top_p pinned as well: some endpoints apply nucleus sampling regardless of
        // temperature, and leaving it at the default undoes half of what temperature 0 buys.
        var body = new Dictionary<string, object>
        {
            ["model"] = Config.Model,
            ["temperature"] = 0,
            ["top_p"] = 1,
            ["messages"] = new object[]
            {
                new { role = "system", content = system },
                new { role = "user", content = user }
            }
        };

        // Temperature 0 is greedy decoding but not a guarantee — ties, batching and
        // floating-point ordering still move things. A fixed seed closes most of what is
        // left where the endpoint honours it.
        if (includeSeed) body["seed"] = DeterministicSeed;

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
