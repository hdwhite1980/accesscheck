using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using AccessCheck.Core.Audit;

namespace AccessCheck.Graph;

/// <summary>Thin raw-HTTP Graph wrapper (no SDK) so the .us endpoints stay explicit.</summary>
public sealed class GraphClient : IDisposable
{
    private readonly HttpClient _http = new();
    private readonly GraphAuth _auth;
    public string GraphBase { get; }
    /// <summary>Exposed for scope diagnostics and forced re-sign-in.</summary>
    public GraphAuth Auth => _auth;

    public GraphClient(GraphAuth auth, CloudEnvironment cloud)
    {
        _auth = auth;
        GraphBase = cloud.GraphBase;
    }

    public async Task<JsonDocument> GetAsync(string pathOrUrl, CancellationToken ct = default) =>
        await GetAsync(pathOrUrl, null, ct);

    /// <summary>GET with optional extra headers (e.g. ConsistencyLevel: eventual for $search).</summary>
    public async Task<JsonDocument> GetAsync(
        string pathOrUrl, IReadOnlyDictionary<string, string>? headers, CancellationToken ct = default)
    {
        var url = pathOrUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? pathOrUrl
            : GraphBase + pathOrUrl;
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (headers is not null)
            foreach (var kv in headers)
                req.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
        return await SendAsync(req, ct);
    }

    /// <summary>Acquires a token without issuing a request — used to surface sign-in before modal UI.</summary>
    public Task<string> WarmUpAuthAsync(CancellationToken ct = default) => _auth.GetTokenAsync(ct);

    public async Task<JsonDocument> PostAsync(string path, object body, CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, GraphBase + path)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
        };
        return await SendAsync(req, ct);
    }

    public async Task DeleteAsync(string path, CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Delete, GraphBase + path);
        using var _ = await SendAsync(req, ct);
    }

    private async Task<JsonDocument> SendAsync(HttpRequestMessage req, CancellationToken ct)
    {
        var token = await _auth.GetTokenAsync(ct);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // The FULL request and the FULL response, not the 300-character summary
        // DescribeError keeps. That truncation is fine for a dialog and useless for
        // diagnosis: "400 Request_BadRequest: Action 'microsoft.directory/use…" cuts off
        // exactly the part that names what Microsoft refused.
        string? requestBody = null;
        if (ActionLog.Enabled && req.Content is not null)
        {
            try { requestBody = await req.Content.ReadAsStringAsync(ct); }
            catch (Exception) { requestBody = "(request body could not be read for logging)"; }
        }
        ActionLog.Request("GRAPH", req.Method.Method, req.RequestUri?.ToString() ?? "", requestBody);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        using var resp = await _http.SendAsync(req, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);
        sw.Stop();

        ActionLog.Response("GRAPH", (int)resp.StatusCode, text, sw.ElapsedMilliseconds);

        if (!resp.IsSuccessStatusCode)
            throw new GraphApiException((int)resp.StatusCode, DescribeError(text),
                req.RequestUri?.ToString() ?? "");
        return JsonDocument.Parse(string.IsNullOrWhiteSpace(text) ? "{}" : text);
    }

    /// <summary>Pull code + message out of a Graph error envelope; fall back to raw text.</summary>
    private static string DescribeError(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("error", out var err))
            {
                var code = err.TryGetProperty("code", out var c) ? c.GetString() : null;
                var msg = err.TryGetProperty("message", out var m) ? m.GetString() : null;
                if (code is not null || msg is not null)
                    return (code ?? "") + (code is not null && msg is not null ? ": " : "") + (msg ?? "");
            }
        }
        catch (JsonException) { /* not a Graph error envelope */ }
        return body.Length > 300 ? body[..300] : body;
    }

    public void Dispose() => _http.Dispose();
}

/// <summary>Graph failure with the HTTP status preserved for precise diagnosis.</summary>
public sealed class GraphApiException : Exception
{
    public int StatusCode { get; }
    public string Url { get; }

    public GraphApiException(int statusCode, string detail, string url)
        : base(statusCode + " " + detail)
    {
        StatusCode = statusCode;
        Url = url;
    }
}
