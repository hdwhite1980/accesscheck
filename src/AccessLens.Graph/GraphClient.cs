using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace AccessLens.Graph;

/// <summary>Thin raw-HTTP Graph wrapper (no SDK) so the .us endpoints stay explicit.</summary>
public sealed class GraphClient : IDisposable
{
    private readonly HttpClient _http = new();
    private readonly GraphAuth _auth;
    public string GraphBase { get; }

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
        using var resp = await _http.SendAsync(req, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException(
                "Graph " + req.Method + " " + req.RequestUri + " -> " +
                (int)resp.StatusCode + ": " + (text.Length > 500 ? text[..500] : text));
        return JsonDocument.Parse(string.IsNullOrWhiteSpace(text) ? "{}" : text);
    }

    public void Dispose() => _http.Dispose();
}
