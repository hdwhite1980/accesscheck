using System.Net;
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

    // ---------- throttling ----------

    /// <summary>
    /// Attempts INCLUDING the first. Graph's role-management endpoints throttle per
    /// tenant, and a catalog sync issues one request per provider plus a page each — a
    /// large tenant reaches the limit on a first sync, which is exactly the moment a new
    /// customer forms an opinion about whether this thing works.
    /// </summary>
    private const int MaxAttempts = 5;

    /// <summary>
    /// Ceiling on a single sleep. Graph occasionally returns a Retry-After measured in
    /// minutes; honouring it literally makes the app look hung, and the caller has a
    /// CancellationToken it can no longer act on meaningfully. Sleep the cap, retry, and
    /// let the next 429 carry the remaining wait.
    /// </summary>
    private static readonly TimeSpan MaxDelay = TimeSpan.FromSeconds(30);

    /// <summary>Fallback backoff when the response carries no Retry-After.</summary>
    private static TimeSpan Backoff(int attempt) =>
        TimeSpan.FromSeconds(Math.Min(Math.Pow(2, attempt), MaxDelay.TotalSeconds));

    /// <summary>
    /// Whether a failed attempt is worth repeating — and this is NOT the same question for
    /// every verb.
    ///
    /// 429 means Microsoft rejected the request without doing it. That is safe to repeat
    /// for anything, including a POST.
    ///
    /// 502/503/504 mean the request may well have been PROCESSED and only the response was
    /// lost. Repeating a GET or DELETE is harmless; repeating the POST that creates a
    /// custom role definition can leave a SECOND real role in the tenant, which is the
    /// orphan this app exists to avoid creating. So gateway failures are retried only for
    /// idempotent verbs.
    ///
    /// 500 is never retried: it is as likely to be a malformed body as a transient fault,
    /// and repeating it just delays a real error.
    /// </summary>
    private static bool ShouldRetry(HttpStatusCode status, HttpMethod method)
    {
        if ((int)status == 429) return true;

        var idempotent = method == HttpMethod.Get
                         || method == HttpMethod.Delete
                         || method == HttpMethod.Head;
        if (!idempotent) return false;

        return status is HttpStatusCode.BadGateway
                      or HttpStatusCode.ServiceUnavailable
                      or HttpStatusCode.GatewayTimeout;
    }

    /// <summary>
    /// Microsoft's own instruction, when present. Retry-After is either delta-seconds or
    /// an HTTP-date; both shapes appear in the wild, and guessing a backoff when the
    /// server has stated one just gets throttled again.
    /// </summary>
    private static TimeSpan? RetryAfter(HttpResponseMessage resp)
    {
        var header = resp.Headers.RetryAfter;
        if (header is null) return null;
        if (header.Delta is { } delta) return delta;
        if (header.Date is { } date)
        {
            var wait = date - DateTimeOffset.UtcNow;
            return wait > TimeSpan.Zero ? wait : TimeSpan.Zero;
        }
        return null;
    }

    // ---------- verbs ----------

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
        // BUFFER EVERYTHING NEEDED TO REBUILD THE REQUEST. An HttpRequestMessage can be
        // sent exactly once — re-sending the same instance throws
        // InvalidOperationException, so a retry has to construct a fresh one. The caller
        // still owns and disposes the original; this method never sends it directly.
        var method = req.Method;
        var uri = req.RequestUri;
        var extraHeaders = req.Headers
            .Select(h => (h.Key, Value: string.Join(",", h.Value)))
            .ToList();

        byte[]? bodyBytes = null;
        string bodyMediaType = "application/json";
        if (req.Content is not null)
        {
            bodyBytes = await req.Content.ReadAsByteArrayAsync(ct);
            bodyMediaType = req.Content.Headers.ContentType?.MediaType ?? "application/json";
        }

        // The FULL request and the FULL response, not the 300-character summary
        // DescribeError keeps. That truncation is fine for a dialog and useless for
        // diagnosis: "400 Request_BadRequest: Action 'microsoft.directory/use…" cuts off
        // exactly the part that names what Microsoft refused.
        string? requestBody = null;
        if (ActionLog.Enabled && bodyBytes is not null)
        {
            try { requestBody = Encoding.UTF8.GetString(bodyBytes); }
            catch (Exception) { requestBody = "(request body could not be read for logging)"; }
        }
        ActionLog.Request("GRAPH", method.Method, uri?.ToString() ?? "", requestBody);

        for (var attempt = 0; ; attempt++)
        {
            // A TOKEN PER ATTEMPT, not one for the whole loop. A long throttle wait can
            // outlive the access token, and MSAL serves a cached one until it cannot —
            // so re-asking is nearly free and removes a 401 that only ever appeared
            // after a slow retry.
            var token = await _auth.GetTokenAsync(ct);

            using var attemptReq = new HttpRequestMessage(method, uri);
            attemptReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            foreach (var (key, value) in extraHeaders)
                attemptReq.Headers.TryAddWithoutValidation(key, value);
            if (bodyBytes is not null)
            {
                attemptReq.Content = new ByteArrayContent(bodyBytes);
                attemptReq.Content.Headers.ContentType =
                    new MediaTypeHeaderValue(bodyMediaType) { CharSet = "utf-8" };
            }

            var sw = System.Diagnostics.Stopwatch.StartNew();
            using var resp = await _http.SendAsync(attemptReq, ct);
            var text = await resp.Content.ReadAsStringAsync(ct);
            sw.Stop();

            ActionLog.Response("GRAPH", (int)resp.StatusCode, text, sw.ElapsedMilliseconds);

            if (resp.IsSuccessStatusCode)
                return JsonDocument.Parse(string.IsNullOrWhiteSpace(text) ? "{}" : text);

            var retryable = ShouldRetry(resp.StatusCode, method) && attempt < MaxAttempts - 1;
            if (!retryable)
            {
                // EXHAUSTED THROTTLING IS NOT A CONSENT PROBLEM. Left as a bare 429 the
                // message classifies as an unexpected failure and the operator is sent to
                // check permissions that were never wrong. Say what happened instead.
                var detail = (int)resp.StatusCode == 429
                    ? "throttled by Microsoft and still throttled after " + MaxAttempts +
                      " attempts — this is a rate limit, NOT a permission problem. "
                      + "Wait a few minutes and run the sync again. [" + DescribeError(text) + "]"
                    : DescribeError(text);

                throw new GraphApiException((int)resp.StatusCode, detail,
                    uri?.ToString() ?? "");
            }

            var delay = RetryAfter(resp) ?? Backoff(attempt);
            if (delay > MaxDelay) delay = MaxDelay;
            if (delay < TimeSpan.Zero) delay = TimeSpan.Zero;

            ActionLog.Request("GRAPH", method.Method, uri?.ToString() ?? "",
                "(retrying after " + (int)delay.TotalSeconds + "s — attempt " +
                (attempt + 2) + " of " + MaxAttempts + ", status " + (int)resp.StatusCode + ")");

            await Task.Delay(delay, ct);
        }
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

    /// <summary>
    /// True when Microsoft rate-limited the call. Distinct from a permission failure and
    /// worth separating: one is fixed by waiting, the other by consent.
    /// </summary>
    public bool IsThrottled => StatusCode == 429;

    public GraphApiException(int statusCode, string detail, string url)
        : base(statusCode + " " + detail)
    {
        StatusCode = statusCode;
        Url = url;
    }
}
