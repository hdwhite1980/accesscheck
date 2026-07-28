using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace AccessCheck.Core.Audit;

/// <summary>
/// Verbatim log of every outbound action and its response.
///
/// The existing logs record what the app INTENDED — the prompt it built, the script it
/// composed. This records what actually happened: the request as sent, the status, and the
/// response body in full. When a grant fails with "400 Request_BadRequest: Action
/// 'microsoft.directory/use…" the truncated message is the least useful part of what
/// Microsoft actually said, and the rest was being thrown away.
///
/// NOTHING IS TRUNCATED. That is the point of it, and it is also why rotation is not
/// optional: a deep catalog sync makes hundreds of round trips and some responses run to
/// megabytes.
///
/// SECRETS ARE REDACTED, and that is not negotiable. Every Graph call carries a bearer
/// token, and app credential creation returns secretText exactly once. A verbatim log
/// without redaction is a credential store with a .log extension.
/// </summary>
public static class ActionLog
{
    private static readonly object Gate = new();
    private static readonly AsyncLocal<string?> CurrentScope = new();

    /// <summary>Directory to write to. Null disables logging entirely.</summary>
    public static string? Directory { get; set; }

    /// <summary>Roll to a new file beyond this size. Default 64 MB.</summary>
    public static long MaxBytes { get; set; } = 64L * 1024 * 1024;

    /// <summary>Delete rotated files older than this. Default 30 days.</summary>
    public static TimeSpan Retention { get; set; } = TimeSpan.FromDays(30);

    public static bool Enabled => !string.IsNullOrWhiteSpace(Directory);

    /// <summary>
    /// Groups everything that follows under one correlation id, so a failed grant can be
    /// read as a sequence rather than reassembled from interleaved lines. Requests from
    /// concurrent operations do interleave in the file; the id is what separates them.
    /// </summary>
    public static IDisposable Scope(string name)
    {
        var previous = CurrentScope.Value;
        var id = Guid.NewGuid().ToString("N")[..8];
        CurrentScope.Value = id;
        Write("SCOPE", name + "  (begin)");
        return new ScopeHandle(previous, name, Stopwatch.StartNew());
    }

    private sealed class ScopeHandle : IDisposable
    {
        private readonly string? _previous;
        private readonly string _name;
        private readonly Stopwatch _sw;
        public ScopeHandle(string? previous, string name, Stopwatch sw)
        { _previous = previous; _name = name; _sw = sw; }

        public void Dispose()
        {
            Write("SCOPE", _name + "  (end, " + _sw.ElapsedMilliseconds + " ms)");
            CurrentScope.Value = _previous;
        }
    }

    /// <summary>An outbound call, with its body exactly as sent.</summary>
    public static void Request(string kind, string method, string target, string? body)
    {
        if (!Enabled) return;
        var sb = new StringBuilder();
        sb.Append(method).Append(' ').Append(target);
        if (!string.IsNullOrWhiteSpace(body))
            sb.AppendLine().Append(Indent(Redact(body)));
        Write(kind + " REQ", sb.ToString());
    }

    /// <summary>A response, in full, whatever its size.</summary>
    public static void Response(string kind, int status, string? body, long elapsedMs)
    {
        if (!Enabled) return;
        var sb = new StringBuilder();
        sb.Append(status).Append("  (").Append(elapsedMs).Append(" ms)");
        if (!string.IsNullOrWhiteSpace(body))
            sb.AppendLine().Append(Indent(Redact(body)));
        Write(kind + " RSP", sb.ToString());
    }

    /// <summary>Anything else worth a line — a decision, a skip, an exception.</summary>
    public static void Note(string kind, string text)
    {
        if (!Enabled) return;
        Write(kind, Redact(text));
    }

    // ---- redaction ------------------------------------------------------------------

    private static readonly (Regex Pattern, string Replacement)[] Secrets =
    {
        // Bearer tokens: on every single Graph call.
        (new Regex(@"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "$1[REDACTED]"),

        // Token payloads in OAuth responses.
        (new Regex(@"""(access_token|id_token|refresh_token)""\s*:\s*""[^""]*""",
                   RegexOptions.IgnoreCase | RegexOptions.Compiled),
         @"""$1"":""[REDACTED]"""),

        // addPassword returns secretText ONCE — the one response that must never be kept.
        (new Regex(@"""(secretText|password|clientSecret|client_secret|passwordCredential)""\s*:\s*""[^""]*""",
                   RegexOptions.IgnoreCase | RegexOptions.Compiled),
         @"""$1"":""[REDACTED]"""),

        // AI provider keys, if one ever reaches a logged body or an error message.
        (new Regex(@"\b(sk-[A-Za-z0-9\-_]{16,})", RegexOptions.Compiled), "[REDACTED-KEY]"),
        (new Regex(@"(api[-_]?key""?\s*[:=]\s*""?)[^""\s,}]+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "$1[REDACTED]"),

        // PowerShell credential literals, in case a script ever carries one.
        (new Regex(@"(-Password\s+)\S+", RegexOptions.IgnoreCase | RegexOptions.Compiled), "$1[REDACTED]"),
    };

    /// <summary>
    /// Strips credentials. Deliberately aggressive: a false redaction costs a debugging
    /// detail, a missed one writes a working token to disk.
    /// </summary>
    public static string Redact(string text)
    {
        if (string.IsNullOrEmpty(text)) return text;
        foreach (var (pattern, replacement) in Secrets)
            text = pattern.Replace(text, replacement);
        return text;
    }

    // ---- writing --------------------------------------------------------------------

    private static string Indent(string body) =>
        string.Join(Environment.NewLine,
            body.Split('\n').Select(l => "    " + l.TrimEnd('\r')));

    private static void Write(string kind, string text)
    {
        var dir = Directory;
        if (string.IsNullOrWhiteSpace(dir)) return;

        var line = new StringBuilder()
            .Append(DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff'Z'"))
            .Append("  [").Append(CurrentScope.Value ?? "--------").Append("]  ")
            .Append(kind.PadRight(12))
            .Append(' ').Append(text)
            .AppendLine()
            .ToString();

        lock (Gate)
        {
            try
            {
                System.IO.Directory.CreateDirectory(dir);
                var path = Path.Combine(dir, "actions-" + DateTime.UtcNow.ToString("yyyy-MM-dd") + ".log");

                // Roll before writing, so a single huge response cannot be split across
                // files in a way that makes it unreadable.
                var info = new FileInfo(path);
                if (info.Exists && info.Length > MaxBytes)
                {
                    var rolled = Path.Combine(dir,
                        "actions-" + DateTime.UtcNow.ToString("yyyy-MM-dd-HHmmss") + ".log");
                    File.Move(path, rolled, overwrite: true);
                    Prune(dir);
                }

                File.AppendAllText(path, line, new UTF8Encoding(false));
            }
            catch (Exception)
            {
                // Logging must never break the operation it is describing.
            }
        }
    }

    private static void Prune(string dir)
    {
        try
        {
            var cutoff = DateTime.UtcNow - Retention;
            foreach (var f in System.IO.Directory.GetFiles(dir, "actions-*.log"))
                if (File.GetLastWriteTimeUtc(f) < cutoff)
                    try { File.Delete(f); } catch { /* best effort */ }
        }
        catch (Exception) { /* best effort */ }
    }
}
