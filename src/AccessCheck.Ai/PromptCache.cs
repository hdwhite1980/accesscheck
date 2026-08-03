using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AccessCheck.Ai;

/// <summary>
/// Remembers what the endpoint answered, keyed on the exact question.
///
/// WHY. Determinism cannot be obtained from the endpoint. temperature 0, top_p 1 and a
/// fixed seed were all set, and identical runs of one job description still split the
/// duties differently — "joiners, movers, and leavers" one time and "joiners, movers and
/// leavers" the next, which then changed every answer downstream. Commercial endpoints
/// batch requests, route across experts and accumulate floating point in whatever order
/// the hardware happens to use; OpenAI documents seed as best-effort for precisely this
/// reason. No client-side setting fixes it.
///
/// So the reproducibility is taken rather than requested. A recommendation that changes
/// between identical runs cannot be reviewed, and cannot be defended six months later when
/// someone asks why an account holds what it holds. With this, re-running a document
/// returns exactly what it returned before — a stronger property than endpoint determinism,
/// because it belongs to this application rather than to a vendor's best effort.
///
/// WHAT IS AND IS NOT CACHED. The key covers the model, the system prompt and the user
/// prompt. Change any of them — a reworded prompt, a different model, freshly imported
/// descriptions that alter the candidate list — and the key changes, so a stale answer can
/// never be served for a question that is no longer the one being asked. That is the whole
/// reason for hashing the prompt rather than the request.
///
/// NOT A PRIVACY BOUNDARY. Entries hold the prompt text, which includes the operator's
/// function description. It sits beside prompt-log.txt, which already records the same
/// thing verbatim, and under the same DPAPI-protected data folder.
/// </summary>
public sealed class PromptCache
{
    private readonly string _path;
    private readonly Dictionary<string, Entry> _entries;
    private bool _dirty;

    public sealed record Entry
    {
        public string Model { get; init; } = "";
        public string Response { get; init; } = "";
        public DateTimeOffset CachedUtc { get; init; }
        /// <summary>First line of the prompt, so the file is readable when diagnosing.</summary>
        public string Preview { get; init; } = "";
    }

    public int Count => _entries.Count;
    public int Hits { get; private set; }
    public int Misses { get; private set; }

    public PromptCache(string path)
    {
        _path = path;
        _entries = Load(path);
    }

    /// <summary>
    /// The cache key. Model included deliberately: the same question put to a different
    /// model is a different question, and serving one model's answer as another's would
    /// make the audit record wrong in a way nothing downstream could detect.
    /// </summary>
    public static string KeyFor(string model, string system, string user)
    {
        var material = model + "\u0000" + system + "\u0000" + user;
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return Convert.ToHexString(hash);
    }

    public bool TryGet(string model, string system, string user, out string response)
    {
        if (_entries.TryGetValue(KeyFor(model, system, user), out var entry))
        {
            response = entry.Response;
            Hits++;
            return true;
        }
        response = "";
        Misses++;
        return false;
    }

    public void Put(string model, string system, string user, string response)
    {
        // AN EMPTY ANSWER IS NOT AN ANSWER. Caching one would make a transient endpoint
        // failure permanent for that exact prompt, and the retry that would have fixed it
        // never happens.
        if (string.IsNullOrWhiteSpace(response)) return;

        var firstLine = user.Split('\n', 2)[0];
        _entries[KeyFor(model, system, user)] = new Entry
        {
            Model = model,
            Response = response,
            CachedUtc = DateTimeOffset.UtcNow,
            Preview = firstLine.Length > 120 ? firstLine[..120] : firstLine
        };
        _dirty = true;
    }

    /// <summary>Writes only when something changed. Called after a run, not per entry.</summary>
    public void Save()
    {
        if (!_dirty) return;
        try
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            var opts = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(_path, JsonSerializer.Serialize(_entries, opts));
            _dirty = false;
        }
        catch (Exception)
        {
            // A cache that cannot be written is a cache miss next time, which is correct
            // behaviour rather than an error worth interrupting anyone over.
        }
    }

    public void Clear()
    {
        _entries.Clear();
        _dirty = true;
        Save();
    }

    private static Dictionary<string, Entry> Load(string path)
    {
        if (!File.Exists(path)) return new Dictionary<string, Entry>(StringComparer.Ordinal);
        try
        {
            var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            var loaded = JsonSerializer.Deserialize<Dictionary<string, Entry>>(
                File.ReadAllText(path), opts);
            return loaded is null
                ? new Dictionary<string, Entry>(StringComparer.Ordinal)
                : new Dictionary<string, Entry>(loaded, StringComparer.Ordinal);
        }
        catch (Exception)
        {
            // A corrupt cache must never block a run — it is a cache, not a record.
            return new Dictionary<string, Entry>(StringComparer.Ordinal);
        }
    }
}
