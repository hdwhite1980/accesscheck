using System.Text.Json;
using AccessCheck.Core.Catalog;
using AccessCheck.Core.Recommendation;

namespace AccessCheck.Ai;

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

    /// <summary>
    /// Proposes the permissions a function needs, in three stages.
    ///
    /// A. WHICH SERVICE owns this feature? Product feature names ("GPO analytics",
    ///    "eDiscovery") appear in no permission string, so keyword search alone finds
    ///    nothing and the model falls back to guessing from role names — which is how a
    ///    request for Intune's GPO analyzer was answered with an Entitlement Management
    ///    permission.
    /// B. CANDIDATE PERMISSIONS from that service, plus keyword matches elsewhere.
    /// C. PICK the minimal set, or say nothing fits.
    ///
    /// The result carries a confidence. An access broker must be able to say "I do not
    /// know": a confident wrong answer gets granted, which is worse than no answer.
    /// </summary>
    public async Task<AiSuggestion> SuggestAsync(
        string functionDescription,
        RoleCatalog catalog,
        IReadOnlyCollection<string>? forcedProviders = null,
        CancellationToken ct = default,
        ReferenceStore? reference = null)
    {
        // ---- Stage A: identify the owning service ----
        var services = new List<string>();
        var serviceConfident = false;
        var serviceNote = "";

        // EVERY known provider, not just those with roles. If the service that owns a task
        // has zero roles synced, the app must still be able to identify it and say so —
        // filtering to "providers we have" made an empty service literally unnameable.
        var providers = new[]
        {
            RbacProviders.Directory, RbacProviders.Intune, RbacProviders.Exchange,
            RbacProviders.Purview, RbacProviders.CloudPc, RbacProviders.Defender,
            RbacProviders.EntitlementManagement
        }.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();

        if (forcedProviders is { Count: > 0 })
        {
            // When the operator already knows the service, saying so beats inference —
            // the inference is the step that gets it wrong most often.
            services = forcedProviders.Where(providers.Contains).ToList();
            serviceConfident = services.Count > 0;
            serviceNote = "service specified by the operator: " +
                string.Join(", ", services.Select(RbacProviders.DisplayName));
        }
        else if (providers.Count > 0)
        {
            var serviceUser = PromptBuilder.BuildServiceUser(functionDescription, providers);
            PromptLogger?.Invoke("service", serviceUser);
            try
            {
                var raw = StripFences(await SendChatAsync(PromptBuilder.ServiceSystem, serviceUser, ct));
                using var doc = JsonDocument.Parse(raw);
                if (doc.RootElement.TryGetProperty("services", out var arr) &&
                    arr.ValueKind == JsonValueKind.Array)
                {
                    services = arr.EnumerateArray()
                        .Select(e => e.GetString() ?? "")
                        .Where(providers.Contains)
                        .ToList();
                }
                serviceConfident = doc.RootElement.TryGetProperty("confident", out var c)
                    && c.ValueKind == JsonValueKind.True;
                serviceNote = doc.RootElement.TryGetProperty("note", out var n)
                    ? n.GetString() ?? "" : "";
            }
            catch (Exception ex)
            {
                // Stage A is an optimisation, not a requirement.
                serviceNote = "service identification unavailable: " + ex.Message;
            }
        }

        // ---- Stage B: candidates ----
        var candidates = PermissionIndex.CandidateActions(functionDescription, catalog, 60, reference).ToList();
        var restrictedToService = false;
        if (services.Count > 0)
        {
            var fromService = PermissionIndex.PermissionsInProviders(
                services, catalog, functionDescription).ToList();

            if (fromService.Count > 0)
            {
                // RESTRICT, do not merely lead. Concatenating keyword hits from other
                // services let the model reach past the right vocabulary into a wrong
                // one — a Purview task answered with Exchange cmdlets that exist but do
                // not do the job. Other services are re-offered only if this yields
                // nothing.
                candidates = fromService;
                restrictedToService = true;
            }
            else
            {
                // THE OWNING SERVICE HAS NO VOCABULARY. Searching unrelated services would
                // produce something approvable that cannot do the job — and in a
                // least-privilege tool a wrong answer is worse than no answer. Stop here.
                return new AiSuggestion
                {
                    RequiredActions = Array.Empty<string>(),
                    Reasoning = "",
                    Confidence = SuggestionConfidence.None,
                    IdentifiedServices = services,
                    CandidatesConsidered = 0,
                    NoMatchExplanation =
                        "This task belongs to "
                        + string.Join(", ", services.Select(RbacProviders.DisplayName))
                        + ", and that service has NO permissions in your synced catalog. "
                        + "Nothing is recommended: any permission found elsewhere would be "
                        + "from the wrong service and would not do the job. Sync that "
                        + "service — Catalog tab, and for Exchange/Purview tick the "
                        + "PowerShell option — then re-run."
                };
            }
        }

        if (candidates.Count == 0)
        {
            return new AiSuggestion
            {
                RequiredActions = Array.Empty<string>(),
                Reasoning = serviceNote.Length == 0
                    ? "Nothing in the synced catalog matched this request."
                    : serviceNote,
                Confidence = SuggestionConfidence.None,
                IdentifiedServices = services,
                CandidatesConsidered = 0,
                NoMatchExplanation =
                    $"No permission in the synced catalog matched '{functionDescription}'" +
                    (services.Count == 0
                        ? ", and the owning service could not be identified."
                        : ", including everything offered by " +
                          string.Join(", ", services.Select(RbacProviders.DisplayName)) + ".") +
                    " Browse Catalog > Permissions to search the vocabulary directly, or " +
                    "describe the task in terms of what is being read or changed rather than " +
                    "the feature's product name."
            };
        }

        // ---- Stage C: choose ----
        var permissionUser = PromptBuilder.BuildPermissionUser(functionDescription, candidates);
        PromptLogger?.Invoke("permissions", permissionUser);
        LastPromptSha256 = PromptBuilder.Sha256Hex(permissionUser);

        var chosenRaw = StripFences(
            await SendChatAsync(PromptBuilder.PermissionSystem, permissionUser, ct));
        var parsed = ParseSuggestion(chosenRaw);

        // Accept only what was offered — but resolve the model's phrasing back to the exact
        // catalog string first. Exchange candidates are full cmdlet signatures and the model
        // replies with the cmdlet name, so a strict comparison would discard a correct answer
        // and report "no match".
        var candidateActions = candidates.Select(c => c.Action).ToList();
        var kept = new List<string>();
        foreach (var proposed in parsed.RequiredActions)
        {
            var resolved = ActionDisplay.Resolve(proposed, candidateActions);
            if (resolved is not null && !kept.Contains(resolved)) kept.Add(resolved);
        }

        if (kept.Count == 0 && restrictedToService)
        {
            // Restricting to the identified service found nothing. Widen once before
            // declaring no match — the service guess may simply have been wrong.
            var wider = PermissionIndex.CandidateActions(functionDescription, catalog, 60, reference).ToList();
            if (wider.Count > 0)
            {
                var widerUser = PromptBuilder.BuildPermissionUser(functionDescription, wider);
                PromptLogger?.Invoke("permissions-widened", widerUser);
                var widerRaw = StripFences(
                    await SendChatAsync(PromptBuilder.PermissionSystem, widerUser, ct));
                var widerParsed = ParseSuggestion(widerRaw);
                var widerActions = wider.Select(c => c.Action).ToList();
                foreach (var proposed in widerParsed.RequiredActions)
                {
                    var resolved = ActionDisplay.Resolve(proposed, widerActions);
                    if (resolved is not null && !kept.Contains(resolved)) kept.Add(resolved);
                }
                if (kept.Count > 0)
                {
                    parsed = widerParsed;
                    candidates = wider;
                    restrictedToService = false;
                }
            }
        }

        if (kept.Count == 0)
        {
            return new AiSuggestion
            {
                RequiredActions = Array.Empty<string>(),
                Reasoning = parsed.Reasoning,
                Confidence = SuggestionConfidence.None,
                IdentifiedServices = services,
                CandidatesConsidered = candidates.Count,
                NoMatchExplanation =
                    $"The model was shown {candidates.Count} candidate permission(s) and " +
                    "judged that none of them covers the function."
            };
        }

        // Confidence is high only when the service was identified confidently AND the chosen
        // permissions come from it. Permissions from a service the model never named are
        // exactly the failure that produced an Entitlement Management answer to an Intune
        // question.
        var chosenProviders = kept.Select(a => catalog.ProviderOf(a))
            .Where(p => p is not null).Select(p => p!)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var insideIdentified = services.Count == 0
            || chosenProviders.All(p => services.Contains(p, StringComparer.OrdinalIgnoreCase));

        // STAGE C CORRECTS STAGE A. Identifying the service is a guess made before seeing
        // any permissions; CHOOSING permissions is a decision made while looking at them,
        // with their descriptions. When every chosen permission lands in ONE service, that
        // is the better evidence — and the cmdlet map can confirm it independently.
        // Treating the earlier guess as authoritative made a CORRECT answer read as LOW
        // CONFIDENCE, which teaches the operator to ignore the confidence line entirely.
        var singleService = chosenProviders.Count == 1;
        var mapConfirms = singleService && kept.All(a =>
        {
            var owner = CmdletServiceMap.OwnerOf(a);
            return owner is null || owner.Equals(chosenProviders[0], StringComparison.OrdinalIgnoreCase);
        });
        var stageCCorrected = !insideIdentified && singleService && mapConfirms;

        var confidence =
            (serviceConfident && services.Count > 0 && insideIdentified) || stageCCorrected
                ? SuggestionConfidence.High
                : SuggestionConfidence.Low;

        var reasoning = parsed.Reasoning;
        if (stageCCorrected)
        {
            // Say what happened rather than hiding it — the earlier guess is still
            // information, and an operator who sees only the corrected answer cannot tell
            // that anything was resolved.
            reasoning += "  [AccessCheck: the service was first identified as " +
                string.Join(", ", services.Select(RbacProviders.DisplayName)) +
                ", but every chosen permission is in " +
                RbacProviders.DisplayName(chosenProviders[0]) +
                " and the cmdlet map agrees. Going with the permissions.]";
            services = new List<string> { chosenProviders[0] };
        }
        else if (!insideIdentified && services.Count > 0)
        {
            reasoning += "  [AccessCheck: the chosen permission(s) are in " +
                string.Join(", ", chosenProviders.Select(RbacProviders.DisplayName)) +
                ", but this task was identified as belonging to " +
                string.Join(", ", services.Select(RbacProviders.DisplayName)) +
                ". Verify before granting.]";
        }
        else if (!serviceConfident && serviceNote.Length > 0)
        {
            reasoning += "  [AccessCheck: the owning service could not be identified " +
                "confidently. Verify before granting.]";
        }

        return new AiSuggestion
        {
            RequiredActions = kept,
            RecommendedRoleId = parsed.RecommendedRoleId,
            Reasoning = reasoning,
            Confidence = confidence,
            IdentifiedServices = services,
            CandidatesConsidered = candidates.Count
        };
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
