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
    /// This transport's web-search tool declaration, or null when it has none.
    ///
    /// EVERY VENDOR SPELLS THIS DIFFERENTLY and some endpoints have no search at all — a
    /// gateway on a government network usually does not. So the capability is declared per
    /// transport rather than assumed, and the PROMPT is written to work either way: with
    /// search the model cites documentation, without it the model may cite only the
    /// candidate list, and with neither it must return empty rather than answer from
    /// memory. Nothing above this line needs to know which kind of endpoint it is talking
    /// to.
    ///
    /// Override in the subclass and include it in the request body when non-null, e.g.
    ///   Anthropic  new { type = "web_search_20250305", name = "web_search" }
    ///   OpenAI     new { type = "web_search" }
    ///   Gemini     new { google_search = new { } }
    /// Leave as null for a gateway that does not support it.
    /// </summary>
    protected virtual object? WebSearchTool => null;

    /// <summary>True when this endpoint can look documentation up rather than recall it.</summary>
    public bool CanSearch => WebSearchTool is not null;

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
                services, catalog, functionDescription, reference: reference).ToList();

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

        // ONE RETRY ON A FORMATTING SLIP. The model writes the correct answer as prose often
        // enough that discarding the whole request over it is the single biggest source of
        // lost runs — three in one test batch, each of which had named the right permission
        // in the text. Salvage first, then ask once more with a terse reminder. If it fails
        // twice the error surfaces exactly as before.
        var parsed = await ChooseWithRetryAsync(permissionUser, ct);

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
            CandidatesConsidered = candidates.Count,
            // Only citations for actions that SURVIVED resolution. A citation for an action
            // the resolver dropped would describe something not being granted.
            Evidence = parsed.Evidence
                .Where(c => kept.Contains(c.Action, StringComparer.OrdinalIgnoreCase))
                .ToList(),
            DocumentedRole = parsed.DocumentedRole,
            CustomRoleEligible = parsed.CustomRoleEligible
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

            // EVIDENCE. The model must quote the description it relied on and say where it
            // came from. Parsed here so the deterministic layer can check a prose claim
            // against Microsoft's own reference — previously the reasoning was displayed
            // and never verified, which is how "typically includes resetting authentication
            // methods" reached the approval screen looking like a finding.
            var evidence = new List<ActionCitation>();
            if (root.TryGetProperty("evidence", out var ev) &&
                ev.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in ev.EnumerateArray())
                {
                    if (el.ValueKind != JsonValueKind.Object) continue;
                    var a = el.TryGetProperty("action", out var ea) ? ea.GetString() : null;
                    if (string.IsNullOrWhiteSpace(a)) continue;
                    evidence.Add(new ActionCitation
                    {
                        Action = a!.Trim(),
                        Description = el.TryGetProperty("description", out var ed)
                            ? ed.GetString() ?? "" : "",
                        Source = el.TryGetProperty("source", out var es)
                            ? es.GetString() ?? "" : ""
                    });
                }
            }

            bool? customRoleEligible = null;
            if (root.TryGetProperty("customRoleEligible", out var cre))
            {
                if (cre.ValueKind == JsonValueKind.True) customRoleEligible = true;
                else if (cre.ValueKind == JsonValueKind.False) customRoleEligible = false;
            }

            string? documentedRole = null;
            if (root.TryGetProperty("documentedRole", out var dr) &&
                dr.ValueKind == JsonValueKind.String)
            {
                var v = dr.GetString();
                if (!string.IsNullOrWhiteSpace(v) &&
                    !string.Equals(v, "null", StringComparison.OrdinalIgnoreCase))
                    documentedRole = v;
            }

            return new AiSuggestion
            {
                RequiredActions = actions,
                RecommendedRoleId = roleId,
                Reasoning = reasoning,
                Evidence = evidence,
                DocumentedRole = documentedRole,
                CustomRoleEligible = customRoleEligible
            };
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException(
                "AI response was not the expected JSON shape: " + Truncate(raw, 300), ex);
        }
    }

    /// <summary>
    /// Sends the choose prompt, and if the reply is not JSON, asks once more for JSON only.
    /// </summary>
    private async Task<AiSuggestion> ChooseWithRetryAsync(string permissionUser, CancellationToken ct)
    {
        var raw = StripFences(await SendChatAsync(PromptBuilder.PermissionSystem, permissionUser, ct));
        try
        {
            return ParseSuggestion(raw);
        }
        catch (InvalidDataException)
        {
            // The reminder is deliberately blunt and repeats the schema, because the failures
            // are always the same shape: a numbered explanation of the right answer with no
            // JSON around it.
            var retryUser = permissionUser
                + "\n\nYOUR PREVIOUS REPLY WAS NOT JSON AND WAS DISCARDED. Reply with the JSON "
                + "object ONLY — no explanation before or after it, no numbered list, no "
                + "markdown. Start your reply with { and end it with }.";

            var retryRaw = StripFences(
                await SendChatAsync(PromptBuilder.PermissionSystem, retryUser, ct));
            return ParseSuggestion(retryRaw);
        }
    }

    /// <summary>
    /// The first balanced {...} in the text, or null. Models frequently wrap correct JSON in
    /// a sentence of explanation; throwing that away loses an answer we already have.
    /// </summary>
    protected static string? ExtractJsonObject(string s)
    {
        var start = s.IndexOf('{', StringComparison.Ordinal);
        if (start < 0) return null;

        var depth = 0;
        var inString = false;
        var escaped = false;

        for (var i = start; i < s.Length; i++)
        {
            var c = s[i];

            if (inString)
            {
                if (escaped) escaped = false;
                else if (c == '\\') escaped = true;
                else if (c == '"') inString = false;
                continue;
            }

            if (c == '"') inString = true;
            else if (c == '{') depth++;
            else if (c == '}')
            {
                depth--;
                if (depth == 0) return s[start..(i + 1)];
            }
        }

        return null;
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
        t = t.Trim();

        // Prose wrapped around correct JSON is common and recoverable. Only reach for this
        // when the reply is not already an object, so well-formed answers are untouched.
        if (!t.StartsWith('{')) t = ExtractJsonObject(t) ?? t;

        return t.Trim();
    }

    protected static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max];

    public void Dispose() => Http.Dispose();
}
