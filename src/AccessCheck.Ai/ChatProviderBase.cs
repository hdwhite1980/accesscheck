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
    /// An optional response cache. When set, an identical question is answered from it
    /// rather than asked again.
    /// </summary>
    public PromptCache? Cache { get; set; }

    /// <summary>
    /// Every stage goes through here rather than calling the transport directly.
    ///
    /// THE ENDPOINT WILL NOT BE DETERMINISTIC. temperature 0, top_p 1 and a fixed seed were
    /// all set and identical runs still diverged — the decomposer split one job description
    /// into "joiners, movers, and leavers" on one pass and "joiners, movers and leavers" on
    /// the next, and every answer downstream moved with it. Commercial endpoints batch,
    /// route across experts, and accumulate floating point in hardware order; seed is
    /// documented as best-effort. There is no client-side setting that fixes this.
    ///
    /// So reproducibility is taken here instead. The same question returns the same answer,
    /// which is what makes a recommendation reviewable — and what lets an auditor asking
    /// "how was this reached" get the actual answer rather than a fresh one that happens to
    /// resemble it.
    /// </summary>
    protected async Task<string> SendCachedAsync(string system, string user, CancellationToken ct)
    {
        if (Cache is not null && Cache.TryGet(Config.Model, system, user, out var cached))
            return cached;

        var response = await SendChatAsync(system, user, ct);
        Cache?.Put(Config.Model, system, user, response);
        return response;
    }

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
                var raw = StripFences(await SendCachedAsync(PromptBuilder.ServiceSystem, serviceUser, ct));
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

        // ---- Stage B2: ask what the task NEEDS, then make sure it is on offer ----
        //
        // Stage B decides what the model is ALLOWED to pick, by keyword score with a cap
        // per provider. Nothing downstream can recover a permission that was never shown:
        // the validator, the guards and the verifier all reason about what came back, not
        // about what was available. So a scoring miss is invisible everywhere and surfaces
        // only as a plausible wrong answer, or as silence.
        //
        // It missed repeatedly. Identical runs of one job description resolved
        // search-and-purge from Purview once and returned nothing the next; users/create
        // was offered to one duty and withheld from the adjacent one; a mailbox-delegation
        // request reached a Microsoft 365 BACKUP permission because that was the only
        // candidate whose name contained "mailbox".
        //
        // This stage asks the model what the task needs WITHOUT showing it a list, then
        // looks each named permission up. Anything real that scoring had missed is added
        // to the candidates. Nothing is granted on the model's say-so — a name that
        // matches nothing in the catalog or the reference is recorded and discarded, which
        // is the same rule the validator applies afterwards.
        var namedNeeds = await NamePermissionsAsync(functionDescription, ct);
        var seededNote = "";
        if (namedNeeds.Count > 0)
        {
            var index = PermissionIndex.Build(catalog, reference);
            var have = candidates.Select(c => c.Action).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var seeded = new List<string>();
            var unknown = new List<string>();

            foreach (var name in namedNeeds)
            {
                var match = index.Entries.FirstOrDefault(e =>
                    e.Action.Equals(name, StringComparison.OrdinalIgnoreCase));

                // A cmdlet is often named without its switch — "New-ComplianceSearchAction"
                // for an entry stored as "New-ComplianceSearchAction -Purge". Match the
                // base name so the switch variants are offered rather than missed.
                match ??= index.Entries.FirstOrDefault(e =>
                    e.Action.StartsWith(name + " ", StringComparison.OrdinalIgnoreCase));

                if (match is null)
                {
                    // A GRAPH SCOPE IS NOT A MISSING RBAC ACTION. User.ReadWrite.All and
                    // DeviceManagementManagedDevices.Read.All are what an APPLICATION
                    // consents to — a different permission system that cannot be granted to
                    // a person through a role. Reporting one as absent from the catalog
                    // sends an operator hunting for something that was never going to be
                    // there, and the prompt forbidding it is guidance rather than a
                    // guarantee.
                    if (LooksLikeGraphScope(name)) continue;
                    unknown.Add(name);
                    continue;
                }

                // A PERMISSION IN THE WRONG SERVICE IS STILL A REAL PERMISSION.
                //
                // This used to refuse anything outside the identified service. That refusal
                // did direct harm: a duty to search for and REMOVE malicious messages had
                // New-ComplianceSearch and New-ComplianceSearchAction -Purge named
                // correctly, both present in Purview, and both discarded because the service
                // stage had said Exchange Online — a reading the pipeline then overturned
                // two steps later. What survived was a role that could only EXPORT the
                // messages. The duty was to delete them.
                //
                // The service stage is a hint, not a verdict, and it is wrong often enough
                // that acting on it destructively is worse than the crowding it prevents.
                // Seeding a candidate widens only what may be CONSIDERED — the validator
                // partitions by provider afterwards, and the service reconciliation already
                // requires positive evidence from the cmdlet map before overriding. So note
                // the mismatch and let the deterministic layers decide.
                var outsideIdentified = services.Count > 0 &&
                    !services.Contains(match.Provider, StringComparer.OrdinalIgnoreCase);

                // CANDIDATE SCORING IS NOT THE ONLY DOOR. PermissionIndex withholds
                // agent-identity permissions from a request about staff accounts, because
                // the model conflates agentUsers with users relentlessly. This stage looks
                // permissions up BY NAME against the whole index, so it walked straight
                // past that filter: a duty to disable user accounts named
                // agentUsers/disable, it was found, seeded, chosen, and then stripped by
                // the verifier — leaving the duty with no answer at all.
                //
                // One rule, applied at both doors.
                if (PermissionIndex.IsSpecialisedIdentity(match.Action) &&
                    !PermissionIndex.RequestMentionsSpecialisedIdentity(functionDescription))
                    continue;

                if (have.Add(match.Action))
                {
                    candidates.Add(match);
                    seeded.Add(match.Action + (outsideIdentified
                        ? " (" + RbacProviders.DisplayName(match.Provider) + ")" : ""));
                }
            }

            if (seeded.Count > 0)
                seededNote += "  [AccessCheck: " + seeded.Count + " permission(s) the task "
                    + "needs were added to the candidate list after keyword scoring missed "
                    + "them — " + string.Join(", ", seeded.Take(4)) + ".]";

            // NAMED AND ABSENT IS A FINDING, NOT A SHRUG. "This needs X, which your catalog
            // does not have" is actionable; silently proposing the nearest wrong thing is
            // how Remove-Mailbox was offered for a request to delete messages.
            if (unknown.Count > 0)
                seededNote += "  [AccessCheck: the task appears to need " +
                    string.Join(", ", unknown.Take(4)) +
                    ", which is not in your synced catalog or Microsoft's reference for the "
                    + "identified service. Nothing was substituted.]";

            PromptLogger?.Invoke("needs-result",
                "named: " + string.Join(", ", namedNeeds) + "\nseeded: " +
                string.Join(", ", seeded) + "\nnot found: " + string.Join(", ", unknown));
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
                    await SendCachedAsync(PromptBuilder.PermissionSystem, widerUser, ct));
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

        // SILENCE IS NOT CONFIRMATION.
        //
        // This read `owner is null || owner.Equals(chosen)`, so an action the map has never
        // heard of counted as agreement. CmdletServiceMap knows CMDLETS; asked about a
        // dotted-path action it returns null for every one — which made the override fire
        // on exactly the actions there is no independent evidence about.
        //
        // Real cost: "a director is on leave and her assistant needs access to her mailbox"
        // was correctly identified as Exchange Online, answered with
        // microsoft.backup/restorePoints/userMailboxes/allProperties/allTasks, and the
        // vacuous confirmation promoted that to HIGH CONFIDENCE and rewrote the service to
        // Entra ID. Microsoft refused the custom role and that is the only reason it was
        // not granted.
        //
        // Overriding the service stage is a strong claim, so it now needs positive
        // evidence: at least one chosen action the map actually recognises, and no
        // recognised action pointing elsewhere.
        var mapOwners = kept
            .Select(a => CmdletServiceMap.OwnerOf(a))
            .Where(o => o is not null)
            .Select(o => o!)
            .ToList();

        var mapConfirms = singleService
            && mapOwners.Count > 0
            && mapOwners.All(o => o.Equals(chosenProviders[0], StringComparison.OrdinalIgnoreCase));

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
                ". Nothing independently confirms the permissions, so the identified " +
                "service stands. The usual cause is that the identified service has no " +
                "usable vocabulary in your catalog — check its permission lists are synced " +
                "before treating these as the answer. Verify before granting.]";
        }
        else if (!serviceConfident && serviceNote.Length > 0)
        {
            reasoning += "  [AccessCheck: the owning service could not be identified " +
                "confidently. Verify before granting.]";
        }

        reasoning += seededNote;

        // ---- Stage D: verification ----
        var verdicts = await VerifyAsync(functionDescription, kept, reference, ct);
        var wrongTarget = verdicts
            .Where(v => v.Verdict == VerifyVerdict.WrongTarget)
            .ToList();

        if (wrongTarget.Count > 0)
        {
            // NARROW ONLY. Dropping an action the verifier says does something else is
            // strictly safer than granting it: the worst case is an under-grant the
            // operator notices immediately. SUBSTITUTING one would be a new proposal made
            // by a model with nothing checking it, so the verifier is never allowed to add.
            var dropped = wrongTarget.Select(v => v.Action).ToHashSet(StringComparer.OrdinalIgnoreCase);
            kept = kept.Where(a => !dropped.Contains(a)).ToList();

            // NOT HIDDEN. An audit record that says "we removed something and will not say
            // what" is worse than the error it corrected. The operator does not have to act
            // on this, but it has to be there.
            reasoning += "  [AccessCheck verification: " + wrongTarget.Count +
                " proposed permission(s) were REMOVED because a separate check found they " +
                "act on something other than what was asked — " +
                string.Join("; ", wrongTarget.Select(v => v.Action + ": " + v.Reason)) +
                ". Nothing was substituted; if the remaining permissions do not cover the " +
                "task, the answer is that this catalog has no permission that does.]";

            // Dropping the whole proposal is a bigger claim than dropping part of it.
            if (kept.Count == 0) confidence = SuggestionConfidence.None;
            else if (confidence == SuggestionConfidence.High) confidence = SuggestionConfidence.Low;
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

    // ================= STAGE B2: what does this NEED? =================

    /// <summary>
    /// Noun.Verb.All — the shape of a Graph API application scope. Distinguished from an
    /// RBAC action by having no slash and no hyphen: actions are paths
    /// (microsoft.directory/users/create) and cmdlets are hyphenated verbs
    /// (Add-MailboxPermission). Nothing in either vocabulary looks like this.
    /// </summary>
    private static bool LooksLikeGraphScope(string name)
    {
        if (name.Contains('/') || name.Contains('-') || name.Contains(' ')) return false;

        var parts = name.Split('.');
        if (parts.Length < 2) return false;

        var last = parts[^1];
        return last.Equals("All", StringComparison.OrdinalIgnoreCase)
            || last.Equals("Read", StringComparison.OrdinalIgnoreCase)
            || last.Equals("ReadWrite", StringComparison.OrdinalIgnoreCase)
            || last.Equals("ReadBasic", StringComparison.OrdinalIgnoreCase);
    }

    private const string NeedsSystem = """
        You name the Microsoft 365 or Azure permissions a task requires. Nothing more.

        You are NOT choosing from a list and you will NOT be shown one. Name what the task
        actually needs, using Microsoft's own naming as precisely as you can recall it:

          microsoft.directory/users/password/update
          Add-MailboxFolderPermission
          New-ComplianceSearchAction -Purge
          Microsoft.Intune_DeviceCompliancePolices_Create

        RULES

        RBAC ACTIONS AND CMDLETS ONLY. These are NOT the same thing as Graph API permission
        scopes, and naming one where the other is wanted is the commonest mistake here.

          WANTED    microsoft.directory/users/password/update
          NOT       User.ReadWrite.All

          WANTED    Microsoft.Intune_DeviceCompliancePolices_Read
          NOT       DeviceManagementManagedDevices.Read.All

        A scope of the form Noun.Verb.All is what an APPLICATION consents to. It is a
        different permission system and cannot be granted to a person through a role. If the
        only thing you can recall is a scope of that shape, name nothing.

        NAME PERMISSIONS, NOT ROLES. "DLP Compliance Management" and "User Administrator" are
        role NAMES. A role is a bundle of the permissions being asked for; naming it answers
        a different question and will be reported as a permission your catalog is missing.

        NAME THE NARROWEST THING THAT DOES THE JOB. Not the role that contains it, not the
        whole service. If a task needs one cmdlet, name one cmdlet.

        NAME THE OPERATION ON THE RIGHT OBJECT. Deleting a MESSAGE is not deleting the
        MAILBOX that holds it. Disabling a USER is not disabling an AGENT user. Managing
        group MEMBERSHIP is not creating an access REVIEW of it. Getting this wrong is the
        single most damaging mistake here, because the wrong answer executes successfully.

        SAY SO WHEN YOU DO NOT KNOW. An empty list is a useful answer. A guessed permission
        name is not — it will be looked up, found not to exist, and reported to an operator
        as a gap in their catalog, when it is really a gap in your recall. Half-remembering
        that a permission "probably looks something like" a name is not recall. Name it only
        if you would expect to find that exact string in Microsoft's documentation.

        DO NOT PAD. Three permissions that do the task beat eight that surround it.

        NAME NOTHING FOR A DUTY THAT IS NOT ABOUT ACCESS — writing documentation, chairing
        a meeting, being on call. Return an empty list.

        Return ONLY: {"permissions":["...","..."]}
        No prose, no markdown fences.
        """;

    /// <summary>
    /// Asks what the task needs, with no candidate list in front of the model.
    ///
    /// The constrained stage answers a different question — "which of these 60 is closest?"
    /// — and cannot report that the right permission was absent, because it has no way to
    /// know. Asking openly first turns a scoring miss from an invisible truncation into
    /// either a permission that gets offered after all, or a stated finding.
    ///
    /// The model is NOT trusted with the answer. Every name is looked up in the catalog and
    /// Microsoft's reference; anything that matches nothing is discarded and reported. This
    /// widens what can be CONSIDERED without widening what can be GRANTED, which stays
    /// exactly where it was: the tenant's own vocabulary, checked by deterministic code.
    /// </summary>
    private async Task<IReadOnlyList<string>> NamePermissionsAsync(
        string functionDescription, CancellationToken ct = default)
    {
        var user = "TASK: " + Truncate(functionDescription, 2000);
        PromptLogger?.Invoke("needs", user);

        try
        {
            var raw = StripFences(await SendCachedAsync(NeedsSystem, user, ct));
            var json = ExtractJsonObject(raw) ?? raw;

            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("permissions", out var arr) ||
                arr.ValueKind != JsonValueKind.Array)
                return Array.Empty<string>();

            return arr.EnumerateArray()
                .Select(e => e.GetString() ?? "")
                .Select(x => x.Trim())
                .Where(x => x.Length > 0)
                // A recalled name longer than this is prose, not an action string.
                .Where(x => x.Length < 200)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(12)
                .ToList();
        }
        catch (Exception)
        {
            // THIS STAGE ONLY EVER ADDS. If it fails, the request proceeds on the candidate
            // list exactly as before — a degraded answer, never a wrong one.
            return Array.Empty<string>();
        }
    }

    // ================= STAGE D: verification =================

    public enum VerifyVerdict
    {
        /// <summary>The permission does what the task asked.</summary>
        Verified = 0,
        /// <summary>The right KIND of operation, on the wrong THING. The dangerous case.</summary>
        WrongTarget = 1,
        /// <summary>Related and necessary, but does not complete the task on its own.</summary>
        Insufficient = 2,
        /// <summary>Not enough evidence to say. Never acted on.</summary>
        Unknown = 3
    }

    public sealed record VerifyResult
    {
        public required string Action { get; init; }
        public required VerifyVerdict Verdict { get; init; }
        public required string Reason { get; init; }
        /// <summary>True when Microsoft's own description was available to check against.</summary>
        public bool Grounded { get; init; }
    }

    private const string VerifySystem = """
        You check whether a permission ACTUALLY PERFORMS a stated task. You are a second
        opinion, deliberately separate from whoever chose it.

        You are NOT choosing permissions and NOT suggesting alternatives. Judge only what
        you are given.

        The failure you exist to catch is RIGHT OPERATION, WRONG TARGET. A permission whose
        name matches the verb but acts on a different object is the most dangerous kind of
        wrong answer, because it looks correct and executes successfully.

          Task: "remove malicious messages from mailboxes"
          Permission: Remove-Mailbox
          -> WRONG_TARGET. It deletes the entire mailbox, not messages within it.

        A NAMED OPERATION NEEDS AN ACTION THAT NAMES IT. Where the task names an operation
        — disable, enable, delete, reset, retire, purge, revoke, restore — a general
        "update" on the same object is NOT that operation, however broad the update sounds.
        Microsoft models them separately precisely because changing a property is not the
        same as changing state.

          Task: "disable user accounts"
          Permission: microsoft.directory/users/basic/update
          -> WRONG_TARGET. It updates basic properties — display name, job title,
             department. Disabling is microsoft.directory/users/disable, a separate action.

        This is the failure that reaches an approver looking most reasonable, so it is worth
        being strict about: reasoning that an update "includes" the named operation is
        exactly the guess this check exists to refuse.

          Task: "create user accounts"
          Permission: microsoft.directory/users/basic/update
          -> INSUFFICIENT. It edits existing users; it cannot bring one into existence.

          Task: "manage group membership"
          Permission: microsoft.directory/accessReviews/definitions.groups/create
          -> WRONG_TARGET. It creates access review campaigns, not memberships.

        Answer for the ONE permission given:
          VERIFIED      - performs the task, or is a necessary part of performing it
          WRONG_TARGET  - acts on a different object, or does a different thing entirely
          INSUFFICIENT  - related and needed, but cannot complete the task alone
          UNKNOWN       - you cannot tell from the evidence given

        WRONG_TARGET causes the permission to be DROPPED, so use it only when you are
        confident the object is wrong. If the permission is plausibly one part of a larger
        task, that is VERIFIED or INSUFFICIENT, not WRONG_TARGET. When genuinely unsure,
        answer UNKNOWN — it is acted on by nobody.

        Return ONLY: {"verdict":"...","reason":"one short sentence"}
        No prose, no markdown fences.
        """;

    /// <summary>
    /// Asks, per proposed permission, whether it does what the task actually asked.
    ///
    /// WHY A SEPARATE CALL. The choosing stage has already committed to an answer, and
    /// asking it to re-examine its own work invites it to defend the choice. This call
    /// never sees the reasoning, the alternatives, or the fact that anything chose this
    /// permission — only the task, the permission, and Microsoft's description of it.
    ///
    /// WHY IT ONLY REMOVES. Verification runs unattended and unreviewed, so it is allowed
    /// to make the grant NARROWER and nothing else. An under-grant is noticed within
    /// minutes by the person who cannot do their job; a silent substitution is a
    /// recommendation nobody made, and would put a model on both sides of the check this
    /// application exists to provide.
    ///
    /// GROUNDING. Microsoft's own description is used where the reference has been synced.
    /// Where it has not — which is every Exchange and Purview cmdlet, since the PowerShell
    /// path carries no descriptions — the model is told so explicitly and instructed to
    /// answer UNKNOWN rather than guess, unless web search is available to check.
    /// </summary>
    public async Task<IReadOnlyList<VerifyResult>> VerifyAsync(
        string functionDescription,
        IReadOnlyCollection<string> actions,
        ReferenceStore? reference,
        CancellationToken ct = default)
    {
        if (actions.Count == 0) return Array.Empty<VerifyResult>();

        var descriptions = reference?.Descriptions();
        var results = new List<VerifyResult>();

        foreach (var action in actions)
        {
            var grounded = descriptions is not null
                           && descriptions.TryGetValue(action, out var desc)
                           && !string.IsNullOrWhiteSpace(desc);

            var evidence = grounded
                ? "MICROSOFT'S DESCRIPTION: " + descriptions![action]
                : "NO MICROSOFT DESCRIPTION IS AVAILABLE for this permission in this "
                  + "tenant's synced reference. Judge from the permission name only, and "
                  + "answer UNKNOWN unless the name makes the target unambiguous.";

            var user = "TASK: " + Truncate(functionDescription, 2000) + "\n\n" +
                       "PERMISSION: " + action + "\n" +
                       evidence;

            PromptLogger?.Invoke("verify", user);

            try
            {
                var raw = StripFences(await SendCachedAsync(VerifySystem, user, ct));
                var json = ExtractJsonObject(raw) ?? raw;

                using var doc = JsonDocument.Parse(json);
                var verdictText = doc.RootElement.TryGetProperty("verdict", out var v)
                    ? v.GetString() ?? "" : "";
                var reason = doc.RootElement.TryGetProperty("reason", out var r)
                    ? r.GetString() ?? "" : "";

                var verdict = verdictText.Trim().ToUpperInvariant() switch
                {
                    "VERIFIED" => VerifyVerdict.Verified,
                    "WRONG_TARGET" => VerifyVerdict.WrongTarget,
                    "INSUFFICIENT" => VerifyVerdict.Insufficient,
                    _ => VerifyVerdict.Unknown
                };

                // AN UNGROUNDED WRONG_TARGET IS A GUESS ABOUT A NAME, and this verdict
                // DELETES a permission from the recommendation. Without Microsoft's words
                // to check against, that is exactly the name-reading this application
                // forbids the model everywhere else, so it is downgraded to a note.
                if (verdict == VerifyVerdict.WrongTarget && !grounded)
                {
                    verdict = VerifyVerdict.Unknown;
                    reason = "Name suggests a different target (" + reason +
                             "), but Microsoft's description is not synced for this " +
                             "service, so this was not acted on.";
                }

                results.Add(new VerifyResult
                {
                    Action = action,
                    Verdict = verdict,
                    Reason = reason,
                    Grounded = grounded
                });
            }
            catch (Exception ex)
            {
                // A VERIFIER THAT FAILS MUST NOT DROP ANYTHING. Its errors are the one
                // outcome that has to leave the recommendation exactly as it was.
                results.Add(new VerifyResult
                {
                    Action = action,
                    Verdict = VerifyVerdict.Unknown,
                    Reason = "Verification did not complete: " + ex.Message,
                    Grounded = grounded
                });
            }
        }

        // Logged in full, agreements included — the verifier's own accuracy has to be
        // auditable, and a log of only its objections cannot show how often it is wrong.
        PromptLogger?.Invoke("verify-result", string.Join("\n",
            results.Select(r => r.Verdict + "  " + r.Action +
                                (r.Grounded ? "  [grounded]" : "  [name only]") +
                                "  " + r.Reason)));

        return results;
    }

    // ================= STAGE 0: decomposition =================

    /// <summary>
    /// One discrete duty pulled out of a longer document, ready to run through the normal
    /// single-function pipeline.
    /// </summary>
    public sealed record FunctionSpec
    {
        /// <summary>The duty, rewritten as a single self-contained request.</summary>
        public required string Text { get; init; }

        /// <summary>Verbatim source line, so the operator can check the rewrite.</summary>
        public string SourceQuote { get; init; } = "";

        /// <summary>
        /// The model's read of whether this duty only LOOKS at things.
        ///
        /// Carried because RequestWantsStateChange is computed per request, and a whole
        /// job description is a single request containing both kinds. One "configure"
        /// anywhere in a page made wantsChange true globally, and CandidateActions then
        /// stripped every read-only permission before the model saw them — so the
        /// monitoring duties came back answered with writes, or not at all.
        /// Splitting first is what makes that flag mean something again.
        /// </summary>
        public bool ReadOnly { get; init; }

        /// <summary>
        /// A duty RBAC cannot express — "liaises with vendors", "mentors junior staff",
        /// "participates in the on-call rota". Reported and skipped rather than forced
        /// into a permission, because forcing it is how unrelated access gets granted.
        /// </summary>
        public bool NotAccessRelated { get; init; }

        /// <summary>Why the model classified it as not access-related. Shown, not acted on.</summary>
        public string Note { get; init; } = "";
    }

    private const string DecomposeSystem = """
        You split a job description, role profile or access request into the DISCRETE
        ADMINISTRATIVE DUTIES it contains.

        You are NOT choosing permissions. Do not name any permission, role or product
        feature. Another stage does that, one duty at a time.

        Rules:

        SPLIT BY DUTY, NOT BY SENTENCE. One sentence often holds two duties ("creates and
        disables user accounts" is two). One duty is often spread over several sentences.

        DO NOT SPLIT A DUTY FROM ITS OWN OUTPUT. "Monitors device compliance reports and
        produces a weekly summary" is ONE duty: the summary is written from the reports the
        first half already reads, and needs no further permission. Splitting it inflates
        the plan with duplicates that then have to be merged back.

        REWRITE EACH AS A STANDALONE REQUEST. "Responsible for ensuring mailboxes are
        delegated during periods of leave" becomes "delegate access to a mailbox while its
        owner is on leave". A later stage sees only this text, so it must stand alone.

        MARK READ-ONLY DUTIES. readOnly=true when the duty only looks at, reports on,
        monitors or audits something. false when it changes anything. If a duty both
        views and changes, split it in two.

        MARK WHAT IS NOT ACCESS AT ALL. notAccessRelated=true for duties no permission
        can grant. Keep them in the list with a short note. Do NOT invent a technical duty
        to make them fit.

        This covers more than meetings and mentoring. A duty is NOT access-related when the
        thing being acted on is not an object in the tenant:
          - attending, chairing or running meetings; mentoring; being on call; liaising
            with suppliers; training people
          - MAINTAINING A DOCUMENT — a register, spreadsheet, wiki page, runbook, log,
            tracker or matrix. "Updates the exception register when an exception is
            approved" is editing a document. No RBAC permission grants that, and hunting
            for the closest-sounding one lands on something unrelated: an exception
            register was answered with an Intune administrative-task permission.
          - producing a report that is WRITTEN by a person from data they can already see.
            Reading the data is the duty; writing the summary is not a second one.
          - approving, deciding, escalating or signing off — these are process steps, not
            permissions.

        THE TEST: if the duty were done entirely outside the Microsoft 365 admin surface —
        in Word, in a meeting, in a ticket — it is notAccessRelated, however technical the
        wording sounds.

        NOTE FOR THE NOTE FIELD: say WHY it is not access-related, do not simply repeat the
        duty back. "Editing a document, not a tenant object" is useful. "Updates the
        exception register." is not.

        DO NOT INVENT DUTIES. Only what the text states. A job description that says
        "manages Microsoft 365" contains one vague duty, not fifteen specific ones you
        assume it implies.

        DO NOT MERGE UNRELATED DUTIES to shorten the list. Two duties in different
        services are always two duties.

        Return ONLY:
        {"functions":[{"text":"...","sourceQuote":"...","readOnly":true|false,
        "notAccessRelated":true|false,"note":"..."}]}
        No prose, no markdown fences.
        """;

    /// <summary>
    /// Splits a document into discrete duties so each can run through the ORDINARY
    /// pipeline unchanged.
    ///
    /// Everything downstream — service identification, candidate selection, validation,
    /// the guards, confidence — assumes ONE task. Feeding it a page defeats all of it at
    /// once: no single service owns the document so Stage A returns nothing or everything;
    /// keyword scoring across a hundred content words stops discriminating; low confidence
    /// then blocks the custom role that a job description most needs.
    ///
    /// And the answer to a job description is not one role. It is a PORTFOLIO — some
    /// duties standing, some time-boxed, some that should be refused outright. A single
    /// role covering every duty on a systems administrator's job description is
    /// approximately Global Administrator, which is the outcome this application exists
    /// to prevent.
    ///
    /// So this stage does no RBAC reasoning at all. It only reads prose and returns a
    /// list, which is the part a language model is reliably good at.
    /// </summary>
    public async Task<IReadOnlyList<FunctionSpec>> DecomposeAsync(
        string documentText, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(documentText))
            return Array.Empty<FunctionSpec>();

        // SHORT INPUT IS ALREADY ONE FUNCTION. Sending a single sentence through
        // decomposition invites the model to invent the duties it thinks the sentence
        // implies, and those inventions would each become a real grant proposal.
        var trimmed = documentText.Trim();
        if (trimmed.Length < 200 && !trimmed.Contains('\n'))
        {
            return new[] { new FunctionSpec { Text = trimmed, SourceQuote = trimmed } };
        }

        var user = "DOCUMENT:\n" + Truncate(trimmed, 12000);
        PromptLogger?.Invoke("decompose", user);

        var raw = StripFences(await SendCachedAsync(DecomposeSystem, user, ct));
        var json = ExtractJsonObject(raw) ?? raw;

        var results = new List<FunctionSpec>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("functions", out var arr) ||
                arr.ValueKind != JsonValueKind.Array)
                return Fallback(trimmed);

            foreach (var el in arr.EnumerateArray())
            {
                var text = el.TryGetProperty("text", out var t) ? t.GetString() : null;
                if (string.IsNullOrWhiteSpace(text)) continue;

                results.Add(new FunctionSpec
                {
                    Text = text!.Trim(),
                    SourceQuote = el.TryGetProperty("sourceQuote", out var q)
                        ? q.GetString() ?? "" : "",
                    ReadOnly = el.TryGetProperty("readOnly", out var r)
                        && r.ValueKind == JsonValueKind.True,
                    NotAccessRelated = el.TryGetProperty("notAccessRelated", out var na)
                        && na.ValueKind == JsonValueKind.True,
                    Note = el.TryGetProperty("note", out var nt) ? nt.GetString() ?? "" : ""
                });
            }
        }
        catch (JsonException)
        {
            return Fallback(trimmed);
        }

        // A DEGRADED SPLIT MUST NOT BECOME A SILENT ONE. Returning an empty list here
        // would read downstream as "this document asks for nothing", which is a very
        // different claim from "the split failed".
        return results.Count > 0 ? results : Fallback(trimmed);

        static IReadOnlyList<FunctionSpec> Fallback(string text) => new[]
        {
            new FunctionSpec
            {
                Text = text,
                SourceQuote = text,
                Note = "Automatic split failed; treating the whole document as one request. "
                     + "Expect poor results on anything covering more than one duty — "
                     + "split it by hand and analyse each part."
            }
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
        return StripFences(await SendCachedAsync(system, user, ct));
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
        var raw = StripFences(await SendCachedAsync(PromptBuilder.PermissionSystem, permissionUser, ct));
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
                await SendCachedAsync(PromptBuilder.PermissionSystem, retryUser, ct));
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
