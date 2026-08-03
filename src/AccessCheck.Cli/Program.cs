using AccessCheck.Ai;
using AccessCheck.Cli;
using AccessCheck.Core.Audit;
using AccessCheck.Core.Catalog;
using AccessCheck.Core.Config;
using AccessCheck.Core.Execution;
using AccessCheck.Core.Recommendation;
using AccessCheck.Graph;
using AccessCheck.PowerShell;

var dataDir = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AccessCheck");
Directory.CreateDirectory(dataDir);
// Install the bundled Purview role list and Exchange cmdlet descriptions on first run.
// Neither can be discovered from a tenant, and without them two whole services answer
// with names alone.
SeedData.EnsureSeeded(dataDir);
var catalogPath = Path.Combine(dataDir, "catalog.json");
var historyPath = Path.Combine(dataDir, "history.jsonl");
var promptLogPath = Path.Combine(dataDir, "prompt-log.txt");
// Same file the GUI writes, so a grant made in the app and revoked by the
// scheduled task leave one continuous record of the scripts that ran.
var psScriptLogPath = Path.Combine(dataDir, "ps-script-log.txt");
// Microsoft's own permission vocabulary, shared with the GUI. Without it ActionRisk
// falls back to its heuristic, which on one real tenant disagreed with Microsoft
// on 568 of 939 directory actions.
var referencePath = Path.Combine(dataDir, "reference.json");
// Microsoft's published Purview role list. The Security and Compliance session cannot
// report what a Purview role contains, so this is the only vocabulary that service has.
var purviewRolesPath = Path.Combine(dataDir, "purview-roles.json");
// Microsoft's published page as downloaded; parsed into the JSON above on first use.
var purviewRolesMarkdownPath = Path.Combine(dataDir, "purview-roles.md");
// Endpoint responses keyed by prompt hash. The endpoint will not be deterministic even
// at temperature 0, so reproducibility is taken here instead.
var promptCachePath = Path.Combine(dataDir, "prompt-cache.json");
// Exchange and Purview cmdlet descriptions, imported from Microsoft's published docs.
// These two services are the only ones whose permissions otherwise reach the model
// with no description at all.
var cmdletDescriptionsPath = Path.Combine(dataDir, "exchange-descriptions.json");
// Hand-written notes distinguishing confusable permissions. Editable, and shipped with
// a built-in set covering the confusions that have actually produced wrong answers.
var actionNotesPath = Path.Combine(dataDir, "action-notes.json");
var configPath = new[]
{
    // THE GUI'S CONFIG COMES FIRST. Both tools share %APPDATA%\AccessCheck for catalog,
    // history and secrets, but the CLI's search list omitted it — so a key stored through
    // the app was looked up under whatever ApiKeyName a repo-local or SAMPLE config
    // happened to carry, found nothing, and reported "no key stored" while the key sat
    // there perfectly intact.
    Path.Combine(dataDir, "appsettings.json"),
    "appsettings.json",
    Path.Combine(AppContext.BaseDirectory, "appsettings.json"),
    Path.Combine("src", "AccessCheck.Cli", "appsettings.json"),
    "appsettings.sample.json",
    Path.Combine(AppContext.BaseDirectory, "appsettings.sample.json"),
    Path.Combine("src", "AccessCheck.Cli", "appsettings.sample.json")
}.FirstOrDefault(File.Exists) ?? "appsettings.json";

if (args.Length == 0)
{
    Console.WriteLine("""
        AccessCheck CLI — least-privilege access broker (pipeline harness)

        usage:
          accesscheck demo "<function description>"     offline: sample catalog + demo suggester
          accesscheck set-key                           store the GenAI API key (DPAPI)
          accesscheck sync                              sync ALL RBAC providers from Graph
          accesscheck recommend "<function>"            GenAI suggest -> validate -> show verdicts
          accesscheck approve <principalId> "<function>" [P14D] [--eligible]
                                                       full flow incl. Graph execution after Y/N
          accesscheck clear-cache                       forget cached endpoint responses
          accesscheck jd <file.txt|"<text>">           split a job description into duties and
                                                       analyse each one separately
          accesscheck housekeeping                      GC roles + remove expired direct grants
          accesscheck housekeeping --unattended [--gc-roles]
                                                       no prompts, for Task Scheduler.
                                                       Removes expired grants; --gc-roles also
                                                       deletes orphaned AccessCheck roles.
                                                       Exit 0 = clean, 1 = something failed.
                                                       --skip-powershell omits Exchange/Purview.
        """);
    return 0;
}

var command = args[0].ToLowerInvariant();

switch (command)
{
    case "demo":
    {
        var function = args.Length > 1 ? args[1] : "reset user passwords for help desk tickets";
        var catalog = LoadCatalog(FindSample());
        var provider = new DemoProvider();
        var suggestion = await provider.SuggestAsync(function, catalog);
        var validator = new RecommendationValidator();
        var outcomes = validator.ValidateMulti(catalog, suggestion, function);
        PrintOutcomes(function, suggestion, outcomes);

        foreach (var po in outcomes)
        {
            var record = RequestRecordBuilder.FromOutcome(function, suggestion, po.Outcome, null)
                with { Provider = po.Provider };
            new RequestHistoryStore(historyPath).Append(record);
        }
        Console.WriteLine("\n[audit] appended to " + historyPath);
        return 0;
    }

    case "set-key":
    {
        var cfg = AppConfig.Load(configPath);
        Console.WriteLine("Secret store: " + SecretStore.BackendDescription);
        if (!SecretStore.IsEncrypted)
            Console.WriteLine("WARNING: on this platform the key is stored in a " +
                              "permission-restricted file, not encrypted.");
        Console.Write("Paste GenAI API key (input not masked in this harness): ");
        var key = Console.ReadLine() ?? "";
        if (key.Trim().Length == 0) { Console.WriteLine("No key entered."); return 1; }
        SecretStore.Save(cfg.Ai.ApiKeyName, key.Trim());
        Console.WriteLine("Stored under '" + cfg.Ai.ApiKeyName + "' (DPAPI, current user).");
        return 0;
    }

    case "sync":
    {
        var cfg = AppConfig.Load(configPath);
        var cloud = CloudEnvironment.Parse(cfg.Cloud);
        var auth = new GraphAuth(cfg.ClientId, cfg.TenantId, cloud,
            cloud.Scopes(cfg.GraphPermissions, cfg.EnableOutreach));
        using var graph = new GraphClient(auth, cloud);
        Console.WriteLine("Syncing all RBAC providers from " + cloud.GraphBase + " ...");
        var (catalog, results) = await new CatalogSync(graph).SyncAllAsync(Console.WriteLine);
        catalog.Save(catalogPath);
        foreach (var r in results)
            Console.WriteLine("  " + RbacProviders.DisplayName(r.Provider) + ": " +
                (r.Error is null ? r.RoleCount + " roles" : "SKIPPED (" + r.Error + ")"));
        Console.WriteLine("Total: " + catalog.Roles.Count + " roles, " +
                          catalog.ActionCount + " distinct actions -> " + catalogPath);
        return 0;
    }

    case "recommend":
    {
        if (args.Length < 2) { Console.WriteLine("recommend needs a function description."); return 1; }
        var function = args[1];
        var cfg = AppConfig.Load(configPath);
        var catalog = LoadCatalog();

        var (suggestion, promptSha) = await SuggestViaGenAi(cfg, function, catalog);
        var validator = new RecommendationValidator
        {
            MaxAcceptableExcessActions = cfg.MaxAcceptableExcessActions
        };
        var outcomes = validator.ValidateMulti(catalog, suggestion, function);
        PrintOutcomes(function, suggestion, outcomes);

        foreach (var po in outcomes)
        {
            var record = RequestRecordBuilder.FromOutcome(function, suggestion, po.Outcome, promptSha)
                with { Provider = po.Provider };
            new RequestHistoryStore(historyPath).Append(record);
        }
        Console.WriteLine("\n[audit] records appended.");
        return 0;
    }

    case "approve":
    {
        if (args.Length < 3)
        {
            Console.WriteLine("approve <principalId> \"<function>\" [durationISO8601] [--eligible]");
            return 1;
        }
        var principalId = args[1];
        var function = args[2];
        var duration = args.Length > 3 && !args[3].StartsWith("--") ? args[3] : "P14D";
        var eligible = args.Contains("--eligible");

        var cfg = AppConfig.Load(configPath);
        var cloud = CloudEnvironment.Parse(cfg.Cloud);
        var catalog = LoadCatalog();

        var (suggestion, promptSha) = await SuggestViaGenAi(cfg, function, catalog);
        var validator = new RecommendationValidator
        {
            MaxAcceptableExcessActions = cfg.MaxAcceptableExcessActions
        };
        var outcomes = validator.ValidateMulti(catalog, suggestion, function);
        PrintOutcomes(function, suggestion, outcomes);

        var store = new RequestHistoryStore(historyPath);
        var actionable = outcomes.Where(o => o.Outcome.ValidActions.Count > 0).ToList();
        if (actionable.Count == 0)
        {
            Console.WriteLine("\nNothing actionable — no valid actions survived validation.");
            return 1;
        }

        var auth = new GraphAuth(cfg.ClientId, cfg.TenantId, cloud,
            cloud.Scopes(cfg.GraphPermissions, cfg.EnableOutreach));
        using var graph = new GraphClient(auth, cloud);
        var executor = new RoleExecutor(graph);

        foreach (var po in actionable)
        {
            var outcome = po.Outcome;
            Console.Write("\n[" + RbacProviders.DisplayName(po.Provider) + "] APPROVE " +
                          (eligible && po.Provider == RbacProviders.Directory ? "ELIGIBLE" : "grant") +
                          " for principal " + principalId + ", duration " + duration + "? [y/N] ");
            var record = RequestRecordBuilder.FromOutcome(function, suggestion, outcome, promptSha)
                with { PrincipalId = principalId, Provider = po.Provider };

            if (!string.Equals(Console.ReadLine()?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
            {
                store.Append(record with { Notes = "Declined at approval prompt." });
                Console.WriteLine("Declined.");
                continue;
            }

            if (RbacProviders.DerivedRoleCapable.Contains(po.Provider))
            {
                store.Append(record with { Notes = po.Provider + ": use the GUI's PowerShell grant path." });
                Console.WriteLine(RbacProviders.DisplayName(po.Provider) +
                    " grants run as PowerShell — use the AccessCheck app (script shown for review), " +
                    "or derive manually: New-ManagementRole -Parent '<best fit>' then " +
                    "Remove-ManagementRoleEntry for each excess cmdlet listed above.");
                continue;
            }

            string roleId;
            if (outcome.CustomRoleRecommended && outcome.CustomRole is not null)
            {
                Console.WriteLine("Creating custom role '" + outcome.CustomRole.DisplayName + "' ...");
                roleId = await executor.CreateCustomRoleAsync(po.Provider, outcome.CustomRole);
                Console.WriteLine("Created role " + roleId);
            }
            else
            {
                roleId = outcome.BestFit!.RoleId;
            }

            if (po.Provider == RbacProviders.Directory)
            {
                var plan = new AssignmentPlan
                {
                    PrincipalId = principalId,
                    RoleDefinitionId = roleId,
                    Justification = "AccessCheck least-privilege grant: " + function,
                    Type = eligible ? AssignmentType.Eligible : AssignmentType.Active,
                    Duration = duration
                };
                var scheduleId = await executor.AssignDirectoryAsync(plan);
                store.Append(record with
                {
                    Approved = true,
                    ApprovedBy = Environment.UserName,
                    ApprovedUtc = DateTimeOffset.UtcNow,
                    AssignmentTypeUsed = plan.Type.ToString(),
                    Duration = duration,
                    ChosenRoleId = roleId,
                    CustomRoleCreated = outcome.CustomRoleRecommended,
                    GraphScheduleRequestId = scheduleId
                });
                Console.WriteLine("PIM schedule request " + scheduleId +
                                  " (afterDuration " + duration + ", server-side).");
            }
            else
            {
                var assignmentId = await executor.AssignMultiAsync(
                    po.Provider, principalId, roleId,
                    "AccessCheck least-privilege grant: " + function);
                var expires = DateTimeOffset.UtcNow + ParseIsoDuration(duration);
                store.Append(record with
                {
                    Approved = true,
                    ApprovedBy = Environment.UserName,
                    ApprovedUtc = DateTimeOffset.UtcNow,
                    AssignmentTypeUsed = "DirectMulti",
                    Duration = duration,
                    ChosenRoleId = roleId,
                    CustomRoleCreated = outcome.CustomRoleRecommended,
                    MultiAssignmentId = assignmentId,
                    TrackedExpiryUtc = expires
                });
                Console.WriteLine("Assigned (" + assignmentId + "). NOTE: no PIM here — " +
                                  "housekeeping removes it after " + expires.ToString("u") + ".");
            }
        }
        return 0;
    }

    case "clear-cache":
    {
        // A CACHED ANSWER IS A STALE ANSWER once the question changes for a reason the hash
        // cannot see — a model upgraded behind the same name, or an endpoint corrected. The
        // key covers the model and both prompts, so ordinary changes invalidate themselves;
        // this is for the rest.
        var cache = new PromptCache(promptCachePath);
        var had = cache.Count;
        cache.Clear();
        Console.WriteLine("Cleared " + had + " cached response(s).");
        return 0;
    }

    case "jd":
    {
        if (args.Length < 2)
        {
            Console.WriteLine("jd needs a file path or the text itself.");
            return 1;
        }

        // A path if it resolves to one, otherwise the argument IS the document. Saves
        // insisting on a temp file for a two-line request.
        var document = File.Exists(args[1]) ? File.ReadAllText(args[1]) : args[1];

        var cfg = AppConfig.Load(configPath);
        var catalog = LoadCatalog();
        var reference = ReferenceStore.Load(referencePath);

        // MERGE THE CMDLET DOCS BEFORE ANYTHING READS THE REFERENCE. PermissionIndex joins
        // against it, ActionRisk reads it, the guards check against it and Stage D grounds
        // its verdicts on it — installing this afterwards would leave every one of them
        // looking at the description-less version.
        var cmdletDocs = CmdletDescriptionStore.Load(cmdletDescriptionsPath);
        if (!cmdletDocs.IsEmpty)
        {
            var addedExo = cmdletDocs.MergeInto(reference, RbacProviders.Exchange);
            if (addedExo > 0)
                Console.WriteLine("(Exchange/Purview: " + addedExo +
                                  " cmdlet description(s) from Microsoft's published docs.)");
        }
        else
        {
            Console.WriteLine("(Exchange/Purview cmdlets have NO descriptions. The model can "
                            + "only read their names — run dist\\import-exchange-descriptions.ps1.)");
        }

        // DISAMBIGUATION NOTES, APPENDED TO MICROSOFT'S OWN WORDS.
        //
        // Where two actions are routinely confused, an accurate description is not always a
        // useful one: "Disable users" beside "Update basic properties on users" reads as
        // though the second is broader and covers the first, and a duty to disable accounts
        // was answered with the property update run after run. The note says which similar
        // thing the permission is NOT. Microsoft still says what it is.
        // ANNOTATE THE STORE, NOT A COPY OF IT. PermissionIndex builds the candidate list
        // the model chooses from out of the ReferenceStore object; a dictionary derived
        // from it reaches only the guards and the validator. Annotating the dictionary left
        // the choosing stage reading the original text and producing the identical wrong
        // reasoning, word for word.
        var actionNotes = ActionNoteStore.Load(actionNotesPath);
        ActionNoteStore.Install(actionNotes);
        if (actionNotes.Count > 0)
            Console.WriteLine("(" + actionNotes.Count + " permission(s) carry a disambiguation note.)");

        // Microsoft's descriptions, unannotated. CitationCheck compares the model's quote
        // against these, so a note written in here would make an honest quote look invented.
        var describedActions = reference.Descriptions();

        ActionRisk.UseAuthoritative(reference.StatedPrivilege());
        ActionRisk.UseDescriptions(describedActions);

        string? aiKey = SecretStore.Load(cfg.Ai.ApiKeyName);
        if (string.IsNullOrEmpty(aiKey))
        {
            // NAME BOTH HALVES. "No key stored" is true of the name that was looked up,
            // not of the machine, and without the name and the config file it was read
            // from there is nothing to check.
            Console.WriteLine("No AI key found under the name '" + cfg.Ai.ApiKeyName + "'.");
            Console.WriteLine("  config read from: " + configPath);
            Console.WriteLine("  If you stored the key in the desktop app, check that file is");
            Console.WriteLine("  %APPDATA%\\AccessCheck\\appsettings.json and that its Ai.ApiKeyName");
            Console.WriteLine("  matches. Otherwise run: accesscheck set-key");
            return 1;
        }

        // ONE PROVIDER FOR THE WHOLE DOCUMENT. Decomposition and every per-duty analysis
        // share it, so a twenty-duty job description opens one connection rather than
        // twenty-one.
        using var jdProvider = AiProviderFactory.Create(new AiProviderConfig
        {
            ProviderKind = cfg.Ai.Provider,
            ApiVersion = cfg.Ai.ApiVersion,
            BaseUrl = cfg.Ai.BaseUrl,
            Model = cfg.Ai.Model,
            AuthHeaderName = cfg.Ai.AuthHeaderName,
            AuthValuePrefix = cfg.Ai.AuthValuePrefix,
            ApiKeyName = cfg.Ai.ApiKeyName,
            ShortlistSize = cfg.Ai.ShortlistSize
        }, aiKey);
        // SAME DOCUMENT, SAME PLAN. Without this, re-running one job description produced a
        // different split and therefore different answers, which makes a plan impossible to
        // review and impossible to defend afterwards.
        var promptCache = new PromptCache(promptCachePath);
        jdProvider.Cache = promptCache;

        jdProvider.PromptLogger = (stage, prompt) =>
            File.AppendAllText(promptLogPath,
                "==== " + DateTimeOffset.UtcNow.ToString("o") + " [" + stage + "] ====\n"
                + prompt + "\n");

        Console.WriteLine("Splitting the document into discrete duties...");
        var functions = await jdProvider.DecomposeAsync(document);
        Console.WriteLine("Found " + functions.Count + " duty(ies).\n");

        // THE SAME VALIDATOR THE APP BUILDS, not a stripped-down one.
        //
        // This was constructed with only the excess threshold, and the three missing
        // properties each cost a correct answer:
        //
        //   Ineligibility — Microsoft REFUSES a subset of directory actions in custom
        //   roles. Without it the CLI confidently recommended "CUSTOM ROLE with exactly 1
        //   action" for users/password/update, which cannot be created and fails at
        //   execution with 400 Request_BadRequest. The app already knew; the CLI did not
        //   read the file.
        //
        //   ReferenceActions — permissions Microsoft documents but no local role grants
        //   are exactly the case a custom role exists to solve. Without them they look
        //   like hallucinations and get rejected.
        //
        //   ReferenceDescriptions — a permission's meaning comes from its own
        //   description. Without them the guards fall back to reading names, which is the
        //   reasoning this app forbids the model.
        var ineligibility = CustomRoleEligibility.Load(
            Path.Combine(dataDir, "custom-role-ineligible.json"));
        var refDescriptions = describedActions;
        var jdValidator = new RecommendationValidator
        {
            MaxAcceptableExcessActions = cfg.MaxAcceptableExcessActions,
            ReferenceActions = reference.ActionNames(),
            Ineligibility = ineligibility,
            ReferenceDescriptions = describedActions
        };
        var jdStore = new RequestHistoryStore(historyPath);
        var skipped = 0;
        var analysed = 0;
        var jdAnalyses = new List<DutyAnalysis>();

        foreach (var fn in functions)
        {
            Console.WriteLine(new string('=', 78));

            // NOT EVERY DUTY IS AN ACCESS REQUEST. "Mentors junior staff" has no
            // permission, and forcing one is how unrelated access gets granted. Report and
            // move on rather than sending it down the pipeline.
            if (fn.NotAccessRelated)
            {
                skipped++;
                Console.WriteLine("SKIPPED (not an access question): " + fn.Text);
                if (fn.Note.Length > 0) Console.WriteLine("  " + fn.Note);
                Console.WriteLine();
                continue;
            }

            analysed++;
            Console.WriteLine("DUTY " + analysed + ": " + fn.Text);
            if (fn.SourceQuote.Length > 0 && fn.SourceQuote != fn.Text)
            {
                var quote = fn.SourceQuote.Replace("\r", " ").Replace("\n", " ").Trim();
                if (quote.Length > 160) quote = quote[..160] + "...";
                Console.WriteLine("  from: \"" + quote + "\"");
            }
            Console.WriteLine("  " + (fn.ReadOnly ? "read-only duty" : "changes state"));
            Console.WriteLine();

            try
            {
                // THE ORDINARY PIPELINE, UNCHANGED. Each duty gets its own service
                // identification, its own candidate set, its own wantsChange flag and its
                // own guards — which is the entire point of splitting first.
                var suggestion = await jdProvider.SuggestAsync(
                    fn.Text, catalog, null, default, reference);
                var outcomes = jdValidator.ValidateMulti(catalog, suggestion, fn.Text);
                PrintOutcomes(fn.Text, suggestion, outcomes);

                // THE GUARDS, WHICH THIS PATH WAS RUNNING NONE OF.
                //
                // The desktop app builds these inline in its code-behind, so the CLI —
                // and therefore every job-description analysis — has been reporting
                // verdicts with the entire deterministic safety layer switched off. A duty
                // reading "review every Conditional Access policy" was answered with a
                // named-locations read and passed without comment; CapabilityCoverage is
                // the guard whose whole purpose is to notice that the proposal cannot do
                // what was asked.
                //
                // Only the two that already live in Core are wired here. The rest
                // (wrong-resource, inverse-permission, limits-RBAC-cannot-express) are
                // still trapped in the WPF layer and remain unavailable to any other
                // caller.
                // EVERY GUARD, NOT THE TWO THAT HAPPENED TO BE REACHABLE. Only
                // CapabilityCoverage and PermissionBreadth were wired here; the other eight
                // ran solely in the desktop app, so this path produced verdicts with most of
                // the deterministic safety layer switched off. A duty answered with
                // Remove-Mailbox — which deletes the mailbox and the user account — passed
                // with no comment, because the guard built to catch exactly that was
                // unreachable from here.
                var guardFindings = GuardReport.Build(
                    fn.Text, outcomes, catalog, refDescriptions, suggestion.Confidence);

                if (guardFindings.Count > 0)
                {
                    Console.WriteLine();
                    Console.Write(GuardReport.Describe(guardFindings));
                }

                // A DUTY THAT PRODUCED NOTHING STILL HAPPENED.
                //
                // Recording only inside the loop below meant a duty with zero provider
                // outcomes vanished from the plan entirely — not listed as a grant, not
                // listed as unresolved, just absent, while the summary counted a smaller
                // number of duties than were analysed. Silence read as success.
                if (outcomes.Count == 0)
                {
                    Console.WriteLine("  NO VERDICT — nothing validated for this duty.");
                    jdAnalyses.Add(new DutyAnalysis
                    {
                        Duty = fn.Text,
                        Provider = RbacProviders.Directory,
                        Actions = Array.Empty<string>(),
                        DeclaredReadOnly = fn.ReadOnly
                    });
                }

                foreach (var po in outcomes)
                {
                    var record = RequestRecordBuilder.FromOutcome(
                        fn.Text, suggestion, po.Outcome, jdProvider.LastPromptSha256)
                        with { Provider = po.Provider };
                    jdStore.Append(record);

                    // Feed the composer. The per-duty print above is a transcript; the
                    // plan at the end is what someone actually approves.
                    var chosenLabel = po.Outcome.CustomRoleRecommended
                        ? po.Outcome.CustomRole?.DisplayName
                        : po.Outcome.BestFit?.DisplayName;
                    jdAnalyses.Add(new DutyAnalysis
                    {
                        Duty = fn.Text,
                        Provider = po.Provider,
                        Actions = po.Outcome.ValidActions,
                        RoleLabel = chosenLabel,
                        CustomRole = po.Outcome.CustomRoleRecommended,
                        DeclaredReadOnly = fn.ReadOnly
                    });
                }
            }
            catch (Exception ex)
            {
                // ONE DUTY FAILING MUST NOT LOSE THE REST OF THE DOCUMENT — NOR ITSELF.
                //
                // Printing the error and moving on dropped the duty from the plan
                // altogether: not a grant, not unresolved, absent, while the summary
                // counted a smaller number of duties than the document contained. A duty
                // whose analysis crashed is exactly the one an operator must be told
                // about, because nothing else will mention it again.
                Console.WriteLine("  ANALYSIS FAILED: " + ex.Message);
                jdAnalyses.Add(new DutyAnalysis
                {
                    Duty = fn.Text,
                    Provider = RbacProviders.Directory,
                    Actions = Array.Empty<string>(),
                    DeclaredReadOnly = fn.ReadOnly
                });
            }
            Console.WriteLine();
        }

        Console.WriteLine(new string('=', 78));
        Console.WriteLine("THE PLAN");
        Console.WriteLine(new string('=', 78));
        Console.WriteLine();

        promptCache.Save();
        if (promptCache.Hits > 0)
            Console.WriteLine("(" + promptCache.Hits + " endpoint call(s) answered from cache; " +
                              promptCache.Misses + " asked.)");

        var portfolio = PortfolioComposer.Compose(jdAnalyses);
        Console.WriteLine(PortfolioComposer.Describe(portfolio));
        Console.WriteLine();
        if (skipped > 0)
            Console.WriteLine(skipped + " duty(ies) skipped as not access-related.");

        Console.WriteLine();
        Console.WriteLine("This is a PORTFOLIO, not one role. A single role covering every");
        Console.WriteLine("duty above is approximately Global Administrator, which is the");
        Console.WriteLine("outcome this tool exists to prevent. Grant the parts you accept:");
        Console.WriteLine("  accesscheck approve <principalId> \"<duty text>\" [duration]");

        // A BLOCKING CONCERN EXITS NON-ZERO. Anything scripting this needs to be able to
        // tell "analysed cleanly" from "analysed, and the combination is an escalation
        // path" without parsing the console output.
        return portfolio.HasBlockingConcern ? 2 : 0;
    }

    case "housekeeping":
    {
        // UNATTENDED IS THE POINT OF THIS COMMAND, not a variant of it.
        //
        // Only Entra directory grants expire on their own, through PIM. Intune, Windows
        // 365, Defender, Exchange, Purview and plain group membership all carry
        // APP-TRACKED expiry: a timestamp in history.jsonl that means nothing until this
        // runs. Left to a human remembering to open the app and tick boxes, "14-day
        // access" is 14-day access in the audit record and permanent access in the tenant.
        var unattended = args.Contains("--unattended", StringComparer.OrdinalIgnoreCase);
        var gcRoles = args.Contains("--gc-roles", StringComparer.OrdinalIgnoreCase);
        // Exchange and Purview revocation shells out to PowerShell, which may need an
        // interactive sign-in this process cannot answer. --skip-powershell lets the Graph
        // half still run on a schedule rather than the whole pass being unusable.
        var skipPs = args.Contains("--skip-powershell", StringComparer.OrdinalIgnoreCase);
        var failures = 0;
        var removed = 0;

        void Log(string message) => Console.WriteLine(
            unattended ? DateTimeOffset.UtcNow.ToString("u") + "  " + message : message);

        var cfg = AppConfig.Load(configPath);
        var cloud = CloudEnvironment.Parse(cfg.Cloud);
        var auth = new GraphAuth(cfg.ClientId, cfg.TenantId, cloud,
            cloud.Scopes(cfg.GraphPermissions, cfg.EnableOutreach));
        using var graph = new GraphClient(auth, cloud);
        var executor = new RoleExecutor(graph);
        var store = new RequestHistoryStore(historyPath);

        // A SCHEDULED TASK MUST NEVER WAIT FOR A SIGN-IN WINDOW. GetTokenAsync falls back
        // to AcquireTokenInteractive when the cache cannot serve the request, which on a
        // headless run opens a browser nobody is watching and blocks forever — the task
        // shows "running" indefinitely and no access is ever revoked. Bound the attempt
        // so a stale cache fails loudly in seconds instead.
        if (unattended)
        {
            using var signIn = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            try
            {
                await auth.GetTokenAsync(signIn.Token);
            }
            catch (OperationCanceledException)
            {
                Log("FAILED: no usable cached sign-in — an interactive prompt was required "
                    + "and cannot be answered here. Open AccessCheck and sign in once as "
                    + "the account this task runs as, then re-run.");
                return 1;
            }
            catch (Exception ex)
            {
                Log("FAILED: sign-in error — " + ex.Message);
                return 1;
            }
        }

        // 1. Remove expired app-tracked direct grants (Intune/CloudPC/Defender)
        foreach (var rec in store.LoadLatest())
        {
            if (rec.MultiAssignmentId is null || rec.RemovedByHousekeeping) continue;
            if (rec.TrackedExpiryUtc is null || rec.TrackedExpiryUtc > DateTimeOffset.UtcNow) continue;
            Log("Expired: " + rec.ChosenRoleDisplay + " for " + rec.PrincipalId +
                " (" + rec.Provider + ") — removing...");
            try
            {
                await executor.RemoveMultiAssignmentAsync(rec.Provider!, rec.MultiAssignmentId);
                store.Append(rec with { RemovedByHousekeeping = true, Notes = "Removed at expiry." });
                removed++;
                Log("Removed.");
            }
            catch (Exception ex)
            {
                failures++;
                Log("FAILED: " + ex.Message);
            }
        }

        // 1b. Expired DIRECT GROUP MEMBERSHIPS. These never expire server-side — there is
        // no PIM behind them at all — so if this pass skips them the access simply stays.
        // The GUI already lists them; the scheduled path was removing role assignments only.
        foreach (var rec in store.LoadLatest())
        {
            if (rec.RemovedByHousekeeping) continue;
            if (!string.Equals(rec.AssignmentTypeUsed, "DirectGroupMember",
                    StringComparison.OrdinalIgnoreCase)) continue;
            if (rec.GroupIdUsed is null || rec.PrincipalId is null) continue;
            if (rec.TrackedExpiryUtc is null || rec.TrackedExpiryUtc > DateTimeOffset.UtcNow) continue;

            Log("Expired membership: " + rec.PrincipalId + " in group " + rec.GroupIdUsed +
                " — removing...");
            try
            {
                await executor.RemoveGroupMemberAsync(rec.GroupIdUsed, rec.PrincipalId);
                store.Append(rec with
                { RemovedByHousekeeping = true, Notes = "Membership removed at expiry." });
                removed++;
                Log("Removed.");
            }
            catch (Exception ex)
            {
                failures++;
                Log("FAILED: " + ex.Message);
            }
        }

        // 1c. Expired Exchange / Purview role-group memberships (PsRoleGroup).
        //
        // THE PATH THAT WAS NEVER REVOKED BY ANYTHING. Exchange and Purview have no PIM,
        // so their expiry is entirely app-tracked; the GUI Housekeeping tab could remove
        // these but the CLI walked straight past them. Every scheduled run therefore
        // reported success while leaving Exchange grants in place indefinitely — and the
        // history record kept asserting an expiry that nothing enforced.
        if (skipPs)
        {
            Log("Skipping Exchange/Purview revocation (--skip-powershell).");
        }
        else
        {
            var psExpired = store.LoadLatest()
                .Where(r => !r.RemovedByHousekeeping
                            && string.Equals(r.AssignmentTypeUsed, "PsRoleGroup",
                                   StringComparison.OrdinalIgnoreCase)
                            && !string.IsNullOrWhiteSpace(r.GroupIdUsed)
                            && !string.IsNullOrWhiteSpace(r.PrincipalId)
                            && r.TrackedExpiryUtc is not null
                            && r.TrackedExpiryUtc <= DateTimeOffset.UtcNow)
                .ToList();

            if (psExpired.Count == 0)
            {
                Log("No expired Exchange/Purview memberships.");
            }
            else
            {
                // BUILD THE SESSION ONCE. Each ExoPurviewExecutor.RunAsync starts a
                // PowerShell process and connects, which costs 20-40 seconds and, on an
                // interactive endpoint, can raise a sign-in prompt. Doing that per record
                // turned a three-grant cleanup into three sign-ins.
                var psEnv = PsEnvironment.For(cfg.Cloud,
                    string.IsNullOrWhiteSpace(cfg.Ps.SccConnectionUriOverride)
                        ? null : cfg.Ps.SccConnectionUriOverride);
                var psRunner = new PowerShellRunner
                {
                    ScriptLogger = script => File.AppendAllText(psScriptLogPath,
                        "==== " + DateTimeOffset.UtcNow.ToString("o") + " [housekeeping] ====" +
                        Environment.NewLine + script + Environment.NewLine)
                };
                var adminUpn = string.IsNullOrWhiteSpace(cfg.Ps.UserPrincipalName)
                    ? null : cfg.Ps.UserPrincipalName;
                var psExec = new ExoPurviewExecutor(psRunner, psEnv, adminUpn);

                Log(psExpired.Count + " expired Exchange/Purview membership(s) to revoke.");

                // ONE SESSION PER SCOPE, not one per membership. Each RunAsync costs a
                // process start plus an Exchange connect — about thirty seconds — so three
                // removals took ninety and fifty would have exceeded the scheduled task's
                // hour.
                foreach (var group in psExpired.GroupBy(r =>
                    string.Equals(r.Provider, RbacProviders.Exchange,
                        StringComparison.OrdinalIgnoreCase)
                        ? RbacScope.Exchange : RbacScope.Purview))
                {
                    var batch = group.ToList();
                    foreach (var rec in batch)
                        Log("Expiring: " + rec.PrincipalId + " in " + rec.GroupIdUsed);

                    try
                    {
                        var script = psExec.BuildRemoveMembersScript(group.Key,
                            batch.Select(r => (r.GroupIdUsed!, r.PrincipalId!)).ToList());
                        using var doc = await psExec.RunAsync(script, ct: default);

                        // Map results back by group+member. Position would be simpler and
                        // wrong the moment the script skips or reorders anything.
                        var states = new Dictionary<string, (string State, string Error)>(
                            StringComparer.OrdinalIgnoreCase);
                        if (doc.RootElement.TryGetProperty("results", out var arr)
                            && arr.ValueKind == System.Text.Json.JsonValueKind.Array)
                        {
                            foreach (var el in arr.EnumerateArray())
                            {
                                var gname = el.TryGetProperty("group", out var gg) ? gg.GetString() ?? "" : "";
                                var mname = el.TryGetProperty("member", out var mm) ? mm.GetString() ?? "" : "";
                                var st = el.TryGetProperty("state", out var ss) ? ss.GetString() ?? "" : "";
                                var er = el.TryGetProperty("error", out var ee) ? ee.GetString() ?? "" : "";
                                states[gname + "\u0000" + mname] = (st, er);
                            }
                        }

                        foreach (var rec in batch)
                        {
                            var key = rec.GroupIdUsed + "\u0000" + rec.PrincipalId;
                            var (state, error) = states.TryGetValue(key, out var v)
                                ? v : ("failed", "no result returned for this membership");

                            switch (state)
                            {
                                case "removed":
                                    store.Append(rec with
                                    {
                                        RemovedByHousekeeping = true,
                                        Notes = "Role-group membership removed at expiry."
                                    });
                                    removed++;
                                    Log("Removed: " + rec.PrincipalId + " from " + rec.GroupIdUsed);
                                    break;

                                // ALREADY GONE IS SUCCESS, NOT FAILURE. The role group was
                                // deleted by hand, so the access this record tracks no longer
                                // exists — which is exactly what housekeeping set out to
                                // achieve. Left as a failure the record never closed, every
                                // later run retried it, and the exit code stayed non-zero
                                // permanently, which is how a real failure gets ignored.
                                case "alreadyGone":
                                    store.Append(rec with
                                    {
                                        RemovedByHousekeeping = true,
                                        Notes = "Role group no longer exists - access already "
                                              + "revoked. Closed by housekeeping."
                                    });
                                    removed++;
                                    Log("Already gone (group deleted): " + rec.GroupIdUsed);
                                    break;

                                default:
                                    failures++;
                                    // Record deliberately NOT closed, so the next run retries.
                                    Log("FAILED: " + rec.GroupIdUsed + " - " + error);
                                    break;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        // The whole batch failed — connection, auth, module. None of these
                        // records are closed.
                        failures += batch.Count;
                        Log("FAILED (" + group.Key + " batch of " + batch.Count + "): " + ex.Message);
                    }
                }
            }
        }

        // 2. GC AccessCheck-created roles with no remaining assignments.
        //
        // OPT-IN WHEN UNATTENDED. Removing an expired grant restores least privilege and
        // is the whole reason to run on a schedule. Deleting a role DEFINITION is a
        // different act: it is destructive, it is not what the expiry promised, and a
        // wrong one is not undone by re-running. So the scheduled default revokes access
        // and leaves role hygiene to a human unless --gc-roles says otherwise.
        if (unattended && !gcRoles)
        {
            Log("Skipping orphaned-role GC (pass --gc-roles to include it).");
            Log("Summary: " + removed + " grant(s) removed, " + failures + " failure(s).");
            return failures > 0 ? 1 : 0;
        }

        Log("Re-syncing catalog for role GC...");
        try
        {
            var (catalog, _) = await new CatalogSync(graph).SyncAllAsync(Log);
            catalog.Save(catalogPath);
            foreach (var role in catalog.Roles.Where(r => r.IsAccessCheckCreated))
            {
                var empty = await executor.RoleHasNoAssignmentsAsync(role.Provider, role.Id);
                if (!empty) { Log("KEEP  " + role.DisplayName + " (still assigned)"); continue; }

                if (!unattended)
                {
                    Console.Write("DELETE unassigned role '" + role.DisplayName +
                                  "' (" + role.Provider + ")? [y/N] ");
                    if (!string.Equals(Console.ReadLine()?.Trim(), "y",
                            StringComparison.OrdinalIgnoreCase))
                        continue;
                }

                try
                {
                    await executor.DeleteRoleAsync(role.Provider, role.Id);
                    Log("Deleted " + role.DisplayName + " (" + role.Id + ")");
                }
                catch (Exception ex)
                {
                    failures++;
                    Log("FAILED to delete " + role.DisplayName + ": " + ex.Message);
                }
            }
        }
        catch (Exception ex)
        {
            failures++;
            Log("FAILED during role GC: " + ex.Message);
        }

        Log("Summary: " + removed + " grant(s) removed, " + failures + " failure(s).");
        return failures > 0 ? 1 : 0;
    }

    default:
        Console.WriteLine("Unknown command: " + command);
        return 1;
}

async Task<(AiSuggestion, string?)> SuggestViaGenAi(AppConfig cfg, string function, RoleCatalog catalog)
{
    string? key = SecretStore.Load(cfg.Ai.ApiKeyName);
    if (string.IsNullOrEmpty(key))
        throw new InvalidOperationException(
            "No GenAI key stored. Run: accesscheck set-key   (config: " + configPath + ")");

    var aiCfg = new AiProviderConfig
    {
        ProviderKind = cfg.Ai.Provider,
        ApiVersion = cfg.Ai.ApiVersion,
        BaseUrl = cfg.Ai.BaseUrl,
        Model = cfg.Ai.Model,
        AuthHeaderName = cfg.Ai.AuthHeaderName,
        AuthValuePrefix = cfg.Ai.AuthValuePrefix,
        ApiKeyName = cfg.Ai.ApiKeyName,
        ShortlistSize = cfg.Ai.ShortlistSize
    };
    using var provider = AiProviderFactory.Create(aiCfg, key);
    provider.PromptLogger = (stage, prompt) =>
        File.AppendAllText(promptLogPath,
            "==== " + DateTimeOffset.UtcNow.ToString("o") + " [" + stage + "] ====\n" + prompt + "\n");
    var suggestion = await provider.SuggestAsync(function, catalog);
    return (suggestion, provider.LastPromptSha256);
}

void PrintOutcomes(string function, AiSuggestion suggestion, IReadOnlyList<ProviderOutcome> outcomes)
{
    Console.WriteLine("\nFUNCTION: " + function);
    Console.WriteLine("AI reasoning: " + suggestion.Reasoning);
    foreach (var po in outcomes)
    {
        var outcome = po.Outcome;
        Console.WriteLine("\n=== " + RbacProviders.DisplayName(po.Provider) + " ===");
        Console.WriteLine("Validated actions (" + outcome.ValidActions.Count + "):");
        foreach (var a in outcome.ValidActions) Console.WriteLine("  + " + a);
        if (outcome.UnknownActionsRejected.Count > 0)
        {
            Console.WriteLine("REJECTED unknown actions:");
            foreach (var a in outcome.UnknownActionsRejected) Console.WriteLine("  x " + a);
        }

        // AN ACTION DROPPED WITHOUT A REASON IS THE WORST OUTPUT THIS TOOL CAN PRODUCE.
        //
        // The validator discards an action in three places besides "unknown": a task
        // coverage contradiction, a citation that misquotes Microsoft, and an action the
        // model never justified. Every one of those was invisible here — the desktop app
        // renders them as cards, the CLI printed nothing, and the audit record stores
        // nothing either.
        //
        // The cost was four rounds of investigation on one duty. The model chose
        // microsoft.directory/users/disable, Stage D verified it, and the verdict read
        // "Validated actions (0)" with an empty rejection list. The reason existed in the
        // outcome object the whole time and reached nobody.
        // Outcome.Contradicted already filters to the exclusions, and .Reason is the field
        // the desktop app renders — worth reusing rather than re-deriving both.
        if (outcome.Contradicted.Count > 0)
        {
            Console.WriteLine("EXCLUDED — cannot do what was asked:");
            foreach (var c in outcome.Contradicted)
                Console.WriteLine("  x " + c.Action + " — " + c.Reason);
        }

        if (outcome.FabricatedCitations.Count > 0)
        {
            Console.WriteLine("EXCLUDED — the quoted description is not Microsoft's:");
            foreach (var c in outcome.FabricatedCitations)
                Console.WriteLine("  x " + c.Action);
        }

        if (outcome.UncitedActions.Count > 0)
        {
            Console.WriteLine("EXCLUDED — proposed with no supporting description:");
            foreach (var a in outcome.UncitedActions) Console.WriteLine("  x " + a);
        }

        // ================= WHAT THE VALIDATOR KNEW AND NOBODY SAW =================
        //
        // An audit of the outcome object found NINE computed fields that reached this
        // command not at all, and five that reached neither interface — the desktop app has
        // never rendered them either. Every one is a qualification on a verdict that was
        // presented without it.
        //
        // This is the same fault that made the last three days expensive: the application
        // knows something, reports nothing, and the operator reads a cleaner answer than
        // the one that was actually computed.

        // A PERMISSION MICROSOFT DOCUMENTS THAT NO ROLE HERE GRANTS. Not an error — it is
        // precisely the case a custom role exists to solve — but the operator is approving
        // something their tenant has never granted before.
        if (outcome.ReferenceOnlyActions.Count > 0)
        {
            Console.WriteLine("DOCUMENTED BUT NOT GRANTED BY ANY ROLE IN THIS TENANT:");
            foreach (var a in outcome.ReferenceOnlyActions) Console.WriteLine("  ? " + a);
        }

        // MICROSOFT REFUSES THESE IN CUSTOM ROLES, so a built-in is the only route and the
        // excess it carries is unavoidable rather than a ranking failure.
        if (outcome.CustomRoleBlockedActions.Count > 0)
        {
            Console.WriteLine("NOT ELIGIBLE FOR A CUSTOM ROLE (Microsoft refuses them):");
            foreach (var a in outcome.CustomRoleBlockedActions) Console.WriteLine("  ! " + a);
        }

        // RECORDED FROM AN EARLIER REFUSAL in this tenant. Worth separating from the above:
        // one is documented, the other is remembered, and a remembered refusal can be wrong.
        if (outcome.CustomRoleRefusedActions.Count > 0)
        {
            Console.WriteLine("PREVIOUSLY REFUSED BY THIS TENANT in a custom role:");
            foreach (var a in outcome.CustomRoleRefusedActions) Console.WriteLine("  ! " + a);
        }

        // THE THREE-STATE MACHINE'S MIDDLE STATE, INVISIBLE UNTIL NOW. "Not on the refused
        // list" is not proof of eligibility — that distinction is why the state exists — and
        // an operator approving a custom role could not tell a proven action from an
        // unverified one.
        if (outcome.EligibilityUnproven.Count > 0)
        {
            Console.WriteLine("UNPROVEN for a custom role — this tenant has never created one "
                            + "with these, so Microsoft may still refuse:");
            foreach (var a in outcome.EligibilityUnproven) Console.WriteLine("  ? " + a);
        }

        if (outcome.CustomRoleRuledOutByDocumentation)
            Console.WriteLine("NOTE: Microsoft's documentation rules out a custom role here.");

        // THE DOCUMENTED ANSWER DISAGREES WITH THE RANKED ONE. Either is defensible; being
        // told only one of them is not.
        if (outcome.DocumentedRoleMismatch && !string.IsNullOrWhiteSpace(outcome.DocumentedRoleName))
            Console.WriteLine("NOTE: Microsoft documents '" + outcome.DocumentedRoleName +
                              "' for this task, and it does not cover what was proposed.");

        if (outcome.DocumentedRolePromoted && !string.IsNullOrWhiteSpace(outcome.DocumentedRoleName))
            Console.WriteLine("NOTE: '" + outcome.DocumentedRoleName +
                              "' was preferred because Microsoft documents it for this task.");
        if (outcome.CustomRoleRecommended && outcome.CustomRole is not null)
        {
            Console.WriteLine("VERDICT: CUSTOM ROLE -> '" + outcome.CustomRole.DisplayName +
                              "' with exactly " + outcome.CustomRole.AllowedResourceActions.Count +
                              " action(s).");
            if (outcome.BestFit is not null)
                Console.WriteLine("(best built-in was '" + outcome.BestFit.DisplayName +
                                  "' with +" + outcome.BestFit.ExcessCount + " excess)");
        }
        else if (outcome.BestFit is not null)
        {
            Console.WriteLine("VERDICT: role '" + outcome.BestFit.DisplayName +
                              "' — delta = " + outcome.BestFit.ExcessCount + " action(s):");
            foreach (var a in outcome.BestFit.ExcessActions) Console.WriteLine("  ~ " + a);
        }
        else
        {
            Console.WriteLine("VERDICT: no covering role" +
                (outcome.ValidActions.Count > 0 ? " and custom roles unsupported for this provider." : "."));
        }
    }
}

static TimeSpan ParseIsoDuration(string iso)
{
    try { return System.Xml.XmlConvert.ToTimeSpan(iso); }
    catch { return TimeSpan.FromDays(14); }
}

/// <summary>
/// Loads the catalog AND applies the Purview role map, which the CLI never did.
///
/// Purview roles arrive from the Security and Compliance session as NAMES ONLY. That
/// session does not expose Get-ManagementRoleEntry — it is an Exchange cmdlet — so the
/// entry fetch is skipped and 120 roles are stored carrying zero cmdlets between them.
/// PurviewRoleMap fills that vocabulary back in, and the desktop app has always called it.
///
/// The CLI did not. Every command here therefore ran against an EMPTY Purview dictionary
/// while reporting a healthy catalog, so a search-and-purge request could not be answered
/// from Purview at any point: the model was shown Exchange, picked the nearest thing
/// containing "mailbox", and proposed Remove-Mailbox for a request about deleting
/// messages. RoleGroupPlan.Build — written specifically to compose Compliance Search with
/// Search And Purge — has never once had those cmdlets to compose.
/// </summary>
RoleCatalog LoadCatalog(string? path = null)
{
    var chosen = path ?? (File.Exists(catalogPath) ? catalogPath : FindSample());
    var loaded = RoleCatalog.Load(chosen);

    var enriched = PurviewRoleMap.EnrichNameOnlyRoles(loaded);
    if (enriched > 0)
        Console.WriteLine("(Purview: filled in cmdlets for " + enriched +
                          " name-only role(s) from the built-in map.)");

    // THEN THE DOCUMENTED ROLE VOCABULARY, for everything the built-in map does not reach.
    // The map covers a handful of roles by hand; Microsoft publishes all of them. Roles
    // still carrying nothing after both passes are invisible to every later stage, and a
    // provider that is invisible produces answers from a different service — which is how
    // a request to purge phishing mail came back with Remove-Mailbox.
    var docs = PurviewRoleCatalog.LoadOrImport(purviewRolesPath, purviewRolesMarkdownPath);
    if (!docs.IsEmpty)
    {
        var filled = docs.EnrichCatalog(loaded);
        if (filled > 0)
        {
            Console.WriteLine("(Purview: " + filled + " role(s) described from Microsoft's " +
                              "published role list.)");

            // PERSIST WHAT THE APPLICATION ACTUALLY USES.
            //
            // Enrichment ran on every launch and was never saved, so catalog.json held 122
            // Purview roles with ZERO permissions while the process held 114 with
            // vocabulary. Every diagnostic anyone ran read the file and reported the service
            // as empty; the application meanwhile answered Purview requests correctly. Days
            // were spent on that contradiction.
            //
            // A file that disagrees with the running application is worse than a missing
            // one: it answers the question confidently and wrongly. Saving also means the
            // 114-role parse and merge happen once rather than on every process start.
            try
            {
                if (File.Exists(catalogPath)) loaded.Save(catalogPath);
            }
            catch (Exception)
            {
                // A failed save costs a re-parse next launch. Not worth interrupting anyone.
            }
        }
    }

    // SAY WHAT IS ACTUALLY MISSING. The first version of this claimed the service could
    // not work at all whenever any role lacked vocabulary — printed on a run where Purview
    // then answered three duties perfectly from the eight roles the built-in map covers.
    // A warning that is false in the common case is one operators learn to scroll past,
    // which is worse than not warning.
    var silent = loaded.RolesFor(RbacProviders.Purview)
        .Count(r => r.AllowedResourceActions.Count == 0);
    if (silent > 0)
    {
        var total = loaded.RolesFor(RbacProviders.Purview).Count();
        Console.WriteLine("(Purview: " + (total - silent) + " of " + total +
                          " role(s) have vocabulary. The other " + silent +
                          " cannot be recommended — run dist\\import-purview-roles.ps1 to " +
                          "describe them from Microsoft's published list.)");
    }

    // THE CHECK NO INDIVIDUAL SYNC STEP IS IN A POSITION TO MAKE. Each step knows whether
    // it succeeded; none of them knows whether the result looks like usable data. Every
    // expensive bug in this application has been a step succeeding and producing something
    // nothing downstream could use.
    var health = CatalogHealth.Check(loaded);
    if (health.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine(CatalogHealth.Describe(health));
        Console.WriteLine();
    }

    return loaded;
}

string FindSample()
{
    string[] candidates =
    {
        Path.Combine(AppContext.BaseDirectory, "sample-catalog.json"),
        "samples/sample-catalog.json",
        "../../samples/sample-catalog.json",
        "../../../samples/sample-catalog.json",
        "../../../../samples/sample-catalog.json"
    };
    foreach (var c in candidates)
        if (File.Exists(c)) return c;
    throw new FileNotFoundException("sample-catalog.json not found; run from the repo root or sync first.");
}
