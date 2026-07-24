using AccessCheck.Ai;
using AccessCheck.Cli;
using AccessCheck.Core.Audit;
using AccessCheck.Core.Catalog;
using AccessCheck.Core.Config;
using AccessCheck.Core.Execution;
using AccessCheck.Core.Recommendation;
using AccessCheck.Graph;

var dataDir = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AccessCheck");
Directory.CreateDirectory(dataDir);
var catalogPath = Path.Combine(dataDir, "catalog.json");
var historyPath = Path.Combine(dataDir, "history.jsonl");
var promptLogPath = Path.Combine(dataDir, "prompt-log.txt");
var configPath = new[]
{
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
          accesscheck housekeeping                      GC roles + remove expired direct grants
        """);
    return 0;
}

var command = args[0].ToLowerInvariant();

switch (command)
{
    case "demo":
    {
        var function = args.Length > 1 ? args[1] : "reset user passwords for help desk tickets";
        var catalog = RoleCatalog.Load(FindSample());
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
        var catalog = RoleCatalog.Load(File.Exists(catalogPath) ? catalogPath : FindSample());

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
        var catalog = RoleCatalog.Load(File.Exists(catalogPath) ? catalogPath : FindSample());

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

    case "housekeeping":
    {
        var cfg = AppConfig.Load(configPath);
        var cloud = CloudEnvironment.Parse(cfg.Cloud);
        var auth = new GraphAuth(cfg.ClientId, cfg.TenantId, cloud,
            cloud.Scopes(cfg.GraphPermissions, cfg.EnableOutreach));
        using var graph = new GraphClient(auth, cloud);
        var executor = new RoleExecutor(graph);
        var store = new RequestHistoryStore(historyPath);

        // 1. Remove expired app-tracked direct grants (Intune/CloudPC/Defender)
        foreach (var rec in store.LoadLatest())
        {
            if (rec.MultiAssignmentId is null || rec.RemovedByHousekeeping) continue;
            if (rec.TrackedExpiryUtc is null || rec.TrackedExpiryUtc > DateTimeOffset.UtcNow) continue;
            Console.WriteLine("Expired: " + rec.ChosenRoleDisplay + " for " + rec.PrincipalId +
                              " (" + rec.Provider + ") — removing...");
            try
            {
                await executor.RemoveMultiAssignmentAsync(rec.Provider!, rec.MultiAssignmentId);
                store.Append(rec with { RemovedByHousekeeping = true, Notes = "Removed at expiry." });
                Console.WriteLine("Removed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("FAILED: " + ex.Message);
            }
        }

        // 2. GC AccessCheck-created roles with no remaining assignments
        Console.WriteLine("Re-syncing catalog for role GC...");
        var (catalog, _) = await new CatalogSync(graph).SyncAllAsync(Console.WriteLine);
        catalog.Save(catalogPath);
        foreach (var role in catalog.Roles.Where(r => r.IsAccessCheckCreated))
        {
            var empty = await executor.RoleHasNoAssignmentsAsync(role.Provider, role.Id);
            if (!empty) { Console.WriteLine("KEEP  " + role.DisplayName + " (still assigned)"); continue; }
            Console.Write("DELETE unassigned role '" + role.DisplayName + "' (" + role.Provider + ")? [y/N] ");
            if (string.Equals(Console.ReadLine()?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
            {
                await executor.DeleteRoleAsync(role.Provider, role.Id);
                Console.WriteLine("Deleted " + role.Id);
            }
        }
        return 0;
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
