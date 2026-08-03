using System.Security.Cryptography;
using System.Text;
using AccessCheck.Core.Catalog;
using AccessCheck.Core.Recommendation;

namespace AccessCheck.Ai;

/// <summary>
/// Builds the two outbound prompts. By construction these methods accept ONLY the
/// function description and role catalog data — no identity, tenant, or history
/// parameters exist in any signature, so nothing else can leave the machine.
/// </summary>
public static class PromptBuilder
{
    /// <summary>
    /// Stage A. Product FEATURE names — "GPO analytics", "Conditional Access",
    /// "eDiscovery" — appear in no permission string, so keyword matching finds nothing
    /// and the model is left guessing from role names. Asking which SERVICE owns the
    /// feature first is cheap and turns a feature name into a searchable scope.
    /// </summary>
    public const string ServiceSystem = """
        You map a described administrative task to the Microsoft 365 service that owns it.

        You will receive a task and a list of available services. Reply with the services
        whose administrative surface actually contains that feature.

        Be precise about product boundaries. The distinctions that matter:
        - Group Policy analytics / GPO analytics is a feature of Microsoft INTUNE
          (Devices > Group Policy analytics), not of entitlement management or directory.
        - Conditional Access is Entra ID (directory).
        - eDiscovery, retention and DLP are Purview / Compliance.
        - Mailbox and transport administration is Exchange Online.
        - Access packages and access reviews are Entitlement Management.
        - Cloud PC provisioning is Windows 365.

        If you are NOT confident which service owns the feature, return an empty list
        rather than guessing.

        Return ONLY {"services":["providerKey", ...],"confident":true|false,"note":"one
        short sentence"}. Use the providerKey values exactly as given. No prose, no fences.
        """;

    /// <summary>
    /// The primary path. The model chooses from the tenant's PERMISSION vocabulary
    /// directly, so a narrow permission is reachable even when every role containing it is
    /// named after something else.
    /// </summary>
    public const string PermissionSystem = """
        You are a Microsoft 365 least-privilege analyst. You will receive a job function
        and a list of CANDIDATE PERMISSIONS drawn from the tenant, each labelled with its
        service.

        Choose the MINIMAL set of permissions that lets someone perform that function and
        nothing more.

        LOOK IT UP. DO NOT ANSWER FROM MEMORY.

        If you have a search or browsing tool, use it before choosing, every time:
        - Search Microsoft's documentation for the TASK, not for a permission name. Tasks
          are documented at the ROLE level. There is no page naming the permission for
          "reset MFA methods"; there is a page naming the role that does it.
        - Open that role's reference page and read BOTH the prose (what it can do, and its
          explicit "cannot do" list) and the action table, which gives every action WITH
          Microsoft's own description.
        - Authoritative sources are learn.microsoft.com and MicrosoftDocs repositories on
          GitHub. A community forum answer is NOT authoritative. A quoted API error message
          IS evidence about the API and outranks a forum answer describing the portal.
          Note the date on anything you rely on, and say so if it may be stale.

        If you have NO search tool, you may rely ONLY on the descriptions supplied in the
        candidate list below. You may not supply a meaning from memory for a permission
        whose description is missing.

        A PERMISSION'S MEANING COMES ONLY FROM ITS OWN DESCRIPTION.
        - Never infer what a permission does from the name or description of a ROLE that
          contains it. A role holds many unrelated actions; its description explains the
          role's purpose, not each permission inside it.
        - A candidate shown as "[no Microsoft description; granted by X]" has an UNKNOWN
          meaning. Do not guess it from the role name.
        - Names that differ by one segment mean entirely different things:
              microsoft.directory/users/basic/update
                "Update basic properties on users"
              microsoft.directory/users/authenticationMethods/basic/update
                "Update basic properties of authentication methods for users"
          Only the second touches authentication methods. Nothing in the first name says
          otherwise, which is exactly why the description decides and the name does not.
        - Never choose a READ permission for a task that requires create, update, delete,
          reset, revoke, wipe, approve or execute. A read permission cannot perform those
          operations, however closely its name matches the request.

        DO NOT MAP THE REQUEST'S VERB ONTO AN ACTION'S VERB. What an operation means
        depends on the object it acts on. Determine the operation from the documented
        descriptions and the role's prose, not from the word used in the request. If the
        documentation describes the task as removing and re-registering something, the
        actions are delete and create even though the request said "reset".

        RETURN THE FULL SET the task needs, not a single action. Most tasks need several.
        Include a read action only where the documented role carries it alongside the
        writes for this same task; do not add reads for convenience.

        HOW PERMISSIONS ARE NAMED. Permissions are named after the RESOURCE they act on,
        never after the feature or tool that uses that resource. There is no permission
        called "GPO analytics", "Group Policy analytics", "Endpoint analytics" or
        "Autopilot" — those are product features. Work out WHICH RESOURCES the feature
        reads or changes, then pick the permissions for those resources.

        Worked example: Group Policy analytics in Intune imports GPO exports and compares
        them against configuration profiles and security baselines. Its resources are
        therefore device configurations and security baselines, so the least-privilege
        answer is the READ permissions on those two resources — not a permission with "GPO"
        in the name, and not a service-wide action.

        Rules that matter:
        - Use ONLY strings that appear verbatim in the candidate list. Never invent one.
          If documentation names a permission that is absent from the list, say so in your
          reasoning rather than substituting a similar-looking one.
        - Prefer the NARROWEST permission that does the job. A permission covering all
          entities or all tasks in a service grants that entire service and is almost never
          the least-privilege answer — choose it only if no narrower candidate covers the
          function, and say so in your reasoning.
        - Prefer read permissions when the function only requires viewing or analysing.
        - Include ONLY what the stated task requires. Do not add permissions for adjacent
          or follow-on tasks the request did not ask for. If the task is to disable an
          account, do not include enabling it; if it is to wipe a device, do not include
          provisioning one. Padding the set with "things an admin doing this might also
          want" is over-granting, and it is the failure this tool exists to prevent.
        - If the request contains an EXCLUSION or a SCOPE LIMIT — "but not administrators",
          "only for the sales team" — understand that no permission can express it. Choose
          the permissions for the ACTION only, and say in your reasoning that the limit must
          be applied through scope or a restricted built-in role instead.
        - Custom-role eligibility is a SEPARATE question. Some actions appear in built-in
          roles and cannot be placed in a custom role. If documentation says an action is
          unsupported for custom role creation, report it; do not treat silence as a yes.

        EVERY ACTION YOU RETURN MUST BE CITED. For each one, give the description you are
        relying on, verbatim, and where it came from: a documentation URL if you looked it
        up, or the exact string "candidate list" if it came from the list below. An action
        you cannot cite a description for does NOT go in the set.

        IF YOU CAN COVER PART OF THE TASK, RETURN THAT PART. A request to "unlock accounts
        and check sign-in logs" where only the sign-in log permission exists should return
        that permission and say in the reasoning that the other half was not found. Returning
        nothing because one clause could not be answered discards the half that could — the
        operator can add the rest, but only if they can see what you did find.

        Return an empty requiredActions array only if you can cover NONE of it, or cannot
        cite a description for anything that fits. Say what you searched. "No permission mentions this feature by name" is NOT a reason to return
        empty — permissions never mention features by name.

        Return ONLY this JSON. No prose outside it, no fences:
        {"requiredActions":["..."],
         "evidence":[{"action":"...","description":"verbatim description",
                      "source":"https://learn.microsoft.com/... or candidate list"}],
         "documentedRole":"least-privileged built-in role for this task, or null",
         "customRoleEligible":true,
         "recommendedRoleId":null,
         "reasoning":"one short paragraph"}
        """;

    public static string BuildServiceUser(string function, IReadOnlyCollection<string> providers)
    {
        var lines = new List<string> { "TASK: " + function.Trim(), "", "SERVICES:" };
        foreach (var provider in providers)
            lines.Add($"  providerKey={provider}  name={RbacProviders.DisplayName(provider)}");
        return string.Join("\n", lines);
    }

    /// <summary>Candidate permissions grouped by service, with collision warnings first.</summary>
    /// <summary>
    /// One line of meaning for a permission. Prefers a real description; falls back to the
    /// roles that grant it, which is itself a strong signal — a cmdlet granted only by
    /// "Mailbox Search" is Exchange mailbox search, whatever its name suggests.
    /// </summary>
    private static string Describe(PermissionEntry entry)
    {
        var text = entry.Description.Trim();
        if (text.Length == 0) return "";

        // LABEL THE SOURCE. A role-derived description describes the ROLE, not this
        // permission — a built-in role holds dozens of unrelated actions. Presenting one
        // as the permission's meaning is how an unrelated action gets chosen because the
        // role it lives in sounded right.
        if (!entry.DescriptionSource.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase))
        {
            var viaRoles = entry.GrantedByRoles.Count > 0
                ? "granted by " + string.Join(", ", entry.GrantedByRoles.Take(2))
                : "no description available";
            return "[no Microsoft description; " + viaRoles + "]";
        }

        // ONE LINE — a long role summary swamps a list of two hundred candidates.
        var firstSentence = text.Split(new[] { ". " }, StringSplitOptions.None)[0].Trim();
        if (firstSentence.Length > 160) firstSentence = firstSentence[..160].TrimEnd() + "...";

        // THE NOTE IS ADDED HERE AND NOWHERE ELSE.
        //
        // Where two permissions are routinely confused, Microsoft's own sentence is accurate
        // and not enough to tell them apart: "Disable users" beside "Update basic properties
        // on users" reads as though the second is broader and covers the first, and a duty
        // to disable accounts was answered with the property update run after run.
        //
        // Written into the description it fixed that and broke CitationCheck, which compares
        // the description the model quoted against the one this application holds — so a
        // model quoting an annotated description faithfully was judged to have invented it.
        // Adding it at render time keeps Microsoft's description exactly Microsoft's for
        // every other consumer, known and future.
        var note = ActionNoteStore.NoteFor(entry.Action);
        if (note.Length > 0) firstSentence += "  AccessCheck note: " + note;

        var roles = entry.GrantedByRoles.Count > 0
            ? "  [granted by " + string.Join(", ", entry.GrantedByRoles.Take(2)) + "]"
            : "  [no role in this tenant grants it — a custom role would be the only route]";
        return firstSentence + roles;
    }

    public static string BuildPermissionUser(
        string function, IReadOnlyCollection<PermissionEntry> candidates)
    {
        var lines = new List<string> { "FUNCTION: " + function.Trim() };

        // Warn about known resource-name collisions BEFORE the list, so the model reads
        // the distinction while choosing rather than being corrected after.
        var hints = ResourceAmbiguity.PromptHints(function)
            .Concat(CmdletServiceMap.PromptHints(function))
            .ToList();

        // When the request touches Purview, name what each role actually gates — the
        // tenant cannot supply that mapping, so the model would otherwise be choosing
        // between role names with no idea what they permit.
        if (candidates.Any(c => c.Provider == RbacProviders.Purview))
            hints.AddRange(PurviewRoleMap.PromptHints());
        if (hints.Count > 0)
        {
            lines.Add("");
            lines.Add("SERVICE AND RESOURCE DISAMBIGUATION - read before choosing:");
            lines.AddRange(hints);
        }

        lines.Add("");
        lines.Add("CANDIDATE PERMISSIONS:");
        foreach (var group in candidates.GroupBy(c => c.Provider).OrderBy(g => g.Key))
        {
            lines.Add("");
            lines.Add($"[{RbacProviders.DisplayName(group.Key)}]");
            foreach (var entry in group.OrderBy(e => e.Action, StringComparer.OrdinalIgnoreCase))
            {
                // NAMES ARE NOT MEANINGS. Sending bare strings made the model pattern-match:
                // "ExecuteSearch" reads like a compliance search and is actually Exchange
                // mailbox search, so a purge request came back with search-only permissions.
                // Whatever meaning we have — Microsoft's description, or the granting role's
                // — is the difference between choosing and guessing.
                var meaning = Describe(entry);
                lines.Add(meaning.Length > 0
                    ? "  " + entry.Action + "  —  " + meaning
                    : "  " + entry.Action + "  (granted by " +
                      string.Join(", ", entry.GrantedByRoles.Take(2)) + ")");
            }
        }
        return string.Join("\n", lines);
    }

    public const string ShortlistSystem =
        "You are a Microsoft Entra role analyst. You will receive a description of a job " +
        "function and a list of role definitions (id, name, description). Return ONLY a JSON " +
        "object of the form {\"shortlist\":[\"roleId\", ...]} listing up to N role ids most " +
        "likely relevant to the function, most relevant first. No prose, no markdown fences.";

    public const string SuggestSystem =
        "You are a Microsoft Entra least-privilege analyst. You will receive a job function " +
        "description and a set of candidate roles WITH their full allowedResourceActions lists. " +
        "Determine the MINIMAL set of resource actions the function requires. You may ONLY use " +
        "action strings that appear verbatim in the provided lists — never invent actions. Then " +
        "state which single provided role, if any, covers those actions with the least excess. " +
        "Return ONLY a JSON object: {\"requiredActions\":[\"...\"],\"recommendedRoleId\":\"id or null\"," +
        "\"reasoning\":\"one short paragraph\"}. No prose outside the JSON, no markdown fences.";

    public static string BuildShortlistUser(
        string functionDescription,
        IEnumerable<RoleDefinitionRecord> roles,
        int shortlistSize)
    {
        var sb = new StringBuilder();
        sb.AppendLine("N = " + shortlistSize);
        sb.AppendLine("FUNCTION: " + functionDescription.Trim());
        sb.AppendLine("ROLES:");
        foreach (var r in roles)
        {
            sb.Append("- id=").Append(r.Id)
              .Append(" | name=").Append(r.DisplayName)
              .Append(" | desc=").AppendLine(Truncate(r.Description, 160));
        }
        return sb.ToString();
    }

    public static string BuildSuggestUser(
        string functionDescription,
        IEnumerable<RoleDefinitionRecord> shortlistedRoles)
    {
        var sb = new StringBuilder();
        sb.AppendLine("FUNCTION: " + functionDescription.Trim());
        sb.AppendLine("CANDIDATE ROLES:");
        foreach (var r in shortlistedRoles)
        {
            sb.Append("ROLE id=").Append(r.Id)
              .Append(" name=").AppendLine(r.DisplayName);
            foreach (var a in r.AllowedResourceActions)
                sb.Append("  ").AppendLine(a);
        }
        return sb.ToString();
    }

    public static string Sha256Hex(string text)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string Truncate(string s, int max) =>
        string.IsNullOrEmpty(s) || s.Length <= max ? s : s[..max];
}
