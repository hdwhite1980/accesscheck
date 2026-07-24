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

        A PERMISSION'S MEANING COMES ONLY FROM ITS OWN DESCRIPTION.
        - Never infer what a permission does from the name or description of a ROLE that
          contains it. A role holds many unrelated actions; its description explains the
          role's purpose, not each permission inside it.
        - A candidate shown as "[no Microsoft description; granted by X]" has an UNKNOWN
          meaning. Do not guess it from the role name. Prefer a permission whose own
          description states what it does.
        - Never choose a READ permission for a task that requires create, update, delete,
          reset, revoke, wipe, approve or execute. A read permission cannot perform those
          operations, however closely its name matches the request.

        HOW PERMISSIONS ARE NAMED. This is the part that trips people up. Permissions are
        named after the RESOURCE they act on, never after the feature or tool that uses
        that resource. There is no permission called "GPO analytics", "Group Policy
        analytics", "Endpoint analytics" or "Autopilot" — those are product features. So do
        not look for the feature's name in the list. Instead work out WHICH RESOURCES the
        feature reads or changes, then pick the permissions for those resources.

        Worked example: Group Policy analytics in Intune imports GPO exports and compares
        them against configuration profiles and security baselines. Its resources are
        therefore device configurations and security baselines, so the least-privilege
        answer is the READ permissions on those two resources — not a permission with "GPO"
        in the name, and not a service-wide action.

        Rules that matter:
        - Use ONLY strings that appear verbatim in the candidate list. Never invent one.
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

        Return an empty requiredActions array ONLY if you genuinely cannot work out which
        resources the feature touches. "No permission mentions this feature by name" is NOT
        a reason to return empty — permissions never mention features by name.

        Return ONLY {"requiredActions":["..."],"recommendedRoleId":null,"reasoning":"one
        short paragraph"}. No prose outside the JSON, no fences.
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

        // One line, so a long role summary does not swamp the candidate list.
        var firstSentence = text.Split(new[] { ". " }, StringSplitOptions.None)[0].Trim();
        if (firstSentence.Length > 160) firstSentence = firstSentence[..160].TrimEnd() + "...";

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
