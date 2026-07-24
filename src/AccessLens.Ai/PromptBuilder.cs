using System.Security.Cryptography;
using System.Text;
using AccessLens.Core.Catalog;

namespace AccessLens.Ai;

/// <summary>
/// Builds the two outbound prompts. By construction these methods accept ONLY the
/// function description and role catalog data — no identity, tenant, or history
/// parameters exist in any signature, so nothing else can leave the machine.
/// </summary>
public static class PromptBuilder
{
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
