using System.Text.Json;
using AccessCheck.Core.Catalog;

namespace AccessCheck.Graph;

/// <summary>
/// What the tenant's PIM role management policy permits for one role. Read BEFORE
/// submitting a schedule request: a policy that forbids permanent assignments, or caps
/// the duration, rejects the request with
/// 400 RoleAssignmentRequestPolicyValidationFailed ["ExpirationRule"] — which is
/// far more useful caught up front than after the fact.
/// </summary>
public sealed record RolePolicyLimits
{
    /// <summary>False when the policy requires an expiry (i.e. permanent is not allowed).</summary>
    public bool PermanentAllowed { get; init; } = true;
    /// <summary>ISO 8601 maximum, e.g. "P180D". Null when unlimited or unknown.</summary>
    public string? MaximumDuration { get; init; }
    public TimeSpan? MaximumSpan { get; init; }
    /// <summary>True when the policy could not be read (permission/endpoint) — checks are skipped.</summary>
    public bool Unknown { get; init; }
    public string? Note { get; init; }

    public static RolePolicyLimits UnknownLimits(string note) =>
        new() { Unknown = true, Note = note };

    public string Describe() => Unknown
        ? "policy unknown (" + Note + ")"
        : (PermanentAllowed ? "permanent allowed" : "expiry REQUIRED") +
          (MaximumDuration is null ? "" : ", max " + MaximumDuration);
}

/// <summary>
/// Reads PIM role management policy rules for Entra directory roles via
/// /policies/roleManagementPolicyAssignments (expand policy/rules).
/// Requires delegated RoleManagementPolicy.Read.Directory (or ReadWrite).
/// </summary>
public sealed class PolicyReader
{
    private readonly GraphClient _graph;
    public PolicyReader(GraphClient graph) => _graph = graph;

    /// <summary>
    /// Limits for a directory role. assignmentRuleId picks which rule applies:
    /// Expiration_Admin_Assignment for active grants, Expiration_Admin_Eligibility for eligible.
    /// </summary>
    public async Task<RolePolicyLimits> GetDirectoryLimitsAsync(
        string roleDefinitionId, bool eligible, string scopeId = "/",
        CancellationToken ct = default)
    {
        var wantedRule = eligible ? "Expiration_Admin_Eligibility" : "Expiration_Admin_Assignment";
        try
        {
            var filter = "scopeId eq '" + scopeId + "' and scopeType eq 'DirectoryRole' and " +
                         "roleDefinitionId eq '" + roleDefinitionId + "'";
            var url = "/v1.0/policies/roleManagementPolicyAssignments?$filter=" +
                      Uri.EscapeDataString(filter) +
                      "&$expand=" + Uri.EscapeDataString("policy($expand=rules)");

            using var doc = await _graph.GetAsync(url, ct);
            if (!doc.RootElement.TryGetProperty("value", out var value) ||
                value.GetArrayLength() == 0)
                return RolePolicyLimits.UnknownLimits("no policy assignment returned for this role");

            foreach (var assignment in value.EnumerateArray())
            {
                if (!assignment.TryGetProperty("policy", out var policy) ||
                    !policy.TryGetProperty("rules", out var rules) ||
                    rules.ValueKind != JsonValueKind.Array) continue;

                foreach (var rule in rules.EnumerateArray())
                {
                    var id = rule.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;
                    if (!string.Equals(id, wantedRule, StringComparison.OrdinalIgnoreCase)) continue;

                    bool expiryRequired =
                        rule.TryGetProperty("isExpirationRequired", out var req) &&
                        req.ValueKind == JsonValueKind.True;
                    string? max = rule.TryGetProperty("maximumDuration", out var m)
                        ? m.GetString() : null;

                    TimeSpan? span = null;
                    if (!string.IsNullOrWhiteSpace(max))
                    {
                        try { span = System.Xml.XmlConvert.ToTimeSpan(max); }
                        catch (FormatException) { /* leave null */ }
                    }

                    return new RolePolicyLimits
                    {
                        PermanentAllowed = !expiryRequired,
                        MaximumDuration = max,
                        MaximumSpan = span
                    };
                }
            }
            return RolePolicyLimits.UnknownLimits("rule '" + wantedRule + "' not present in policy");
        }
        catch (GraphApiException gex) when (gex.StatusCode is 401 or 403)
        {
            return RolePolicyLimits.UnknownLimits(
                "consent RoleManagementPolicy.Read.Directory to pre-check PIM policy limits");
        }
        catch (Exception ex)
        {
            return RolePolicyLimits.UnknownLimits(Head(ex.Message));
        }
    }

    private static string Head(string s) => s.Length <= 160 ? s : s[..160];
}
