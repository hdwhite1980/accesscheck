using System.Net.Http.Headers;
using System.Text.Json;
using AccessCheck.Core.Catalog;

namespace AccessCheck.Graph;

public sealed record AzureSubscription(string Id, string DisplayName, string State);

public sealed record AzureRoleAssignmentInfo(
    string Scope, string RoleDefinitionId, string RoleName,
    string PrincipalId, string PrincipalType);

/// <summary>
/// Azure resource RBAC lives in Azure Resource Manager, not Microsoft Graph: a different
/// host, a different token audience, and a different permission model (Actions /
/// NotActions / DataActions instead of resource actions). It is the largest privilege
/// surface most tenants have and is invisible to every Graph-based review.
/// Needs no app permission — ARM authorizes on the signed-in user's Azure role.
/// </summary>
public sealed class AzureRbacClient : IDisposable
{
    private readonly GraphAuth _auth;
    private readonly HttpClient _http = new();
    private readonly string _armBase;
    private readonly string[] _armScopes;

    public AzureRbacClient(GraphAuth auth, CloudEnvironment cloud)
    {
        _auth = auth;
        // US Gov clouds use a different ARM host.
        _armBase = cloud.Name == "Commercial"
            ? "https://management.azure.com"
            : "https://management.usgovcloudapi.net";
        _armScopes = new[] { _armBase + "/user_impersonation" };
    }

    public List<string> Warnings { get; } = new();

    private async Task<JsonDocument> GetAsync(string url, CancellationToken ct)
    {
        var token = await _auth.GetTokenForAsync(_armScopes, ct);
        using var req = new HttpRequestMessage(HttpMethod.Get,
            url.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? url : _armBase + url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var resp = await _http.SendAsync(req, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException(
                "ARM " + (int)resp.StatusCode + ": " + (text.Length > 300 ? text[..300] : text));
        return JsonDocument.Parse(string.IsNullOrWhiteSpace(text) ? "{}" : text);
    }

    public async Task<IReadOnlyList<AzureSubscription>> ListSubscriptionsAsync(
        CancellationToken ct = default)
    {
        var subs = new List<AzureSubscription>();
        using var doc = await GetAsync("/subscriptions?api-version=2020-01-01", ct);
        if (doc.RootElement.TryGetProperty("value", out var v))
        {
            foreach (var el in v.EnumerateArray())
            {
                subs.Add(new AzureSubscription(
                    el.TryGetProperty("subscriptionId", out var i) ? i.GetString() ?? "" : "",
                    el.TryGetProperty("displayName", out var d) ? d.GetString() ?? "" : "",
                    el.TryGetProperty("state", out var st) ? st.GetString() ?? "" : ""));
            }
        }
        return subs;
    }

    /// <summary>
    /// Azure role definitions for a subscription, mapped into the app's catalog shape so
    /// they rank and compare alongside every other provider. Actions are prefixed
    /// "azure:" to keep the vocabularies from colliding.
    /// </summary>
    public async Task<List<RoleDefinitionRecord>> ReadRoleDefinitionsAsync(
        string subscriptionId, CancellationToken ct = default)
    {
        var roles = new List<RoleDefinitionRecord>();
        string? url = "/subscriptions/" + subscriptionId +
                      "/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01";
        int guard = 0;
        while (url is not null && guard++ < 100)
        {
            using var doc = await GetAsync(url, ct);
            if (doc.RootElement.TryGetProperty("value", out var v))
            {
                foreach (var el in v.EnumerateArray())
                    roles.Add(MapRole(el));
            }
            url = doc.RootElement.TryGetProperty("nextLink", out var n) ? n.GetString() : null;
        }
        return roles;
    }

    private static RoleDefinitionRecord MapRole(JsonElement el)
    {
        var id = el.TryGetProperty("id", out var i) ? i.GetString() ?? "" : "";
        var name = "";
        var description = "";
        var type = "";
        var actions = new List<string>();

        if (el.TryGetProperty("properties", out var props))
        {
            name = props.TryGetProperty("roleName", out var rn) ? rn.GetString() ?? "" : "";
            description = props.TryGetProperty("description", out var d) ? d.GetString() ?? "" : "";
            type = props.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "";

            if (props.TryGetProperty("permissions", out var perms) &&
                perms.ValueKind == JsonValueKind.Array)
            {
                foreach (var perm in perms.EnumerateArray())
                {
                    void Collect(string prop, string prefix)
                    {
                        if (!perm.TryGetProperty(prop, out var arr) ||
                            arr.ValueKind != JsonValueKind.Array) return;
                        foreach (var a in arr.EnumerateArray())
                        {
                            var s = a.GetString();
                            if (!string.IsNullOrWhiteSpace(s)) actions.Add(prefix + s);
                        }
                    }
                    Collect("actions", "azure:");
                    Collect("dataActions", "azure:data:");
                    // NotActions subtract; recorded so the delta stays visible.
                    Collect("notActions", "azure:not:");
                    Collect("notDataActions", "azure:notdata:");
                }
            }
        }

        return new RoleDefinitionRecord
        {
            Id = id,
            DisplayName = name,
            Description = description,
            IsBuiltIn = string.Equals(type, "BuiltInRole", StringComparison.OrdinalIgnoreCase),
            Provider = RbacProviders.Azure,
            AllowedResourceActions = actions.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }

    public async Task<List<AzureRoleAssignmentInfo>> ReadRoleAssignmentsAsync(
        string subscriptionId, IReadOnlyDictionary<string, string>? roleNames = null,
        CancellationToken ct = default)
    {
        var result = new List<AzureRoleAssignmentInfo>();
        string? url = "/subscriptions/" + subscriptionId +
                      "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01";
        int guard = 0;
        while (url is not null && guard++ < 100)
        {
            using var doc = await GetAsync(url, ct);
            if (doc.RootElement.TryGetProperty("value", out var v))
            {
                foreach (var el in v.EnumerateArray())
                {
                    if (!el.TryGetProperty("properties", out var p)) continue;
                    var rdId = p.TryGetProperty("roleDefinitionId", out var r)
                        ? r.GetString() ?? "" : "";
                    var name = roleNames is not null && roleNames.TryGetValue(rdId, out var rn)
                        ? rn : rdId[(rdId.LastIndexOf('/') + 1)..];
                    result.Add(new AzureRoleAssignmentInfo(
                        p.TryGetProperty("scope", out var sc) ? sc.GetString() ?? "" : "",
                        rdId, name,
                        p.TryGetProperty("principalId", out var pi) ? pi.GetString() ?? "" : "",
                        p.TryGetProperty("principalType", out var pt) ? pt.GetString() ?? "" : ""));
                }
            }
            url = doc.RootElement.TryGetProperty("nextLink", out var n) ? n.GetString() : null;
        }
        return result;
    }

    /// <summary>Full Azure sync across every readable subscription.</summary>
    public async Task<(List<RoleDefinitionRecord> Roles, List<AzureRoleAssignmentInfo> Assignments,
                       List<AzureSubscription> Subscriptions)>
        SyncAsync(Action<string>? progress = null, CancellationToken ct = default)
    {
        Warnings.Clear();
        var roles = new List<RoleDefinitionRecord>();
        var assignments = new List<AzureRoleAssignmentInfo>();
        var subs = new List<AzureSubscription>();

        try
        {
            progress?.Invoke("Listing Azure subscriptions...");
            subs = (await ListSubscriptionsAsync(ct)).ToList();
        }
        catch (Exception ex)
        {
            Warnings.Add("Azure subscriptions unreadable (" + Head(ex.Message) +
                         "). If this tenant has no Azure subscriptions, or your account has no " +
                         "Azure role, that is expected.");
            return (roles, assignments, subs);
        }

        foreach (var sub in subs)
        {
            try
            {
                progress?.Invoke("Reading role definitions in " + sub.DisplayName + "...");
                var subRoles = await ReadRoleDefinitionsAsync(sub.Id, ct);
                roles.AddRange(subRoles);

                var names = subRoles.ToDictionary(r => r.Id, r => r.DisplayName,
                    StringComparer.OrdinalIgnoreCase);
                progress?.Invoke("Reading role assignments in " + sub.DisplayName + "...");
                assignments.AddRange(await ReadRoleAssignmentsAsync(sub.Id, names, ct));
            }
            catch (Exception ex)
            {
                Warnings.Add(sub.DisplayName + ": " + Head(ex.Message));
            }
        }

        // Same role definition repeats per subscription — keep one of each.
        roles = roles
            .GroupBy(r => r.Id, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();
        return (roles, assignments, subs);
    }

    private static string Head(string s) => s.Length <= 200 ? s : s[..200];

    public void Dispose() => _http.Dispose();
}
