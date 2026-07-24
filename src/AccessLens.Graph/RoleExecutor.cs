using AccessLens.Core.Catalog;
using AccessLens.Core.Execution;
using AccessLens.Core.Recommendation;

namespace AccessLens.Graph;

/// <summary>
/// Executes ONLY human-approved plans.
/// - directory: PIM schedule requests (afterDuration) — expiry enforced server-side.
/// - deviceManagement / cloudPC / defender: unifiedRoleAssignmentMultiple (no PIM),
///   so either (a) grant via a PIM-governed group (server-side expiry preserved), or
///   (b) direct assignment with app-tracked expiry removed at housekeeping.
/// - exchange: catalog/recommendation only; assignment stays a documented manual step.
/// </summary>
public sealed class RoleExecutor
{
    private readonly GraphClient _graph;
    public RoleExecutor(GraphClient graph) => _graph = graph;

    // ---------- custom roles ----------

    /// <summary>POST /roleManagement/{provider}/roleDefinitions. Returns the new role id.</summary>
    public async Task<string> CreateCustomRoleAsync(
        string provider, CustomRoleDraft draft, CancellationToken ct = default)
    {
        if (!RbacProviders.CustomRoleCapable.Contains(provider))
            throw new NotSupportedException(
                "Custom role creation is not supported for provider '" + provider + "'.");

        var path = provider == RbacProviders.Directory
            ? "/v1.0/roleManagement/directory/roleDefinitions"
            : "/beta/roleManagement/" + provider + "/roleDefinitions";

        var body = new
        {
            displayName = draft.DisplayName,
            description = draft.Description,
            isEnabled = true,
            rolePermissions = new object[]
            {
                new { allowedResourceActions = draft.AllowedResourceActions }
            }
        };
        using var doc = await _graph.PostAsync(path, body, ct);
        return doc.RootElement.GetProperty("id").GetString()
               ?? throw new InvalidDataException("Role creation returned no id.");
    }

    // ---------- directory (PIM, server-side expiry) ----------

    public async Task<string> AssignDirectoryAsync(AssignmentPlan plan, CancellationToken ct = default)
    {
        var path = plan.Type == AssignmentType.Eligible
            ? "/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"
            : "/v1.0/roleManagement/directory/roleAssignmentScheduleRequests";

        var body = new
        {
            action = "adminAssign",
            justification = plan.Justification,
            roleDefinitionId = plan.RoleDefinitionId,
            directoryScopeId = plan.DirectoryScopeId,
            principalId = plan.PrincipalId,
            scheduleInfo = new
            {
                startDateTime = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                expiration = new { type = "afterDuration", duration = plan.Duration }
            }
        };
        using var doc = await _graph.PostAsync(path, body, ct);
        return doc.RootElement.GetProperty("id").GetString() ?? "";
    }

    public async Task RemoveDirectoryAssignmentAsync(
        string principalId, string roleDefinitionId, string justification,
        bool eligible = false, CancellationToken ct = default)
    {
        var path = eligible
            ? "/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"
            : "/v1.0/roleManagement/directory/roleAssignmentScheduleRequests";
        var body = new
        {
            action = "adminRemove",
            justification,
            roleDefinitionId,
            directoryScopeId = "/",
            principalId
        };
        using var _ = await _graph.PostAsync(path, body, ct);
    }

    // ---------- Intune / CloudPC / Defender (multi, app-tracked expiry) ----------

    /// <summary>
    /// Direct assignment via POST /beta/roleManagement/{provider}/roleAssignments.
    /// No server-side expiry exists here — the caller records TrackedExpiryUtc and
    /// housekeeping removes it. Intune scopes via appScopeIds; others directoryScopeIds.
    /// </summary>
    public async Task<string> AssignMultiAsync(
        string provider, string principalId, string roleDefinitionId,
        string justification, CancellationToken ct = default)
    {
        var path = "/beta/roleManagement/" + provider + "/roleAssignments";
        object body = provider == RbacProviders.Intune
            ? new
            {
                displayName = "AccessLens grant",
                description = justification,
                roleDefinitionId,
                principalIds = new[] { principalId },
                appScopeIds = new[] { "/" }
            }
            : new
            {
                displayName = "AccessLens grant",
                description = justification,
                roleDefinitionId,
                principalIds = new[] { principalId },
                directoryScopeIds = new[] { "/" }
            };
        using var doc = await _graph.PostAsync(path, body, ct);
        return doc.RootElement.GetProperty("id").GetString() ?? "";
    }

    public Task RemoveMultiAssignmentAsync(
        string provider, string assignmentId, CancellationToken ct = default) =>
        _graph.DeleteAsync("/beta/roleManagement/" + provider + "/roleAssignments/" + assignmentId, ct);

    /// <summary>
    /// Creates the security group used for the PIM-for-Groups pattern. Requires
    /// delegated Group.ReadWrite.All. The group is onboarded to PIM implicitly at
    /// its first assignment schedule request, so create + role-attach is the whole
    /// pre-staging. Returns the new group id.
    /// </summary>
    public async Task<string> CreateSecurityGroupAsync(
        string displayName, string description, CancellationToken ct = default)
    {
        var nickname = new string(displayName
            .Where(char.IsLetterOrDigit)
            .Take(40)
            .ToArray());
        if (nickname.Length == 0) nickname = "accesslens";
        var body = new
        {
            displayName,
            description,
            mailEnabled = false,
            mailNickname = nickname.ToLowerInvariant(),
            securityEnabled = true
        };
        using var doc = await _graph.PostAsync("/v1.0/groups", body, ct);
        return doc.RootElement.GetProperty("id").GetString()
               ?? throw new InvalidDataException("Group creation returned no id.");
    }

    // ---------- PIM for Groups (server-side expiry for ANY group-granted access) ----------

    /// <summary>
    /// Time-bound group membership via POST
    /// /v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests.
    /// Use for non-directory providers: assign the role to the group once, then
    /// AccessLens grants membership with afterDuration — expiry stays server-side.
    /// The group must be onboarded to PIM for Groups.
    /// </summary>
    public async Task<string> AssignGroupMembershipAsync(
        string groupId, string principalId, string duration, string justification,
        CancellationToken ct = default)
    {
        var body = new
        {
            accessId = "member",
            principalId,
            groupId,
            action = "adminAssign",
            justification,
            scheduleInfo = new
            {
                startDateTime = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                expiration = new { type = "afterDuration", duration }
            }
        };
        using var doc = await _graph.PostAsync(
            "/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests", body, ct);
        return doc.RootElement.GetProperty("id").GetString() ?? "";
    }

    // ---------- housekeeping ----------

    public async Task<bool> RoleHasNoAssignmentsAsync(
        string provider, string roleDefinitionId, CancellationToken ct = default)
    {
        var filter = "$filter=roleDefinitionId eq '" + roleDefinitionId + "'";

        if (provider == RbacProviders.Directory)
        {
            using var assignments = await _graph.GetAsync(
                "/v1.0/roleManagement/directory/roleAssignments?" + filter, ct);
            if (assignments.RootElement.TryGetProperty("value", out var a) &&
                a.GetArrayLength() > 0) return false;

            using var eligibilities = await _graph.GetAsync(
                "/v1.0/roleManagement/directory/roleEligibilitySchedules?" + filter, ct);
            if (eligibilities.RootElement.TryGetProperty("value", out var e) &&
                e.GetArrayLength() > 0) return false;
            return true;
        }

        using var multi = await _graph.GetAsync(
            "/beta/roleManagement/" + provider + "/roleAssignments?" + filter, ct);
        return !(multi.RootElement.TryGetProperty("value", out var m) && m.GetArrayLength() > 0);
    }

    public Task DeleteRoleAsync(string provider, string roleDefinitionId, CancellationToken ct = default)
    {
        var path = provider == RbacProviders.Directory
            ? "/v1.0/roleManagement/directory/roleDefinitions/" + roleDefinitionId
            : "/beta/roleManagement/" + provider + "/roleDefinitions/" + roleDefinitionId;
        return _graph.DeleteAsync(path, ct);
    }
}
