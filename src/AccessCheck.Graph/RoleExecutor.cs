using System.Text.Json;
using AccessCheck.Core.Catalog;
using AccessCheck.Core.Execution;
using AccessCheck.Core.Recommendation;

namespace AccessCheck.Graph;

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

    /// <summary>
    /// Creates a custom role. The body shape differs by provider:
    ///  - directory: unified v1.0, FLAT rolePermissions[].allowedResourceActions
    ///  - Intune: the Intune-native endpoint /beta/deviceManagement/roleDefinitions with
    ///    NESTED rolePermissions[].resourceActions[].allowedResourceActions + roleScopeTagIds
    ///  - cloudPC / defender: unified beta first, nested as a fallback
    /// Each candidate is attempted in order; if all fail, every error is reported so the
    /// actual rejection is visible rather than just the last one.
    /// </summary>
    public async Task<string> CreateCustomRoleAsync(
        string provider, CustomRoleDraft draft, CancellationToken ct = default)
    {
        if (!RbacProviders.CustomRoleCapable.Contains(provider))
            throw new NotSupportedException(
                "Custom role creation is not supported for provider '" + provider + "'.");

        var attempts = BuildCreateAttempts(provider, draft);
        var errors = new List<string>();

        foreach (var (path, body) in attempts)
        {
            try
            {
                using var doc = await _graph.PostAsync(path, body, ct);
                var id = doc.RootElement.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;
                if (!string.IsNullOrEmpty(id))
                {
                    LastCustomRoleCreatePath = path;
                    return id;
                }
                errors.Add(path + " -> succeeded but returned no id");
            }
            catch (Exception ex)
            {
                errors.Add(path + " -> " + ex.Message);
            }
        }

        throw new InvalidOperationException(
            "Custom role creation failed for " + RbacProviders.DisplayName(provider) + "." +
            Environment.NewLine + string.Join(Environment.NewLine, errors));
    }

    /// <summary>
    /// Which endpoint the last custom role was actually created at. Matters for Intune:
    /// a role created through the unified path is NOT visible at
    /// /deviceManagement/roleDefinitions, so an assignment binding to that path fails
    /// with 404 ResourceNotFound.
    /// </summary>
    public string? LastCustomRoleCreatePath { get; private set; }

    private static List<(string Path, object Body)> BuildCreateAttempts(
        string provider, CustomRoleDraft draft)
    {
        var actions = draft.AllowedResourceActions;

        // Flat form — unified RBAC (directory, and some beta providers).
        object FlatBody() => new
        {
            displayName = draft.DisplayName,
            description = draft.Description,
            isEnabled = true,
            rolePermissions = new object[]
            {
                new { allowedResourceActions = actions }
            }
        };

        // Nested form — Intune-style roleDefinition.
        object NestedBody() => new
        {
            displayName = draft.DisplayName,
            description = draft.Description,
            isBuiltIn = false,
            roleScopeTagIds = new[] { "0" },
            rolePermissions = new object[]
            {
                new
                {
                    resourceActions = new object[]
                    {
                        new
                        {
                            allowedResourceActions = actions,
                            notAllowedResourceActions = Array.Empty<string>()
                        }
                    }
                }
            }
        };

        if (provider == RbacProviders.Directory)
            return new List<(string, object)>
            {
                ("/v1.0/roleManagement/directory/roleDefinitions", FlatBody())
            };

        if (provider == RbacProviders.Intune)
            return new List<(string, object)>
            {
                // ONLY Intune's own endpoint. The unified path will happily create a role
                // that Intune itself cannot see, which then can't be assigned to anything —
                // an orphan. Better to fail here with the real reason.
                ("/beta/deviceManagement/roleDefinitions", NestedBody()),
                ("/v1.0/deviceManagement/roleDefinitions", NestedBody())
            };

        return new List<(string, object)>
        {
            ("/beta/roleManagement/" + provider + "/roleDefinitions", FlatBody()),
            ("/beta/roleManagement/" + provider + "/roleDefinitions", NestedBody())
        };
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
                expiration = plan.Permanent
                    ? (object)new { type = "noExpiration" }
                    : new { type = "afterDuration", duration = plan.Duration }
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
    /// Finds a role that already grants exactly the drafted permission set (or carries the
    /// drafted name) within the same provider — so an existing role can be reused instead
    /// of minting a near-duplicate. Exact set match first, then name match.
    /// </summary>
    public static RoleDefinitionRecord? FindEquivalentRole(
        RoleCatalog catalog, string provider, CustomRoleDraft draft)
    {
        var wanted = new HashSet<string>(draft.AllowedResourceActions, StringComparer.OrdinalIgnoreCase);

        var exact = catalog.RolesFor(provider).FirstOrDefault(r =>
            r.AllowedResourceActions.Count == wanted.Count &&
            r.AllowedResourceActions.All(wanted.Contains));
        if (exact is not null) return exact;

        return catalog.RolesFor(provider).FirstOrDefault(r =>
            string.Equals(r.DisplayName, draft.DisplayName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Scope for an Intune role assignment. Intune REQUIRES one: with the default
    /// scopeType 'resourceScope' the resourceScopes list must contain at least one
    /// security group id, otherwise the service returns
    /// 400 "When ScopeType is set to 'ResourceScope', ResourceScopes must contain a one
    /// or more AAD Security Group IDs". The all* scope types must leave it empty.
    /// </summary>
    public sealed record IntuneAssignmentScope(string ScopeType, IReadOnlyList<string> ResourceScopes)
    {
        public static IntuneAssignmentScope AllDevicesAndUsers =>
            new("allDevicesAndLicensedUsers", Array.Empty<string>());
        public static IntuneAssignmentScope AllDevices =>
            new("allDevices", Array.Empty<string>());
        public static IntuneAssignmentScope AllLicensedUsers =>
            new("allLicensedUsers", Array.Empty<string>());
        public static IntuneAssignmentScope ForGroups(IEnumerable<string> groupIds) =>
            new("resourceScope", groupIds.ToList());

        public string Describe() => ScopeType == "resourceScope"
            ? "scoped to " + ResourceScopes.Count + " group(s)"
            : ScopeType;
    }

    /// <summary>
    /// Direct assignment for the non-PIM providers.
    ///  - Intune: ONLY /beta/deviceManagement/roleAssignments works for writes. The
    ///    unified /beta/roleManagement/deviceManagement/roleAssignments path returns
    ///    404 ResourceNotFound on POST even though reads succeed there. `members` are
    ///    security GROUP ids, and a scope is mandatory.
    ///  - cloudPC / defender: unifiedRoleAssignmentMultiple with principalIds.
    /// </summary>
    public async Task<string> AssignMultiAsync(
        string provider, string principalId, string roleDefinitionId,
        string justification, IntuneAssignmentScope? intuneScope = null,
        CancellationToken ct = default)
    {
        var attempts = new List<(string Path, object Body)>();

        if (provider == RbacProviders.Intune)
        {
            // The role MUST be visible at the Intune-native endpoint, because that is what
            // the assignment binds to. A role created through the unified path is not, and
            // the bind then fails with a bare 404 ResourceNotFound that names nothing.
            var visibleNatively = await IntuneRoleExistsNativelyAsync(roleDefinitionId, ct);
            if (!visibleNatively)
                throw new InvalidOperationException(
                    "The Intune role " + roleDefinitionId + " is not readable at " +
                    "/beta/deviceManagement/roleDefinitions, so an assignment cannot bind to it." +
                    Environment.NewLine + Environment.NewLine +
                    "This happens when the role was created through the unified " +
                    "/roleManagement/deviceManagement path instead of Intune's own endpoint." +
                    (LastCustomRoleCreatePath is not null
                        ? Environment.NewLine + "It was created at: " + LastCustomRoleCreatePath
                        : "") +
                    Environment.NewLine + Environment.NewLine +
                    "Delete that role and re-run, or create the role in the Intune portal and " +
                    "pick it from the catalog instead of drafting a new one.");

            var scope = intuneScope ?? IntuneAssignmentScope.AllDevicesAndUsers;

            object BodyWithBind(string bind, bool includeScopeType)
            {
                var d = new Dictionary<string, object>
                {
                    ["@odata.type"] = "#microsoft.graph.deviceAndAppManagementRoleAssignment",
                    ["displayName"] = "AccessCheck grant",
                    ["description"] = justification,
                    ["members"] = new[] { principalId },
                    ["resourceScopes"] = scope.ResourceScopes.ToArray(),
                    ["roleDefinition@odata.bind"] = bind
                };
                if (includeScopeType) d["scopeType"] = scope.ScopeType;
                return d;
            }

            var bindParen = _graph.GraphBase + "/beta/deviceManagement/roleDefinitions('" +
                            roleDefinitionId + "')";
            var bindSlash = _graph.GraphBase + "/beta/deviceManagement/roleDefinitions/" +
                            roleDefinitionId;

            attempts.Add(("/beta/deviceManagement/roleAssignments", BodyWithBind(bindParen, true)));
            attempts.Add(("/beta/deviceManagement/roleAssignments", BodyWithBind(bindSlash, true)));
            attempts.Add(("/beta/deviceManagement/roleAssignments", BodyWithBind(bindParen, false)));

            // v1.0 nests the assignment under the role definition and has no scopeType.
            attempts.Add((
                "/v1.0/deviceManagement/roleDefinitions/" + roleDefinitionId + "/roleAssignments",
                new Dictionary<string, object>
                {
                    ["@odata.type"] = "#microsoft.graph.deviceAndAppManagementRoleAssignment",
                    ["displayName"] = "AccessCheck grant",
                    ["description"] = justification,
                    ["members"] = new[] { principalId },
                    ["resourceScopes"] = scope.ResourceScopes.ToArray()
                }));
        }
        else
        {
            attempts.Add((
                "/beta/roleManagement/" + provider + "/roleAssignments",
                new
                {
                    displayName = "AccessCheck grant",
                    description = justification,
                    roleDefinitionId,
                    principalIds = new[] { principalId },
                    directoryScopeIds = new[] { "/" }
                }));
        }

        var errors = new List<string>();
        foreach (var (path, body) in attempts)
        {
            try
            {
                using var doc = await _graph.PostAsync(path, body, ct);
                var id = doc.RootElement.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;
                if (!string.IsNullOrEmpty(id)) return id;
                errors.Add(path + " -> succeeded but returned no id");
            }
            catch (Exception ex)
            {
                errors.Add(path + " -> " + ex.Message);
            }
        }

        var hint = provider == RbacProviders.Intune
            ? Environment.NewLine + Environment.NewLine +
              "NOTE: Intune RBAC assigns roles to SECURITY GROUPS, and every assignment needs " +
              "a scope (all devices/users, or specific scope groups)."
            : "";

        throw new InvalidOperationException(
            "Assignment failed for " + RbacProviders.DisplayName(provider) + "." +
            Environment.NewLine + string.Join(Environment.NewLine, errors) + hint);
    }

    public async Task RemoveMultiAssignmentAsync(
        string provider, string assignmentId, CancellationToken ct = default)
    {
        var candidates = provider == RbacProviders.Intune
            ? new List<string>
            {
                "/beta/deviceManagement/roleAssignments/" + assignmentId,
                "/beta/roleManagement/" + provider + "/roleAssignments/" + assignmentId
            }
            : new List<string>
            {
                "/beta/roleManagement/" + provider + "/roleAssignments/" + assignmentId
            };

        var errors = new List<string>();
        foreach (var path in candidates)
        {
            try { await _graph.DeleteAsync(path, ct); return; }
            catch (Exception ex) { errors.Add(path + " -> " + ex.Message); }
        }
        throw new InvalidOperationException(
            "Assignment removal failed." + Environment.NewLine +
            string.Join(Environment.NewLine, errors));
    }

    /// <summary>
    /// Creates the security group used for the PIM-for-Groups pattern. Requires
    /// delegated Group.ReadWrite.All. The group is onboarded to PIM implicitly at
    /// its first assignment schedule request, so create + role-attach is the whole
    /// pre-staging. Returns the new group id.
    /// </summary>
    public async Task<string> CreateSecurityGroupAsync(
        string displayName, string description, bool roleAssignable = false,
        CancellationToken ct = default)
    {
        var nickname = new string(displayName
            .Where(char.IsLetterOrDigit)
            .Take(40)
            .ToArray());
        if (nickname.Length == 0) nickname = "accesscheck";
        // isAssignableToRole is REQUIRED for a group that will hold Entra directory roles,
        // and cannot be changed after creation. Setting it needs Privileged Role Administrator
        // plus RoleManagement.ReadWrite.Directory.
        object body = roleAssignable
            ? new
            {
                displayName,
                description,
                mailEnabled = false,
                mailNickname = nickname.ToLowerInvariant(),
                securityEnabled = true,
                isAssignableToRole = true
            }
            : new
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
    /// AccessCheck grants membership with afterDuration — expiry stays server-side.
    /// The group must be onboarded to PIM for Groups.
    /// </summary>
    public async Task<string> AssignGroupMembershipAsync(
        string groupId, string principalId, string duration, string justification,
        bool permanent = false, CancellationToken ct = default)
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
                expiration = permanent
                    ? (object)new { type = "noExpiration" }
                    : new { type = "afterDuration", duration }
            }
        };
        using var doc = await _graph.PostAsync(
            "/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests", body, ct);
        return doc.RootElement.GetProperty("id").GetString() ?? "";
    }

    // ---------- give a GROUP a role (pre-staging) ----------

    /// <summary>
    /// Assigns a directory role to a principal permanently via plain roleAssignments —
    /// used to give a GROUP a role, where time-bounding belongs at the membership layer,
    /// not the role layer. Avoids PIM schedule-request policy validation entirely.
    /// The group MUST have been created role-assignable or Graph rejects this.
    /// </summary>
    public async Task<string> AssignDirectoryRoleToPrincipalAsync(
        string principalId, string roleDefinitionId, string directoryScopeId = "/",
        CancellationToken ct = default)
    {
        var body = new
        {
            principalId,
            roleDefinitionId,
            directoryScopeId
        };
        using var doc = await _graph.PostAsync(
            "/v1.0/roleManagement/directory/roleAssignments", body, ct);
        return doc.RootElement.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "";
    }

    /// <summary>
    /// Does this principal (typically a GROUP) already hold this specific role?
    /// Used before granting membership: putting someone in a group that does NOT carry
    /// the role grants them nothing, which is a silent no-op worth catching.
    /// </summary>
    public async Task<bool> DoesPrincipalHoldRoleAsync(
        string provider, string principalId, string roleDefinitionId,
        CancellationToken ct = default)
    {
        try
        {
            if (provider == RbacProviders.Directory)
            {
                var filter = "principalId eq '" + principalId + "' and roleDefinitionId eq '" +
                             roleDefinitionId + "'";
                using var doc = await _graph.GetAsync(
                    "/v1.0/roleManagement/directory/roleAssignments?$filter=" +
                    Uri.EscapeDataString(filter), ct);
                return doc.RootElement.TryGetProperty("value", out var v) && v.GetArrayLength() > 0;
            }

            // Intune: only the native endpoint is authoritative for assignments.
            if (provider == RbacProviders.Intune)
                return await IntuneHoldsRoleAsync(principalId, roleDefinitionId, ct);

            // Unified providers: principalIds is a collection, so match client-side.
            string? url = "/beta/roleManagement/" + provider + "/roleAssignments?$filter=" +
                          Uri.EscapeDataString("roleDefinitionId eq '" + roleDefinitionId + "'");
            int guard = 0;
            while (url is not null && guard++ < 50)
            {
                using var doc = await _graph.GetAsync(url, ct);
                if (doc.RootElement.TryGetProperty("value", out var v))
                {
                    foreach (var el in v.EnumerateArray())
                    {
                        if (el.TryGetProperty("principalIds", out var pids) &&
                            pids.ValueKind == JsonValueKind.Array &&
                            pids.EnumerateArray().Any(p => string.Equals(
                                p.GetString(), principalId, StringComparison.OrdinalIgnoreCase)))
                            return true;
                    }
                }
                url = doc.RootElement.TryGetProperty("@odata.nextLink", out var n)
                    ? n.GetString() : null;
            }

            return false;
        }
        catch (Exception)
        {
            // Unknown rather than false — the caller decides how to treat it.
            return false;
        }
    }

    /// <summary>Where an Intune role can actually be found.</summary>
    public enum IntuneRoleState
    {
        /// <summary>Readable at Intune's own endpoint — assignable.</summary>
        Usable,
        /// <summary>Exists only under the unified path — cannot be assigned.</summary>
        UnifiedOnly,
        /// <summary>Not present anywhere. The catalog entry is stale.</summary>
        Missing
    }

    /// <summary>
    /// Is this Intune role actually usable — i.e. readable at Intune's own endpoint?
    /// A role created through the unified path is NOT, and can never be assigned.
    /// </summary>
    public Task<bool> IsIntuneRoleUsableAsync(string roleDefinitionId, CancellationToken ct = default) =>
        IntuneRoleExistsNativelyAsync(roleDefinitionId, ct);

    /// <summary>
    /// Locates an Intune role so the caller can tell a wrong-endpoint orphan apart from
    /// a role that simply no longer exists — a stale cached catalog looks identical to a
    /// broken role until you check both places.
    /// </summary>
    public async Task<IntuneRoleState> GetIntuneRoleStateAsync(
        string roleDefinitionId, CancellationToken ct = default)
    {
        if (await IntuneRoleExistsNativelyAsync(roleDefinitionId, ct))
            return IntuneRoleState.Usable;

        try
        {
            using var doc = await _graph.GetAsync(
                "/beta/roleManagement/deviceManagement/roleDefinitions/" + roleDefinitionId, ct);
            if (doc.RootElement.TryGetProperty("id", out _)) return IntuneRoleState.UnifiedOnly;
        }
        catch (Exception) { /* fall through */ }

        return IntuneRoleState.Missing;
    }

    /// <summary>Is this role readable at Intune's own roleDefinitions endpoint?</summary>
    private async Task<bool> IntuneRoleExistsNativelyAsync(
        string roleDefinitionId, CancellationToken ct)
    {
        foreach (var path in new[]
                 {
                     "/beta/deviceManagement/roleDefinitions/" + roleDefinitionId,
                     "/v1.0/deviceManagement/roleDefinitions/" + roleDefinitionId
                 })
        {
            try
            {
                using var doc = await _graph.GetAsync(path, ct);
                if (doc.RootElement.TryGetProperty("id", out _)) return true;
            }
            catch (Exception) { /* try the next */ }
        }
        return false;
    }

    private async Task<bool> IntuneHoldsRoleAsync(
        string principalId, string roleDefinitionId, CancellationToken ct)
    {
        // Ask the role for its assignments rather than listing all assignments with
        // $expand, which fails when any assignment has a null roleDefinition.
        string? url = "/beta/deviceManagement/roleDefinitions/" + roleDefinitionId +
                      "/roleAssignments?$top=50";
        int guard = 0;
        while (url is not null && guard++ < 50)
        {
            using var doc = await _graph.GetAsync(url, ct);
            if (doc.RootElement.TryGetProperty("value", out var v))
            {
                foreach (var el in v.EnumerateArray())
                {
                    if (el.TryGetProperty("members", out var members) &&
                        members.ValueKind == JsonValueKind.Array &&
                        members.EnumerateArray().Any(m => string.Equals(
                            m.GetString(), principalId, StringComparison.OrdinalIgnoreCase)))
                        return true;
                }
            }
            url = doc.RootElement.TryGetProperty("@odata.nextLink", out var n)
                ? n.GetString() : null;
        }
        return false;
    }

    // ---------- plain group membership (no PIM) ----------

    /// <summary>
    /// Adds a principal straight into a group: POST /groups/{id}/members/$ref.
    /// No PIM involved — so no licensing requirement, no role-management-policy
    /// validation, and NO server-side expiry: removal is entirely up to Housekeeping.
    /// Needs GroupMember.ReadWrite.All (or Group.ReadWrite.All); a role-assignable
    /// group additionally requires RoleManagement.ReadWrite.Directory.
    /// </summary>
    public async Task AddGroupMemberAsync(
        string groupId, string principalId, CancellationToken ct = default)
    {
        var body = new Dictionary<string, object>
        {
            ["@odata.id"] = _graph.GraphBase + "/v1.0/directoryObjects/" + principalId
        };
        using var _ = await _graph.PostAsync("/v1.0/groups/" + groupId + "/members/$ref", body, ct);
    }

    public Task RemoveGroupMemberAsync(
        string groupId, string principalId, CancellationToken ct = default) =>
        _graph.DeleteAsync("/v1.0/groups/" + groupId + "/members/" + principalId + "/$ref", ct);

    /// <summary>True when the principal is already a direct member (avoids a pointless 400).</summary>
    public async Task<bool> IsGroupMemberAsync(
        string groupId, string principalId, CancellationToken ct = default)
    {
        try
        {
            var url = "/v1.0/groups/" + groupId + "/members?$select=id&$top=999";
            while (url is not null)
            {
                using var doc = await _graph.GetAsync(url, ct);
                if (doc.RootElement.TryGetProperty("value", out var value))
                {
                    foreach (var el in value.EnumerateArray())
                    {
                        var id = el.TryGetProperty("id", out var i) ? i.GetString() : null;
                        if (string.Equals(id, principalId, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
                url = doc.RootElement.TryGetProperty("@odata.nextLink", out var n)
                    ? n.GetString() : null;
            }
        }
        catch (Exception) { /* best effort — fall through and let the add attempt decide */ }
        return false;
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

    public async Task DeleteRoleAsync(
        string provider, string roleDefinitionId, CancellationToken ct = default)
    {
        var candidates = provider switch
        {
            RbacProviders.Directory => new[]
                { "/v1.0/roleManagement/directory/roleDefinitions/" + roleDefinitionId },
            RbacProviders.Intune => new[]
            {
                "/beta/deviceManagement/roleDefinitions/" + roleDefinitionId,
                "/beta/roleManagement/deviceManagement/roleDefinitions/" + roleDefinitionId
            },
            _ => new[]
                { "/beta/roleManagement/" + provider + "/roleDefinitions/" + roleDefinitionId }
        };

        var errors = new List<string>();
        bool allNotFound = true;
        foreach (var path in candidates)
        {
            try { await _graph.DeleteAsync(path, ct); return; }
            catch (GraphApiException gex)
            {
                if (gex.StatusCode != 404) allNotFound = false;
                errors.Add(path + " -> " + gex.Message);
            }
            catch (Exception ex)
            {
                allNotFound = false;
                errors.Add(path + " -> " + ex.Message);
            }
        }

        // Every endpoint says "not found": the role is already gone. Deleting something
        // that doesn't exist is a success, not a failure.
        if (allNotFound) return;

        throw new InvalidOperationException(
            "Role deletion failed." + Environment.NewLine + string.Join(Environment.NewLine, errors));
    }
}
