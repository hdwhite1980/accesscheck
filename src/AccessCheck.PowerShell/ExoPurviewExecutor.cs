using System.Text;
using System.Text.Json;
using AccessCheck.Core.Catalog;
using AccessCheck.Core.Recommendation;

namespace AccessCheck.PowerShell;

/// <summary>
/// Write side for Exchange Online and Purview (Security &amp; Compliance) RBAC.
/// Exchange-model customs can't be composed from scratch: they are DERIVED —
/// New-ManagementRole -Parent &lt;covering role&gt;, then Remove-ManagementRoleEntry
/// for every excess cmdlet, leaving EXACTLY the required set. The validator's
/// BestFit is the parent and its ExcessActions are the removal list, so the
/// deterministic delta computation IS the derivation recipe.
/// Grants go through an AccessCheck role group; time-bounding is app-tracked
/// (housekeeping removes members), since neither endpoint has PIM.
/// Every script is returned for display BEFORE execution and logged verbatim.
/// </summary>
public sealed class ExoPurviewExecutor
{
    private readonly PowerShellRunner _runner;
    private readonly PsEnvironment _env;
    private readonly string? _upn;

    public const string Marker = "AccessCheck least-privilege role";

    public ExoPurviewExecutor(PowerShellRunner runner, PsEnvironment env, string? userPrincipalName)
    {
        _runner = runner;
        _env = env;
        _upn = userPrincipalName;
    }

    /// <summary>
    /// -BypassSecurityGroupManagerCheck exists on Exchange Online's role-group cmdlets but
    /// NOT on Security &amp; Compliance's, which fail with "A parameter cannot be found that
    /// matches parameter name 'BypassSecurityGroupManagerCheck'".
    ///
    /// Same shape as New-ManagementRole: the cmdlet NAME is shared, the parameter SET is
    /// not. Assuming Exchange's surface applies to Purview has now cost two round trips,
    /// so this is one helper rather than four call sites to keep in step.
    /// </summary>
    /// <summary>
    /// The endpoint's own account of what it supports, when a sync has probed it. Null
    /// means unprobed — in which case the hard-coded scope rules below still apply, but
    /// nothing is blocked.
    /// </summary>
    public CmdletCapabilityStore? Capabilities { get; set; }

    private string ScopeKey(RbacScope scope) =>
        scope == RbacScope.Exchange ? "exchange" : "purview";

    /// <summary>
    /// Emit a parameter ONLY if the endpoint is known to accept it.
    ///
    /// This is the general form of four separate failures. Rather than hard-coding each
    /// Exchange-vs-SCC difference as it is discovered, ask what the endpoint reported.
    /// Unprobed endpoints fall back to the scope rule so behaviour never regresses.
    /// </summary>
    private string ParamIfSupported(RbacScope scope, string cmdlet, string parameter,
                                    string emit, bool scopeDefault)
    {
        var cap = Capabilities?.Find(cmdlet, ScopeKey(scope));
        if (cap is null) return scopeDefault ? emit : "";
        if (!cap.Exists) return "";
        if (cap.Parameters.Count == 0) return scopeDefault ? emit : "";
        return cap.HasParameter(parameter) ? emit : "";
    }

    private string BypassSwitch(RbacScope scope) =>
        ParamIfSupported(scope, "Add-RoleGroupMember", "BypassSecurityGroupManagerCheck",
                         " -BypassSecurityGroupManagerCheck",
                         scope == RbacScope.Exchange);

    /// <summary>
    /// Cmdlets this script needs that the endpoint does not have. Checked BEFORE the script
    /// is shown for review, so an impossible grant is refused with a reason rather than
    /// failing halfway through.
    /// </summary>
    public IReadOnlyList<string> MissingCmdlets(RbacScope scope, params string[] needed)
    {
        if (Capabilities is null) return Array.Empty<string>();
        var key = ScopeKey(scope);
        return needed
            .Where(c => !Capabilities.CmdletExists(c, key))
            .ToList();
    }

    /// <summary>
    /// Refuses to return a script containing an EMPTY required argument.
    ///
    /// "The property DisplayName can't be empty" has now been chased down two different
    /// call paths and reappeared both times, because the failure is not really in any one
    /// of them — it is that a blank name can reach emission from several directions and
    /// nothing checks the finished text. So the check moves to the OUTPUT, where every
    /// path converges and no future one can bypass it.
    ///
    /// It also names the offending line, which is what was missing: Exchange's error says
    /// what was empty but not which call, and the app said nothing at all.
    /// </summary>
    private static string Guarded(StringBuilder sb)
    {
        var script = sb.ToString();

        // Parameters whose value can never legitimately be blank.
        string[] required = { "Name", "Identity", "DisplayName", "Member", "Parent", "Roles" };

        var lineNo = 0;
        foreach (var line in script.Split('\n'))
        {
            lineNo++;
            foreach (var param in required)
            {
                // -Name '' or -Name ""  — an empty literal that will reach the service.
                if (line.Contains("-" + param + " ''", StringComparison.Ordinal)
                    || line.Contains("-" + param + " \"\"", StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "This grant would run a command with an EMPTY -" + param
                        + ", which the service rejects (\"The property DisplayName can't be "
                        + "empty\" or similar). Nothing was run."
                        + Environment.NewLine + Environment.NewLine
                        + "Offending line " + lineNo + ":" + Environment.NewLine
                        + "  " + line.Trim()
                        + Environment.NewLine + Environment.NewLine
                        + "This usually means the selected option carried no role name. "
                        + "Re-analyze the request and pick a role from the dropdown before "
                        + "approving.");
                }
            }
        }

        return script;
    }

    /// <summary>
    /// Emits a single server-side pipeline that keeps only the wanted cmdlets on a derived
    /// role and removes the rest.
    ///
    /// A role created with -Parent inherits the parent's ENTIRE entry set — often ~200
    /// cmdlets. Removing the unwanted ones one Remove-ManagementRoleEntry at a time meant
    /// ~200 sequential round-trips in a single Exchange Online session, and the session was
    /// throttled and severed partway ("Error while copying content to a stream" after 25s).
    /// Get | Where-Object | Remove-ManagementRoleEntry runs as ONE operation — Microsoft's
    /// own documented form — and does not depend on how many entries must go.
    /// </summary>
    private static void EmitKeepOnlyPipeline(
        StringBuilder sb, string roleName, IEnumerable<string> keptActions)
    {
        var keepNames = keptActions
            .Select(a => AccessCheck.Core.Recommendation.ActionDisplay.Short(a))
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // Nothing kept would strip every entry, leaving a useless role — refuse instead.
        if (keepNames.Count == 0)
        {
            sb.AppendLine("    throw \"Refusing to derive '" + PsEnvironment.PsQ(roleName) +
                          "': no cmdlets would remain. Nothing was changed.\"");
            return;
        }

        var keepList = string.Join(",", keepNames.Select(n => "'" + PsEnvironment.PsQ(n) + "'"));

        sb.AppendLine("    $keep = @(" + keepList + ")");

        // RETRY WITH WAIT. A role created moments ago may not enumerate its inherited
        // entries yet — the first Get-ManagementRoleEntry can return nothing, and removing
        // nothing leaves the role carrying its FULL inherited set (64 entries where 2 were
        // wanted). So: enumerate, remove the unwanted, re-check; if the role still carries
        // far more than the wanted set, wait and try again. This is the operator's own
        // suggestion, and it matches how Exchange replication actually settles.
        sb.AppendLine("    $trimmed = $false");
        sb.AppendLine("    foreach ($attempt in 1..4) {");
        sb.AppendLine("      $entries = @(Get-ManagementRoleEntry '" + PsEnvironment.PsQ(roleName) +
                      "\\*' -ErrorAction SilentlyContinue)");
        sb.AppendLine("      if ($entries.Count -eq 0) { Start-Sleep -Seconds 3; continue }");
        sb.AppendLine("      $toRemove = @($entries | Where-Object { $keep -notcontains $_.Name })");
        sb.AppendLine("      foreach ($entry in $toRemove) {");
        sb.AppendLine("        Remove-ManagementRoleEntry -Identity (\"{0}\\{1}\" -f '" +
                      PsEnvironment.PsQ(roleName) + "', $entry.Name) " +
                      "-Confirm:$false -ErrorAction SilentlyContinue");
        sb.AppendLine("      }");
        sb.AppendLine("      $remaining = @(Get-ManagementRoleEntry '" + PsEnvironment.PsQ(roleName) +
                      "\\*' -ErrorAction SilentlyContinue)");
        sb.AppendLine("      if ($remaining.Count -le ($keep.Count + 2)) { $trimmed = $true; break }");
        sb.AppendLine("      Start-Sleep -Seconds 3");
        sb.AppendLine("    }");

        // Only fail if it STILL carries too much after all attempts — an over-privileged
        // role is the opposite of the point, so refuse rather than hand it to a member.
        sb.AppendLine("    if (-not $trimmed) {");
        sb.AppendLine("      $finalCount = @(Get-ManagementRoleEntry '" + PsEnvironment.PsQ(roleName) +
                      "\\*' -ErrorAction SilentlyContinue).Count");
        sb.AppendLine("      throw ('Derived role ''" + PsEnvironment.PsQ(roleName) +
                      "'' still carries ' + $finalCount + ' entries after 4 attempts, expected ' + " +
                      "$keep.Count + '. Refusing to grant an over-privileged role. Nothing was assigned.')");
        sb.AppendLine("    }");
    }

    // ---------- script builders (pure — shown to the approver before any run) ----------

    /// <summary>
    /// Derive an exact-permission role, wrap it in a role group, add the member.
    /// If draft is null, the existing coveringRole is granted as-is via a role group.
    /// </summary>
    public string BuildGrantScript(
        RbacScope scope, CustomRoleDraft? draft, string coveringRoleName,
        string memberIdentity, string justification, string? customName = null)
    {
        var roleToGrant = draft is not null ? draft.DisplayName : coveringRoleName;

        // The operator's chosen name overrides the group stem (the role name already carries
        // it via the draft). Prefixes are still applied below.
        var nameStem = string.IsNullOrWhiteSpace(customName) ? roleToGrant : customName!.Trim();

        // A blank name produces "The property DisplayName can't be empty" from Exchange —
        // a confusing failure for what is really a missing input. Catch it here, where the
        // cause is still visible.
        if (string.IsNullOrWhiteSpace(roleToGrant))
        {
            throw new InvalidOperationException(
                "No role name was resolved for this grant, so the script would create a "
                + "role group with an empty name. This usually means the selected option "
                + "carried no parent or covering role. Re-analyze the request and choose a "
                + "role from the dropdown before approving. Nothing was changed.");
        }

        var groupName = Truncate("ACG - " + nameStem, 64);


        var sb = new StringBuilder();
        Prologue(sb, scope);

        // Purview has NO New-ManagementRole. Attempting a derivation there fails with
        // "This endpoint does not support creating custom management roles", so the only
        // honest path is to grant the covering role as-is through the role group.
        var canDerive = RbacProviders.DerivationCapable.Contains(
            scope == RbacScope.Exchange ? RbacProviders.Exchange : RbacProviders.Purview);

        if (draft is not null && !canDerive)
        {
            sb.AppendLine("  # This service cannot create custom management roles, so '" +
                          PsEnvironment.PsQ(roleToGrant) + "' is granted as-is.");
            sb.AppendLine("  # Least privilege here is role-group COMPOSITION, not role derivation.");
            draft = null;
            roleToGrant = coveringRoleName;
            groupName = Truncate("ACG - " + coveringRoleName, 64);
        }

        if (draft is not null)
        {
            var parent = draft.ParentRoleName ?? coveringRoleName;
            sb.AppendLine("  # Derive exact-permission role from parent '" + PsEnvironment.PsQ(parent) + "'");
            sb.AppendLine("  if (-not (Get-Command New-ManagementRole -ErrorAction SilentlyContinue)) {");
            sb.AppendLine("    throw 'This endpoint does not support creating custom management roles " +
                          "(New-ManagementRole is unavailable). Grant an existing role instead, or " +
                          "create the custom role in Exchange Online where it is supported.'");
            sb.AppendLine("  }");
            sb.AppendLine("  if (-not (Get-ManagementRole -Identity '" + PsEnvironment.PsQ(draft.DisplayName) +
                          "' -ErrorAction SilentlyContinue)) {");
            sb.AppendLine("    New-ManagementRole -Parent '" + PsEnvironment.PsQ(parent) +
                          "' -Name '" + PsEnvironment.PsQ(draft.DisplayName) +
                          "' -Description '" + PsEnvironment.PsQ(draft.Description) + "' | Out-Null");

            // KEEP the wanted cmdlets, remove the rest in ONE server-side pipeline.
            //
            // A parented role is born with the parent's ENTIRE entry set (~200 for a broad
            // parent). Emitting one Remove-ManagementRoleEntry per unwanted entry meant ~200
            // sequential round-trips in a single Exchange Online session, which throttling
            // tore down mid-run ("Error while copying content to a stream" after 25s).
            // Get | Where | Remove is one operation, and it is Microsoft's documented form.
            EmitKeepOnlyPipeline(sb, draft.DisplayName, draft.AllowedResourceActions);
            sb.AppendLine("  }");
        }

        sb.AppendLine("  # Role group carrying the grant");
        EmitRoleGroupEnsure(sb, scope, groupName,
            "'" + PsEnvironment.PsQ(roleToGrant) + "'", justification, memberIdentity);
        sb.AppendLine("  $payload = [pscustomobject]@{ ok = $true; roleGroup = $groupName; " +
                      "roles = $finalRoles }");
        Epilogue(sb);
        return Guarded(sb);
    }

    /// <summary>
    /// Executes a MULTI-ROLE plan: one role group carrying every role the plan needs, each
    /// derived down to only the required cmdlets.
    ///
    /// A single-parent derivation cannot express a task that spans two roles —
    /// search-and-purge needs Compliance Search for the search and Search And Purge for
    /// the -Purge switch, and no single role holds both. Before this, such a plan was
    /// DISPLAYED correctly and then executed as its first role only, which would have
    /// granted the search and silently omitted the purge.
    ///
    /// Order matters: create or derive every role FIRST, then create the role group
    /// carrying all of them, then add the member. A role group cannot reference a role
    /// that does not exist yet.
    /// </summary>
    public string BuildMultiRoleGrantScript(
        RbacScope scope, RoleGroupPlan plan, string memberIdentity, string justification,
        string? customName = null)
    {
        // Encode the role set in the name: a group created for a different set cannot be
        // corrected afterwards, so avoiding the collision entirely is the only clean fix.
        var groupName = Truncate(
            string.IsNullOrWhiteSpace(customName)
                ? plan.DistinctGroupName
                : "ACG - " + customName!.Trim(),
            64);
        if (string.IsNullOrWhiteSpace(groupName))
        {
            throw new InvalidOperationException(
                "The plan produced an empty role-group name. Nothing was changed.");
        }
        var rolesForGroup = new List<string>();

        var sb = new StringBuilder();
        Prologue(sb, scope);

        sb.AppendLine("  $created = @()");
        sb.AppendLine("  $reused = @()");
        sb.AppendLine("  $groupExisted = $false");
        // Declared up front so the recovery branch can reassign it and every later line sees it.
        sb.AppendLine("  $groupName = '" + PsEnvironment.PsQ(groupName) + "'");

        foreach (var planned in plan.Roles)
        {
            if (!planned.NeedsDerivation)
            {
                // Used as-is: either it already grants exactly what is needed, or this
                // service cannot create custom roles at all (Security & Compliance has no
                // New-ManagementRole) and composing built-in roles is the only lever.
                rolesForGroup.Add(planned.RoleName);
                var why = planned.Excess.Count == 0
                    ? "' already grants exactly what is needed — used as-is"
                    : "' used as-is, carrying " + planned.Excess.Count +
                      " unavoidable extra cmdlet(s) (this endpoint cannot create custom roles)";
                sb.AppendLine("  # '" + PsEnvironment.PsQ(planned.RoleName) + why);
                sb.AppendLine("  $reused += '" + PsEnvironment.PsQ(planned.RoleName) + "'");
                continue;
            }

            var derivedName = Truncate("AC - " + planned.RoleName + " (minimal)", 64);
            rolesForGroup.Add(derivedName);

            sb.AppendLine("  # Derive '" + PsEnvironment.PsQ(derivedName) + "' from '" +
                          PsEnvironment.PsQ(planned.RoleName) + "', stripping " +
                          planned.Excess.Count + " excess cmdlet(s)");
            sb.AppendLine("  if (-not (Get-Command New-ManagementRole -ErrorAction SilentlyContinue)) {");
            sb.AppendLine("    throw 'This endpoint does not support creating custom management roles.'");
            sb.AppendLine("  }");
            sb.AppendLine("  if (-not (Get-ManagementRole -Identity '" + PsEnvironment.PsQ(derivedName) +
                          "' -ErrorAction SilentlyContinue)) {");
            sb.AppendLine("    New-ManagementRole -Parent '" + PsEnvironment.PsQ(planned.RoleName) +
                          "' -Name '" + PsEnvironment.PsQ(derivedName) +
                          "' -Description '" + PsEnvironment.PsQ(Marker + ". " + justification) +
                          "' | Out-Null");

            // Keep only what this role needs to cover; remove the rest in ONE pipeline.
            // (Was one Remove-ManagementRoleEntry per excess entry — ~200 round-trips that
            // Exchange throttling severed mid-session.)
            EmitKeepOnlyPipeline(sb, derivedName, planned.Covers);

            sb.AppendLine("    $created += '" + PsEnvironment.PsQ(derivedName) + "'");
            sb.AppendLine("  } else { $reused += '" + PsEnvironment.PsQ(derivedName) + "' }");
        }

        var roleList = string.Join(",", rolesForGroup.Select(r => "'" + PsEnvironment.PsQ(r) + "'"));

        sb.AppendLine("  # ONE role group carrying every role the plan needs");
        EmitRoleGroupEnsure(sb, scope, groupName, roleList, justification, memberIdentity);
        sb.AppendLine("  $members = @((Get-RoleGroupMember -Identity $groupName" +
                      " -ErrorAction SilentlyContinue) | ForEach-Object { $_.Name })");
        sb.AppendLine("  $payload = [pscustomobject]@{ ok = $true; roleGroup = $groupName; " +
                      "roles = $finalRoles; created = $created; reused = $reused; members = $members }");
        Epilogue(sb);
        return Guarded(sb);
    }

    /// <summary>
    /// Ensures a role group exists carrying EXACTLY the wanted roles, adds the member, and
    /// then READS THE RESULT BACK and fails if it does not match.
    ///
    /// This is shared because the two grant paths had drifted apart, and the gap granted
    /// real access. The single-role path checked only whether a group of that NAME existed
    /// and reused it unconditionally — so an operator-named group that already carried 64
    /// management roles (Mailbox Import Export, Mailbox Search, Legal Hold, Move Mailboxes)
    /// was silently adopted for a request needing one cmdlet. Worse, its payload reported
    /// the INTENDED role from C# rather than the group's actual contents, so the audit
    /// record showed the narrow grant that was meant while the tenant held the wide one
    /// that happened.
    ///
    /// The multi-role path checked contents but asked only whether anything was MISSING.
    /// A group carrying the wanted role plus sixty others has nothing missing, so it too
    /// would have been reused.
    ///
    /// So the test is set EQUALITY, in both directions:
    ///   missing -> the group cannot do the job
    ///   extra   -> the group grants more than was approved, which is the whole failure
    ///              this application exists to prevent
    /// Either way the group is unusable and a fresh suffixed one is created instead. Role
    /// group membership is fixed at creation — there is no Set-RoleGroup -Roles — so
    /// correcting one in place is not an option.
    ///
    /// Leaves $groupName and $finalRoles set for the caller's payload.
    /// </summary>
    private void EmitRoleGroupEnsure(
        StringBuilder sb, RbacScope scope, string groupName, string roleListPs,
        string justification, string memberIdentity)
    {
        sb.AppendLine("  $groupName = '" + PsEnvironment.PsQ(groupName) + "'");
        sb.AppendLine("  $wanted = @(" + roleListPs + ")");
        sb.AppendLine("  $desc = '" + PsEnvironment.PsQ(Marker + ". " + justification) + "'");
        sb.AppendLine("  function Get-AcRoleNames($g) {");
        sb.AppendLine("    return @($g.Roles | ForEach-Object { $_.ToString().Split('\\')[-1] })");
        sb.AppendLine("  }");

        sb.AppendLine("  $group = Get-RoleGroup -Identity $groupName -ErrorAction SilentlyContinue");
        sb.AppendLine("  if (-not $group) {");
        sb.AppendLine("    New-RoleGroup -Name $groupName -Roles $wanted -Description $desc | Out-Null");
        sb.AppendLine("  } else {");
        sb.AppendLine("    $have = Get-AcRoleNames $group");
        sb.AppendLine("    $missing = @($wanted | Where-Object { $have -notcontains $_ })");
        sb.AppendLine("    $extra   = @($have | Where-Object { $wanted -notcontains $_ })");
        sb.AppendLine("    if ($missing.Count -eq 0 -and $extra.Count -eq 0) {");
        sb.AppendLine("      [Console]::Out.WriteLine('###PROGRESS###role group already carries exactly the needed role(s); adding the member')");
        sb.AppendLine("    } else {");
        sb.AppendLine("      [Console]::Out.WriteLine('###PROGRESS###existing group ' + $groupName + ' carries ' + $have.Count + ' role(s), ' + $extra.Count + ' more than approved - it will NOT be reused')");
        sb.AppendLine("      $base = $groupName");
        sb.AppendLine("      $picked = $null");
        sb.AppendLine("      foreach ($i in 2..20) {");
        sb.AppendLine("        $tag = ' (' + $i + ')'");
        sb.AppendLine("        $candidate = $base");
        sb.AppendLine("        if (($candidate.Length + $tag.Length) -gt 64) {");
        sb.AppendLine("          $candidate = $candidate.Substring(0, 64 - $tag.Length)");
        sb.AppendLine("        }");
        sb.AppendLine("        $candidate = $candidate + $tag");
        sb.AppendLine("        $found = Get-RoleGroup -Identity $candidate -ErrorAction SilentlyContinue");
        sb.AppendLine("        if (-not $found) {");
        sb.AppendLine("          New-RoleGroup -Name $candidate -Roles $wanted -Description $desc | Out-Null");
        sb.AppendLine("          $picked = $candidate; break");
        sb.AppendLine("        }");
        sb.AppendLine("        $fHave = Get-AcRoleNames $found");
        sb.AppendLine("        $fMissing = @($wanted | Where-Object { $fHave -notcontains $_ })");
        sb.AppendLine("        $fExtra   = @($fHave | Where-Object { $wanted -notcontains $_ })");
        sb.AppendLine("        if ($fMissing.Count -eq 0 -and $fExtra.Count -eq 0) { $picked = $candidate; break }");
        sb.AppendLine("      }");
        sb.AppendLine("      if (-not $picked) {");
        sb.AppendLine("        throw 'Could not find or create a role group carrying exactly the approved role(s) after 20 attempts. Remove the unused ACG- groups for this grant and re-run. Nothing was granted.'");
        sb.AppendLine("      }");
        sb.AppendLine("      $groupName = $picked");
        sb.AppendLine("    }");
        sb.AppendLine("  }");

        sb.AppendLine("  Add-RoleGroupMember -Identity $groupName" +
                      " -Member '" + PsEnvironment.PsQ(memberIdentity) +
                      "'" + BypassSwitch(scope) + " -ErrorAction Stop");

        // CREATION SUCCEEDING IS AN ATTEMPT; THIS IS THE RESULT. Everything above reasons
        // about what SHOULD be there. Only this reads what IS, and it is the last point at
        // which an over-grant can still be caught by the app rather than by an auditor.
        sb.AppendLine("  $final = Get-RoleGroup -Identity $groupName");
        sb.AppendLine("  $finalRoles = Get-AcRoleNames $final");
        sb.AppendLine("  $verifyExtra = @($finalRoles | Where-Object { $wanted -notcontains $_ })");
        sb.AppendLine("  if ($verifyExtra.Count -gt 0) {");
        sb.AppendLine("    Remove-RoleGroupMember -Identity $groupName -Member '" +
                      PsEnvironment.PsQ(memberIdentity) + "'" + BypassSwitch(scope) +
                      " -Confirm:$false -ErrorAction SilentlyContinue");
        sb.AppendLine("    throw 'OVER-GRANT BLOCKED: role group ' + $groupName + ' carries ' + " +
                      "$verifyExtra.Count + ' role(s) beyond what was approved (' + " +
                      "($verifyExtra -join ', ') + '). The member has been removed again and " +
                      "nothing was granted.'");
        sb.AppendLine("  }");
    }

    /// <summary>
    /// Removes MANY memberships in ONE session, and distinguishes "already gone" from
    /// "failed".
    ///
    /// Two problems with doing them one at a time, both seen on a real run:
    ///
    /// COST. Every RunAsync starts a PowerShell process and reconnects to Exchange —
    /// roughly thirty seconds. Three expired grants took a minute and a half; fifty would
    /// take twenty-five minutes, inside a scheduled task with a one-hour ceiling.
    ///
    /// CLASSIFICATION. A role group deleted by hand reports "object couldn't be found",
    /// which was counted as a failure. But the access IS revoked — that is the outcome
    /// housekeeping wanted. Treating it as a failure meant the record was never closed,
    /// every later run retried it, and the exit code stayed non-zero forever. A scheduled
    /// task that always reports failure is a scheduled task nobody reads, so a genuine
    /// failure would have been lost in the noise.
    ///
    /// Returns results[] with state = removed | alreadyGone | failed, per membership.
    /// </summary>
    public string BuildRemoveMembersScript(
        RbacScope scope, IReadOnlyList<(string Group, string Member)> removals)
    {
        var sb = new StringBuilder();
        Prologue(sb, scope);
        sb.AppendLine("  $results = @()");

        foreach (var (group, member) in removals)
        {
            var g = PsEnvironment.PsQ(group);
            var m = PsEnvironment.PsQ(member);
            sb.AppendLine("  try {");
            sb.AppendLine("    Remove-RoleGroupMember -Identity '" + g + "' -Member '" + m +
                          "'" + BypassSwitch(scope) + " -Confirm:$false -ErrorAction Stop");
            sb.AppendLine("    $results += [pscustomobject]@{ group = '" + g + "'; member = '" + m +
                          "'; state = 'removed'; error = '' }");
            sb.AppendLine("  } catch {");
            sb.AppendLine("    $m = $_.Exception.Message");
            // The apostrophe in "couldn't" is not always the ASCII one, so wildcard across
            // it rather than matching the exact phrase.
            sb.AppendLine("    if ($m -like '*couldn*t be found*' -or $m -like '*not found*' " +
                          "-or $m -like '*ManagementObjectNotFound*' -or $m -like '*isn*t a member*') {");
            sb.AppendLine("      $results += [pscustomobject]@{ group = '" + g + "'; member = '" + m +
                          "'; state = 'alreadyGone'; error = $m }");
            sb.AppendLine("    } else {");
            sb.AppendLine("      $results += [pscustomobject]@{ group = '" + g + "'; member = '" + m +
                          "'; state = 'failed'; error = $m }");
            sb.AppendLine("    }");
            sb.AppendLine("  }");
        }

        sb.AppendLine("  $payload = [pscustomobject]@{ ok = $true; results = $results }");
        Epilogue(sb);
        return Guarded(sb);
    }

    public string BuildRemoveMemberScript(RbacScope scope, string groupName, string memberIdentity)
    {
        var sb = new StringBuilder();
        Prologue(sb, scope);
        sb.AppendLine("  Remove-RoleGroupMember -Identity '" + PsEnvironment.PsQ(groupName) +
                      "' -Member '" + PsEnvironment.PsQ(memberIdentity) +
                      "'" + BypassSwitch(scope) + " -Confirm:$false -ErrorAction Stop");
        sb.AppendLine("  $payload = [pscustomobject]@{ ok = $true }");
        Epilogue(sb);
        return Guarded(sb);
    }

    /// <summary>Lists AccessCheck role groups with their member counts, for housekeeping.</summary>
    public string BuildListAlGroupsScript(RbacScope scope)
    {
        var sb = new StringBuilder();
        Prologue(sb, scope);
        sb.AppendLine("  $groups = @(Get-RoleGroup | Where-Object { $_.Description -like '*" +
                      Marker + "*' } | ForEach-Object {");
        sb.AppendLine("    [pscustomobject]@{ name = $_.Name; roles = @($_.Roles | ForEach-Object { [string]$_ });");
        sb.AppendLine("      members = @($_.Members | ForEach-Object { [string]$_ }) }");
        sb.AppendLine("  })");
        sb.AppendLine("  $payload = [pscustomobject]@{ ok = $true; groups = $groups }");
        Epilogue(sb);
        return Guarded(sb);
    }

    public string BuildDeleteGroupAndRoleScript(
        RbacScope scope, string groupName, string? derivedRoleName)
    {
        var sb = new StringBuilder();
        Prologue(sb, scope);
        sb.AppendLine("  Remove-RoleGroup -Identity '" + PsEnvironment.PsQ(groupName) +
                      "'" + BypassSwitch(scope) + " -Confirm:$false -ErrorAction Stop");
        if (!string.IsNullOrWhiteSpace(derivedRoleName))
        {
            sb.AppendLine("  Remove-ManagementRole -Identity '" + PsEnvironment.PsQ(derivedRoleName) +
                          "' -Confirm:$false -ErrorAction SilentlyContinue");
        }
        sb.AppendLine("  $payload = [pscustomobject]@{ ok = $true }");
        Epilogue(sb);
        return Guarded(sb);
    }

    // ---------- execution ----------

    public async Task<JsonDocument> RunAsync(string script, CancellationToken ct = default)
    {
        var result = await _runner.RunAsync(script, TimeSpan.FromMinutes(20), ct);
        var json = result.JsonPayload
            ?? throw new InvalidOperationException(
                "PowerShell produced no JSON result. stderr: " + Head(result.StdErr));
        var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.False)
        {
            var err = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : "unknown";
            doc.Dispose();
            throw new InvalidOperationException("PowerShell step failed: " + err);
        }
        return doc;
    }

    // ---------- shared script scaffolding ----------

    private void Prologue(StringBuilder sb, RbacScope scope)
    {
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        sb.AppendLine("$ProgressPreference = 'SilentlyContinue'");
        sb.AppendLine("try {");
        sb.AppendLine("  Import-Module ExchangeOnlineManagement -ErrorAction Stop");
        sb.Append(_env.ConnectBlock(scope, _upn));
    }

    private static void Epilogue(StringBuilder sb)
    {
        sb.AppendLine("  Write-Output '###JSON-BEGIN###'");
        sb.AppendLine("  Write-Output ($payload | ConvertTo-Json -Depth 5 -Compress)");
        sb.AppendLine("  Write-Output '###JSON-END###'");
        sb.AppendLine("} catch {");
        sb.AppendLine("  $err = [pscustomobject]@{ ok = $false; error = $_.Exception.Message }");
        sb.AppendLine("  Write-Output '###JSON-BEGIN###'");
        sb.AppendLine("  Write-Output ($err | ConvertTo-Json -Compress)");
        sb.AppendLine("  Write-Output '###JSON-END###'");
        sb.AppendLine("  exit 1");
        sb.AppendLine("}");
    }

    private static string Head(string s) => s.Length <= 400 ? s : s[..400];
    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];
}
