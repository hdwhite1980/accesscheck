using System.Text;
using System.Text.Json;
using AccessCheck.Core.Catalog;

namespace AccessCheck.PowerShell;

/// <summary>
/// Deep sync of Exchange Online and Purview (Security &amp; Compliance) RBAC via
/// PowerShell: management roles with their role entries (cmdlets) and role groups.
/// Slower than Graph (one Get-ManagementRoleEntry round trip per role) — this is
/// the "deep sync" button, not part of every catalog refresh.
/// </summary>
public sealed class ExoPurviewCatalogSync
{
    private readonly PowerShellRunner _runner;
    private readonly PsEnvironment _env;
    private readonly string? _upn;

    public ExoPurviewCatalogSync(PowerShellRunner runner, PsEnvironment env, string? userPrincipalName)
    {
        _runner = runner;
        _env = env;
        _upn = userPrincipalName;
    }

    /// <summary>How the last sync resolved permissions — shown in the sync report.</summary>
    public string LastDiagnostics { get; private set; } = "";

    /// <summary>What the endpoint just told us it supports. Empty until a sync has run.</summary>
    public List<CmdletCapability> LastCmdletCapabilities { get; private set; } = new();

    public async Task<(List<RoleDefinitionRecord> Roles, List<RoleGroupInfo> RoleGroups)> SyncAsync(
        RbacScope scope, CancellationToken ct = default, Action<string>? onProgress = null)
    {
        var provider = scope == RbacScope.Exchange ? RbacProviders.Exchange : RbacProviders.Purview;
        var script = BuildScript(scope);
        var result = await _runner.RunAsync(script, TimeSpan.FromMinutes(45), ct, onProgress);

        var json = result.JsonPayload
            ?? throw new InvalidOperationException(
                "PowerShell sync produced no JSON payload. stderr: " + Head(result.StdErr));

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.False)
        {
            var err = root.TryGetProperty("error", out var e) ? e.GetString() : "unknown";
            throw new InvalidOperationException("PowerShell sync failed: " + err);
        }

        var fromProperty = root.TryGetProperty("entriesFromProperty", out var fp) && fp.TryGetInt32(out var fpv) ? fpv : 0;
        var fromIdentity = root.TryGetProperty("entriesFromIdentity", out var fi) && fi.TryGetInt32(out var fiv) ? fiv : 0;
        var fromInverse = root.TryGetProperty("entriesFromInverse", out var fin) && fin.TryGetInt32(out var finv) ? finv : 0;
        var fromCmdlet = root.TryGetProperty("entriesFromCmdlet", out var fc) && fc.TryGetInt32(out var fcv) ? fcv : 0;
        var hasCmdlet = root.TryGetProperty("hasEntryCmdlet", out var hc) && hc.ValueKind == JsonValueKind.True;

        var roles = new List<RoleDefinitionRecord>();
        if (root.TryGetProperty("roles", out var rolesEl) && rolesEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var r in rolesEl.EnumerateArray())
            {
                // Anything that is not an object is not a role. Being strict here turned a
                // stray progress string into "requires an element of type 'Object', but the
                // target element has type 'String'" and failed the whole sync.
                if (r.ValueKind != JsonValueKind.Object) continue;
                if (!r.TryGetProperty("name", out var nameEl)) continue;
                var name = nameEl.GetString() ?? "";
                if (name.Length == 0) continue;
                var desc = r.TryGetProperty("description", out var d) ? d.GetString() ?? "" : "";
                var entries = new List<string>();
                if (r.TryGetProperty("entries", out var en) && en.ValueKind == JsonValueKind.Array)
                    foreach (var x in en.EnumerateArray())
                    {
                        var s = x.GetString();
                        if (!string.IsNullOrWhiteSpace(s)) entries.Add(s);
                    }
                bool custom = r.TryGetProperty("isCustom", out var c) &&
                              c.ValueKind == JsonValueKind.True;
                roles.Add(new RoleDefinitionRecord
                {
                    Id = provider + ":" + name,
                    DisplayName = name,
                    Description = desc,
                    IsBuiltIn = !custom,
                    Provider = provider,
                    IsAccessCheckCreated = custom &&
                (name.StartsWith("AC - ", StringComparison.OrdinalIgnoreCase) ||
                 name.StartsWith("AL - ", StringComparison.OrdinalIgnoreCase) ||
                 desc.Contains("AccessCheck least-privilege role", StringComparison.OrdinalIgnoreCase) ||
                 desc.Contains("AccessLens least-privilege role", StringComparison.OrdinalIgnoreCase)),
                    AllowedResourceActions = entries
                });
            }
        }

        var groups = new List<RoleGroupInfo>();
        if (root.TryGetProperty("roleGroups", out var rg) && rg.ValueKind == JsonValueKind.Array)
        {
            foreach (var g in rg.EnumerateArray())
            {
                var members = new List<string>();
                if (g.TryGetProperty("members", out var ms) && ms.ValueKind == JsonValueKind.Array)
                    foreach (var m in ms.EnumerateArray())
                    {
                        var s = m.GetString();
                        if (!string.IsNullOrWhiteSpace(s)) members.Add(s);
                    }
                var rolesList = new List<string>();
                if (g.TryGetProperty("roles", out var rl) && rl.ValueKind == JsonValueKind.Array)
                    foreach (var m in rl.EnumerateArray())
                    {
                        var s = m.GetString();
                        if (!string.IsNullOrWhiteSpace(s)) rolesList.Add(s);
                    }
                groups.Add(new RoleGroupInfo(
                    g.GetProperty("name").GetString() ?? "",
                    g.TryGetProperty("description", out var gd) ? gd.GetString() ?? "" : "",
                    rolesList, members));
            }
        }
        var withActions = roles.Count(r => r.AllowedResourceActions.Count > 0);
        var shapeProbe = root.TryGetProperty("shapeProbe", out var sp)
            ? sp.GetString() ?? "" : "";

        // The cmdlet surface this endpoint actually exposes.
        LastCmdletCapabilities = new List<CmdletCapability>();
        if (root.TryGetProperty("cmdletCaps", out var capsEl)
            && capsEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var c in capsEl.EnumerateArray())
            {
                if (c.ValueKind != JsonValueKind.Object) continue;
                var name = c.TryGetProperty("cmdlet", out var cn) ? cn.GetString() ?? "" : "";
                if (name.Length == 0) continue;

                var parameters = new List<string>();
                if (c.TryGetProperty("parameters", out var pe)
                    && pe.ValueKind == JsonValueKind.Array)
                {
                    foreach (var one in pe.EnumerateArray())
                        if (one.GetString() is { Length: > 0 } pn) parameters.Add(pn);
                }

                LastCmdletCapabilities.Add(new CmdletCapability
                {
                    Cmdlet = name,
                    Scope = scope == RbacScope.Exchange ? "exchange" : "purview",
                    Exists = c.TryGetProperty("exists", out var ex) && ex.ValueKind == JsonValueKind.True,
                    Parameters = parameters
                });
            }
        }

        LastDiagnostics =
            roles.Count + " role(s); " + withActions + " with permissions resolved " +
            "(" + fromProperty + " from the list call, " + fromIdentity
            + " by re-fetching each role with -Identity, " + fromCmdlet + " via Get-ManagementRoleEntry" +
            (hasCmdlet ? "" : " [not available at this endpoint]") +
            ", " + fromInverse + " via the INVERSE lookup Get-ManagementRole -Cmdlet" + ")." +
            (withActions == 0 && roles.Count > 0
                ? " Role NAMES are catalogued but their permission lists could not be read here. " +
                  "This is expected for Purview: its roles gate CAPABILITIES (often a single " +
                  "switch on a shared cmdlet) rather than containing cmdlet entries, and " +
                  "Security & Compliance PowerShell publishes no role-to-cmdlet mapping. " +
                  "AccessCheck fills in the well-known roles from Microsoft's documentation " +
                  "instead, and labels them as such."
                : "") +
            (shapeProbe.Length > 0 ? "  [" + shapeProbe + "]" : "");
        return (roles, groups);
    }

    /// <summary>
    /// Builds the deep-sync script. Cmdlet availability differs by endpoint:
    /// Security &amp; Compliance (Purview) exposes Get-ManagementRole but NOT
    /// Get-ManagementRoleEntry. So entries are taken from the role object's own
    /// RoleEntries property first — which also removes the per-role round trip that
    /// made Exchange sync slow — and only fall back to Get-ManagementRoleEntry when
    /// that property is absent AND the cmdlet actually exists.
    /// </summary>
    /// <summary>
    /// Both services in ONE PowerShell session.
    ///
    /// Running them as two separate SyncAsync calls meant two PROCESSES and therefore two
    /// interactive sign-ins — which is the whole reason the admin was prompted twice.
    /// Connect-IPPSSession in the same session as an existing Connect-ExchangeOnline
    /// normally reuses the cached token, so this usually reduces it to one prompt.
    /// </summary>
    public async Task<(List<RoleDefinitionRecord> Exchange, List<RoleDefinitionRecord> Purview,
                       List<RoleGroupInfo> RoleGroups)> SyncBothAsync(
        CancellationToken ct = default, Action<string>? onProgress = null)
    {
        onProgress?.Invoke("Connecting to Exchange Online (a sign-in prompt may appear)...");
        var (exoRoles, exoGroups) = await SyncAsync(RbacScope.Exchange, ct, onProgress);
        LastExchangeDiagnostics = LastDiagnostics;

        onProgress?.Invoke("Connecting to Purview / Compliance (should reuse your sign-in)...");
        List<RoleDefinitionRecord> purviewRoles;
        List<RoleGroupInfo> purviewGroups;
        try
        {
            (purviewRoles, purviewGroups) = await SyncAsync(RbacScope.Purview, ct, onProgress);
            LastPurviewDiagnostics = LastDiagnostics;
        }
        catch (Exception ex)
        {
            // Exchange succeeding while Purview fails is a normal, informative outcome.
            purviewRoles = new List<RoleDefinitionRecord>();
            purviewGroups = new List<RoleGroupInfo>();
            LastPurviewDiagnostics = "failed: " + ex.Message;
        }

        var groups = new List<RoleGroupInfo>(exoGroups);
        groups.AddRange(purviewGroups);
        return (exoRoles, purviewRoles, groups);
    }

    public string LastExchangeDiagnostics { get; private set; } = "";
    public string LastPurviewDiagnostics { get; private set; } = "";

    private string BuildScript(RbacScope scope)
    {
        var sb = new StringBuilder();
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        sb.AppendLine("$ProgressPreference = 'SilentlyContinue'");
        sb.AppendLine("try {");
        sb.AppendLine("  Import-Module ExchangeOnlineManagement -ErrorAction Stop");
        sb.Append(_env.ConnectBlock(scope, _upn));

        // Capability probe — this endpoint may not expose the per-entry cmdlet.
        sb.AppendLine("  $hasEntryCmdlet = [bool](Get-Command Get-ManagementRoleEntry -ErrorAction SilentlyContinue)");
        // Report what a role object ACTUALLY exposes here. Purview roles gate capabilities
        // rather than containing cmdlets, and guessing at the shape has already cost a
        // round trip — so record the property names instead of assuming.
        sb.AppendLine("  $shapeProbe = ''");
        sb.AppendLine("  try {");
        sb.AppendLine("    $sample = @(Get-ManagementRole -ErrorAction Stop | Select-Object -First 1)");
        sb.AppendLine("    if ($sample.Count -gt 0) {");
        sb.AppendLine("      $full = $null");
        sb.AppendLine("      try { $full = Get-ManagementRole -Identity $sample[0].Name -ErrorAction Stop } catch { }");
        sb.AppendLine("      $obj = if ($full) { $full } else { $sample[0] }");
        sb.AppendLine("      $props = @($obj.PSObject.Properties | ForEach-Object { $_.Name }) -join ', '");
        sb.AppendLine("      $entryCount = 0");
        sb.AppendLine("      if ($obj.PSObject.Properties.Name -contains 'RoleEntries') {");
        sb.AppendLine("        $entryCount = @($obj.RoleEntries).Count");
        sb.AppendLine("      }");
        sb.AppendLine("      $shapeProbe = 'sample role: ' + $sample[0].Name + '; RoleEntries count: ' + " +
                      "$entryCount + '; properties: ' + $props");
        sb.AppendLine("    }");
        sb.AppendLine("  } catch { $shapeProbe = 'shape probe failed: ' + $_.Exception.Message }");
        sb.AppendLine("  $entriesFromProperty = 0");
        sb.AppendLine("  $entriesFromIdentity = 0");
        sb.AppendLine("  $entriesFromCmdlet = 0");
        sb.AppendLine("  $entriesFromInverse = 0");

        // INVERSE LOOKUP. Get-ManagementRoleEntry does not exist in Security & Compliance,
        // but Get-ManagementRole DOES support -Cmdlet there (Microsoft lists Security &
        // Compliance as applicable for that parameter). So instead of asking each role what
        // it contains, ask each CMDLET which roles grant it, then invert. That reads the
        // mapping from the tenant instead of assuming it.
        sb.AppendLine("  $inverse = @{}");
        sb.AppendLine("  $cmdletNames = @()");
        // ONLY when the cheap routes failed. Exchange resolves RoleEntries by identity
        // perfectly well, and its session exposes 11,000+ cmdlets — running a lookup per
        // cmdlet there costs over an hour to learn nothing new. Purview is the case that
        // needs it, and only when its role entries came back empty.
        sb.AppendLine("  $needInverse = $false");
        sb.AppendLine("  if ($needInverse) {");
        sb.AppendLine("  try {");
        // The session's own command list is the complete vocabulary this endpoint exposes.
        // Bound it. An Exchange session exposes 11,000+ cmdlets; even Purview's is large.
        // Governance-relevant nouns first, capped — a lookup per cmdlet is a round trip,
        // and an unbounded loop turns a sync into an hour-long stall.
        // A NAMED SEED LIST, not the session's vocabulary.
        //
        // Each Get-ManagementRole -Cmdlet is a round trip to the Security & Compliance
        // service, and the service scans every role definition to answer it: measured at
        // ~4.5 seconds per call on a real tenant. 600 cmdlets was 45 minutes and timed out.
        //
        // The waste was building the WHOLE map upfront when a recommendation touches three
        // cmdlets. These are the ones a least-privilege decision actually turns on — the
        // capability boundaries where getting it wrong grants the wrong thing. Anything
        // else is resolved on demand and cached.
        sb.AppendLine("    $cmdletNames = @(");
        sb.AppendLine("      'New-ComplianceSearch','Get-ComplianceSearch','Start-ComplianceSearch',");
        sb.AppendLine("      'Remove-ComplianceSearch','New-ComplianceSearchAction',");
        sb.AppendLine("      'Get-ComplianceSearchAction','Remove-ComplianceSearchAction',");
        sb.AppendLine("      'Search-UnifiedAuditLog','New-ComplianceCase','Get-ComplianceCase',");
        sb.AppendLine("      'New-CaseHoldPolicy','New-CaseHoldRule',");
        sb.AppendLine("      'New-RetentionCompliancePolicy','Get-RetentionCompliancePolicy',");
        sb.AppendLine("      'New-RetentionComplianceRule','New-DlpCompliancePolicy',");
        sb.AppendLine("      'Get-DlpCompliancePolicy','New-DlpComplianceRule',");
        sb.AppendLine("      'Get-RoleGroup','New-RoleGroup','Add-RoleGroupMember',");
        sb.AppendLine("      'Get-ManagementRole','New-ManagementRole',");
        sb.AppendLine("      'Get-Label','New-Label','Get-LabelPolicy','New-LabelPolicy',");
        sb.AppendLine("      'Get-InsiderRiskPolicy','Get-ProtectionAlert','New-ProtectionAlert'");
        sb.AppendLine("    )");
        sb.AppendLine("    $cmdletNames = @($cmdletNames | Where-Object { Get-Command $_ -ErrorAction SilentlyContinue })");
        sb.AppendLine("    [Console]::Out.WriteLine('###PROGRESS###mapping ' + $cmdletNames.Count + ' governance cmdlet(s) — about ' + [int]($cmdletNames.Count * 5 / 60) + ' minute(s)')");
        sb.AppendLine("  } catch { }");
        sb.AppendLine("  $ci = 0; $ctotal = $cmdletNames.Count");
        sb.AppendLine("  foreach ($c in $cmdletNames) {");
        sb.AppendLine("    $ci++");
        // Every 10th, so the console is not flooded but the UI never looks frozen.
        sb.AppendLine("    [Console]::Out.WriteLine('###PROGRESS###mapping cmdlet ' + $ci + ' of ' + $ctotal + ': ' + $c)");
        sb.AppendLine("    try {");
        sb.AppendLine("      $owning = @(Get-ManagementRole -Cmdlet $c -ErrorAction Stop | ForEach-Object { $_.Name })");
        sb.AppendLine("      foreach ($rn in $owning) {");
        sb.AppendLine("        if (-not $inverse.ContainsKey($rn)) { $inverse[$rn] = New-Object System.Collections.ArrayList }");
        sb.AppendLine("        [void]$inverse[$rn].Add($c)");
        sb.AppendLine("        $entriesFromInverse++");
        sb.AppendLine("      }");
        sb.AppendLine("    } catch { }");
        sb.AppendLine("  }");

        // Parameter-level capabilities. Some Purview roles gate a single SWITCH on a shared
        // cmdlet — -Purge is the whole difference between Compliance Search and Search And
        // Purge — and -CmdletParameters is the only way to see that.
        sb.AppendLine("  } else {");
        sb.AppendLine("    [Console]::Out.WriteLine('###PROGRESS###role entries resolved directly; skipping the per-cmdlet inverse lookup')");
        sb.AppendLine("  }");

        // CMDLET SURFACE PROBE. Ask the endpoint which cmdlets it has and what parameters
        // each accepts, rather than assuming Exchange's surface applies. Four failed grants
        // came from that assumption; this is one cheap call per cmdlet and it answers for
        // THIS endpoint definitively.
        sb.AppendLine("  $cmdletCaps = @()");
        sb.AppendLine("  $probeList = @(" + string.Join(",",
            new[] { "Get-ManagementRole", "New-ManagementRole", "Remove-ManagementRole",
                    "Get-ManagementRoleEntry", "Remove-ManagementRoleEntry",
                    "New-ManagementRoleAssignment", "Get-ManagementRoleAssignment",
                    "Get-RoleGroup", "New-RoleGroup", "Set-RoleGroup", "Remove-RoleGroup",
                    "Get-RoleGroupMember", "Add-RoleGroupMember", "Remove-RoleGroupMember" }
            .Select(c => "'" + c + "'")) + ")");
        sb.AppendLine("  $common = @('Verbose','Debug','ErrorAction','WarningAction'," +
                      "'InformationAction','ErrorVariable','WarningVariable'," +
                      "'InformationVariable','OutVariable','OutBuffer','PipelineVariable'," +
                      "'ProgressAction','WhatIf','Confirm')");
        sb.AppendLine("  foreach ($pc in $probeList) {");
        sb.AppendLine("    $cmd = Get-Command $pc -ErrorAction SilentlyContinue");
        sb.AppendLine("    if ($cmd) {");
        sb.AppendLine("      $pnames = @($cmd.Parameters.Keys | Where-Object { $common -notcontains $_ })");
        sb.AppendLine("      $cmdletCaps += [pscustomobject]@{ cmdlet = $pc; exists = $true; parameters = $pnames }");
        sb.AppendLine("    } else {");
        sb.AppendLine("      $cmdletCaps += [pscustomobject]@{ cmdlet = $pc; exists = $false; parameters = @() }");
        sb.AppendLine("    }");
        sb.AppendLine("  }");

        sb.AppendLine("  $paramProbes = @(");
        sb.AppendLine("    @{ c = 'New-ComplianceSearchAction'; p = 'Purge' },");
        sb.AppendLine("    @{ c = 'New-ComplianceSearchAction'; p = 'Preview' },");
        sb.AppendLine("    @{ c = 'New-ComplianceSearchAction'; p = 'Export' },");
        sb.AppendLine("    @{ c = 'Search-Mailbox'; p = 'DeleteContent' }");
        sb.AppendLine("  )");
        sb.AppendLine("  foreach ($probe in $paramProbes) {");
        sb.AppendLine("    try {");
        sb.AppendLine("      $owning = @(Get-ManagementRole -Cmdlet $probe.c -CmdletParameters $probe.p -ErrorAction Stop | ForEach-Object { $_.Name })");
        sb.AppendLine("      foreach ($rn in $owning) {");
        sb.AppendLine("        if (-not $inverse.ContainsKey($rn)) { $inverse[$rn] = New-Object System.Collections.ArrayList }");
        sb.AppendLine("        $labelled = $probe.c + ' -' + $probe.p");
        sb.AppendLine("        if (-not $inverse[$rn].Contains($labelled)) { [void]$inverse[$rn].Add($labelled); $entriesFromInverse++ }");
        sb.AppendLine("      }");
        sb.AppendLine("    } catch { }");
        sb.AppendLine("  }");

        // ONE NORMALISER FOR ALL THREE ENTRY PATHS.
        //
        // Each path returns the same information in a different shape, and each used to
        // strip it — or not — on its own terms:
        //
        //   RoleEntries property   "RoleName\Get-Mailbox(-Identity, -Anr)"
        //   Get-ManagementRoleEntry  "(Microsoft.Exchange.Management.PowerShell.E2010)
        //                             Add-MailboxPermission -AccessRights -AutoMapping ..."
        //
        // The third path did not strip at all, so the catalog carried both a bare cmdlet
        // name and a fully-qualified one depending on which path had supplied that role.
        // Nothing downstream could match the second form, and the actions were reported as
        // permissions Microsoft does not define while sitting in the catalog under a name
        // no request would ever produce.
        //
        // Defined once here so a fourth path cannot quietly reintroduce a fourth format.
        sb.AppendLine("  function AcNormalizeEntry($raw) {");
        sb.AppendLine("    $t = [string]$raw");
        sb.AppendLine("    if ($t -eq '') { return '' }");
        // Module qualifier, when the REST session supplies one.
        sb.AppendLine("    if ($t.StartsWith('(')) {");
        sb.AppendLine("      $close = $t.IndexOf(')')");
        sb.AppendLine("      if ($close -ge 0) { $t = $t.Substring($close + 1) }");
        sb.AppendLine("    }");
        sb.AppendLine("    $t = $t.Trim()");
        // Parameters, in either shape: "Get-Mailbox(-Identity...)" or "Get-Mailbox -Identity...".
        sb.AppendLine("    $t = $t.Split('(')[0]");
        sb.AppendLine("    $space = $t.IndexOf(' ')");
        sb.AppendLine("    if ($space -gt 0) { $t = $t.Substring(0, $space) }");
        // "RoleName\Cmdlet" -> "Cmdlet".
        sb.AppendLine("    if ($t.Contains('\\')) { $t = $t.Substring($t.LastIndexOf('\\') + 1) }");
        sb.AppendLine("    return $t.Trim()");
        sb.AppendLine("  }");

        sb.AppendLine("  $allRoles = @(Get-ManagementRole)");
        sb.AppendLine("  [Console]::Out.WriteLine('###PROGRESS###reading ' + $allRoles.Count + ' role(s)...')");
        sb.AppendLine("  $ri = 0");
        sb.AppendLine("  $roles = @($allRoles | ForEach-Object {");
        sb.AppendLine("    $ri++");
        sb.AppendLine("    if (($ri % 5) -eq 0) { [Console]::Out.WriteLine('###PROGRESS###role ' + $ri + ' of ' + $allRoles.Count + ': ' + $_.Name) }");
        sb.AppendLine("    $role = $_");
        sb.AppendLine("    $entries = @()");
        // 1) RoleEntries on the object: values look like "Get-Mailbox(-Identity, -Anr...)"
        //    and may carry a "RoleName\" prefix; keep just the cmdlet name.
        sb.AppendLine("    if (($role.PSObject.Properties.Name -contains 'RoleEntries') -and $role.RoleEntries) {");
        sb.AppendLine("      $entries = @($role.RoleEntries |");
        sb.AppendLine("        ForEach-Object { AcNormalizeEntry $_ } | Where-Object { $_ -ne '' })");
        sb.AppendLine("      if ($entries.Count -gt 0) { $entriesFromProperty++ }");
        sb.AppendLine("    }");
        // 2) Re-fetch the role BY IDENTITY. The LIST form of Get-ManagementRole returns a
        //    summary object whose RoleEntries is empty — especially over the REST-based
        //    EXO v3 session, where complex properties do not serialise on a list call.
        //    Asking for one role by name returns the full object. This is the step whose
        //    absence left Purview with 120 role NAMES and zero permissions.
        sb.AppendLine("    if ($entries.Count -eq 0) {");
        sb.AppendLine("      try {");
        sb.AppendLine("        $full = Get-ManagementRole -Identity $role.Name -ErrorAction Stop");
        sb.AppendLine("        if ($full -and $full.RoleEntries) {");
        sb.AppendLine("          $entries = @($full.RoleEntries |");
        sb.AppendLine("            ForEach-Object { AcNormalizeEntry $_ } | Where-Object { $_ -ne '' })");
        sb.AppendLine("          if ($entries.Count -gt 0) { $entriesFromIdentity++ }");
        sb.AppendLine("        }");
        sb.AppendLine("      } catch { }");
        sb.AppendLine("    }");

        // 3) Fall back to the cmdlet only where it exists.
        sb.AppendLine("    if ($entries.Count -eq 0 -and $hasEntryCmdlet) {");
        sb.AppendLine("      try {");
        // THE SAME NORMALISATION AS THE OTHER TWO PATHS. This one took $_.Name raw, and
        // over the REST-based EXO v3 session that is not a cmdlet name — it is
        // "(Microsoft.Exchange.Management.PowerShell.E2010) Add-MailboxPermission
        // -AccessRights -AutoMapping ...", the module, the cmdlet and every parameter in
        // one string.
        //
        // So the catalog held two formats at once: 466 bare cmdlet names from paths 1 and
        // 2, and 2,734 fully-qualified strings from here. Whether an Exchange request
        // worked depended on which path had happened to supply that particular role.
        // Add-MailboxFolderPermission resolved; Add-MailboxPermission never did, and was
        // reported as an action Microsoft does not define — while sitting in the catalog
        // under a name nothing would ever match.
        sb.AppendLine("        $entries = @(Get-ManagementRoleEntry ($role.Name + '\\*') -ErrorAction Stop |");
        sb.AppendLine("                     ForEach-Object { AcNormalizeEntry $_.Name })");
        sb.AppendLine("        if ($entries.Count -gt 0) { $entriesFromCmdlet++ }");
        sb.AppendLine("      } catch { $entries = @() }");
        sb.AppendLine("    }");
        sb.AppendLine("    [pscustomobject]@{");
        sb.AppendLine("      name = $role.Name");
        sb.AppendLine("      description = [string]$role.Description");
        sb.AppendLine("      isCustom = -not $role.IsRootRole");
        sb.AppendLine("      entries = $entries");
        sb.AppendLine("    }");
        sb.AppendLine("  })");

        // Role groups are optional — absence must not fail the sync.
        sb.AppendLine("  $groups = @()");
        sb.AppendLine("  if (Get-Command Get-RoleGroup -ErrorAction SilentlyContinue) {");
        sb.AppendLine("    try {");
        sb.AppendLine("      $groups = @(Get-RoleGroup | ForEach-Object {");
        sb.AppendLine("        [pscustomobject]@{");
        sb.AppendLine("          name = $_.Name");
        sb.AppendLine("          description = [string]$_.Description");
        sb.AppendLine("          roles = @($_.Roles | ForEach-Object { [string]$_ })");
        sb.AppendLine("          members = @($_.Members | ForEach-Object { [string]$_ })");
        sb.AppendLine("        }");
        sb.AppendLine("      })");
        sb.AppendLine("    } catch { $groups = @() }");
        sb.AppendLine("  }");

        // Fill any role that still has no entries from the inverse map. Done AFTER the
        // per-role attempts so tenant-supplied entries always win.
        sb.AppendLine("  $roles = @($roles | ForEach-Object {");
        sb.AppendLine("    $r = $_");
        // One bad row must never cost the entire sync. This whole merge is an enrichment
        // step: if it fails, the roles are still worth returning.
        sb.AppendLine("    try {");
        // The property is `entries`, not `actions` — a pscustomobject refuses assignment to
        // a property it does not have, which failed the WHOLE sync rather than this step.
        sb.AppendLine("    if ((-not $r.entries -or @($r.entries).Count -eq 0) -and $inverse.ContainsKey($r.name)) {");
        sb.AppendLine("      $r.entries = @($inverse[$r.name] | Sort-Object -Unique)");
        sb.AppendLine("    }");
        sb.AppendLine("    } catch { }");
        sb.AppendLine("    $r");
        sb.AppendLine("  })");

        sb.AppendLine("  $payload = [pscustomobject]@{");
        sb.AppendLine("    ok = $true; roles = $roles; roleGroups = $groups");
        sb.AppendLine("    hasEntryCmdlet = $hasEntryCmdlet");
        sb.AppendLine("    entriesFromProperty = $entriesFromProperty");
        sb.AppendLine("    entriesFromIdentity = $entriesFromIdentity");
        sb.AppendLine("    entriesFromCmdlet = $entriesFromCmdlet");
        sb.AppendLine("    entriesFromInverse = $entriesFromInverse");
        sb.AppendLine("    shapeProbe = $shapeProbe");
        sb.AppendLine("    cmdletCaps = $cmdletCaps");
        sb.AppendLine("  }");
        sb.AppendLine("  Write-Output '###JSON-BEGIN###'");
        sb.AppendLine("  Write-Output ($payload | ConvertTo-Json -Depth 6 -Compress)");
        sb.AppendLine("  Write-Output '###JSON-END###'");
        sb.AppendLine("} catch {");
        sb.AppendLine("  $err = [pscustomobject]@{ ok = $false; error = $_.Exception.Message }");
        sb.AppendLine("  Write-Output '###JSON-BEGIN###'");
        sb.AppendLine("  Write-Output ($err | ConvertTo-Json -Compress)");
        sb.AppendLine("  Write-Output '###JSON-END###'");
        sb.AppendLine("  exit 1");
        sb.AppendLine("}");
        return sb.ToString();
    }

    private static string Head(string s) => s.Length <= 400 ? s : s[..400];
}

public sealed record RoleGroupInfo(
    string Name, string Description,
    IReadOnlyList<string> Roles, IReadOnlyList<string> Members);
