using AccessCheck.Core.Catalog;

namespace AccessCheck.Core.Recommendation;

/// <summary>
/// What each Purview / Security &amp; Compliance role actually gates.
///
/// WHY THIS IS CURATED RATHER THAN SYNCED. Purview roles are not Exchange-style
/// containers of cmdlets. "Search And Purge" and "Compliance Search" gate CAPABILITIES —
/// often a single parameter on a shared cmdlet — and Security &amp; Compliance PowerShell
/// exposes no readable role-to-cmdlet mapping: Get-ManagementRoleEntry does not exist
/// there, and RoleEntries comes back empty even when a role is fetched by identity.
/// Microsoft documents the mapping in prose on each cmdlet page instead
/// ("In Security &amp; Compliance PowerShell, this parameter is available only in the
/// Search and Purge role").
///
/// So this is transcribed from Microsoft's documentation, NOT read from the tenant, and
/// every consumer must label it that way. It is deliberately small: the well-known roles
/// where being wrong would cost a real grant, not a guess at all 120.
/// </summary>
public static class PurviewRoleMap
{
    public sealed record Capability
    {
        public required string RoleName { get; init; }
        /// <summary>Cmdlets or cmdlet+switch combinations this role permits.</summary>
        public required IReadOnlyList<string> Grants { get; init; }
        public required string Summary { get; init; }
        /// <summary>Where in Microsoft's documentation this came from.</summary>
        public required string Source { get; init; }
    }

    private static readonly Capability[] Known =
    {
        new()
        {
            RoleName = "Compliance Search",
            Grants = new[] { "New-ComplianceSearch", "Get-ComplianceSearch",
                             "Start-ComplianceSearch", "Set-ComplianceSearch",
                             "Remove-ComplianceSearch", "Get-ComplianceSearchAction" },
            Summary = "Create and run content searches across mailboxes and sites, and see "
                    + "the results — but NOT act on them.",
            Source = "New-ComplianceSearch / Get-ComplianceSearchAction cmdlet reference"
        },
        new()
        {
            RoleName = "Search And Purge",
            Grants = new[] { "New-ComplianceSearchAction -Purge" },
            Summary = "Permanently delete the messages a content search found. This is the "
                    + "ONLY role that unlocks the -Purge switch; without it the cmdlet fails "
                    + "with \"A parameter cannot be found that matches parameter name 'Purge'\". "
                    + "Assigned by default only to Organization Management and Data Investigator.",
            Source = "New-ComplianceSearchAction cmdlet reference"
        },
        new()
        {
            RoleName = "Preview",
            Grants = new[] { "New-ComplianceSearchAction -Preview" },
            Summary = "View the items a content search returned. Assigned by default only to "
                    + "the eDiscovery Manager role group.",
            Source = "New-ComplianceSearchAction cmdlet reference"
        },
        new()
        {
            RoleName = "Export",
            Grants = new[] { "New-ComplianceSearchAction -Export" },
            Summary = "Export search results, including to PST. Separate from Preview and "
                    + "from Search And Purge.",
            Source = "New-ComplianceSearchAction cmdlet reference"
        },
        new()
        {
            RoleName = "Case Management",
            Grants = new[] { "New-ComplianceCase", "Get-ComplianceCase", "Set-ComplianceCase",
                             "New-CaseHoldPolicy", "New-CaseHoldRule" },
            Summary = "Create and manage eDiscovery cases and the holds attached to them.",
            Source = "eDiscovery permissions reference"
        },
        new()
        {
            RoleName = "Retention Management",
            Grants = new[] { "New-RetentionCompliancePolicy", "Get-RetentionCompliancePolicy",
                             "New-RetentionComplianceRule", "Set-RetentionCompliancePolicy" },
            Summary = "Create and manage Purview retention policies and rules. NOT the same as "
                    + "Exchange Online's own MRM retention policies.",
            Source = "Purview role reference"
        },
        new()
        {
            RoleName = "DLP Compliance Management",
            Grants = new[] { "New-DlpCompliancePolicy", "Get-DlpCompliancePolicy",
                             "New-DlpComplianceRule", "Set-DlpCompliancePolicy" },
            Summary = "Create and manage data loss prevention policies.",
            Source = "Purview role reference"
        },
        new()
        {
            RoleName = "Audit Logs",
            Grants = new[] { "Search-UnifiedAuditLog", "Get-AdminAuditLogConfig" },
            Summary = "Search the unified audit log. This is Purview, not Exchange Online.",
            Source = "Search-UnifiedAuditLog cmdlet reference"
        }
    };

    /// <summary>Roles that permit a given cmdlet, by documented capability.</summary>
    public static IReadOnlyList<Capability> RolesGranting(string action)
    {
        var cmdlet = ActionDisplay.CmdletName(action) ?? action;
        return Known
            .Where(c => c.Grants.Any(g =>
                g.StartsWith(cmdlet, StringComparison.OrdinalIgnoreCase)
                || g.Contains(cmdlet, StringComparison.OrdinalIgnoreCase)))
            .ToList();
    }

    public static Capability? Find(string roleName) =>
        Known.FirstOrDefault(c => c.RoleName.Equals(roleName, StringComparison.OrdinalIgnoreCase));

    public static IReadOnlyList<Capability> All => Known;

    /// <summary>
    /// Fills in permissions for Purview roles the tenant catalogued by NAME only.
    /// Returns the roles it enriched, so the caller can say how many and from where.
    /// </summary>
    public static int EnrichNameOnlyRoles(RoleCatalog catalog)
    {
        var existing = catalog.RolesFor(RbacProviders.Purview).ToList();

        // SEED, not just enrich. Documentation is the authority on what a Purview
        // permission IS; the tenant only says which roles exist here. Returning early on
        // an empty service left Purview with NO vocabulary at all, so the model was
        // offered Exchange's instead and answered a purge request with a search.
        if (existing.Count == 0)
        {
            var seeded = Known.Select(c => new RoleDefinitionRecord
            {
                Id = "documented:" + c.RoleName.Replace(" ", "-").ToLowerInvariant(),
                DisplayName = c.RoleName,
                Provider = RbacProviders.Purview,
                IsBuiltIn = true,
                Description = c.Summary
                    + "  [from Microsoft's documentation — this role was NOT returned by "
                    + "your tenant, so confirm it exists before granting]",
                AllowedResourceActions = c.Grants.ToList()
            }).ToList();

            catalog.ReplaceProvider(RbacProviders.Purview, seeded);
            return seeded.Count;
        }

        var enriched = 0;
        var rebuilt = new List<RoleDefinitionRecord>(existing.Count);

        foreach (var role in existing)
        {
            // Never overwrite what the tenant actually supplied. Only fill in the blanks.
            if (role.AllowedResourceActions.Count > 0)
            {
                rebuilt.Add(role);
                continue;
            }

            var known = Find(role.DisplayName);
            if (known is null)
            {
                rebuilt.Add(role);
                continue;
            }

            // Records are immutable, so produce a new one rather than mutating.
            rebuilt.Add(role with
            {
                AllowedResourceActions = known.Grants.ToList(),
                Description = string.IsNullOrWhiteSpace(role.Description)
                    ? known.Summary + "  [permissions from Microsoft's documentation, not "
                      + "read from this tenant]"
                    : role.Description
            });
            enriched++;
        }

        if (enriched > 0) catalog.ReplaceProvider(RbacProviders.Purview, rebuilt);
        return enriched;
    }

    /// <summary>Guidance for the model when Purview roles are name-only.</summary>
    public static IReadOnlyList<string> PromptHints()
    {
        var lines = new List<string>
        {
            "- PURVIEW ROLES AND WHAT THEY GATE (from Microsoft's documentation, because "
            + "Security & Compliance PowerShell exposes no role-to-cmdlet mapping):"
        };
        foreach (var capability in Known)
        {
            lines.Add("    " + capability.RoleName + " -> "
                      + string.Join(", ", capability.Grants));
        }
        return lines;
    }
}
