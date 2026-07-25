using AccessCheck.Core.Catalog;

namespace AccessCheck.Core.Recommendation;

/// <summary>
/// Pins cmdlet families to the service that ACTUALLY grants them.
///
/// Exchange Online and Purview expose overlapping cmdlets, so the same string can appear
/// in both slices of the catalog and whichever the candidate list favours wins. That is
/// how a phishing search-and-purge was labelled "Exchange Online": the cmdlets were right,
/// the service was not.
///
/// The distinction is not cosmetic. Microsoft is explicit that the Organization Management
/// role group exists separately in Exchange Online and in Purview, that membership in the
/// Exchange one does NOT grant permission to delete messages, and that without the Search
/// And Purge role in Purview the purge fails with "A parameter cannot be found that matches
/// parameter name 'Purge'". Executing against the wrong service produces a grant that
/// cannot do the job.
/// </summary>
public static class CmdletServiceMap
{
    /// <summary>Cmdlet name (verb-noun) -> the provider that really owns it.</summary>
    private static readonly Dictionary<string, string> Owner = new(StringComparer.OrdinalIgnoreCase)
    {
        // Content search and purge: Security & Compliance PowerShell only.
        ["New-ComplianceSearch"] = RbacProviders.Purview,
        ["Get-ComplianceSearch"] = RbacProviders.Purview,
        ["Set-ComplianceSearch"] = RbacProviders.Purview,
        ["Remove-ComplianceSearch"] = RbacProviders.Purview,
        ["Start-ComplianceSearch"] = RbacProviders.Purview,
        ["Stop-ComplianceSearch"] = RbacProviders.Purview,
        ["New-ComplianceSearchAction"] = RbacProviders.Purview,
        ["Get-ComplianceSearchAction"] = RbacProviders.Purview,
        ["Remove-ComplianceSearchAction"] = RbacProviders.Purview,

        // eDiscovery cases and holds.
        ["New-ComplianceCase"] = RbacProviders.Purview,
        ["Get-ComplianceCase"] = RbacProviders.Purview,
        ["New-CaseHoldPolicy"] = RbacProviders.Purview,
        ["New-CaseHoldRule"] = RbacProviders.Purview,

        // Retention and DLP.
        ["New-RetentionCompliancePolicy"] = RbacProviders.Purview,
        ["New-RetentionComplianceRule"] = RbacProviders.Purview,
        ["New-DlpCompliancePolicy"] = RbacProviders.Purview,
        ["New-DlpComplianceRule"] = RbacProviders.Purview,
        ["Get-DlpCompliancePolicy"] = RbacProviders.Purview,

        // Audit log search is Purview, despite feeling like Exchange.
        ["Search-UnifiedAuditLog"] = RbacProviders.Purview,

        // Retired in Exchange Online. If the model reaches for it, the wrong-service card
        // fires and says why — it exists in the catalog but cannot do the job.
        ["Search-Mailbox"] = RbacProviders.Purview,

        // Mailbox and transport administration is genuinely Exchange.
        ["Set-Mailbox"] = RbacProviders.Exchange,
        ["Get-Mailbox"] = RbacProviders.Exchange,
        ["New-Mailbox"] = RbacProviders.Exchange,
        ["Set-TransportRule"] = RbacProviders.Exchange,
        ["New-TransportRule"] = RbacProviders.Exchange,
        ["Get-TransportRule"] = RbacProviders.Exchange,
        ["Set-CASMailbox"] = RbacProviders.Exchange,
        ["Add-MailboxPermission"] = RbacProviders.Exchange,
        ["Set-DistributionGroup"] = RbacProviders.Exchange
    };

    /// <summary>The provider that truly owns this action, or null when unmapped.</summary>
    public static string? OwnerOf(string action)
    {
        var cmdlet = ActionDisplay.CmdletName(action);
        if (cmdlet is null) return null;
        return Owner.TryGetValue(cmdlet, out var provider) ? provider : null;
    }

    /// <summary>
    /// Corrects an action's provider when the catalog surfaced it under the wrong one.
    /// Returns the provider to use.
    /// </summary>
    public static string Correct(string action, string catalogProvider)
        => OwnerOf(action) ?? catalogProvider;

    public sealed record Finding
    {
        public required string Action { get; init; }
        public required string FoundUnder { get; init; }
        public required string BelongsTo { get; init; }
        public required string Message { get; init; }
    }

    /// <summary>
    /// Flags actions attributed to the wrong service. This is a correctness problem, not a
    /// presentation one: the grant would be executed against the wrong endpoint.
    /// </summary>
    public static IReadOnlyList<Finding> Findings(
        IReadOnlyCollection<string> actions, string assignedProvider)
    {
        var findings = new List<Finding>();
        foreach (var action in actions)
        {
            var owner = OwnerOf(action);
            if (owner is null) continue;
            if (owner.Equals(assignedProvider, StringComparison.OrdinalIgnoreCase)) continue;

            var cmdlet = ActionDisplay.Short(action);
            findings.Add(new Finding
            {
                Action = action,
                FoundUnder = assignedProvider,
                BelongsTo = owner,
                Message =
                    $"'{cmdlet}' is being granted through {RbacProviders.DisplayName(assignedProvider)}, " +
                    $"but it is a {RbacProviders.DisplayName(owner)} cmdlet. " +
                    (owner == RbacProviders.Purview
                        ? "Purview and Exchange have SEPARATE role groups with the same names — " +
                          "membership in Exchange's Organization Management does not grant the " +
                          "Purview permission. A purge granted through Exchange fails with " +
                          "\"A parameter cannot be found that matches parameter name 'Purge'\"."
                        : "The grant must be made in the service that owns the cmdlet.") +
                    " Re-run with the Service picker set to " +
                    RbacProviders.DisplayName(owner) + "."
            });
        }
        return findings;
    }

    /// <summary>Prompt guidance so the model attributes the service correctly first time.</summary>
    public static IReadOnlyList<string> PromptHints(string functionDescription)
    {
        // Hints must come from what the request ASKS FOR. "They should not be able to purge
        // anything" contains "purge", and would have produced a hint instructing the model to
        // choose Purview purge permissions — the app steering toward the forbidden capability.
        var text = RequestNegation.Positive(functionDescription).ToLowerInvariant();
        var hints = new List<string>();

        // "permanently delete it" matched none of the original triggers, and the model
        // answered with Exchange cmdlets that exist but cannot purge. Phrasing varies far
        // more than the capability does.
        var purgeMarkers = new[]
        {
            "purge", "remove it from", "delete the email", "delete the message",
            "phishing", "content search", "permanently delete", "hard delete",
            "soft delete", "delete from all mailboxes", "remove from all mailboxes",
            "delete across mailboxes", "search all mailboxes", "malicious attachment",
            "malicious email", "remove the email", "delete emails", "ediscovery"
        };
        if (purgeMarkers.Any(m => text.Contains(m, StringComparison.Ordinal)))
        {
            hints.Add("- Searching mailboxes and DELETING or PURGING messages across them is " +
                      "PURVIEW / Security & Compliance, NOT Exchange Online. The cmdlets are " +
                      "New-ComplianceSearch (Compliance Search role) and " +
                      "New-ComplianceSearchAction -Purge (Search And Purge role). " +
                      "Search-Mailbox is RETIRED in Exchange Online and cannot do this. " +
                      "Choose permissions from Purview.");
        }

        if (text.Contains("audit log", StringComparison.Ordinal))
            hints.Add("- Unified audit log search is Purview, not Exchange Online.");

        if (text.Contains("retention", StringComparison.Ordinal)
            || text.Contains("dlp", StringComparison.Ordinal)
            || text.Contains("data loss", StringComparison.Ordinal))
            hints.Add("- Retention and DLP policies are Purview, not Exchange Online.");

        return hints;
    }
}
