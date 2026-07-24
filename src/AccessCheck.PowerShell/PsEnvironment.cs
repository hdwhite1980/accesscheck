namespace AccessCheck.PowerShell;

public enum RbacScope { Exchange, Purview }

/// <summary>
/// Per-cloud connection parameters for Exchange Online and Security &amp; Compliance
/// (Purview) PowerShell. Values verified against Microsoft's connect docs; the
/// SCC URIs are overridable in config because the DoD compliance endpoint has
/// appeared under two hosts in current documentation.
/// </summary>
public sealed record PsEnvironment
{
    /// <summary>-ExchangeEnvironmentName for Connect-ExchangeOnline. Null = commercial default.</summary>
    public string? ExchangeEnvironmentName { get; init; }
    /// <summary>-ConnectionUri for Connect-IPPSSession. Null = commercial default.</summary>
    public string? SccConnectionUri { get; init; }
    /// <summary>-AzureADAuthorizationEndpointUri for Connect-IPPSSession. Null = commercial default.</summary>
    public string? SccAuthEndpoint { get; init; }

    public static PsEnvironment For(string cloudName,
        string? sccUriOverride = null) => cloudName.Trim().ToLowerInvariant() switch
    {
        "dod" => new PsEnvironment
        {
            ExchangeEnvironmentName = "O365USGovDoD",
            SccConnectionUri = sccUriOverride ??
                "https://l5.ps.compliance.protection.office365.us/powershell-liveid/",
            SccAuthEndpoint = "https://login.microsoftonline.us/organizations"
        },
        "gcchigh" or "gcc-high" or "gcc high" => new PsEnvironment
        {
            ExchangeEnvironmentName = "O365USGovGCCHigh",
            SccConnectionUri = sccUriOverride ??
                "https://ps.compliance.protection.office365.us/powershell-liveid/",
            SccAuthEndpoint = "https://login.microsoftonline.us/organizations"
        },
        _ => new PsEnvironment
        {
            ExchangeEnvironmentName = null,
            SccConnectionUri = sccUriOverride,
            SccAuthEndpoint = null
        }
    };

    /// <summary>
    /// Emits a splatted connect block for the requested scope. Uses -DisableWAM when
    /// the installed module supports it (checked at runtime, so older modules still
    /// work): WAM brokered auth fails inside a redirected child process with
    /// "A window handle must be configured", and disabling it falls back to browser auth.
    /// </summary>
    public string ConnectBlock(RbacScope scope, string? userPrincipalName)
    {
        var sb = new System.Text.StringBuilder();
        var cmdlet = scope == RbacScope.Exchange ? "Connect-ExchangeOnline" : "Connect-IPPSSession";

        sb.AppendLine("  $connParams = @{}");
        if (scope == RbacScope.Exchange)
        {
            if (ExchangeEnvironmentName is not null)
                sb.AppendLine("  $connParams['ExchangeEnvironmentName'] = '" +
                              PsQ(ExchangeEnvironmentName) + "'");
            sb.AppendLine("  $connParams['ShowBanner'] = $false");
        }
        else
        {
            if (SccConnectionUri is not null)
                sb.AppendLine("  $connParams['ConnectionUri'] = '" + PsQ(SccConnectionUri) + "'");
            if (SccAuthEndpoint is not null)
                sb.AppendLine("  $connParams['AzureADAuthorizationEndpointUri'] = '" +
                              PsQ(SccAuthEndpoint) + "'");
        }
        if (!string.IsNullOrWhiteSpace(userPrincipalName))
            sb.AppendLine("  $connParams['UserPrincipalName'] = '" + PsQ(userPrincipalName) + "'");

        sb.AppendLine("  $connCmd = Get-Command " + cmdlet + " -ErrorAction Stop");
        sb.AppendLine("  if ($connCmd.Parameters.ContainsKey('DisableWAM')) { $connParams['DisableWAM'] = $true }");
        sb.AppendLine("  " + cmdlet + " @connParams");
        return sb.ToString();
    }

    /// <summary>Back-compat single-line form (unused by the current scripts).</summary>
    public string ConnectLine(RbacScope scope, string? userPrincipalName) =>
        ConnectBlock(scope, userPrincipalName);

    /// <summary>Single-quote escaping for values embedded in PowerShell single-quoted strings.</summary>
    public static string PsQ(string s) => s.Replace("'", "''");
}
