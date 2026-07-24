namespace AccessLens.PowerShell;

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

    /// <summary>The connect line for the requested scope. UPN speeds interactive sign-in.</summary>
    public string ConnectLine(RbacScope scope, string? userPrincipalName)
    {
        var upn = string.IsNullOrWhiteSpace(userPrincipalName)
            ? "" : " -UserPrincipalName '" + PsQ(userPrincipalName) + "'";
        if (scope == RbacScope.Exchange)
        {
            var env = ExchangeEnvironmentName is null
                ? "" : " -ExchangeEnvironmentName " + ExchangeEnvironmentName;
            return "Connect-ExchangeOnline" + env + upn + " -ShowBanner:$false";
        }
        var uri = SccConnectionUri is null
            ? "" : " -ConnectionUri '" + PsQ(SccConnectionUri) + "'";
        var auth = SccAuthEndpoint is null
            ? "" : " -AzureADAuthorizationEndpointUri '" + PsQ(SccAuthEndpoint) + "'";
        return "Connect-IPPSSession" + uri + auth + upn;
    }

    /// <summary>Single-quote escaping for values embedded in PowerShell single-quoted strings.</summary>
    public static string PsQ(string s) => s.Replace("'", "''");
}
