namespace AccessLens.Exo;

/// <summary>
/// PowerShell connection parameters per Microsoft cloud.
/// Exchange Online: Connect-ExchangeOnline -ExchangeEnvironmentName ...
/// Security &amp; Compliance (Purview): Connect-IPPSSession -ConnectionUri ... -AzureADAuthorizationEndpointUri ...
/// Values per Microsoft's Exchange PowerShell docs for GCC High / DoD.
/// </summary>
public sealed record ExoEnvironment
{
    public required string CloudName { get; init; }
    /// <summary>Null for Commercial (module default).</summary>
    public string? ExchangeEnvironmentName { get; init; }
    /// <summary>Null for Commercial (module default).</summary>
    public string? IppsConnectionUri { get; init; }
    public string? IppsAuthorizationEndpoint { get; init; }

    public static ExoEnvironment For(string cloudName) => cloudName.Trim().ToLowerInvariant() switch
    {
        "commercial" => new ExoEnvironment { CloudName = "Commercial" },
        "gcchigh" or "gcc-high" or "gcc high" => new ExoEnvironment
        {
            CloudName = "GccHigh",
            ExchangeEnvironmentName = "O365USGovGCCHigh",
            IppsConnectionUri = "https://ps.compliance.protection.office365.us/powershell-liveid/",
            IppsAuthorizationEndpoint = "https://login.microsoftonline.us/organizations"
        },
        "dod" => new ExoEnvironment
        {
            CloudName = "Dod",
            ExchangeEnvironmentName = "O365USGovDoD",
            IppsConnectionUri = "https://l5.ps.compliance.protection.office365.us/powershell-liveid/",
            IppsAuthorizationEndpoint = "https://login.microsoftonline.us/organizations"
        },
        _ => throw new ArgumentException("Unknown cloud: " + cloudName)
    };

    public string ExoConnectLine() =>
        "Connect-ExchangeOnline -ShowBanner:$false" +
        (ExchangeEnvironmentName is null ? "" : " -ExchangeEnvironmentName " + ExchangeEnvironmentName);

    public string IppsConnectLine() =>
        "Connect-IPPSSession" +
        (IppsConnectionUri is null ? "" :
            " -ConnectionUri '" + IppsConnectionUri + "'" +
            " -AzureADAuthorizationEndpointUri '" + IppsAuthorizationEndpoint + "'");
}
