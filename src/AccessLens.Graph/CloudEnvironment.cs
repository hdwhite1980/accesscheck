namespace AccessLens.Graph;

/// <summary>
/// Endpoint presets per Microsoft cloud. MED365/IL5 = Dod
/// (login.microsoftonline.us + dod-graph.microsoft.us).
/// </summary>
public sealed record CloudEnvironment
{
    public required string Name { get; init; }
    public required string AuthorityBase { get; init; }
    public required string GraphBase { get; init; }

    public static readonly CloudEnvironment Commercial = new()
    {
        Name = "Commercial",
        AuthorityBase = "https://login.microsoftonline.com",
        GraphBase = "https://graph.microsoft.com"
    };

    public static readonly CloudEnvironment GccHigh = new()
    {
        Name = "GCC High",
        AuthorityBase = "https://login.microsoftonline.us",
        GraphBase = "https://graph.microsoft.us"
    };

    public static readonly CloudEnvironment Dod = new()
    {
        Name = "DoD",
        AuthorityBase = "https://login.microsoftonline.us",
        GraphBase = "https://dod-graph.microsoft.us"
    };

    public static CloudEnvironment Parse(string name) => name.Trim().ToLowerInvariant() switch
    {
        "commercial" => Commercial,
        "gcchigh" or "gcc-high" or "gcc high" => GccHigh,
        "dod" => Dod,
        _ => throw new ArgumentException("Unknown cloud: " + name + " (use Commercial | GccHigh | Dod)")
    };

    public string Authority(string tenantId) => AuthorityBase + "/" + tenantId;

    /// <summary>
    /// Builds delegated scopes from configured permission names. Outreach scopes
    /// are only requested when outreach is enabled.
    /// </summary>
    public string[] Scopes(IEnumerable<string> permissionNames, bool includeOutreach)
    {
        var list = permissionNames
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => GraphBase + "/" + p.Trim())
            .ToList();
        if (list.Count == 0)
            list.Add(GraphBase + "/RoleManagement.ReadWrite.Directory");
        if (includeOutreach)
        {
            list.Add(GraphBase + "/Mail.Send");
            list.Add(GraphBase + "/Chat.ReadWrite");
        }
        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }
}
