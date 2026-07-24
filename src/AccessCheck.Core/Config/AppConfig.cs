using System.Text.Json;

namespace AccessCheck.Core.Config;

public sealed record AppConfig
{
    public string Cloud { get; init; } = "Dod";
    public string TenantId { get; init; } = "";
    public string ClientId { get; init; } = "";
    public bool EnableOutreach { get; init; }
    public int MaxAcceptableExcessActions { get; init; } = 5;

    /// <summary>
    /// Minutes to allow the Exchange/Purview PowerShell sync before abandoning it and
    /// using Microsoft's documented vocabulary instead. Those services have no bulk API,
    /// so a full read can take tens of minutes — and the definitions are published anyway.
    /// </summary>
    public int PowerShellSyncMinutes { get; init; } = 5;

    /// <summary>
    /// Graph permission names (appended to the cloud's Graph base as delegated scopes).
    /// Trim this list if a permission isn't consentable in your tenant yet —
    /// sync degrades gracefully per provider.
    /// </summary>
    /// <summary>
    /// Scopes this build needs. A saved config keeps its own list, but Load() unions
    /// these in — otherwise a config written by an older build silently pins the app
    /// to the old scope set and newly added permissions never reach the token.
    /// </summary>
    public static readonly IReadOnlyList<string> DefaultGraphPermissions = new[]
    {
        "RoleManagement.ReadWrite.Directory",
        "RoleManagement.Read.All",
        "DeviceManagementRBAC.ReadWrite.All",
        "RoleManagement.ReadWrite.Exchange",
        "RoleManagement.ReadWrite.CloudPC",
        "RoleManagement.ReadWrite.Defender",
        "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup",
        "PrivilegedEligibilitySchedule.Read.AzureADGroup",
        "User.Read.All",
        "Group.ReadWrite.All",
        "GroupMember.Read.All",
        "RoleManagementPolicy.Read.Directory",
        "GroupMember.ReadWrite.All",
        "AdministrativeUnit.Read.All",
        "Application.Read.All",
        "EntitlementManagement.Read.All"
    };

    public List<string> GraphPermissions { get; init; } = new()
    {
        "RoleManagement.ReadWrite.Directory",
        "RoleManagement.Read.All",
        "DeviceManagementRBAC.ReadWrite.All",
        "RoleManagement.ReadWrite.Exchange",
        "RoleManagement.ReadWrite.CloudPC",
        "RoleManagement.ReadWrite.Defender",
        "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup",
        "PrivilegedEligibilitySchedule.Read.AzureADGroup",
        "User.Read.All",
        "Group.ReadWrite.All",
        "GroupMember.Read.All",
        "RoleManagementPolicy.Read.Directory",
        "GroupMember.ReadWrite.All",
        "AdministrativeUnit.Read.All",
        "Application.Read.All",
        "EntitlementManagement.Read.All"
    };

    public AiSection Ai { get; init; } = new();
    public PsSection Ps { get; init; } = new();

    /// <summary>Exchange Online / Purview PowerShell settings.</summary>
    public sealed record PsSection
    {
        /// <summary>Admin UPN passed to Connect-ExchangeOnline / Connect-IPPSSession (speeds interactive sign-in).</summary>
        public string UserPrincipalName { get; init; } = "";
        /// <summary>Override the Security &amp; Compliance ConnectionUri if your cloud's endpoint differs from the preset.</summary>
        public string SccConnectionUriOverride { get; init; } = "";
    }

    public sealed record AiSection
    {
        /// <summary>openai-compatible | azure-openai | anthropic</summary>
        public string Provider { get; init; } = "openai-compatible";
        /// <summary>Azure OpenAI api-version (ignored by other providers).</summary>
        public string ApiVersion { get; init; } = "";
        public string BaseUrl { get; init; } = "";
        public string Model { get; init; } = "";
        public string AuthHeaderName { get; init; } = "Authorization";
        public string AuthValuePrefix { get; init; } = "Bearer ";
        public string ApiKeyName { get; init; } = "accesscheck-genai";
        public int ShortlistSize { get; init; } = 8;
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        WriteIndented = true
    };

    public static AppConfig Load(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("Config not found: " + path);
        var loaded = JsonSerializer.Deserialize<AppConfig>(File.ReadAllText(path), JsonOpts)
                     ?? throw new InvalidDataException("Config file was empty or invalid.");

        // Union in any scopes this build added since the config was written.
        var merged = new List<string>(loaded.GraphPermissions);
        foreach (var scope in DefaultGraphPermissions)
            if (!merged.Contains(scope, StringComparer.OrdinalIgnoreCase))
                merged.Add(scope);
        if (merged.Count != loaded.GraphPermissions.Count)
            loaded = loaded with { GraphPermissions = merged };
        return loaded;
    }

    public void Save(string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(this, JsonOpts));
}
