using System.Text.Json;

namespace AccessLens.Core.Config;

public sealed record AppConfig
{
    public string Cloud { get; init; } = "Dod";
    public string TenantId { get; init; } = "";
    public string ClientId { get; init; } = "";
    public bool EnableOutreach { get; init; }
    public int MaxAcceptableExcessActions { get; init; } = 5;

    /// <summary>
    /// Graph permission names (appended to the cloud's Graph base as delegated scopes).
    /// Trim this list if a permission isn't consentable in your tenant yet —
    /// sync degrades gracefully per provider.
    /// </summary>
    public List<string> GraphPermissions { get; init; } = new()
    {
        "RoleManagement.ReadWrite.Directory",
        "RoleManagement.Read.All",
        "DeviceManagementRBAC.ReadWrite.All",
        "RoleManagement.ReadWrite.Exchange",
        "RoleManagement.ReadWrite.CloudPC",
        "RoleManagement.ReadWrite.Defender",
        "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup",
        "User.Read.All",
        "Group.ReadWrite.All"
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
        public string ApiKeyName { get; init; } = "accesslens-genai";
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
        return JsonSerializer.Deserialize<AppConfig>(File.ReadAllText(path), JsonOpts)
               ?? throw new InvalidDataException("Config file was empty or invalid.");
    }

    public void Save(string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(this, JsonOpts));
}
