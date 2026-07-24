namespace AccessCheck.Ai;

/// <summary>
/// Same provider shape as MacLens: an OpenAI-compatible chat-completions endpoint
/// with a configurable base URL, so the app points at the org GenAI gateway
/// (VPN-side) today and can swap endpoints later without code changes.
/// The API key is NEVER stored here — it lives in SecretStore (DPAPI).
/// </summary>
public sealed record AiProviderConfig
{
    /// <summary>Which transport: openai-compatible (default), azure-openai, anthropic.</summary>
    public string? ProviderKind { get; init; }
    /// <summary>Azure OpenAI only: api-version query parameter.</summary>
    public string? ApiVersion { get; init; }
    /// <summary>Base URL. OpenAI-compatible: up to /chat/completions. Azure: the resource endpoint. Anthropic: blank for api.anthropic.com.</summary>
    public required string BaseUrl { get; init; }
    public required string Model { get; init; }
    /// <summary>Header carrying the key. Default matches OpenAI-compatible gateways.</summary>
    public string AuthHeaderName { get; init; } = "Authorization";
    /// <summary>Prefix before the key in the auth header. Empty string for gateways using a bare api-key header.</summary>
    public string AuthValuePrefix { get; init; } = "Bearer ";
    /// <summary>Name under which the key is stored in SecretStore.</summary>
    public string ApiKeyName { get; init; } = "accesscheck-genai";
    public int TimeoutSeconds { get; init; } = 120;
    /// <summary>Max roles sent with full action lists in stage 2.</summary>
    public int ShortlistSize { get; init; } = 8;
}
