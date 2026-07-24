namespace AccessCheck.Ai;

/// <summary>Builds the configured transport. Every provider shares the same pipeline base.</summary>
public static class AiProviderFactory
{
    public const string OpenAiCompatible = "openai-compatible";
    public const string AzureOpenAi = "azure-openai";
    public const string Anthropic = "anthropic";

    public static readonly string[] Kinds = { OpenAiCompatible, AzureOpenAi, Anthropic };

    public static ChatProviderBase Create(AiProviderConfig config, string apiKey) =>
        (config.ProviderKind ?? OpenAiCompatible).Trim().ToLowerInvariant() switch
        {
            AzureOpenAi => new AzureOpenAiProvider(config, apiKey),
            Anthropic => new AnthropicProvider(config, apiKey),
            _ => new OpenAiCompatibleProvider(config, apiKey)
        };

    public static string DisplayName(string kind) => kind switch
    {
        AzureOpenAi => "Azure OpenAI (deployment)",
        Anthropic => "Anthropic (Claude)",
        _ => "OpenAI-compatible endpoint"
    };
}
