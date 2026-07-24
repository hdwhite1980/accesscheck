using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Identity.Client;

namespace AccessCheck.Graph;

/// <summary>
/// MSAL public client with interactive sign-in. No client secret exists anywhere:
/// the app acts AS the signed-in admin (delegated), so every Graph write lands in
/// the Entra audit log attributed to that admin account. Token cache is a
/// DPAPI-encrypted file so scheduled --housekeeping runs work silently.
/// </summary>
public sealed class GraphAuth
{
    private readonly IPublicClientApplication _pca;
    private readonly string[] _scopes;

    public GraphAuth(string clientId, string tenantId, CloudEnvironment cloud, string[] scopes)
    {
        _scopes = scopes;
        _pca = PublicClientApplicationBuilder.Create(clientId)
            .WithAuthority(cloud.Authority(tenantId))
            .WithRedirectUri("http://localhost")
            .Build();

        TokenCacheStore.Bind(_pca.UserTokenCache);
    }

    /// <summary>Scopes actually present in the last issued token — the definitive diagnostic.</summary>
    public IReadOnlyList<string> LastGrantedScopes { get; private set; } = Array.Empty<string>();

    /// <summary>Scopes this client requests.</summary>
    public IReadOnlyList<string> RequestedScopes => _scopes;

    /// <summary>Account the last token was issued for.</summary>
    public string? SignedInAccount { get; private set; }

    public async Task<string> GetTokenAsync(CancellationToken ct = default)
    {
        var accounts = await _pca.GetAccountsAsync();
        var first = accounts.FirstOrDefault();
        try
        {
            var silent = await _pca.AcquireTokenSilent(_scopes, first).ExecuteAsync(ct);
            Record(silent);
            return silent.AccessToken;
        }
        catch (MsalUiRequiredException)
        {
            var interactive = await _pca.AcquireTokenInteractive(_scopes).ExecuteAsync(ct);
            Record(interactive);
            return interactive.AccessToken;
        }
    }

    /// <summary>
    /// Acquires a token for a DIFFERENT audience using the same signed-in account —
    /// Azure Resource Manager is not Microsoft Graph and needs its own token.
    /// </summary>
    public async Task<string> GetTokenForAsync(string[] otherScopes, CancellationToken ct = default)
    {
        var accounts = await _pca.GetAccountsAsync();
        var first = accounts.FirstOrDefault();
        try
        {
            var silent = await _pca.AcquireTokenSilent(otherScopes, first).ExecuteAsync(ct);
            return silent.AccessToken;
        }
        catch (MsalUiRequiredException)
        {
            var interactive = await _pca.AcquireTokenInteractive(otherScopes).ExecuteAsync(ct);
            return interactive.AccessToken;
        }
    }

    /// <summary>Acquire a token purely to populate the scope diagnostics.</summary>
    public Task<string> WarmUpOrToken(CancellationToken ct = default) => GetTokenAsync(ct);

    private void Record(AuthenticationResult result)
    {
        LastGrantedScopes = result.Scopes?.ToList() ?? new List<string>();
        SignedInAccount = result.Account?.Username;
    }

    /// <summary>
    /// Forgets every cached account and deletes the token cache, so the next call
    /// signs in fresh. Needed after adding consent: a cached token keeps its original
    /// scope set and will not pick up newly granted permissions on its own.
    /// </summary>
    public async Task SignOutAsync()
    {
        foreach (var account in await _pca.GetAccountsAsync())
        {
            try { await _pca.RemoveAsync(account); } catch (MsalException) { /* best effort */ }
        }
        LastGrantedScopes = Array.Empty<string>();
        SignedInAccount = null;
        TokenCacheStore.Delete();
    }
}

/// <summary>
/// Persists the MSAL token cache through SecretStore, so it is protected by DPAPI on
/// Windows and the login Keychain on macOS. The cache is binary, so it is base64'd
/// before storage.
/// </summary>
internal static class TokenCacheStore
{
    private const string CacheName = "msal-token-cache";

    public static void Delete()
    {
        try { AccessCheck.Ai.SecretStore.Delete(CacheName); }
        catch (Exception) { /* best effort */ }
    }

    public static void Bind(ITokenCache cache)
    {
        cache.SetBeforeAccess(args =>
        {
            try
            {
                var stored = AccessCheck.Ai.SecretStore.Load(CacheName);
                if (!string.IsNullOrEmpty(stored))
                    args.TokenCache.DeserializeMsalV3(Convert.FromBase64String(stored));
            }
            catch (Exception) { /* a corrupt cache just means signing in again */ }
        });

        cache.SetAfterAccess(args =>
        {
            if (!args.HasStateChanged) return;
            try
            {
                var blob = args.TokenCache.SerializeMsalV3();
                AccessCheck.Ai.SecretStore.Save(CacheName, Convert.ToBase64String(blob));
            }
            catch (Exception) { /* the app still works, it just re-prompts next launch */ }
        });
    }
}
