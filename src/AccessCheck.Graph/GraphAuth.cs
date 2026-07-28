using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Identity.Client;

namespace AccessCheck.Graph;

/// <summary>
/// MSAL public client with interactive sign-in. No client secret exists anywhere:
/// the app acts AS the signed-in admin (delegated), so every Graph write lands in
/// the Entra audit log attributed to that admin account. Token cache is a
/// cache is held by SecretStore — DPAPI on Windows, Keychain on macOS — so scheduled
/// --housekeeping runs work silently on either platform.
/// </summary>
public sealed class GraphAuth
{
    private readonly IPublicClientApplication _pca;
    private readonly string[] _scopes;

    // Kept so a failure can NAME the values that are wrong. "AADSTS700016: application not
    // found" is unactionable; the same message quoting the client id actually sent, against
    // the cloud actually selected, usually diagnoses itself.
    private readonly string _clientId;
    private readonly string _tenantId;
    // The graph endpoint rather than a friendly cloud name: it is a member I can be sure
    // exists, and for diagnosing a cloud mismatch "https://graph.microsoft.us" is more
    // use than "GCC High" anyway.
    private readonly string _graphBase;
    private const string RedirectUri = "http://localhost";

    public GraphAuth(string clientId, string tenantId, CloudEnvironment cloud, string[] scopes)
    {
        _scopes = scopes;
        _clientId = clientId;
        _tenantId = tenantId;
        _graphBase = cloud.GraphBase;

        _pca = PublicClientApplicationBuilder.Create(clientId)
            .WithAuthority(cloud.Authority(tenantId))
            .WithRedirectUri(RedirectUri)
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
            try
            {
                var interactive = await _pca.AcquireTokenInteractive(_scopes).ExecuteAsync(ct);
                Record(interactive);
                return interactive.AccessToken;
            }
            catch (MsalException ex)
            {
                throw new SignInFailedException(Explain(ex), ex);
            }
        }
        catch (MsalException ex)
        {
            throw new SignInFailedException(Explain(ex), ex);
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
            try
            {
                var interactive = await _pca.AcquireTokenInteractive(otherScopes).ExecuteAsync(ct);
                return interactive.AccessToken;
            }
            catch (MsalException ex)
            {
                throw new SignInFailedException(Explain(ex), ex);
            }
        }
        catch (MsalException ex)
        {
            throw new SignInFailedException(Explain(ex), ex);
        }
    }

    /// <summary>Acquire a token purely to populate the scope diagnostics.</summary>
    public Task<string> WarmUpOrToken(CancellationToken ct = default) => GetTokenAsync(ct);

    /// <summary>
    /// Turns the AADSTS codes this app can actually provoke into instructions.
    ///
    /// A raw Azure error says what failed; it almost never says what to change. Each of
    /// these cost real time to diagnose the first time, and the fix is always a specific
    /// blade with a specific setting — so the message names it.
    /// </summary>
    private string Explain(MsalException ex)
    {
        var text = ex.Message ?? "";

        if (text.Contains("AADSTS50011", StringComparison.Ordinal))
            return "The redirect URI '" + RedirectUri + "' is not registered on this " +
                   "application." +
                   "\n\nAdd it once, then retry:" +
                   "\n  Entra admin center > App registrations > (this app) > Authentication" +
                   "\n  > Add a platform > Mobile and desktop applications" +
                   "\n  > tick " + RedirectUri +
                   "\n  > Save" +
                   "\n\nThe macOS build uses a custom scheme instead, because its sign-in " +
                   "sheet cannot intercept a loopback address. Both can be registered at the " +
                   "same time and do not conflict." +
                   "\n\nApp id in the request: " + _clientId +
                   "\n\nAzure's message: " + text;

        if (text.Contains("AADSTS65001", StringComparison.Ordinal)
            || string.Equals(ex.ErrorCode, "consent_required", StringComparison.OrdinalIgnoreCase))
            return "Admin consent has not been granted for one or more requested permissions." +
                   "\n\n  Entra admin center > App registrations > (this app) > API permissions" +
                   "\n  > Grant admin consent" +
                   "\n\nIf a permission cannot be consented in this tenant, remove it from " +
                   "graphPermissions in appsettings.json and sign in again — the catalog sync " +
                   "degrades per provider rather than failing outright." +
                   "\n\nAzure's message: " + text;

        if (text.Contains("AADSTS700016", StringComparison.Ordinal)
            || text.Contains("AADSTS900023", StringComparison.Ordinal))
            return "The application or tenant id was not found in this directory." +
                   "\n\nCheck Settings: client id '" + _clientId + "' and tenant id '" +
                   _tenantId + "' must BOTH belong to the cloud currently selected (" +
                   _graphBase + "). A commercial app id in a GCC High tenant fails exactly " +
                   "this way." +
                   "\n\nAzure's message: " + text;

        if (text.Contains("AADSTS7000218", StringComparison.Ordinal))
            return "The app registration is not configured as a public client." +
                   "\n\n  Entra admin center > App registrations > (this app) > Authentication" +
                   "\n  > Advanced settings > Allow public client flows > Yes" +
                   "\n\nAccessCheck deliberately holds no client secret — it acts AS the " +
                   "signed-in admin so every write is attributed to that account — so it must " +
                   "be a public client." +
                   "\n\nAzure's message: " + text;

        return string.IsNullOrWhiteSpace(text) ? ex.ErrorCode ?? "Sign-in failed." : text;
    }

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

/// <summary>
/// Sign-in failed, with the reason already translated into something actionable. The
/// original MsalException is preserved as InnerException for the action log.
/// </summary>
public sealed class SignInFailedException : Exception
{
    public SignInFailedException(string message, Exception inner) : base(message, inner) { }
}
