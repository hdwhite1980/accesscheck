using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Identity.Client;

namespace AccessLens.Graph;

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

        if (OperatingSystem.IsWindows())
            TokenCacheFile.Bind(_pca.UserTokenCache);
    }

    public async Task<string> GetTokenAsync(CancellationToken ct = default)
    {
        var accounts = await _pca.GetAccountsAsync();
        var first = accounts.FirstOrDefault();
        try
        {
            var silent = await _pca.AcquireTokenSilent(_scopes, first).ExecuteAsync(ct);
            return silent.AccessToken;
        }
        catch (MsalUiRequiredException)
        {
            var interactive = await _pca.AcquireTokenInteractive(_scopes).ExecuteAsync(ct);
            return interactive.AccessToken;
        }
    }
}

[SupportedOSPlatform("windows")]
internal static class TokenCacheFile
{
    private static string CachePath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                     "AccessLens", "msal.cache.bin");

    public static void Bind(ITokenCache cache)
    {
        cache.SetBeforeAccess(args =>
        {
            if (File.Exists(CachePath))
            {
                var clear = ProtectedData.Unprotect(
                    File.ReadAllBytes(CachePath), null, DataProtectionScope.CurrentUser);
                args.TokenCache.DeserializeMsalV3(clear);
            }
        });
        cache.SetAfterAccess(args =>
        {
            if (!args.HasStateChanged) return;
            Directory.CreateDirectory(Path.GetDirectoryName(CachePath)!);
            var protectedBytes = ProtectedData.Protect(
                args.TokenCache.SerializeMsalV3(), null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(CachePath, protectedBytes);
        });
    }
}
