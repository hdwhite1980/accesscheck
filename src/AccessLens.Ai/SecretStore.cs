using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace AccessLens.Ai;

/// <summary>
/// Windows analog of the MacLens Keychain store: per-user DPAPI-encrypted secrets
/// under %APPDATA%\AccessLens\secrets. Keys never touch config files or logs.
/// </summary>
[SupportedOSPlatform("windows")]
public static class SecretStore
{
    private static string Dir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                     "AccessLens", "secrets");

    private static string PathFor(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return Path.Combine(Dir, name + ".bin");
    }

    public static void Save(string name, string secret)
    {
        Directory.CreateDirectory(Dir);
        var protectedBytes = ProtectedData.Protect(
            Encoding.UTF8.GetBytes(secret), null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(PathFor(name), protectedBytes);
    }

    public static string? Load(string name)
    {
        var p = PathFor(name);
        if (!File.Exists(p)) return null;
        var clear = ProtectedData.Unprotect(
            File.ReadAllBytes(p), null, DataProtectionScope.CurrentUser);
        return Encoding.UTF8.GetString(clear);
    }

    public static void Delete(string name)
    {
        var p = PathFor(name);
        if (File.Exists(p)) File.Delete(p);
    }
}
