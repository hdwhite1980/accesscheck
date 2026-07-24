using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace AccessCheck.Ai;

/// <summary>
/// Per-user secret storage, backed by whatever the OS actually provides:
///   Windows — DPAPI, bound to the Windows account
///   macOS   — the login Keychain via the `security` tool
///   Linux   — a 0600 file, which is NOT encrypted; the store says so rather than pretending
/// Secrets never land in config files or logs on any platform.
/// </summary>
public static class SecretStore
{
    private static string Dir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                     "AccessCheck", "secrets");

    /// <summary>Keychain service name on macOS.</summary>
    private const string KeychainService = "AccessCheck";

    /// <summary>Human description of where secrets go on this machine.</summary>
    public static string BackendDescription =>
        OperatingSystem.IsWindows() ? "Windows DPAPI (bound to your user account)"
        : OperatingSystem.IsMacOS() ? "macOS login Keychain (service '" + KeychainService + "')"
        : "file with owner-only permissions at " + Dir + " — NOT encrypted";

    /// <summary>True when the platform gives real cryptographic protection.</summary>
    public static bool IsEncrypted => OperatingSystem.IsWindows() || OperatingSystem.IsMacOS();

    public static void Save(string name, string secret)
    {
        if (OperatingSystem.IsWindows()) { SaveDpapi(name, secret); return; }
        if (OperatingSystem.IsMacOS()) { SaveKeychain(name, secret); return; }
        SaveFile(name, secret);
    }

    public static string? Load(string name)
    {
        if (OperatingSystem.IsWindows()) return LoadDpapi(name);
        if (OperatingSystem.IsMacOS()) return LoadKeychain(name);
        return LoadFile(name);
    }

    public static void Delete(string name)
    {
        if (OperatingSystem.IsWindows()) { DeleteFile(PathFor(name)); return; }
        if (OperatingSystem.IsMacOS())
        {
            RunSecurity("delete-generic-password", "-a", name, "-s", KeychainService);
            return;
        }
        DeleteFile(PathFor(name));
    }

    // ---------- Windows (DPAPI) ----------

    [SupportedOSPlatform("windows")]
    private static void SaveDpapi(string name, string secret)
    {
        Directory.CreateDirectory(Dir);
        var protectedBytes = ProtectedData.Protect(
            Encoding.UTF8.GetBytes(secret), null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(PathFor(name), protectedBytes);
    }

    [SupportedOSPlatform("windows")]
    private static string? LoadDpapi(string name)
    {
        var p = PathFor(name);
        if (!File.Exists(p)) return null;
        try
        {
            var clear = ProtectedData.Unprotect(
                File.ReadAllBytes(p), null, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(clear);
        }
        catch (CryptographicException) { return null; }
    }

    // ---------- macOS (login Keychain via `security`) ----------

    private static void SaveKeychain(string name, string secret)
    {
        // -U updates in place when the item already exists.
        var (exit, _, err) = RunSecurity(
            "add-generic-password", "-a", name, "-s", KeychainService, "-w", secret, "-U");
        if (exit != 0)
            throw new InvalidOperationException(
                "Could not write to the macOS Keychain: " + err.Trim());
    }

    private static string? LoadKeychain(string name)
    {
        var (exit, stdout, _) = RunSecurity(
            "find-generic-password", "-a", name, "-s", KeychainService, "-w");
        if (exit != 0) return null;
        var value = stdout.TrimEnd('\n', '\r');
        return value.Length == 0 ? null : value;
    }

    private static (int Exit, string StdOut, string StdErr) RunSecurity(params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "/usr/bin/security",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        try
        {
            using var proc = Process.Start(psi);
            if (proc is null) return (-1, "", "could not start /usr/bin/security");
            var so = proc.StandardOutput.ReadToEnd();
            var se = proc.StandardError.ReadToEnd();
            proc.WaitForExit(30_000);
            return (proc.ExitCode, so, se);
        }
        catch (Exception ex)
        {
            return (-1, "", ex.Message);
        }
    }

    // ---------- Linux / fallback ----------

    private static void SaveFile(string name, string secret)
    {
        Directory.CreateDirectory(Dir);
        var path = PathFor(name);
        File.WriteAllText(path, secret);

        // Owner-only permissions, on the platforms that have them. The guard is an
        // explicit OS check rather than a try/catch so the platform analyser can prove
        // the call is unreachable on Windows (CA1416).
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch (IOException) { /* best effort — the file is still written */ }
            catch (UnauthorizedAccessException) { /* best effort */ }
        }
    }

    private static string? LoadFile(string name)
    {
        var p = PathFor(name);
        return File.Exists(p) ? File.ReadAllText(p) : null;
    }

    // ---------- shared ----------

    private static string PathFor(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return Path.Combine(Dir, name + ".bin");
    }

    private static void DeleteFile(string path)
    {
        if (File.Exists(path)) File.Delete(path);
    }
}
