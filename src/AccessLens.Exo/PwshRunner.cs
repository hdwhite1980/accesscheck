using System.Diagnostics;
using System.Text;

namespace AccessLens.Exo;

public sealed record PwshResult(int ExitCode, string StdOut, string StdErr)
{
    public bool Succeeded => ExitCode == 0;
}

/// <summary>
/// Runs a script in a fresh PowerShell 7 (pwsh) process. Each run is isolated —
/// no session leaks between Exchange and Purview connections. Scripts are written
/// to a temp .ps1, logged verbatim to the AccessLens data folder for audit, then
/// executed with -NoProfile.
/// </summary>
public sealed class PwshRunner
{
    private readonly string _scriptLogPath;

    public PwshRunner(string scriptLogPath) => _scriptLogPath = scriptLogPath;

    public static string? FindPwsh()
    {
        // PATH first
        var pathDirs = (Environment.GetEnvironmentVariable("PATH") ?? "")
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
        foreach (var dir in pathDirs)
        {
            var candidate = Path.Combine(dir.Trim(), "pwsh.exe");
            if (File.Exists(candidate)) return candidate;
        }
        // standard install locations
        string[] roots =
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
        };
        foreach (var root in roots)
        {
            if (string.IsNullOrEmpty(root)) continue;
            var psRoot = Path.Combine(root, "PowerShell");
            if (!Directory.Exists(psRoot)) continue;
            foreach (var ver in Directory.GetDirectories(psRoot).OrderByDescending(d => d))
            {
                var candidate = Path.Combine(ver, "pwsh.exe");
                if (File.Exists(candidate)) return candidate;
            }
        }
        return null;
    }

    public async Task<PwshResult> RunAsync(string script, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        var pwsh = FindPwsh()
            ?? throw new InvalidOperationException(
                "PowerShell 7 (pwsh.exe) not found. Install PowerShell 7 and the " +
                "ExchangeOnlineManagement module: Install-Module ExchangeOnlineManagement");

        var dir = Path.GetDirectoryName(_scriptLogPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.AppendAllText(_scriptLogPath,
            "==== " + DateTimeOffset.UtcNow.ToString("o") + " ====\n" + script + "\n");

        var tempPath = Path.Combine(Path.GetTempPath(),
            "accesslens-" + Guid.NewGuid().ToString("N") + ".ps1");
        await File.WriteAllTextAsync(tempPath, script, new UTF8Encoding(false), ct);

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = pwsh,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = false // interactive auth may pop a browser/window
            };
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-ExecutionPolicy");
            psi.ArgumentList.Add("Bypass");
            psi.ArgumentList.Add("-File");
            psi.ArgumentList.Add(tempPath);

            using var proc = Process.Start(psi)
                ?? throw new InvalidOperationException("Failed to start pwsh.");

            var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
            var stderrTask = proc.StandardError.ReadToEndAsync(ct);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(timeout ?? TimeSpan.FromMinutes(15));
            try
            {
                await proc.WaitForExitAsync(timeoutCts.Token);
            }
            catch (OperationCanceledException)
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* best effort */ }
                throw new TimeoutException("PowerShell run exceeded the time limit.");
            }

            return new PwshResult(proc.ExitCode, await stdoutTask, await stderrTask);
        }
        finally
        {
            try { File.Delete(tempPath); } catch { /* best effort */ }
        }
    }
}
