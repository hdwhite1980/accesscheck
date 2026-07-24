using System.Diagnostics;
using System.Text;

namespace AccessLens.PowerShell;

public sealed record PsResult(int ExitCode, string StdOut, string StdErr)
{
    public bool Succeeded => ExitCode == 0;

    /// <summary>
    /// Extracts the JSON payload the script emitted between sentinel markers,
    /// ignoring module banners and progress noise around it.
    /// </summary>
    public string? JsonPayload
    {
        get
        {
            const string begin = "###JSON-BEGIN###";
            const string end = "###JSON-END###";
            var b = StdOut.IndexOf(begin, StringComparison.Ordinal);
            var e = StdOut.IndexOf(end, StringComparison.Ordinal);
            if (b < 0 || e < 0 || e <= b) return null;
            return StdOut[(b + begin.Length)..e].Trim();
        }
    }
}

/// <summary>
/// Runs a PowerShell script in an external pwsh/powershell process.
/// stdout and stderr are captured on SEPARATE pipes — never merged — because
/// merged streams interleave mid-JSON and break machine parsing.
/// Interactive auth prompts (Connect-ExchangeOnline browser sign-in) work
/// because the process is started without -NonInteractive.
/// </summary>
public sealed class PowerShellRunner
{
    /// <summary>Full script text of the last run — logged for the audit trail.</summary>
    public string? LastScript { get; private set; }

    public Action<string>? ScriptLogger { get; set; }

    public async Task<PsResult> RunAsync(string script, TimeSpan? timeout = null,
        CancellationToken ct = default)
    {
        LastScript = script;
        ScriptLogger?.Invoke(script);

        var exe = FindPowerShell();
        var scriptPath = Path.Combine(Path.GetTempPath(),
            "accesslens-" + Guid.NewGuid().ToString("N") + ".ps1");
        await File.WriteAllTextAsync(scriptPath, script, new UTF8Encoding(false), ct);

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                // Run from temp, not the app's working directory — avoids odd
                // "working directory" errors and keeps script paths predictable.
                WorkingDirectory = Path.GetTempPath()
            };
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-ExecutionPolicy");
            psi.ArgumentList.Add("Bypass");
            psi.ArgumentList.Add("-File");
            psi.ArgumentList.Add(scriptPath);

            using var proc = Process.Start(psi)
                ?? throw new InvalidOperationException("Failed to start " + exe);

            var stdOutTask = proc.StandardOutput.ReadToEndAsync(ct);
            var stdErrTask = proc.StandardError.ReadToEndAsync(ct);

            var limit = timeout ?? TimeSpan.FromMinutes(30);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(limit);
            try
            {
                await proc.WaitForExitAsync(timeoutCts.Token);
            }
            catch (OperationCanceledException)
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* best effort */ }
                throw new TimeoutException("PowerShell run exceeded " + limit + ".");
            }

            return new PsResult(proc.ExitCode, await stdOutTask, await stdErrTask);
        }
        finally
        {
            try { File.Delete(scriptPath); } catch { /* best effort */ }
        }
    }

    /// <summary>
    /// Locates a PowerShell host. Prefers PowerShell 7 (pwsh) but falls back to
    /// Windows PowerShell 5.1, which is present on every Windows box —
    /// ExchangeOnlineManagement v3 works in both.
    /// </summary>
    public static string FindPowerShell()
    {
        // 1) PowerShell 7 in its standard install locations.
        string[] pwshPaths =
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "PowerShell", "7", "pwsh.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "PowerShell", "7", "pwsh.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "WindowsApps", "pwsh.exe")
        };
        foreach (var p in pwshPaths)
            if (File.Exists(p)) return p;

        // 2) pwsh.exe anywhere on PATH.
        var onPath = ProbePath("pwsh.exe");
        if (onPath is not null) return onPath;

        // 3) Windows PowerShell 5.1 — always present.
        var winPs = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe");
        if (File.Exists(winPs)) return winPs;

        var onPath51 = ProbePath("powershell.exe");
        if (onPath51 is not null) return onPath51;

        throw new FileNotFoundException(
            "No PowerShell host found. Install PowerShell 7 (winget install Microsoft.PowerShell) " +
            "or ensure powershell.exe is available.");
    }

    private static string? ProbePath(string exeName)
    {
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathVar.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var candidate = Path.Combine(dir.Trim(), exeName);
                if (File.Exists(candidate)) return candidate;
            }
            catch (ArgumentException) { /* malformed PATH entry */ }
        }
        return null;
    }

    /// <summary>Which host will be used, for diagnostics in the UI.</summary>
    public static string DescribeHost()
    {
        try { return FindPowerShell(); }
        catch (Exception ex) { return "(none: " + ex.Message + ")"; }
    }

}
