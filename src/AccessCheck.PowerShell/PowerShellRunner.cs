using System.Diagnostics;
using System.Text;
using AccessCheck.Core.Audit;

namespace AccessCheck.PowerShell;

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
    /// <summary>Lines with this prefix are progress, not output to be parsed.</summary>
    public const string ProgressMarker = "###PROGRESS###";

    /// <summary>Full script text of the last run — logged for the audit trail.</summary>
    public string? LastScript { get; private set; }

    public Action<string>? ScriptLogger { get; set; }

    public async Task<PsResult> RunAsync(string script, TimeSpan? timeout = null,
        CancellationToken ct = default,
        Action<string>? onProgress = null)
    {
        LastScript = script;
        ScriptLogger?.Invoke(script);

        var exe = FindPowerShell();
        // The script verbatim. ScriptLogger already receives it, but that log is separate
        // from the response side — pairing them under one scope is what makes a failed
        // Exchange grant readable after the fact.
        ActionLog.Request("PWSH", "RUN", exe, script);
        var swRun = Stopwatch.StartNew();
        var scriptPath = Path.Combine(Path.GetTempPath(),
            "accesscheck-" + Guid.NewGuid().ToString("N") + ".ps1");
        await File.WriteAllTextAsync(scriptPath, script, new UTF8Encoding(false), ct);

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                // A visible console gives brokered auth (WAM) a window handle and lets
                // the admin see sign-in prompts; stdout/stderr still flow through pipes.
                CreateNoWindow = false,
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

            // Read line by line rather than ReadToEnd. A deep sync makes hundreds of round
            // trips and can run for many minutes; waiting for the process to exit before
            // showing anything makes a working sync indistinguishable from a hung one.
            var stdOut = new System.Text.StringBuilder();
            var stdErr = new System.Text.StringBuilder();
            var stdOutDone = new TaskCompletionSource();
            var stdErrDone = new TaskCompletionSource();

            proc.OutputDataReceived += (_, e) =>
            {
                if (e.Data is null) { stdOutDone.TrySetResult(); return; }
                stdOut.AppendLine(e.Data);
                if (e.Data.StartsWith(ProgressMarker, StringComparison.Ordinal))
                    onProgress?.Invoke(e.Data[ProgressMarker.Length..].Trim());
            };
            proc.ErrorDataReceived += (_, e) =>
            {
                if (e.Data is null) { stdErrDone.TrySetResult(); return; }
                stdErr.AppendLine(e.Data);
            };
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();

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

            // Both streams signal completion with a null Data event.
            await Task.WhenAny(Task.WhenAll(stdOutDone.Task, stdErrDone.Task),
                               Task.Delay(TimeSpan.FromSeconds(5), ct));
            swRun.Stop();

            var outText = stdOut.ToString();
            var errText = stdErr.ToString();

            // BOTH streams, in full. stderr is where Exchange puts the reason a cmdlet
            // refused, and it was previously only surfaced if something chose to show it.
            ActionLog.Response("PWSH", proc.ExitCode,
                "--- stdout ---" + Environment.NewLine + outText
                + (errText.Length > 0
                    ? Environment.NewLine + "--- stderr ---" + Environment.NewLine + errText
                    : ""),
                swRun.ElapsedMilliseconds);

            return new PsResult(proc.ExitCode, outText, errText);
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
        // 1) PowerShell 7 in the standard install locations for this OS.
        var candidates = new List<string>();
        if (OperatingSystem.IsWindows())
        {
            candidates.Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "PowerShell", "7", "pwsh.exe"));
            candidates.Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "PowerShell", "7", "pwsh.exe"));
            candidates.Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "WindowsApps", "pwsh.exe"));
        }
        else
        {
            // macOS: Homebrew on Apple silicon, Homebrew on Intel, and the pkg installer.
            candidates.Add("/opt/homebrew/bin/pwsh");
            candidates.Add("/usr/local/bin/pwsh");
            candidates.Add("/usr/local/microsoft/powershell/7/pwsh");
            candidates.Add("/usr/bin/pwsh");
            candidates.Add("/snap/bin/pwsh");
        }

        foreach (var p in candidates)
            if (File.Exists(p)) return p;

        // 2) pwsh anywhere on PATH.
        var exe = OperatingSystem.IsWindows() ? "pwsh.exe" : "pwsh";
        var onPath = ProbePath(exe);
        if (onPath is not null) return onPath;

        // 3) Windows PowerShell 5.1 — always present on Windows, absent elsewhere.
        if (OperatingSystem.IsWindows())
        {
            var winPs = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe");
            if (File.Exists(winPs)) return winPs;

            var onPath51 = ProbePath("powershell.exe");
            if (onPath51 is not null) return onPath51;
        }

        throw new FileNotFoundException(
            OperatingSystem.IsWindows()
                ? "No PowerShell host found. Install PowerShell 7 " +
                  "(winget install Microsoft.PowerShell) or ensure powershell.exe is available."
                : "PowerShell 7 not found. Install it with 'brew install --cask powershell' " +
                  "(macOS), then 'pwsh -c \"Install-Module ExchangeOnlineManagement -Scope CurrentUser\"'. " +
                  "Exchange and Purview features need it; everything else works without it.");
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
