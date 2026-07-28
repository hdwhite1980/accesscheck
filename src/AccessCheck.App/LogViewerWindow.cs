using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace AccessCheck.App;

/// <summary>
/// Reads the verbatim action log, exports it, and asks the AI about it.
///
/// IDENTIFIERS ARE SCRUBBED BEFORE ANYTHING IS SENT. The New Request flow states plainly
/// that the endpoint sees no username and no tenant id, and a raw log is full of both —
/// UPNs, object ids, group names, tenant guids. Shipping one wholesale would quietly break
/// the promise printed at the top of the app.
///
/// Scrubbing uses STABLE placeholders rather than deletion: every occurrence of one guid
/// becomes the same [guid-3], so "the role in this POST is the one that 404'd above" is
/// still visible. That is the relationship an analysis depends on, and it survives.
/// </summary>
public sealed class LogViewerWindow : Window
{
    private readonly string _logDir;
    private readonly Func<string, string, Task<string>> _ask;   // (system, user) -> answer

    private readonly ComboBox _files = new() { MinWidth = 260, Margin = new Thickness(0, 0, 8, 0) };
    private readonly TextBox _body = new()
    {
        IsReadOnly = true,
        FontFamily = new FontFamily("Consolas"),
        FontSize = 12,
        TextWrapping = TextWrapping.NoWrap,
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
        AcceptsReturn = true
    };
    private readonly TextBox _answer = new()
    {
        IsReadOnly = true,
        TextWrapping = TextWrapping.Wrap,
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        Background = Brushes.WhiteSmoke,
        MinHeight = 120
    };
    private readonly CheckBox _scrub = new()
    {
        Content = "Scrub identifiers before sending (UPNs, object IDs)",
        IsChecked = true,
        VerticalAlignment = VerticalAlignment.Center,
        Margin = new Thickness(12, 0, 0, 0)
    };
    private readonly TextBlock _status = new() { Margin = new Thickness(0, 6, 0, 0), Opacity = 0.75 };

    /// <summary>How much of a long log to send when analysing the whole thing.</summary>
    private const int WholeLogCharLimit = 60_000;

    public LogViewerWindow(string logDir, Func<string, string, Task<string>> ask)
    {
        _logDir = logDir;
        _ask = ask;

        Title = "Action log";
        Width = 1150;
        Height = 780;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        var openFolder = Button("Open folder", (_, _) => OpenFolder());
        var refresh = Button("Reload", (_, _) => LoadSelectedFile());
        var export = Button("Export...", (_, _) => Export());
        var askSel = Button("Ask AI about selection", async (_, _) => await AskAsync(selectionOnly: true));
        var askAll = Button("Analyse whole log", async (_, _) => await AskAsync(selectionOnly: false));

        var bar = new WrapPanel { Margin = new Thickness(10, 10, 10, 6) };
        bar.Children.Add(new TextBlock
        {
            Text = "File:",
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 6, 0)
        });
        bar.Children.Add(_files);
        foreach (var b in new[] { refresh, openFolder, export, askSel, askAll }) bar.Children.Add(b);
        bar.Children.Add(_scrub);

        var grid = new Grid { Margin = new Thickness(10, 0, 10, 10) };
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(3, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        Grid.SetRow(_body, 0);
        var answerLabel = new TextBlock { Text = "AI analysis", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 8, 0, 4) };
        Grid.SetRow(answerLabel, 1);
        Grid.SetRow(_answer, 2);
        grid.Children.Add(_body);
        grid.Children.Add(answerLabel);
        grid.Children.Add(_answer);

        var root = new DockPanel();
        DockPanel.SetDock(bar, Dock.Top);
        root.Children.Add(bar);
        var statusHost = new StackPanel { Margin = new Thickness(10, 0, 10, 8) };
        statusHost.Children.Add(_status);
        DockPanel.SetDock(statusHost, Dock.Bottom);
        root.Children.Add(statusHost);
        root.Children.Add(grid);
        Content = root;

        _files.SelectionChanged += (_, _) => LoadSelectedFile();
        Loaded += (_, _) => PopulateFiles();
    }

    private static Button Button(string text, RoutedEventHandler onClick)
    {
        var b = new Button { Content = text, Margin = new Thickness(0, 0, 8, 0), Padding = new Thickness(10, 4, 10, 4) };
        b.Click += onClick;
        return b;
    }

    private void PopulateFiles()
    {
        _files.Items.Clear();
        if (!Directory.Exists(_logDir))
        {
            _status.Text = "No log directory yet: " + _logDir;
            return;
        }

        var files = new DirectoryInfo(_logDir)
            .GetFiles("actions-*.log")
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .ToList();

        foreach (var f in files)
            _files.Items.Add(f.Name + "   (" + (f.Length / 1024) + " KB)");

        if (_files.Items.Count > 0) _files.SelectedIndex = 0;
        else _status.Text = "No logs yet — perform an action and reload.";
    }

    private string? SelectedPath()
    {
        if (_files.SelectedItem is not string label) return null;
        var name = label.Split("   (")[0];
        return Path.Combine(_logDir, name);
    }

    private void LoadSelectedFile()
    {
        var path = SelectedPath();
        if (path is null || !File.Exists(path)) return;
        try
        {
            // Shared read: the app is very likely still appending to this file.
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            _body.Text = sr.ReadToEnd();
            _body.ScrollToEnd();
            _status.Text = Path.GetFileName(path) + " — " + _body.Text.Length.ToString("N0") + " characters.";
        }
        catch (Exception ex)
        {
            _status.Text = "Could not read the log: " + ex.Message;
        }
    }

    private void OpenFolder()
    {
        try
        {
            Directory.CreateDirectory(_logDir);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = _logDir,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            _status.Text = "Could not open the folder: " + ex.Message;
        }
    }

    private void Export()
    {
        var path = SelectedPath();
        if (path is null) { _status.Text = "Nothing selected to export."; return; }

        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            FileName = Path.GetFileName(path),
            Filter = "Log files (*.log)|*.log|Text files (*.txt)|*.txt|All files (*.*)|*.*",
            Title = "Export action log"
        };
        if (dlg.ShowDialog(this) != true) return;

        try
        {
            // Exports what is ON SCREEN, so an export taken with scrubbing in mind matches
            // what was analysed. The file on disk is never modified.
            File.WriteAllText(dlg.FileName,
                _scrub.IsChecked == true ? Scrub(_body.Text) : _body.Text,
                new UTF8Encoding(false));
            _status.Text = "Exported to " + dlg.FileName
                           + (_scrub.IsChecked == true ? " (identifiers scrubbed)." : " (verbatim).");
        }
        catch (Exception ex)
        {
            _status.Text = "Export failed: " + ex.Message;
        }
    }

    private async Task AskAsync(bool selectionOnly)
    {
        var text = selectionOnly ? _body.SelectedText : _body.Text;

        if (selectionOnly && string.IsNullOrWhiteSpace(text))
        {
            _status.Text = "Select some of the log first, then ask.";
            return;
        }
        if (string.IsNullOrWhiteSpace(text)) { _status.Text = "Nothing to analyse."; return; }

        var truncated = false;
        if (text.Length > WholeLogCharLimit)
        {
            // The END of a log is where a failure lands, so keep the tail rather than the head.
            text = text[^WholeLogCharLimit..];
            truncated = true;
        }

        var payload = _scrub.IsChecked == true ? Scrub(text) : text;

        const string system =
            "You are debugging a Microsoft Graph and PowerShell integration from its request/" +
            "response log. Identify what FAILED and why, quoting the specific request that " +
            "failed and the error it returned. Distinguish a transient fault (retry succeeded, " +
            "or would) from a structural one (the same request will always fail). Say plainly " +
            "which it is. If an expected request is MISSING from the sequence, say so — an " +
            "absent call is often the real defect. Identifiers may appear as placeholders like " +
            "[guid-2]; treat repeated placeholders as the same object. Be concise and specific; " +
            "no markdown.";

        var user = (selectionOnly ? "SELECTED PORTION OF LOG" : "ACTION LOG")
                   + (truncated ? " (tail only — earlier lines omitted)" : "")
                   + ":\n\n" + payload;

        try
        {
            _status.Text = "Asking the AI (" + payload.Length.ToString("N0") + " characters"
                           + (_scrub.IsChecked == true ? ", scrubbed" : ", VERBATIM") + ")...";
            _answer.Text = "";
            IsEnabled = false;
            _answer.Text = await _ask(system, user);
            _status.Text = "Analysis complete.";
        }
        catch (Exception ex)
        {
            _answer.Text = "";
            _status.Text = "Analysis failed: " + ex.Message;
        }
        finally
        {
            IsEnabled = true;
        }
    }

    // ---- scrubbing ------------------------------------------------------------------

    private static readonly Regex GuidPattern = new(
        @"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        RegexOptions.Compiled);

    private static readonly Regex UpnPattern = new(
        @"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled);

    /// <summary>
    /// Replaces identifiers with STABLE placeholders — the same guid always becomes the same
    /// [guid-n]. Deleting them would destroy the only thing an analysis needs: which object
    /// in this request is the object that failed in that one.
    /// </summary>
    public static string Scrub(string text)
    {
        var guids = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var upns = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        text = GuidPattern.Replace(text, m =>
        {
            if (!guids.TryGetValue(m.Value, out var tag))
            {
                tag = "[guid-" + (guids.Count + 1) + "]";
                guids[m.Value] = tag;
            }
            return tag;
        });

        text = UpnPattern.Replace(text, m =>
        {
            if (!upns.TryGetValue(m.Value, out var tag))
            {
                tag = "[user-" + (upns.Count + 1) + "@example.com]";
                upns[m.Value] = tag;
            }
            return tag;
        });

        return text;
    }
}
