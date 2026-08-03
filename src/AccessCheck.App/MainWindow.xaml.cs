using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using AccessCheck.Ai;
using AccessCheck.Core.Audit;
using AccessCheck.Core.Catalog;
using AccessCheck.Core.Config;
using AccessCheck.Core.Execution;
using AccessCheck.Core.Groups;
using AccessCheck.Core.Recommendation;
using Microsoft.Win32;
using AccessCheck.Core.Review;
using AccessCheck.Graph;
using AccessCheck.PowerShell;

namespace AccessCheck.App;

public partial class MainWindow : Window
{
    private readonly string _dataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AccessCheck");
    private string CatalogPath => Path.Combine(_dataDir, "catalog.json");
    private string GroupCatalogPath => Path.Combine(_dataDir, "groups.json");
    private string HistoryPath => Path.Combine(_dataDir, "history.jsonl");
    private string PromptLogPath => Path.Combine(_dataDir, "prompt-log.txt");
    private string PsScriptLogPath => Path.Combine(_dataDir, "ps-script-log.txt");
    private string ConfigPath => Path.Combine(_dataDir, "appsettings.json");

    private AppConfig _config = new();
    private RoleCatalog? _catalog;
    private GroupCatalog? _groupCatalog;
    private GraphClient? _graph;
    private CloudEnvironment? _cloud;

    // last analysis state
    private AiSuggestion? _lastSuggestion;
    private string? _lastPromptSha;
    private string _lastFunction = "";
    private readonly List<OutcomeCard> _cards = new();
    /// <summary>Actions the approver added by hand — merged into validation, audited separately.</summary>
    private readonly List<string> _manualActions = new();

    /// <summary>
    /// Permissions the operator has explicitly taken OUT of the suggestion. There was an
    /// add path but no remove path, so a wrongly-chosen permission could be supplemented
    /// and never withdrawn.
    /// </summary>
    private readonly List<string> _removedActions = new();
    /// <summary>Role ids proven not to exist this session — never matched again.</summary>
    private readonly HashSet<string> _staleRoleIdsIgnored =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _explainCache =
        new(StringComparer.OrdinalIgnoreCase);

    private sealed class OutcomeCard
    {
        public required string Provider { get; init; }
        public required ValidationOutcome Outcome { get; init; }
        public required CheckBox Include { get; init; }
        public required ComboBox Choice { get; init; }
        /// <summary>Index-aligned with Choice items: CustomRoleDraft or RoleFit.</summary>
        public required List<object> Options { get; init; }
    }

    public MainWindow() => InitializeComponent();

    // ---------------- lifecycle / settings ----------------

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(_dataDir);
        MigrateLegacyDataFolder();

        // Always show which build is running — diagnosing a bug against the wrong
        // binary wastes more time than the bug does.
        var asm = System.Reflection.Assembly.GetExecutingAssembly();
        var version = asm.GetName().Version?.ToString(3) ?? "?";
        var packaged = IsPackaged() ? " (MSIX)" : "";
        HeaderVersion.Text = "v" + version + packaged;
        if (File.Exists(ConfigPath))
        {
            try { _config = AppConfig.Load(ConfigPath); }
            catch (Exception ex) { Status("Config load failed: " + ex.Message); }
        }
        ApplyConfigToUi();

        // THE REFERENCE MUST LOAD FIRST. PermissionIndex takes Microsoft's descriptions from
        // it, so building the index before the reference exists produced an index with no
        // real descriptions — and it stayed that way until the next rebuild.
        // FIRST RUN ONLY, AND NEVER OVERWRITING. Two files carry knowledge no tenant can
        // produce for itself: Microsoft exposes no Purview role contents through any API,
        // and Exchange Online's REST proxy cmdlets carry no help text. Without them a fresh
        // install holds vocabulary for 8 Purview roles out of 120 and reads Exchange cmdlet
        // NAMES with nothing to check them against — which is how a request to remove
        // messages came back with Remove-Mailbox.
        //
        // Seeded BEFORE the reference and catalog load below, or the first launch runs
        // without them and the user sees the degraded behaviour once for no reason.
        var seeded = SeedData.EnsureSeeded(_dataDir);
        if (seeded.Count > 0)
            _lastSyncReport.Add("First run: installed bundled reference data (" +
                                string.Join(", ", seeded) + ").");

        _referenceStore = ReferenceStore.Load(ReferencePath);
        _cmdletCapabilities = CmdletCapabilityStore.Load(CmdletCapabilityPath);
        _ineligibility = CustomRoleEligibility.Load(IneligibilityPath);
        // BEFORE ActionRisk READS IT. Exchange and Purview cmdlets carry no description
        // from any API — Exchange Online's REST mode generates proxy cmdlets with no help
        // content, so even Get-Help returns an empty synopsis. Merging afterwards would
        // leave UseDescriptions, PermissionIndex, the guards and the verifier all looking
        // at the description-less version.
        var cmdletDocs = CmdletDescriptionStore.Load(CmdletDescriptionsPath);
        if (!cmdletDocs.IsEmpty) cmdletDocs.MergeInto(_referenceStore, RbacProviders.Exchange);

        ActionRisk.UseAuthoritative(_referenceStore.StatedPrivilege());
        // BOTH CORRECTIONS, NOT ONE. UseAuthoritative covers only actions where Microsoft
        // STATES a privilege flag, and Intune states none for any action at all — so on
        // that service the heuristic's "unknown shape: treat as privileged" default decided
        // everything, rating View_reports as escalation-capable at six times a read's cost
        // in every ranking decision. The descriptions are the only correction available
        // there, and installing one without the other left it switched off.
        ActionRisk.UseDescriptions(_referenceStore.Descriptions());

        if (File.Exists(CatalogPath))
        {
            try
            {
                _catalog = RoleCatalog.Load(CatalogPath);
                PurviewRoleMap.EnrichNameOnlyRoles(_catalog);
                // The built-in map covers a handful by hand; Microsoft publishes all 119.
                PurviewRoleCatalog.LoadOrImport(PurviewRolesPath, PurviewRolesMarkdownPath)
                    .EnrichCatalog(_catalog);
                RefreshCatalogGrid();
        RebuildPermissionCatalog();
        RefreshForcedProviderList();
                SyncSummary.Text = _catalog.Roles.Count + " roles / " +
                    _catalog.ActionCount + " actions (synced " +
                    (_catalog.LastSyncedUtc?.ToString("u") ?? "?") + ")";
            }
            catch (Exception ex) { Status("Catalog load failed: " + ex.Message); }
        }
        if (File.Exists(GroupCatalogPath))
        {
            try
            {
                _groupCatalog = GroupCatalog.Load(GroupCatalogPath);
                RefreshGroupsGrid();
                GroupSyncSummary.Text = _groupCatalog.Groups.Count +
                    " group(s) carrying roles (synced " +
                    (_groupCatalog.LastSyncedUtc?.ToString("u") ?? "?") + ")";
            }
            catch (Exception ex) { Status("Group catalog load failed: " + ex.Message); }
        }

        RefreshHistoryGrid();
        RestoreTutorialState();
        CheckCatalogState();
    }

    // ---------------- group entitlements ----------------

    private sealed record GroupRow(
        string Name, string Roles, string Services, int ActionCount,
        string RoleAssignable, string GroupId)
    {
        public IReadOnlyList<string> Actions { get; init; } = Array.Empty<string>();
    }

    private List<GroupRow> _groupRows = new();
    private List<string> _lastGroupSyncReport = new();

    private async void AssignRoleToGroup_Click(object sender, RoutedEventArgs e)
    {
        if (_catalog is null || _catalog.Roles.Count == 0)
        {
            MessageBox.Show("Sync the role catalog first (Catalog tab).",
                "No role catalog", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        AssignRoleToGroupButton.IsEnabled = false;
        try
        {
            var graph = GetGraph();
            await graph.Auth.WarmUpOrToken();

            // --- pick the group ---
            var typed = PromptForText("Assign role to group",
                "Group name or object ID that should CARRY the role:", "");
            if (string.IsNullOrWhiteSpace(typed)) return;

            var lookup = new DirectoryLookup(graph);
            GroupHit target;
            if (Guid.TryParse(typed.Trim(), out _))
            {
                var byId = await lookup.SearchGroupsAsync(typed.Trim());
                target = byId.FirstOrDefault(g => g.Id == typed.Trim())
                         ?? new GroupHit(typed.Trim(), typed.Trim(), false);
            }
            else
            {
                var matches = await lookup.SearchGroupsAsync(typed.Trim());
                if (matches.Count == 0)
                {
                    MessageBox.Show("No group name starts with '" + typed.Trim() + "'.",
                        "Not found", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                var chosenText = matches.Count == 1
                    ? matches[0].ToString()
                    : PickFromList("Select the group", matches.Select(m => m.ToString()).ToList());
                if (chosenText is null) return;
                target = matches.First(m => m.ToString() == chosenText);
            }

            // --- pick the role ---
            var roleQuery = PromptForText("Assign role to group",
                "Role name (or part of it) to assign to '" + target.DisplayName + "':", "");
            if (string.IsNullOrWhiteSpace(roleQuery)) return;

            var roleMatches = _catalog.Roles
                .Where(r => r.DisplayName.Contains(roleQuery.Trim(), StringComparison.OrdinalIgnoreCase))
                .OrderBy(r => r.Provider).ThenBy(r => r.DisplayName)
                .Take(200)
                .ToList();
            if (roleMatches.Count == 0)
            {
                MessageBox.Show("No role in the catalog matches '" + roleQuery.Trim() + "'.",
                    "Not found", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            var labels = roleMatches
                .Select(r => RbacProviders.DisplayName(r.Provider) + "  |  " + r.DisplayName +
                             "  (" + r.AllowedResourceActions.Count + " permissions)")
                .ToList();
            var pickedLabel = roleMatches.Count == 1 ? labels[0]
                : PickFromList("Select the role to assign to '" + target.DisplayName + "'", labels);
            if (pickedLabel is null) return;
            var role = roleMatches[labels.IndexOf(pickedLabel)];

            // --- role-assignable gate for directory roles ---
            if (role.Provider == RbacProviders.Directory && !target.IsRoleAssignable)
            {
                MessageBox.Show(
                    "'" + target.DisplayName + "' is NOT role-assignable, so Entra will reject " +
                    "an Entra directory role on it.\n\n" +
                    "That flag can only be set when a group is created and cannot be changed " +
                    "afterwards — this group can never hold a directory role.\n\n" +
                    "Options:\n" +
                    "  • Create a new role-assignable group for directory roles, or\n" +
                    "  • Assign an Intune / Windows 365 / Defender role instead — those do not " +
                    "require the flag.",
                    "Group cannot hold directory roles",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (RbacProviders.DerivedRoleCapable.Contains(role.Provider))
            {
                MessageBox.Show(
                    "Exchange and Purview roles are carried by role groups through PowerShell, " +
                    "not by assigning a role to a security group. Use a New Request grant for " +
                    "those services instead.",
                    "Not applicable", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var confirm = MessageBox.Show(
                "Assign role '" + role.DisplayName + "' (" +
                RbacProviders.DisplayName(role.Provider) + ", " +
                role.AllowedResourceActions.Count + " permissions)\n" +
                "to group '" + target.DisplayName + "' (" + target.Id + ")?\n\n" +
                "This is a PERMANENT assignment to the GROUP — that is normal for pre-staging. " +
                "Time-bound access is then controlled by who is a MEMBER of the group.\n\n" +
                "Anyone in this group gains those permissions immediately.",
                "Confirm role assignment", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes) return;

            Status("Assigning role to group...");
            var executor = new RoleExecutor(graph);
            string assignmentId;
            if (role.Provider == RbacProviders.Directory)
                assignmentId = await executor.AssignDirectoryRoleToPrincipalAsync(target.Id, role.Id);
            else
            {
                RoleExecutor.IntuneAssignmentScope? scope = null;
                if (role.Provider == RbacProviders.Intune)
                {
                    scope = await ChooseIntuneScopeAsync(role.DisplayName);
                    if (scope is null) { Status("Cancelled at scope selection."); return; }
                }
                assignmentId = await executor.AssignMultiAsync(
                    role.Provider, target.Id, role.Id,
                    "AccessCheck: pre-stage group with role for delegated access", scope);
            }

            new RequestHistoryStore(HistoryPath).Append(new RequestRecord
            {
                Id = Guid.NewGuid().ToString("N"),
                CreatedUtc = DateTimeOffset.UtcNow,
                FunctionDescription = "Pre-stage group '" + target.DisplayName +
                                      "' with role '" + role.DisplayName + "'",
                PrincipalId = target.Id,
                Provider = role.Provider,
                ChosenRoleId = role.Id,
                ChosenRoleDisplay = role.DisplayName,
                Approved = true,
                ApprovedBy = Environment.UserName,
                ApprovedUtc = DateTimeOffset.UtcNow,
                AssignmentTypeUsed = "RoleToGroup",
                Duration = "PERMANENT",
                PermanentGrant = true,
                GroupIdUsed = target.Id,
                Notes = "Role assigned to the group itself (assignment id " + assignmentId + ")."
            });

            MessageBox.Show(
                "Assigned.\n\n'" + target.DisplayName + "' now carries '" + role.DisplayName +
                "'.\n\nRun 'Sync groups' to see it listed, after which New Request will offer " +
                "this group whenever a request matches its permissions.",
                "Role assigned", MessageBoxButton.OK, MessageBoxImage.Information);
            Status("Role assigned to group — re-sync groups to pick it up.");
            RefreshHistoryGrid();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ExplainGrantFailure(ex), "Assignment failed",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Status("Role-to-group assignment failed.");
        }
        finally { AssignRoleToGroupButton.IsEnabled = true; }
    }

    private async void InspectGroup_Click(object sender, RoutedEventArgs e)
    {
        if (_catalog is null)
        {
            MessageBox.Show("Sync the role catalog first (Catalog tab) — role names and " +
                            "permission counts come from it.",
                "No role catalog", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        GroupHit? hit = null;
        try
        {
            InspectGroupButton.IsEnabled = false;
            var graph = GetGraph();
            await graph.Auth.WarmUpOrToken();

            var typed = PromptForText("Inspect a group",
                "Group name or object ID to inspect:", "");
            if (string.IsNullOrWhiteSpace(typed)) return;

            var lookup = new DirectoryLookup(graph);
            if (Guid.TryParse(typed.Trim(), out _))
            {
                hit = new GroupHit(typed.Trim(), typed.Trim(), false);
            }
            else
            {
                var matches = await lookup.SearchGroupsAsync(typed.Trim());
                if (matches.Count == 0)
                {
                    MessageBox.Show("No group name starts with '" + typed.Trim() + "'.",
                        "Not found", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                hit = matches.Count == 1
                    ? matches[0]
                    : matches.FirstOrDefault(m => string.Equals(
                          m.DisplayName, typed.Trim(), StringComparison.OrdinalIgnoreCase))
                      ?? matches[0];
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Lookup failed", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        finally { InspectGroupButton.IsEnabled = true; }

        if (hit is null) return;

        InspectGroupButton.IsEnabled = false;
        try
        {
            Status("Inspecting '" + hit.DisplayName + "' across every assignment surface...");
            var inspector = new GroupInspector(GetGraph(), _catalog);
            var report = await inspector.InspectAsync(hit.Id, msg => Status(msg));
            Status("Inspection complete.");

            var box = new TextBox
            {
                Text = report, IsReadOnly = true, TextWrapping = TextWrapping.NoWrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                BorderThickness = new Thickness(0), Margin = new Thickness(12),
                FontFamily = new FontFamily("Consolas"), FontSize = 12
            };
            new Window
            {
                Title = "Group inspection — " + hit.DisplayName,
                Width = 860, Height = 640, Owner = this,
                WindowStartupLocation = WindowStartupLocation.CenterOwner, Content = box
            }.Show();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Inspection failed",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Status("Inspection failed.");
        }
        finally { InspectGroupButton.IsEnabled = true; }
    }

    // ---------------- permission drill-down (group -> permissions -> groups) ----------------

    private GroupPermissionIndex? _permIndex;

    private GroupPermissionIndex? BuildPermIndex()
    {
        if (_groupCatalog is null || _catalog is null) return null;
        _permIndex = GroupPermissionIndex.Build(_groupCatalog, _catalog);
        return _permIndex;
    }

    private void GroupsGrid_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        => OpenSelectedGroupPermissions();

    private void ViewGroupPerms_Click(object sender, RoutedEventArgs e)
        => OpenSelectedGroupPermissions();

    private void OpenSelectedGroupPermissions()
    {
        if (GroupsGrid.SelectedItem is not GroupRow row)
        {
            Status("Select a group first.");
            return;
        }
        if (BuildPermIndex() is null)
        {
            MessageBox.Show("Sync the role catalog and the group catalog first.",
                "Nothing to show", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        ShowGroupPermissionsWindow(row.GroupId, row.Name);
    }

    /// <summary>Forward view: everything this group grants, and which role supplies each.</summary>
    private void ShowGroupPermissionsWindow(string groupId, string groupName)
    {
        if (_permIndex is null && BuildPermIndex() is null) return;
        var entries = _permIndex!.PermissionsOf(groupId);
        var privileged = entries.Count(en => en.IsPrivileged);

        var header = new StackPanel { Margin = new Thickness(12, 12, 12, 6) };
        header.Children.Add(new TextBlock
        {
            Text = groupName,
            FontSize = 16, FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)FindResource("Steel")
        });
        header.Children.Add(new TextBlock
        {
            Text = entries.Count + " permission(s) — " + privileged + " privileged, " +
                   (entries.Count - privileged) + " read-only. Anyone in this group gets all of them.",
            Style = (Style)FindResource("Hint"), Margin = new Thickness(0, 4, 0, 0),
            TextWrapping = TextWrapping.Wrap
        });
        header.Children.Add(new TextBlock
        {
            Text = "Double-click a permission to see every group that grants it.",
            Style = (Style)FindResource("Hint"), Margin = new Thickness(0, 4, 0, 0)
        });

        var grid = new DataGrid
        {
            AutoGenerateColumns = false, IsReadOnly = true,
            HeadersVisibility = DataGridHeadersVisibility.Column,
            GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
            CanUserSortColumns = true, Margin = new Thickness(10),
            ItemsSource = entries.Select(en => new PermRow(
                en.Action, en.RiskLabel, RbacProviders.DisplayName(en.Provider),
                en.ViaRolesLabel, groupId)).ToList()
        };
        grid.Columns.Add(new DataGridTextColumn
        { Header = "Permission", Binding = new System.Windows.Data.Binding("Action"), Width = 380 });
        grid.Columns.Add(new DataGridTextColumn
        { Header = "Risk", Binding = new System.Windows.Data.Binding("Risk"), Width = 90 });
        grid.Columns.Add(new DataGridTextColumn
        { Header = "Service", Binding = new System.Windows.Data.Binding("Service"), Width = 170 });
        grid.Columns.Add(new DataGridTextColumn
        { Header = "Granted by role", Binding = new System.Windows.Data.Binding("Via"), Width = 250 });

        grid.MouseDoubleClick += (_, _) =>
        {
            if (grid.SelectedItem is PermRow pr) ShowPermissionGroupsWindow(pr.Action);
        };

        var explainBtn = new Button
        {
            Content = "Explain selected permission", Margin = new Thickness(10, 0, 10, 10),
            HorizontalAlignment = HorizontalAlignment.Left
        };
        explainBtn.Click += async (_, _) =>
        {
            if (grid.SelectedItem is PermRow pr) await ShowExplanationAsync(pr.Action);
        };

        var root = new DockPanel();
        DockPanel.SetDock(header, Dock.Top);
        DockPanel.SetDock(explainBtn, Dock.Bottom);
        root.Children.Add(header);
        root.Children.Add(explainBtn);
        root.Children.Add(grid);

        new Window
        {
            Title = "Permissions granted by " + groupName,
            Width = 940, Height = 620, Owner = this,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, Content = root
        }.Show();
    }

    /// <summary>Reverse view: every group that grants one permission.</summary>
    private void ShowPermissionGroupsWindow(string action)
    {
        if (_permIndex is null && BuildPermIndex() is null) return;
        var sources = _permIndex!.GroupsGranting(action);

        var header = new StackPanel { Margin = new Thickness(12, 12, 12, 6) };
        header.Children.Add(new TextBlock
        {
            Text = action,
            FontSize = 15, FontWeight = FontWeights.SemiBold,
            FontFamily = new FontFamily("Consolas"),
            Foreground = (Brush)FindResource("Steel"),
            TextWrapping = TextWrapping.Wrap
        });
        header.Children.Add(new TextBlock
        {
            Text = ActionRisk.IsPrivileged(action)
                ? "Privileged — this can change state or perform an administrative task."
                : "Read-only.",
            Foreground = (Brush)FindResource(ActionRisk.IsPrivileged(action) ? "Warn" : "Ok"),
            Margin = new Thickness(0, 4, 0, 0)
        });
        header.Children.Add(new TextBlock
        {
            Text = sources.Count == 0
                ? "No group in the synced catalog grants this permission."
                : sources.Count + " group(s) grant it. Anyone in any of them holds this permission." +
                  (sources.Count > 1
                      ? "  Multiple groups granting the same permission is worth consolidating."
                      : ""),
            Style = (Style)FindResource("Hint"),
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0)
        });

        var grid = new DataGrid
        {
            AutoGenerateColumns = false, IsReadOnly = true,
            HeadersVisibility = DataGridHeadersVisibility.Column,
            GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
            CanUserSortColumns = true, Margin = new Thickness(10),
            ItemsSource = sources.Select(x => new SourceRow(
                x.GroupName, x.ViaRolesLabel, x.GroupTotalPermissions, x.GroupId)).ToList()
        };
        grid.Columns.Add(new DataGridTextColumn
        { Header = "Group", Binding = new System.Windows.Data.Binding("Group"), Width = 260 });
        grid.Columns.Add(new DataGridTextColumn
        { Header = "Granted by role", Binding = new System.Windows.Data.Binding("Via"), Width = 260 });
        grid.Columns.Add(new DataGridTextColumn
        { Header = "Group's total perms", Binding = new System.Windows.Data.Binding("Total"), Width = 130 });
        grid.Columns.Add(new DataGridTextColumn
        { Header = "Group ID", Binding = new System.Windows.Data.Binding("GroupId"), Width = 280 });

        // Double-click a group here to walk back the other way.
        grid.MouseDoubleClick += (_, _) =>
        {
            if (grid.SelectedItem is SourceRow sr)
                ShowGroupPermissionsWindow(sr.GroupId, sr.Group);
        };

        var root = new DockPanel();
        DockPanel.SetDock(header, Dock.Top);
        root.Children.Add(header);
        root.Children.Add(grid);

        new Window
        {
            Title = "Groups granting " + action,
            Width = 960, Height = 560, Owner = this,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, Content = root
        }.Show();
    }

    private sealed record PermRow(string Action, string Risk, string Service, string Via, string GroupId);
    private sealed record SourceRow(string Group, string Via, int Total, string GroupId);

    private void GroupSyncReport_Click(object sender, RoutedEventArgs e)
    {
        var text = _lastGroupSyncReport.Count == 0
            ? "No group sync has run yet in this session."
            : string.Join(Environment.NewLine, _lastGroupSyncReport) +
              Environment.NewLine + Environment.NewLine +
              "Reading notes:" + Environment.NewLine +
              "- A source marked FAILED is skipped; everything else still synced." + Environment.NewLine +
              "- 403 means the delegated permission isn't consented, or the service isn't licensed." +
              Environment.NewLine +
              "- Groups only appear here if they actually hold a role. A tenant that assigns " +
              "roles straight to users will show none, which is a finding in itself.";
        var box = new TextBox
        {
            Text = text, IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            BorderThickness = new Thickness(0), Margin = new Thickness(12), FontSize = 12
        };
        new Window
        {
            Title = "Group sync details", Width = 720, Height = 480, Owner = this,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, Content = box
        }.Show();
    }

    private async void GroupSync_Click(object sender, RoutedEventArgs e)
    {
        if (_catalog is null)
        {
            MessageBox.Show(
                "Sync the role catalog first (Catalog tab) — group permissions are expanded " +
                "from the roles those groups hold.",
                "No role catalog", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        GroupSyncButton.IsEnabled = false;
        GroupSyncWarnings.Text = "";
        try
        {
            var sync = new GroupEntitlementSync(GetGraph(), _catalog);
            var result = await sync.SyncAsync(msg => Status(msg));
            _groupCatalog = result;
            result.Save(GroupCatalogPath);

            var totalActions = result.Groups
                .SelectMany(g => g.GrantedActions)
                .Distinct(StringComparer.OrdinalIgnoreCase).Count();
            _lastGroupSyncReport = new List<string>(sync.SourceCounts);
            var byType = sync.Holders
                .GroupBy(h => h.Type, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.Count() + " " + g.Key + (g.Count() == 1 ? "" : "s"))
                .ToList();
            _lastGroupSyncReport.Insert(0,
                sync.PrincipalsExamined + " principal(s) hold a role" +
                (byType.Count > 0 ? ": " + string.Join(", ", byType) : "") + ".");

            if (sync.Holders.Count > 0)
            {
                _lastGroupSyncReport.Add("");
                _lastGroupSyncReport.Add("Who holds roles directly:");
                foreach (var h in sync.Holders)
                    _lastGroupSyncReport.Add("  [" + h.Type + "] " + h.Name +
                                             " — " + h.RoleCount + " role(s)");
                var directUsers = sync.Holders.Count(h =>
                    h.Type.Equals("user", StringComparison.OrdinalIgnoreCase));
                if (directUsers > 0)
                {
                    _lastGroupSyncReport.Add("");
                    _lastGroupSyncReport.Add(
                        "FINDING: " + directUsers + " user(s) hold roles by DIRECT assignment " +
                        "rather than through a group. Direct assignments have to be granted and " +
                        "revoked one at a time, and they don't show up in group-based reviews.");
                }
            }
            if (sync.Warnings.Count > 0)
            {
                _lastGroupSyncReport.Add("");
                _lastGroupSyncReport.AddRange(sync.Warnings);
            }

            GroupSyncSummary.Text = result.Groups.Count + " group(s) carrying roles, " +
                                    totalActions + " distinct permission(s).";

            // A zero result has two very different meanings — say which one it is.
            if (result.Groups.Count == 0)
            {
                if (sync.PrincipalsExamined == 0)
                {
                    GroupSyncSummary.Text += "  No role assignments could be read at all — see Details.";
                }
                else
                {
                    var users = sync.Holders.Count(h =>
                        h.Type.Equals("user", StringComparison.OrdinalIgnoreCase));
                    var sps = sync.Holders.Count(h =>
                        h.Type.StartsWith("service", StringComparison.OrdinalIgnoreCase));
                    GroupSyncSummary.Text +=
                        "  Confirmed by lookup: of " + sync.PrincipalsExamined +
                        " role-holding principal(s), " + users + " are users and " + sps +
                        " are service principals — none are groups. Click Details for who.";
                }
            }

            // Partial reads never hide what DID come back.
            // Only genuine problems get a banner. Unlicensed services and absent providers
            // are expected conditions and belong in Details, not in the operator's face.
            GroupSyncWarnings.Text = sync.Issues.BannerText;
            if (GroupSyncWarnings.Text.Length == 0 && sync.Issues.All.Count > 0)
                _lastGroupSyncReport.Add("");
            foreach (var issue in sync.Issues.All) _lastGroupSyncReport.Add(issue.Line);

            RefreshGroupsGrid();
            BuildPermIndex();
            var actionable = sync.Issues.Actionable.Count;
            Status("Group sync complete — " + result.Groups.Count + " group(s) shown" +
                   (actionable > 0
                       ? " (" + actionable + " issue(s) need attention — see Details)."
                       : sync.Issues.All.Count > 0
                           ? " (" + sync.Issues.All.Count + " expected condition(s) logged)."
                           : "."));
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Group sync failed",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Status("Group sync failed.");
        }
        finally { GroupSyncButton.IsEnabled = true; }
    }

    private void RefreshGroupsGrid()
    {
        if (_groupCatalog is null) return;
        _groupRows = _groupCatalog.Groups.Select(g => new GroupRow(
            g.DisplayName,
            g.RolesLabel,
            string.Join(", ", g.Providers.Select(RbacProviders.DisplayName)),
            g.GrantedActions.Count,
            g.IsRoleAssignable ? "yes" : "no",
            g.GroupId) { Actions = g.GrantedActions }).ToList();
        ApplyGroupFilter();
    }

    private void GroupFilter_TextChanged(object sender, TextChangedEventArgs e) => ApplyGroupFilter();

    private void ApplyGroupFilter()
    {
        var q = GroupFilter.Text.Trim();
        GroupsGrid.ItemsSource = q.Length == 0
            ? _groupRows
            : _groupRows.Where(r =>
                r.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                r.Roles.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                r.Actions.Any(a => a.Contains(q, StringComparison.OrdinalIgnoreCase))).ToList();
    }

    /// <summary>
    /// Shows existing groups that already grant what the request needs, so the admin can
    /// add the user to a proven group instead of minting another role.
    /// </summary>
    private void RenderGroupMatches(IReadOnlyList<string> requiredActions)
    {
        GroupMatchPanel.Children.Clear();
        if (_groupCatalog is null || _groupCatalog.Groups.Count == 0 || requiredActions.Count == 0)
            return;

        var fits = GroupMatcher.Rank(_groupCatalog.Groups, requiredActions);
        if (fits.Count == 0) return;

        var card = new Border { Style = (Style)FindResource("Card") };
        var stack = new StackPanel();
        card.Child = stack;

        var full = fits.Where(f => f.FullyCovers).ToList();
        stack.Children.Add(new TextBlock
        {
            Text = full.Count > 0
                ? "Existing groups already grant this"
                : "No existing group fully covers this — closest matches",
            FontSize = 15, FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)FindResource(full.Count > 0 ? "Ok" : "Steel")
        });
        stack.Children.Add(new TextBlock
        {
            Text = full.Count > 0
                ? "Adding the user to one of these avoids creating another role. Ranked by " +
                  "risk-weighted excess — fewer privileged extras is better."
                : "These grant some of what's needed. Using one still leaves gaps, listed per group.",
            Style = (Style)FindResource("Hint"),
            Margin = new Thickness(0, 4, 0, 8)
        });

        foreach (var fit in fits.Take(6))
        {
            var row = new StackPanel { Margin = new Thickness(0, 6, 0, 6) };
            row.Children.Add(new TextBlock
            {
                Text = fit.Group.DisplayName +
                       (fit.Group.IsRoleAssignable ? "  [role-assignable]" : ""),
                FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource("Steel"),
                TextWrapping = TextWrapping.Wrap
            });
            row.Children.Add(new TextBlock
            {
                Text = fit.Summary + "  ·  holds: " + fit.Group.RolesLabel,
                TextWrapping = TextWrapping.Wrap,
                Foreground = (Brush)FindResource(fit.FullyCovers ? "Ok" : "Warn"),
                Margin = new Thickness(0, 2, 0, 0)
            });

            if (fit.MissingActions.Count > 0)
                row.Children.Add(MakeChipRow("Still missing:",
                    fit.MissingActions.Take(12), MakeActionChip));
            if (fit.ExcessActions.Count > 0)
                row.Children.Add(MakeChipRow("Extra granted by joining:",
                    fit.ExcessActions.Take(15), MakeActionChip));

            var use = new Button
            {
                Content = "Use this group",
                HorizontalAlignment = HorizontalAlignment.Left,
                Margin = new Thickness(0, 8, 0, 0),
                Tag = fit.Group.GroupId
            };
            var groupId = fit.Group.GroupId;
            var groupName = fit.Group.DisplayName;
            use.Click += (_, _) =>
            {
                PimGroupBox.Text = groupId;
                foreach (var c in _cards) c.Include.IsChecked = false;
                ExecutePanel.Visibility = Visibility.Visible;
                Status("Group '" + groupName + "' selected — every card is now unticked, so " +
                       "approving adds the user to this group without granting any new role. " +
                       "Pick the grant mode below.");
            };
            row.Children.Add(use);
            stack.Children.Add(row);
        }

        GroupMatchPanel.Children.Add(card);
    }

    /// <summary>
    /// One-time carry-over from the previous product name so existing settings,
    /// catalog, history, stored API key, and MSAL token cache survive the rename.
    /// DPAPI blobs are bound to the user, not the path, so copying is sufficient.
    /// </summary>
    private void MigrateLegacyDataFolder()
    {
        try
        {
            var legacy = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AccessLens");
            if (!Directory.Exists(legacy)) return;
            if (File.Exists(Path.Combine(_dataDir, "appsettings.json"))) return; // already set up

            foreach (var dir in Directory.GetDirectories(legacy, "*", SearchOption.AllDirectories))
                Directory.CreateDirectory(dir.Replace(legacy, _dataDir));
            foreach (var file in Directory.GetFiles(legacy, "*", SearchOption.AllDirectories))
            {
                var target = file.Replace(legacy, _dataDir);
                if (!File.Exists(target)) File.Copy(file, target);
            }
            Status("Carried over settings from the previous install.");
        }
        catch (Exception)
        {
            // Migration is best-effort; a fresh setup still works.
        }
    }

    /// <summary>True when running from an installed MSIX rather than a loose folder.</summary>
    private static bool IsPackaged()
    {
        try
        {
            // Packaged processes have a package family name; unpackaged ones throw.
            return !string.IsNullOrEmpty(
                Environment.GetEnvironmentVariable("MSIX_PACKAGE_FAMILY_NAME"))
                || AppContext.BaseDirectory.Contains(@"\WindowsApps\",
                    StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception) { return false; }
    }

    private void ApplyConfigToUi()
    {
        foreach (ComboBoxItem item in CloudCombo.Items)
            if (string.Equals((string)item.Content, _config.Cloud, StringComparison.OrdinalIgnoreCase))
                CloudCombo.SelectedItem = item;
        if (CloudCombo.SelectedItem is null) CloudCombo.SelectedIndex = 0;
        TenantBox.Text = _config.TenantId;
        ClientBox.Text = _config.ClientId;
        ExcessBox.Text = _config.MaxAcceptableExcessActions.ToString();
        foreach (ComboBoxItem item in AiProviderCombo.Items)
            if (string.Equals((string)item.Content, _config.Ai.Provider, StringComparison.OrdinalIgnoreCase))
                AiProviderCombo.SelectedItem = item;
        if (AiProviderCombo.SelectedItem is null) AiProviderCombo.SelectedIndex = 0;
        AiUrlBox.Text = _config.Ai.BaseUrl;
        AiModelBox.Text = _config.Ai.Model;
        AiHeaderBox.Text = _config.Ai.AuthHeaderName;
        AiApiVersionBox.Text = _config.Ai.ApiVersion;
        bool hasKey = SecretStore.Load(_config.Ai.ApiKeyName) is not null;
        KeyStatus.Text = hasKey ? "Key stored." : "No key stored yet.";
    }

    private AppConfig ReadConfigFromUi() => _config with
    {
        Cloud = (CloudCombo.SelectedItem as ComboBoxItem)?.Content as string ?? "Dod",
        TenantId = TenantBox.Text.Trim(),
        ClientId = ClientBox.Text.Trim(),
        MaxAcceptableExcessActions =
            int.TryParse(ExcessBox.Text.Trim(), out var n) ? Math.Max(0, n) : 5,
        Ai = _config.Ai with
        {
            Provider = (AiProviderCombo.SelectedItem as ComboBoxItem)?.Content as string
                       ?? "openai-compatible",
            BaseUrl = AiUrlBox.Text.Trim(),
            Model = AiModelBox.Text.Trim(),
            AuthHeaderName = string.IsNullOrWhiteSpace(AiHeaderBox.Text)
                ? "Authorization" : AiHeaderBox.Text.Trim(),
            ApiVersion = AiApiVersionBox.Text.Trim()
        }
    };

    private void SaveSettings_Click(object sender, RoutedEventArgs e)
    {
        _config = ReadConfigFromUi();
        _config.Save(ConfigPath);
        _graph = null; // force re-auth with possibly-new tenant/cloud
        SettingsStatus.Text = "Saved to " + ConfigPath;
    }

    private async void SignOut_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var graph = GetGraph();
            await graph.Auth.SignOutAsync();
            _graph = null; // next call builds a fresh client and signs in again
            SettingsStatus.Text = "Signed out — the next Graph action will prompt for a fresh sign-in.";
            Status("Token cache cleared.");
        }
        catch (Exception ex)
        {
            SettingsStatus.Text = "Sign-out failed: " + ex.Message;
        }
    }

    private async void CheckScopes_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            SettingsStatus.Text = "Acquiring token...";
            var graph = GetGraph();
            await graph.Auth.WarmUpOrToken();

            var requested = graph.Auth.RequestedScopes
                .Select(s2 => s2.Contains('/') ? s2[(s2.LastIndexOf('/') + 1)..] : s2)
                .ToList();
            var granted = graph.Auth.LastGrantedScopes
                .Select(s2 => s2.Contains('/') ? s2[(s2.LastIndexOf('/') + 1)..] : s2)
                .ToList();
            var missing = requested
                .Where(r => !granted.Contains(r, StringComparer.OrdinalIgnoreCase))
                .ToList();

            var report =
                "Signed in as: " + (graph.Auth.SignedInAccount ?? "(unknown)") + Environment.NewLine +
                "Cloud: " + (_cloud?.Name ?? "?") + "  ·  " + (_cloud?.GraphBase ?? "?") +
                Environment.NewLine + Environment.NewLine +
                "REQUESTED by this build (" + requested.Count + "):" + Environment.NewLine +
                string.Join(Environment.NewLine, requested.Select(r => "  " + r)) +
                Environment.NewLine + Environment.NewLine +
                "GRANTED in the issued token (" + granted.Count + "):" + Environment.NewLine +
                string.Join(Environment.NewLine, granted.Select(g => "  " + g)) +
                Environment.NewLine + Environment.NewLine +
                (missing.Count == 0
                    ? "All requested scopes are present in the token."
                    : "MISSING from the token (" + missing.Count + "):" + Environment.NewLine +
                      string.Join(Environment.NewLine, missing.Select(m => "  " + m)) +
                      Environment.NewLine + Environment.NewLine +
                      "If these ARE consented in Entra, the cached token predates the consent — " +
                      "click 'Sign out / re-consent', then retry.");

            var box = new TextBox
            {
                Text = report, IsReadOnly = true, TextWrapping = TextWrapping.NoWrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                BorderThickness = new Thickness(0), Margin = new Thickness(12),
                FontFamily = new FontFamily("Consolas"), FontSize = 12
            };
            new Window
            {
                Title = "Token scope check", Width = 640, Height = 560, Owner = this,
                WindowStartupLocation = WindowStartupLocation.CenterOwner, Content = box
            }.Show();
            SettingsStatus.Text = missing.Count == 0
                ? "Token carries all requested scopes."
                : missing.Count + " requested scope(s) missing from the token.";
        }
        catch (Exception ex)
        {
            SettingsStatus.Text = "Scope check failed: " + ex.Message;
        }
    }

    private void StoreKey_Click(object sender, RoutedEventArgs e)
    {
        var key = AiKeyBox.Password;
        if (string.IsNullOrWhiteSpace(key)) { KeyStatus.Text = "Enter a key first."; return; }
        SecretStore.Save(_config.Ai.ApiKeyName, key.Trim());
        AiKeyBox.Clear();
        KeyStatus.Text = "Key stored (DPAPI).";
    }

    // ---------------- plumbing ----------------

    private GraphClient GetGraph()
    {
        if (_graph is not null) return _graph;
        _config = ReadConfigFromUi();
        if (string.IsNullOrWhiteSpace(_config.TenantId) || string.IsNullOrWhiteSpace(_config.ClientId))
            throw new InvalidOperationException("Set Tenant ID and Client ID in Settings first.");
        _cloud = CloudEnvironment.Parse(_config.Cloud);
        var auth = new GraphAuth(_config.ClientId, _config.TenantId, _cloud,
            _cloud.Scopes(_config.GraphPermissions, _config.EnableOutreach));
        _graph = new GraphClient(auth, _cloud);
        HeaderStatus.Text = _cloud.Name + " · " + _cloud.GraphBase;
        return _graph;
    }

    private (PowerShellRunner Runner, PsEnvironment Env, string? AdminUpn) GetPs()
    {
        _config = ReadConfigFromUi();
        var env = PsEnvironment.For(_config.Cloud,
            string.IsNullOrWhiteSpace(_config.Ps.SccConnectionUriOverride)
                ? null : _config.Ps.SccConnectionUriOverride);
        var runner = new PowerShellRunner
        {
            ScriptLogger = script => File.AppendAllText(PsScriptLogPath,
                "==== " + DateTimeOffset.UtcNow.ToString("o") + " ====\n" + script + "\n")
        };
        var upn = string.IsNullOrWhiteSpace(_config.Ps.UserPrincipalName)
            ? null : _config.Ps.UserPrincipalName;
        return (runner, env, upn);
    }

    private AiProviderConfig BuildAiConfig() => new()
    {
        ProviderKind = _config.Ai.Provider,
        ApiVersion = _config.Ai.ApiVersion,
        BaseUrl = _config.Ai.BaseUrl,
        Model = _config.Ai.Model,
        AuthHeaderName = _config.Ai.AuthHeaderName,
        AuthValuePrefix = _config.Ai.AuthValuePrefix,
        ApiKeyName = _config.Ai.ApiKeyName,
        ShortlistSize = _config.Ai.ShortlistSize
    };

    private void Status(string s) => StatusText.Text = s;

    // ---------------- access review ----------------

    private List<HeldRole> _reviewHeld = new();
    private IssueLog? _reviewIssues;

    private void ReviewDetails_Click(object sender, RoutedEventArgs e)
    {
        var text = _reviewIssues is null
            ? "No access load has run yet in this session."
            : _reviewIssues.DetailText + Environment.NewLine + Environment.NewLine +
              "[info] lines are expected conditions — an unlicensed service, or a provider " +
              "that doesn't exist in this cloud. They never block a review." + Environment.NewLine +
              "[ACTION] lines need something from you, usually consenting a scope and " +
              "signing out/in again.";
        ShowTextWindow("Access review — read details", text);
    }

    /// <summary>Shared read-only text window used by the Details buttons.</summary>
    private void ShowTextWindow(string title, string text)
    {
        var box = new TextBox
        {
            Text = text, IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            BorderThickness = new Thickness(0), Margin = new Thickness(12),
            FontFamily = new FontFamily("Consolas"), FontSize = 12
        };
        new Window
        {
            Title = title, Width = 780, Height = 520, Owner = this,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, Content = box
        }.Show();
    }
    private string _reviewUserLabel = "";

    private sealed record ReviewRoleRow(
        string Service, string Role, string Path, int ActionCount, string Scope);

    private async void ReviewFindUser_Click(object sender, RoutedEventArgs e)
    {
        var hit = await PickUserAsync();
        if (hit is null) return;
        ReviewPrincipalBox.Text = hit.Id;
        _reviewUserLabel = hit.DisplayName;
        ReviewUserDisplay.Text = hit.DisplayName + "  ·  " + hit.Upn;
    }

    private async void ReviewLoad_Click(object sender, RoutedEventArgs e)
    {
        var principal = ReviewPrincipalBox.Text.Trim();
        if (principal.Length == 0) { Status("Enter or find a user first."); return; }
        if (_catalog is null)
        {
            MessageBox.Show("Sync the catalog first (Catalog tab) — roles are expanded to " +
                            "permissions using the synced catalog.",
                "No catalog", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        ReviewLoadButton.IsEnabled = false;
        ReviewResultPanel.Children.Clear();
        ReviewWarnings.Text = "";
        try
        {
            var reader = new UserAccessReader(GetGraph(), _catalog);
            var held = await reader.ReadAsync(principal, msg => Status(msg));
            _reviewHeld = held.ToList();

            ReviewRolesGrid.ItemsSource = held.Select(h => new ReviewRoleRow(
                RbacProviders.DisplayName(h.Provider), h.DisplayName, h.PathLabel,
                h.GrantedActions.Count,
                h.DirectoryScope == "/" ? "tenant-wide" : h.DirectoryScope)).ToList();

            _reviewIssues = reader.Issues;
            ReviewWarnings.Text = reader.Issues.BannerText;   // empty unless action is needed
            if (ReviewWarnings.Text.Length == 0 && reader.Issues.All.Count > 0)
                Status(reader.Issues.QuietSummary);

            var totalActions = held.SelectMany(h => h.GrantedActions)
                .Distinct(StringComparer.OrdinalIgnoreCase).Count();
            Status(held.Count + " role(s) held, " + totalActions + " distinct permission(s). " +
                   "Now describe what this person actually does.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Load failed", MessageBoxButton.OK, MessageBoxImage.Error);
            Status("Access load failed.");
        }
        finally { ReviewLoadButton.IsEnabled = true; }
    }

    private async void ReviewAnalyze_Click(object sender, RoutedEventArgs e)
    {
        if (_catalog is null) { Status("Sync the catalog first."); return; }
        if (_reviewHeld.Count == 0)
        {
            Status("Load the user's current access first.");
            return;
        }
        var function = ReviewFunctionText.Text.Trim();
        if (function.Length == 0) { Status("Describe what this person actually does."); return; }

        ReviewAnalyzeButton.IsEnabled = false;
        ReviewResultPanel.Children.Clear();
        try
        {
            _config = ReadConfigFromUi();

            // 1) What does the stated function require? (same pipeline as a new request)
            AiSuggestion suggestion;
            if (ReviewDemoCheck.IsChecked == true)
            {
                Status("Running offline demo suggester...");
                suggestion = await new DemoSuggester().SuggestAsync(function, _catalog);
            }
            else
            {
                var key = SecretStore.Load(_config.Ai.ApiKeyName);
                if (string.IsNullOrEmpty(key))
                    throw new InvalidOperationException(
                        "No AI key stored — set one in Settings, or tick the offline demo box.");
                Status("Asking AI what this function requires...");
                using var provider = AiProviderFactory.Create(BuildAiConfig(), key);
                provider.PromptLogger = LogPrompt;
                suggestion = await provider.SuggestAsync(function, _catalog, SelectedForcedProviders(), default, _referenceStore);
            }

            var validator = new RecommendationValidator
            {
                MaxAcceptableExcessActions = _config.MaxAcceptableExcessActions,
                ReferenceActions = _referenceStore.ActionNames(),
                Ineligibility = _ineligibility,
                ReferenceDescriptions = _referenceStore.Entries
                    .Where(e => e.Description.Length > 0)
                    .GroupBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(g => g.Key, g => g.First().Description, StringComparer.OrdinalIgnoreCase)
            };
            var outcomes = validator.ValidateMulti(_catalog, suggestion, function);
            var requiredActions = outcomes.SelectMany(o => o.Outcome.ValidActions)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            // 2) Deterministic comparison against what they hold.
            var result = AccessReviewer.Compare(_reviewHeld, requiredActions);

            RenderReview(result, outcomes, suggestion);
            Status("Review complete.");

            // 3) AI narrates the risk of the computed excess (never decides it).
            if (ReviewDemoCheck.IsChecked != true && result.ExcessCount > 0)
                await AppendRiskNarrativeAsync(function, result);
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Analysis failed", MessageBoxButton.OK, MessageBoxImage.Error);
            Status("Review failed.");
        }
        finally { ReviewAnalyzeButton.IsEnabled = true; }
    }

    private void RenderReview(
        AccessReviewResult result,
        IReadOnlyList<ProviderOutcome> outcomes,
        AiSuggestion suggestion)
    {
        // Headline verdict
        var headCard = new Border { Style = (Style)FindResource("Card") };
        var headStack = new StackPanel();
        headCard.Child = headStack;
        headStack.Children.Add(new TextBlock
        {
            Text = result.OverPrivileged ? "Over-privileged" : "Right-sized",
            FontSize = 16, FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)FindResource(result.OverPrivileged ? "Warn" : "Ok")
        });
        headStack.Children.Add(new TextBlock
        {
            Text = result.Headline, TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 6, 0, 0)
        });
        headStack.Children.Add(new TextBlock
        {
            Text = "AI's reading of the function: " + suggestion.Reasoning,
            Style = (Style)FindResource("Hint"), Margin = new Thickness(0, 6, 0, 0)
        });
        ReviewResultPanel.Children.Add(headCard);

        // Per-role verdicts
        foreach (var ra in result.RoleAssessments)
        {
            var card = new Border { Style = (Style)FindResource("Card") };
            var stack = new StackPanel();
            card.Child = stack;

            var tone = ra.Verdict switch
            {
                RoleVerdict.FullyJustified => "Ok",
                RoleVerdict.NotJustified => "Bad",
                RoleVerdict.PartiallyJustified => "Warn",
                _ => "Steel"
            };
            stack.Children.Add(new TextBlock
            {
                Text = ra.Role.DisplayName + "  —  " +
                       RbacProviders.DisplayName(ra.Role.Provider) + "  ·  " + ra.Role.PathLabel,
                FontSize = 14, FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource("Steel"), TextWrapping = TextWrapping.Wrap
            });
            stack.Children.Add(new TextBlock
            {
                Text = ra.VerdictLabel, Margin = new Thickness(0, 4, 0, 0),
                FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource(tone)
            });
            if (ra.JustifiedActions.Count > 0)
                stack.Children.Add(MakeChipRow("Needed:", ra.JustifiedActions.Take(20), MakeActionChip));
            if (ra.ExcessActions.Count > 0)
                stack.Children.Add(MakeChipRow(
                    "Excess (" + ra.ExcessActions.Count + "):",
                    ra.ExcessActions.Take(25), MakeActionChip));
            ReviewResultPanel.Children.Add(card);
        }

        // Missing permissions
        if (result.MissingActions.Count > 0)
        {
            var card = new Border { Style = (Style)FindResource("Card") };
            var stack = new StackPanel();
            card.Child = stack;
            stack.Children.Add(new TextBlock
            {
                Text = "Missing for the stated function", FontSize = 14,
                FontWeight = FontWeights.SemiBold, Foreground = (Brush)FindResource("Steel")
            });
            stack.Children.Add(new TextBlock
            {
                Text = "The function needs these, but no role the user holds grants them:",
                Style = (Style)FindResource("Hint"), Margin = new Thickness(0, 4, 0, 0)
            });
            stack.Children.Add(MakeChipRow("", result.MissingActions.Take(25), MakeActionChip));
            ReviewResultPanel.Children.Add(card);
        }

        // Right-sized recommendation (the normal recommendation pipeline)
        var recCard = new Border { Style = (Style)FindResource("Card") };
        var recStack = new StackPanel();
        recCard.Child = recStack;
        recStack.Children.Add(new TextBlock
        {
            Text = "Right-sized replacement", FontSize = 14,
            FontWeight = FontWeights.SemiBold, Foreground = (Brush)FindResource("Steel")
        });
        if (outcomes.Count == 0 || outcomes.All(o => o.Outcome.ValidActions.Count == 0))
        {
            recStack.Children.Add(new TextBlock
            {
                Text = "The stated function produced no catalog-valid permissions, so no " +
                       "replacement can be proposed. Try describing the tasks more concretely.",
                Style = (Style)FindResource("Hint"), TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 0)
            });
        }
        else
        {
            foreach (var po in outcomes.Where(o => o.Outcome.ValidActions.Count > 0))
            {
                var o = po.Outcome;
                string line;
                if (o.CustomRoleRecommended && o.CustomRole is not null)
                    line = RbacProviders.DisplayName(po.Provider) + ": custom role '" +
                           o.CustomRole.DisplayName + "' with exactly " +
                           o.CustomRole.AllowedResourceActions.Count + " action(s)" +
                           (o.CustomRole.ParentRoleName is null
                               ? "" : " (derived from '" + o.CustomRole.ParentRoleName + "')");
                else if (o.BestFit is not null)
                    line = RbacProviders.DisplayName(po.Provider) + ": '" + o.BestFit.DisplayName +
                           "' (" + o.BestFit.ExcessLabel + ")";
                else
                    line = RbacProviders.DisplayName(po.Provider) +
                           ": no single role covers the needed actions.";
                recStack.Children.Add(new TextBlock
                {
                    Text = "•  " + line, TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 4, 0, 0)
                });
            }
            recStack.Children.Add(new TextBlock
            {
                Text = "To apply: copy the function description into New Request, approve the " +
                       "grant, then remove the over-broad roles listed above in Entra.",
                Style = (Style)FindResource("Hint"), TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 8, 0, 0)
            });
        }
        ReviewResultPanel.Children.Add(recCard);
    }

    private async Task AppendRiskNarrativeAsync(string function, AccessReviewResult result)
    {
        try
        {
            Status("Asking AI to assess the excess permissions...");
            var key = SecretStore.Load(_config.Ai.ApiKeyName);
            if (string.IsNullOrEmpty(key)) return;
            using var ai = AiProviderFactory.Create(BuildAiConfig(), key);
            ai.PromptLogger = LogPrompt;

            const string system =
                "You are a Microsoft 365 least-privilege auditor. You are given a job function, " +
                "and a DETERMINISTICALLY COMPUTED list of permissions the person holds beyond " +
                "that function. Do not recompute or dispute the list. Rank the riskiest excess " +
                "permissions, say concretely what damage each could enable, and give one short " +
                "removal priority. Under 200 words, plain text, no markdown.";
            var user = "FUNCTION: " + function +
                       "\nEXCESS PERMISSIONS (" + result.ExcessCount + "):\n" +
                       string.Join("\n", result.ExcessActions.Take(120));
            var text = await ai.CompleteAsync("review-risk", system, user);

            var card = new Border { Style = (Style)FindResource("Card") };
            var stack = new StackPanel();
            card.Child = stack;
            stack.Children.Add(new TextBlock
            {
                Text = "Risk assessment of the excess", FontSize = 14,
                FontWeight = FontWeights.SemiBold, Foreground = (Brush)FindResource("Steel")
            });
            stack.Children.Add(new TextBlock
            {
                Text = text, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0)
            });
            ReviewResultPanel.Children.Add(card);
            Status("Review complete.");
        }
        catch (Exception ex)
        {
            Status("Risk narrative unavailable: " + ex.Message);
        }
    }

    private void LogPrompt(string stage, string prompt) =>
        File.AppendAllText(PromptLogPath,
            "==== " + DateTimeOffset.UtcNow.ToString("o") + " [" + stage + "] ====" +
            Environment.NewLine + prompt + Environment.NewLine);

    // ---------------- administrative unit scoping ----------------

    private string _directoryScopeId = "/";

    /// <summary>
    /// Scope notices rendered inside constraint cards. They restate the CURRENT scope, so
    /// they have to be refreshed when it changes — a card still saying "tenant-wide" after
    /// the operator scoped the grant would be worse than saying nothing.
    /// </summary>
    private readonly List<TextBlock> _scopeEchoBlocks = new();

    private void RefreshScopeEchoes()
    {
        foreach (var block in _scopeEchoBlocks)
        {
            block.Text = _directoryScopeId == "/"
                ? "Currently TENANT-WIDE — the limit above is not yet applied."
                : "Currently scoped to " + ScopeDisplay.Text + ".";
            block.Foreground = _directoryScopeId == "/"
                ? (Brush)FindResource("Warn")
                : (Brush)FindResource("Ok");
        }
    }

    private async void PickScope_Click(object sender, RoutedEventArgs e)
    {
        PickScopeButton.IsEnabled = false;
        try
        {
            var graph = GetGraph();
            await graph.Auth.WarmUpOrToken();
            Status("Reading administrative units...");
            var units = await new AdministrativeUnitReader(graph).ListAsync();
            if (units.Count == 0)
            {
                MessageBox.Show(
                    "No administrative units exist in this tenant, so directory roles can only " +
                    "be granted tenant-wide.\n\nAUs are how a directory role is narrowed to a " +
                    "slice of the directory — worth creating if you delegate by region, " +
                    "department, or site.",
                    "No administrative units", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var labels = units.Select(u => u.ToString()).ToList();
            var picked = PickFromList("Scope the directory role to an administrative unit", labels);
            if (picked is null) return;
            var unit = units[labels.IndexOf(picked)];
            _directoryScopeId = unit.DirectoryScopeId;
            ScopeBox.Text = _directoryScopeId;
            ScopeDisplay.Text = "AU: " + unit.DisplayName;
            RefreshScopeEchoes();
            Status("Directory grants will be scoped to '" + unit.DisplayName + "'.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message + Environment.NewLine + Environment.NewLine +
                "Reading administrative units needs AdministrativeUnit.Read.All (or " +
                "Directory.Read.All) consented on the app registration.",
                "Could not read administrative units",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { PickScopeButton.IsEnabled = true; }
    }

    private void ClearScope_Click(object sender, RoutedEventArgs e)
    {
        _directoryScopeId = "/";
        ScopeBox.Text = "/";
        ScopeDisplay.Text = "tenant-wide";
        RefreshScopeEchoes();
        Status("Directory grants will be tenant-wide.");
    }

    // ---------------- applications (service principal permissions) ----------------

    private sealed record AppRow(
        string Name, int HighRisk, int AppOnly, int Total, string Roles, string Permissions)
    {
        public IReadOnlyList<string> RawPermissions { get; init; } = Array.Empty<string>();
    }

    private List<AppRow> _appRows = new();

    private async void AppScan_Click(object sender, RoutedEventArgs e)
    {
        AppScanButton.IsEnabled = false;
        AppScanWarnings.Text = "";
        try
        {
            var reader = new AppPermissionReader(GetGraph());
            var apps = await reader.ReadAsync(msg => Status(msg),
                AppOnlyWithPermsCheck.IsChecked == true);

            _appRows = apps.Select(a => new AppRow(
                a.DisplayName,
                a.HighRiskCount,
                a.AppOnlyCount,
                a.Permissions.Count,
                string.Join(", ", a.DirectoryRoles),
                string.Join(", ", a.Permissions.Select(p => p.Label)))
            { RawPermissions = a.Permissions.Select(p => p.PermissionValue).ToList() }).ToList();

            ApplyAppFilter();

            var risky = apps.Count(a => a.HighRiskCount > 0);
            var withRoles = apps.Count(a => a.DirectoryRoles.Count > 0);
            AppScanSummary.Text = apps.Count + " application(s); " + risky +
                " hold high-risk permissions; " + withRoles + " hold a directory role.";
            AppScanWarnings.Text = reader.Warnings.Count == 0
                ? "" : "Partial read — " + string.Join("  ", reader.Warnings);
            Status("Application scan complete.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Application scan failed",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Status("Application scan failed.");
        }
        finally { AppScanButton.IsEnabled = true; }
    }

    private void AppFilter_TextChanged(object sender, TextChangedEventArgs e) => ApplyAppFilter();

    private void ApplyAppFilter()
    {
        var q = AppFilter.Text.Trim();
        AppsGrid.ItemsSource = q.Length == 0
            ? _appRows
            : _appRows.Where(r =>
                r.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                r.Roles.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                r.RawPermissions.Any(p => p.Contains(q, StringComparison.OrdinalIgnoreCase))).ToList();
    }

    // ---------------- Azure resource RBAC ----------------

    private async void AzureSync_Click(object sender, RoutedEventArgs e)
    {
        AzureSyncButton.IsEnabled = false;
        try
        {
            _config = ReadConfigFromUi();
            var cloud = CloudEnvironment.Parse(_config.Cloud);
            var graph = GetGraph();
            using var arm = new AzureRbacClient(graph.Auth, cloud);

            Status("Signing in to Azure Resource Manager (separate token)...");
            var (roles, assignments, subs) = await arm.SyncAsync(msg => Status(msg));

            if (subs.Count == 0)
            {
                MessageBox.Show(
                    "No Azure subscriptions were readable." + Environment.NewLine + Environment.NewLine +
                    (arm.Warnings.Count > 0 ? string.Join(Environment.NewLine, arm.Warnings)
                                            : "This tenant may have no Azure subscriptions, or your " +
                                              "account may hold no Azure role.") +
                    Environment.NewLine + Environment.NewLine +
                    "Azure RBAC is authorized by your Azure role assignments, not by the app " +
                    "registration's Graph permissions.",
                    "No Azure subscriptions", MessageBoxButton.OK, MessageBoxImage.Information);
                Status("Azure sync found no subscriptions.");
                return;
            }

            // Merge Azure roles into the catalog alongside every other provider.
            _catalog ??= new RoleCatalog();
            _catalog.ReplaceProvider(RbacProviders.Azure, roles);
            // Purview roles usually arrive name-only, because SCC publishes no role-to-cmdlet
            // mapping. Fill in the well-known ones from Microsoft's documentation so the
            // service is usable — clearly labelled, and never overwriting tenant data.
            var enrichedPurview = PurviewRoleMap.EnrichNameOnlyRoles(_catalog);
            enrichedPurview += PurviewRoleCatalog.LoadOrImport(PurviewRolesPath, PurviewRolesMarkdownPath)
                    .EnrichCatalog(_catalog);
            if (enrichedPurview > 0)
            {
                _lastSyncReport.Add("Purview: filled in " + enrichedPurview + " role(s) from "
                    + "Microsoft's documented capabilities, because Security & Compliance "
                    + "PowerShell exposes no role-to-cmdlet mapping. These are marked in the "
                    + "role description and are NOT read from your tenant.");
            }

            _catalog.Save(CatalogPath);
            RefreshCatalogGrid();
        RebuildPermissionCatalog();
        RefreshForcedProviderList();

            _lastSyncReport = new List<string>
            {
                "Azure subscriptions readable: " + subs.Count,
                "Azure role definitions: " + roles.Count,
                "Azure role assignments: " + assignments.Count
            };
            foreach (var sub in subs)
            {
                var n = assignments.Count(a =>
                    a.Scope.Contains(sub.Id, StringComparison.OrdinalIgnoreCase));
                _lastSyncReport.Add("  " + sub.DisplayName + " (" + sub.State + "): " +
                                    n + " assignment(s)");
            }
            var users = assignments.Count(a =>
                a.PrincipalType.Equals("User", StringComparison.OrdinalIgnoreCase));
            var sps = assignments.Count(a =>
                a.PrincipalType.Equals("ServicePrincipal", StringComparison.OrdinalIgnoreCase));
            var grps = assignments.Count(a =>
                a.PrincipalType.Equals("Group", StringComparison.OrdinalIgnoreCase));
            _lastSyncReport.Add("");
            _lastSyncReport.Add("Assignments by principal type — users " + users +
                                ", groups " + grps + ", service principals " + sps + ".");
            if (arm.Warnings.Count > 0)
            {
                _lastSyncReport.Add("");
                _lastSyncReport.AddRange(arm.Warnings);
            }

            SyncSummary.Text = "Azure: " + roles.Count + " role definition(s) across " +
                               subs.Count + " subscription(s), " + assignments.Count +
                               " assignment(s). See Sync report for detail.";
            Status("Azure RBAC synced — " + roles.Count + " roles merged into the catalog.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Azure sync failed",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Status("Azure sync failed.");
        }
        finally { AzureSyncButton.IsEnabled = true; }
    }

    // ---------------- home / setup ----------------

    /// <summary>
    /// A setup step's state. "Configured" is not the same as "verified" — green here
    /// means a real read succeeded against the tenant just now.
    /// </summary>
    private enum StepState { Unknown, Busy, Ok, Warn, Failed }

    private sealed record ServiceStatusRow(
        string Glyph, string Colour, string Service, string Detail);

    private void SetStep(TextBlock glyph, StepState state)
    {
        (glyph.Text, glyph.Foreground) = state switch
        {
            StepState.Ok => ("\u2713", (Brush)FindResource("Ok")),
            StepState.Warn => ("!", (Brush)FindResource("Warn")),
            StepState.Failed => ("\u2715", (Brush)FindResource("Bad")),
            StepState.Busy => ("\u2026", (Brush)FindResource("Steel")),
            _ => ("?", (Brush)FindResource("Steel"))
        };
    }

    private async void RunAllChecks_Click(object sender, RoutedEventArgs e)
    {
        RunAllChecksButton.IsEnabled = false;
        SetupSummary.Text = "Checking...";
        try
        {
            await CheckSignInAsync();
            await ProbeServicesAsync();
            CheckPowerShellPrereqs();
            CheckCatalogState();
            await VerifyAiAsync();

            var glyphs = new[] { StepSignInGlyph, StepServicesGlyph, StepPsGlyph,
                                 StepCatalogGlyph, StepAiGlyph };
            var failed = glyphs.Count(g => g.Text == "\u2715");
            var warned = glyphs.Count(g => g.Text == "!");
            SetupSummary.Text = failed == 0 && warned == 0
                ? "Everything checks out — the app is ready to use."
                : failed + " step(s) failed, " + warned + " need attention. "
                  + "A failure on a service you are not licensed for is expected.";
        }
        finally { RunAllChecksButton.IsEnabled = true; }
    }

    // --- 1. sign in ---

    private async void StepSignIn_Click(object sender, RoutedEventArgs e) => await CheckSignInAsync();

    private async Task CheckSignInAsync()
    {
        SetStep(StepSignInGlyph, StepState.Busy);
        StepSignInStatus.Text = "Signing in — a browser window will open...";
        try
        {
            var graph = GetGraph();
            await graph.Auth.WarmUpOrToken();
            var account = graph.Auth.SignedInAccount ?? "(unknown account)";
            var granted = graph.Auth.LastGrantedScopes.Count;
            var requested = _config.GraphPermissions.Count;

            if (granted < requested)
            {
                SetStep(StepSignInGlyph, StepState.Warn);
                StepSignInStatus.Text = "Signed in as " + account + ". " + granted + " of "
                    + requested + " requested scopes granted — use Check permissions to see "
                    + "which are missing, then grant admin consent and sign in again.";
            }
            else
            {
                SetStep(StepSignInGlyph, StepState.Ok);
                StepSignInStatus.Text = "Signed in as " + account + " ("
                    + CloudEnvironment.Parse(_config.Cloud).Name + "). "
                    + granted + " scope(s) granted.";
            }
        }
        catch (Exception ex)
        {
            SetStep(StepSignInGlyph, StepState.Failed);
            StepSignInStatus.Text = "Sign-in failed: " + Trim(ex.Message);
        }
    }

    // --- 2. per-service probe ---

    private async void StepServices_Click(object sender, RoutedEventArgs e) => await ProbeServicesAsync();

    /// <summary>
    /// Reads one role definition from each provider. A licensing 403 is reported as
    /// EXPECTED rather than as a failure, because knowing which services you actually
    /// have is the point — the app degrades per provider either way.
    /// </summary>
    private async Task ProbeServicesAsync()
    {
        SetStep(StepServicesGlyph, StepState.Busy);
        var rows = new List<ServiceStatusRow>();
        ServiceStatusList.ItemsSource = null;

        var probes = new (string Provider, string Path)[]
        {
            (RbacProviders.Directory, "/v1.0/roleManagement/directory/roleDefinitions?$top=1"),
            (RbacProviders.Intune, "/beta/deviceManagement/roleDefinitions?$top=1"),
            (RbacProviders.Exchange, "/beta/roleManagement/exchange/roleDefinitions?$top=1"),
            (RbacProviders.CloudPc, "/beta/roleManagement/cloudPC/roleDefinitions?$top=1"),
            (RbacProviders.Defender, "/beta/roleManagement/defender/roleDefinitions?$top=1"),
            (RbacProviders.EntitlementManagement,
                "/v1.0/roleManagement/entitlementManagement/roleDefinitions?$top=1")
        };

        var ok = 0;
        var expected = 0;
        var problems = 0;

        foreach (var probe in probes)
        {
            try
            {
                using var doc = await GetGraph().GetAsync(probe.Path);
                var count = doc.RootElement.TryGetProperty("value", out var v)
                    ? v.GetArrayLength() : 0;
                rows.Add(new ServiceStatusRow("\u2713", "#2E7D32",
                    RbacProviders.DisplayName(probe.Provider),
                    count > 0 ? "readable" : "readable, no roles defined in this tenant"));
                ok++;
            }
            catch (Exception ex)
            {
                var issue = SyncIssue.FromError(RbacProviders.DisplayName(probe.Provider), ex.Message);
                if (issue.IsActionable)
                {
                    rows.Add(new ServiceStatusRow("\u2715", "#B71C1C",
                        RbacProviders.DisplayName(probe.Provider), issue.Message));
                    problems++;
                }
                else
                {
                    rows.Add(new ServiceStatusRow("\u2013", "#888888",
                        RbacProviders.DisplayName(probe.Provider),
                        "not available — " + issue.Message));
                    expected++;
                }
            }
        }

        ServiceStatusList.ItemsSource = rows;
        SetStep(StepServicesGlyph, problems > 0 ? StepState.Warn : StepState.Ok);
        Status(ok + " service(s) readable, " + expected + " unavailable as expected, "
               + problems + " needing attention.");
    }

    // --- 3. PowerShell, announced before it launches ---

    private void StepPsCheck_Click(object sender, RoutedEventArgs e) => CheckPowerShellPrereqs();

    private void CheckPowerShellPrereqs()
    {
        SetStep(StepPsGlyph, StepState.Busy);
        try
        {
            var host = PowerShellRunner.FindPowerShell();
            var isPwsh7 = host.EndsWith("pwsh.exe", StringComparison.OrdinalIgnoreCase)
                       || host.EndsWith("pwsh", StringComparison.OrdinalIgnoreCase);
            SetStep(StepPsGlyph, StepState.Ok);
            StepPsStatus.Text = "PowerShell host: " + host
                + (isPwsh7 ? " (PowerShell 7)" : " (Windows PowerShell 5.1 — works, but 7 is better)")
                + ". Exchange and Purview are only needed if you grant access to those services.";
        }
        catch (Exception ex)
        {
            SetStep(StepPsGlyph, StepState.Warn);
            StepPsStatus.Text = "No PowerShell host found: " + Trim(ex.Message)
                + "  Everything except Exchange and Purview still works without it.";
        }
    }

    /// <summary>
    /// Says exactly what is about to happen BEFORE any console window appears. A
    /// PowerShell window opening unannounced, with its own sign-in prompt, looks like the
    /// app has done something alarming.
    /// </summary>
    private async void StepPsConnect_Click(object sender, RoutedEventArgs e)
    {
        var upn = string.IsNullOrWhiteSpace(_config.Ps.UserPrincipalName)
            ? "(no UPN set in Settings — you will be prompted)"
            : _config.Ps.UserPrincipalName;

        var proceed = MessageBox.Show(
            "About to connect to EXCHANGE ONLINE and then PURVIEW / SECURITY & COMPLIANCE."
            + Environment.NewLine + Environment.NewLine
            + "What will happen, in order:" + Environment.NewLine
            + "  1. A PowerShell console window opens and stays open while it works."
            + Environment.NewLine
            + "  2. Connect-ExchangeOnline runs and prompts you to sign in — that prompt "
            + "comes from Microsoft's module, not from this app." + Environment.NewLine
            + "  3. Connect-IPPSSession runs for Purview and may prompt again."
            + Environment.NewLine
            + "  4. The app reads role definitions at cmdlet level and closes the session."
            + Environment.NewLine + Environment.NewLine
            + "Account: " + upn + Environment.NewLine
            + "Nothing is changed in either service — this is a read."
            + Environment.NewLine + Environment.NewLine + "Continue?",
            "Connecting to Exchange and Purview",
            MessageBoxButton.OKCancel, MessageBoxImage.Information);

        if (proceed != MessageBoxResult.OK)
        {
            StepPsStatus.Text = "Cancelled — nothing launched.";
            return;
        }

        SetStep(StepPsGlyph, StepState.Busy);
        StepPsStatus.Text = "Connecting to Exchange Online — watch the console window...";
        try
        {
            var (runner, env, adminUpn) = GetPs();
            var deep = new ExoPurviewCatalogSync(runner, env, adminUpn);

            // Each scope is its own connection and its own failure. Exchange working while
            // Purview does not is a normal, informative outcome — not a reason to report
            // the whole step as failed.
            var lines = new List<string>();
            var anyOk = false;
            var anyFailed = false;

            foreach (var scope in new[] { RbacScope.Exchange, RbacScope.Purview })
            {
                var label = scope == RbacScope.Exchange ? "Exchange Online" : "Purview / Compliance";
                StepPsStatus.Text = "Connecting to " + label + " — watch the console window...";
                Status("Connecting to " + label + " via PowerShell...");
                try
                {
                    var (roles, roleGroups) = await deep.SyncAsync(scope);
                    lines.Add(label + ": " + roles.Count + " role(s), "
                              + roleGroups.Count + " role group(s)");
                    anyOk = true;
                }
                catch (Exception ex)
                {
                    lines.Add(label + ": FAILED — " + Trim(ex.Message));
                    anyFailed = true;
                }
            }

            SetStep(StepPsGlyph, anyFailed ? (anyOk ? StepState.Warn : StepState.Failed)
                                           : StepState.Ok);
            StepPsStatus.Text = string.Join("   ", lines)
                + "   Run a catalog sync with the Exchange & Purview box ticked to merge "
                + "these in at cmdlet level.";
        }
        catch (Exception ex)
        {
            SetStep(StepPsGlyph, StepState.Failed);
            StepPsStatus.Text = "Connection failed: " + Trim(ex.Message);
        }
    }

    // --- 4. catalog ---

    /// <summary>
    /// Per-service role counts, with ZEROES named explicitly. A service silently absent
    /// from the catalog makes every downstream recommendation look like a reasoning
    /// failure when it is really a missing input.
    /// </summary>
    private string DescribeCatalogCoverage()
    {
        if (_catalog is null) return "";

        var all = new[]
        {
            RbacProviders.Directory, RbacProviders.Intune, RbacProviders.Exchange,
            RbacProviders.Purview, RbacProviders.CloudPc, RbacProviders.Defender,
            RbacProviders.EntitlementManagement
        };

        var present = new List<string>();
        var missing = new List<string>();
        foreach (var provider in all)
        {
            var roles = _catalog.RolesFor(provider).ToList();
            var actions = roles.SelectMany(r => r.AllowedResourceActions).Distinct(
                StringComparer.OrdinalIgnoreCase).Count();

            if (roles.Count == 0)
                missing.Add(RbacProviders.DisplayName(provider));
            else if (actions == 0)
            {
                // Role names without permission lists cannot drive a recommendation.
                missing.Add(RbacProviders.DisplayName(provider)
                            + " (" + roles.Count + " roles, NO permissions)");
            }
            else
                present.Add(RbacProviders.DisplayName(provider) + " " + roles.Count);
        }

        var text = string.Join(" · ", present);
        if (missing.Count > 0)
        {
            text += "   NO ROLES: " + string.Join(", ", missing)
                  + " — requests for those services cannot be answered correctly.";
        }
        return text;
    }

    private void CheckCatalogState()
    {
        if (_catalog is null || _catalog.Roles.Count == 0)
        {
            SetStep(StepCatalogGlyph, StepState.Failed);
            StepCatalogStatus.Text = "No catalog yet. Nothing can be recommended until this runs.";
            return;
        }

        var age = _catalog.LastSyncedUtc is null
            ? (TimeSpan?)null
            : DateTimeOffset.UtcNow - _catalog.LastSyncedUtc.Value;

        if (age is not null && age.Value.TotalDays > 7)
        {
            SetStep(StepCatalogGlyph, StepState.Warn);
            StepCatalogStatus.Text = _catalog.Roles.Count + " roles, "
                + _catalog.ActionCount + " permissions — but last synced "
                + (int)age.Value.TotalDays + " days ago. The catalog is a snapshot; "
                + "re-sync after anyone changes roles in a portal.";
            return;
        }

        var coverage = DescribeCatalogCoverage();
        var hasGaps = coverage.Contains("NO ROLES:", StringComparison.Ordinal);

        SetStep(StepCatalogGlyph, hasGaps ? StepState.Warn : StepState.Ok);
        StepCatalogStatus.Text = coverage + "   " + _catalog.Roles.Count + " roles, " + _catalog.ActionCount
            + " permissions across " + _catalog.Roles.Select(r => r.Provider)
                .Distinct(StringComparer.OrdinalIgnoreCase).Count() + " service(s)."
            + (_groupCatalog is null ? "  Groups not synced yet." : "");
    }

    // --- 5. AI endpoint and tenant match ---

    private async void StepAiVerify_Click(object sender, RoutedEventArgs e) => await VerifyAiAsync();

    private async Task VerifyAiAsync()
    {
        SetStep(StepAiGlyph, StepState.Busy);
        StepAiStatus.Text = "Probing the endpoint...";
        _config = ReadConfigFromUi();

        var notes = new List<string>();

        // Tenant match: the app can be configured for one tenant while you are signed in
        // to another, and every recommendation would then be validated against the wrong
        // catalog.
        var signedIn = GetGraph().Auth.SignedInAccount;
        if (!string.IsNullOrWhiteSpace(signedIn))
        {
            var domain = signedIn.Contains('@') ? signedIn.Split('@').Last() : signedIn;
            notes.Add("signed in as " + signedIn + " (" + domain + ")");
        }
        else
        {
            notes.Add("not signed in — sign in first so the tenant can be compared");
        }

        if (string.IsNullOrWhiteSpace(_config.TenantId))
        {
            SetStep(StepAiGlyph, StepState.Warn);
            StepAiStatus.Text = "No tenant id configured in Settings.";
            return;
        }

        var key = SecretStore.Load(_config.Ai.ApiKeyName);
        if (string.IsNullOrWhiteSpace(key))
        {
            SetStep(StepAiGlyph, StepState.Failed);
            StepAiStatus.Text = "No AI key stored. Add one in Settings — without it the app "
                + "can still sync and review, but cannot recommend.";
            return;
        }

        try
        {
            using var provider = AiProviderFactory.Create(BuildAiConfig(), key);
            var reply = await provider.CompleteAsync(
                "verify",
                "Reply with exactly the word READY and nothing else.",
                "Connectivity check.");

            var healthy = reply.Contains("READY", StringComparison.OrdinalIgnoreCase);
            SetStep(StepAiGlyph, healthy ? StepState.Ok : StepState.Warn);
            StepAiStatus.Text = (healthy
                    ? "Endpoint answered correctly. "
                    : "Endpoint answered, but not as expected (\"" + Trim(reply) + "\"). ")
                + "Model: " + _config.Ai.Model + ". Tenant: " + _config.TenantId
                + "; " + string.Join("; ", notes) + "."
                + "  The endpoint receives only job descriptions and permission names — "
                + "never identities.";
        }
        catch (Exception ex)
        {
            SetStep(StepAiGlyph, StepState.Failed);
            StepAiStatus.Text = "Endpoint failed: " + Trim(ex.Message);
        }
    }

    // --- tutorial ---

    private void SkipTutorial_Click(object sender, RoutedEventArgs e)
    {
        TutorialCard.Visibility = Visibility.Collapsed;
        try
        {
            File.WriteAllText(Path.Combine(_dataDir, "tutorial-dismissed"), "1");
        }
        catch (Exception) { /* cosmetic only */ }
    }

    private void RestoreTutorialState()
    {
        try
        {
            if (File.Exists(Path.Combine(_dataDir, "tutorial-dismissed")))
                TutorialCard.Visibility = Visibility.Collapsed;
        }
        catch (Exception) { /* cosmetic only */ }
    }

    // ---------------- Microsoft permission reference ----------------

    private List<ReferenceAction> _reference = new();
    private ReferenceComparison? _referenceComparison;

    private sealed record ReferenceRow(
        string Name, string Service, string Source, string Risk, string AppRisk,
        string InCatalog, string Description);

    /// <summary>
    /// Pulls Microsoft's own permission list. This is the answer to "how do I keep up with
    /// the latest permissions": not a scraped documentation page that goes stale and breaks
    /// when the markup changes, but the API Microsoft maintains — with descriptions and a
    /// stated isPrivileged flag, available in the Gov and DoD clouds.
    /// </summary>
    private async void RefSync_Click(object sender, RoutedEventArgs e)
    {
        RefSyncButton.IsEnabled = false;
        RefWarnings.Text = "";
        RefSummary.Text = "Reading from Microsoft...";
        try
        {
            var reference = new PermissionReference(GetGraph());
            _reference = await reference.SyncAsync(msg => Dispatcher.Invoke(() =>
            {
                RefSummary.Text = msg;
                Status(msg);
            }));

            if (_catalog is not null)
                _referenceComparison = ReferenceComparison.Build(_reference, _catalog);

            RefSummary.Text = _referenceComparison?.Summary
                ?? (_reference.Count + " permission(s) read. Sync the catalog to compare.");

            // Which services published a reference, and which genuinely have none. Saying
            // "Exchange has no Graph reference" is information; silence is a gap.
            var report = new List<string>(reference.SourceReport);
            if (reference.Warnings.Count > 0) report.AddRange(reference.Warnings);
            RefWarnings.Text = string.Join("   ", report.Where(r => r.Length > 0));

            // Persist so validation can use it without a live call, and so it survives a
            // restart — the whole point of a weekly cadence.
            _referenceStore = new ReferenceStore
            {
                LastSyncedUtc = DateTimeOffset.UtcNow,
                Entries = _reference.Select(r => new ReferenceStore.ReferenceEntry
                {
                    Name = r.Name, Provider = r.Provider, Description = r.Description,
                    IsPrivileged = r.IsPrivileged, Source = r.Source
                }).ToList()
            };
            try { _referenceStore.Save(ReferencePath); } catch (Exception) { /* cache only */ }

            var stated = _referenceStore.StatedPrivilege();
            ActionRisk.UseAuthoritative(stated);
            // Re-installed here as well as at startup, so a fresh sync takes effect without
            // restarting the app — matching what UseAuthoritative already does.
            ActionRisk.UseDescriptions(_referenceStore.Descriptions());
            _lastSyncReport.Add("Risk ratings: " + stated.Count + " action(s) now use Microsoft's "
                + "stated privilege level instead of this app's inference. "
                + ActionRisk.DescribedCount + " action(s) carry a description that can "
                + "downgrade an over-cautious guess — the only correction available for "
                + "Intune, which states no privilege flag at all.");

            RefreshReferenceProviderList();
            ApplyReferenceFilter();
            Status("Permission reference synced — " + _reference.Count + " permission(s).");
        }
        catch (Exception ex)
        {
            RefSummary.Text = "Failed: " + Trim(ex.Message);
            Status("Permission reference sync failed.");
        }
        finally { RefSyncButton.IsEnabled = true; }
    }

    /// <summary>
    /// Adds Exchange and Purview from the PowerShell-synced catalog. They do not use
    /// unified RBAC, so no Graph reference exists — their role entries ARE the reference.
    /// </summary>
    private void RefExo_Click(object sender, RoutedEventArgs e)
    {
        if (_catalog is null)
        {
            RefSummary.Text = "Sync the catalog first — Exchange and Purview vocabulary "
                + "comes from the roles read through PowerShell.";
            return;
        }

        var fromPs = PermissionReference.FromPowerShellCatalog(_catalog);

        // Always show what each service contributed — including nothing, and why.
        RefWarnings.Text = string.Join("   ", PermissionReference.LastPowerShellReport)
            + (RefWarnings.Text.Length > 0 ? "   " + RefWarnings.Text : "");

        if (fromPs.Count == 0)
        {
            RefSummary.Text = "No Exchange or Purview roles in the catalog yet. On the "
                + "Catalog tab, tick \"Include Exchange & Purview via PowerShell\" and sync — "
                + "if a service still shows zero, the Sync report says why.";
            return;
        }

        // Replace rather than append, so pressing this twice cannot double the list.
        _reference = _reference
            .Where(r => r.Source != "PowerShell role entries")
            .Concat(fromPs)
            .OrderBy(r => r.Provider, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        _referenceComparison = ReferenceComparison.Build(_reference, _catalog);
        RefSummary.Text = _referenceComparison.Summary;
        RefreshReferenceProviderList();
        ApplyReferenceFilter();
        Status("Added " + fromPs.Count + " Exchange/Purview permission(s) from PowerShell.");
    }

    private void RefreshReferenceProviderList()
    {
        var previous = RefProviderFilter.SelectedItem as string;
        RefProviderFilter.Items.Clear();
        RefProviderFilter.Items.Add("all services");
        foreach (var provider in _reference.Select(r => r.Provider)
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .OrderBy(p => RbacProviders.DisplayName(p), StringComparer.OrdinalIgnoreCase))
        {
            RefProviderFilter.Items.Add(RbacProviders.DisplayName(provider));
        }
        RefProviderFilter.SelectedItem = previous ?? "all services";
        if (RefProviderFilter.SelectedItem is null) RefProviderFilter.SelectedIndex = 0;
    }

    private void RefProviderFilter_Changed(object sender, SelectionChangedEventArgs e)
        => ApplyReferenceFilter();

    private void RefDocs_Click(object sender, RoutedEventArgs e)
    {
        // The API gives the vocabulary; the docs give the prose. Both are useful.
        OpenUrl("https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference");
    }

    private static void OpenUrl(string url)
    {
        try
        {
            System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception) { /* no browser available; not worth interrupting for */ }
    }

    private void RefMode_Changed(object sender, RoutedEventArgs e) => ApplyReferenceFilter();

    private void RefFilter_TextChanged(object sender, TextChangedEventArgs e)
        => ApplyReferenceFilter();

    private void ApplyReferenceFilter()
    {
        if (ReferenceGrid is null) return;

        if (_reference.Count == 0)
        {
            ReferenceGrid.ItemsSource = null;
            return;
        }

        // Membership must be checked against the SAME provider, or every Exchange cmdlet
        // reads "NO" merely because it is not a directory action.
        var inCatalogByProvider = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        if (_catalog is not null)
        {
            foreach (var provider in _reference.Select(r => r.Provider)
                         .Distinct(StringComparer.OrdinalIgnoreCase))
            {
                inCatalogByProvider[provider] = _catalog.RolesFor(provider)
                    .SelectMany(r => r.AllowedResourceActions)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
            }
        }

        IEnumerable<ReferenceAction> source = _reference;

        if (RefProviderFilter.SelectedItem is string selectedProvider
            && selectedProvider != "all services")
        {
            source = source.Where(r =>
                RbacProviders.DisplayName(r.Provider) == selectedProvider);
        }

        if (RefGapMode?.IsChecked == true && _referenceComparison is not null)
            source = _referenceComparison.NotInAnyRole;
        else if (RefRiskMode?.IsChecked == true && _referenceComparison is not null)
        {
            var disputed = _referenceComparison.RiskDisagreements
                .Select(d => d.Action).ToHashSet(StringComparer.OrdinalIgnoreCase);
            source = _reference.Where(r => disputed.Contains(r.Name));
        }

        var query = RefFilter.Text.Trim();
        if (query.Length > 0)
        {
            source = source.Where(r =>
                r.Name.Contains(query, StringComparison.OrdinalIgnoreCase)
                || r.Description.Contains(query, StringComparison.OrdinalIgnoreCase));
        }

        var rows = source.Take(1000).Select(r => new ReferenceRow(
            ActionDisplay.Short(r.Name),
            RbacProviders.DisplayName(r.Provider),
            r.Source,
            // Only claim Microsoft "says" something where Microsoft actually stated it.
            r.IsPrivileged is null ? "not stated" : (r.IsPrivileged.Value ? "privileged" : "read"),
            // The "this app infers" column must show the INFERENCE, otherwise it silently
            // becomes a second copy of Microsoft's column.
            ActionRisk.IsPrivilegedHeuristic(r.Name) ? "privileged" : "read",
            inCatalogByProvider.TryGetValue(r.Provider, out var have) && have.Contains(r.Name)
                ? "yes" : "NO",
            r.Description)).ToList();

        ReferenceGrid.ItemsSource = rows;

        var mode = RefGapMode?.IsChecked == true ? "not granted by any role you have"
                 : RefRiskMode?.IsChecked == true ? "risk-rating disagreements"
                 : "all Microsoft permissions";
        Status(rows.Count + " row(s) — " + mode + ".");
    }

    // ---------------- permissions view ----------------

    private PermissionIndex? _permissionCatalog;

    /// <summary>Microsoft's permission vocabulary, cached so validation can use it
    /// without a live call and so it survives restarts.</summary>
    private ReferenceStore _referenceStore = new();

    /// <summary>What each PowerShell endpoint reported it supports, from the last sync.</summary>
    private CmdletCapabilityStore _cmdletCapabilities = new();

    /// <summary>Actions this tenant has refused to put in a custom role.</summary>
    private CustomRoleEligibility _ineligibility = new();
    private string IneligibilityPath => Path.Combine(_dataDir, "custom-role-ineligible.json");
    /// <summary>Microsoft's published Purview role list. The Security and Compliance session
    /// cannot report what a Purview role contains, so this is the only vocabulary it has.</summary>
    private string PurviewRolesPath => Path.Combine(_dataDir, "purview-roles.json");
    /// <summary>Microsoft's published page as downloaded. Parsed into the JSON above on
    /// first use, so the package ships what Microsoft publishes rather than a cache.</summary>
    private string PurviewRolesMarkdownPath => Path.Combine(_dataDir, "purview-roles.md");
    /// <summary>Exchange and Purview cmdlet descriptions. No API supplies these, and without
    /// them the model reads names only — which is how a request to remove MESSAGES became
    /// Remove-Mailbox, a cmdlet that deletes the mailbox and the user account with it.</summary>
    private string CmdletDescriptionsPath => Path.Combine(_dataDir, "exchange-descriptions.json");
    /// <summary>Endpoint responses keyed by prompt hash. The endpoint will not be
    /// deterministic even at temperature 0, so reproducibility is taken here instead.</summary>
    private string PromptCachePath => Path.Combine(_dataDir, "prompt-cache.json");
    private string CmdletCapabilityPath => Path.Combine(_dataDir, "cmdlet-capabilities.json");
    private string ReferencePath => Path.Combine(_dataDir, "reference.json");

    private sealed record PermissionRow(
        string Action, string Risk, string Service, int RoleCount, string GrantedBy);

    /// <summary>
    /// Roles answer "what does this grant?"; permissions answer the question a
    /// least-privilege decision starts from — "what exists for this task, and which is
    /// narrowest?" Only having the first view is what let a request for the GPO analyzer
    /// be answered with all of Intune.
    /// </summary>
    /// <summary>
    /// Fills the Service override list. Naming the service removes the one judgement the
    /// model gets wrong most often — a feature name like "GPO analytics" appears in no
    /// permission string, so the model has to infer which product owns it.
    /// </summary>
    private void RefreshForcedProviderList()
    {
        var previous = ForcedProviderBox.SelectedItem as string;
        ForcedProviderBox.Items.Clear();
        ForcedProviderBox.Items.Add("auto-detect service");

        if (_catalog is not null)
        {
            foreach (var provider in _catalog.Roles
                         .Select(r => r.Provider)
                         .Distinct(StringComparer.OrdinalIgnoreCase)
                         .OrderBy(p => RbacProviders.DisplayName(p), StringComparer.OrdinalIgnoreCase))
            {
                ForcedProviderBox.Items.Add(RbacProviders.DisplayName(provider));
            }
        }

        ForcedProviderBox.SelectedItem = previous ?? "auto-detect service";
        if (ForcedProviderBox.SelectedItem is null) ForcedProviderBox.SelectedIndex = 0;
    }

    /// <summary>The provider keys to force, or empty for auto-detect.</summary>
    private IReadOnlyCollection<string> SelectedForcedProviders()
    {
        if (_catalog is null) return Array.Empty<string>();
        if (ForcedProviderBox.SelectedItem is not string selected
            || selected == "auto-detect service") return Array.Empty<string>();

        var match = _catalog.Roles
            .Select(r => r.Provider)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(p => RbacProviders.DisplayName(p) == selected);
        return match is null ? Array.Empty<string>() : new[] { match };
    }

    private void RebuildPermissionCatalog()
    {
        // Microsoft's reference supplies the DESCRIPTIONS and contributes permissions no
        // local role bundles. Building from roles alone hid exactly the set a custom role
        // exists to grant, and attached role descriptions to unrelated permissions.
        _permissionCatalog = _catalog is null
            ? null
            : PermissionIndex.Build(_catalog, _referenceStore);

        var previous = PermProviderFilter.SelectedItem as string;
        PermProviderFilter.Items.Clear();
        PermProviderFilter.Items.Add("all services");
        if (_permissionCatalog is not null)
            foreach (var provider in _permissionCatalog.Providers)
                PermProviderFilter.Items.Add(RbacProviders.DisplayName(provider));
        PermProviderFilter.SelectedItem = previous ?? "all services";
        if (PermProviderFilter.SelectedItem is null) PermProviderFilter.SelectedIndex = 0;
    }

    private void CatalogMode_Changed(object sender, RoutedEventArgs e)
    {
        if (PermissionsGrid is null || CatalogGrid is null) return;
        var permissions = CatalogPermsMode.IsChecked == true;

        PermissionsGrid.Visibility = permissions ? Visibility.Visible : Visibility.Collapsed;
        CatalogGrid.Visibility = permissions ? Visibility.Collapsed : Visibility.Visible;
        PermProviderFilter.Visibility = permissions ? Visibility.Visible : Visibility.Collapsed;

        if (permissions) ApplyPermissionFilter(); else PermCountText.Text = "";
    }

    private void PermProviderFilter_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (CatalogPermsMode?.IsChecked == true) ApplyPermissionFilter();
    }

    private void ApplyPermissionFilter()
    {
        if (_permissionCatalog is null)
        {
            PermissionsGrid.ItemsSource = null;
            PermCountText.Text = "Sync the catalog to build the permission index.";
            return;
        }

        string? provider = null;
        if (PermProviderFilter.SelectedItem is string selected && selected != "all services")
        {
            provider = _permissionCatalog.Providers
                .FirstOrDefault(p => RbacProviders.DisplayName(p) == selected);
        }

        var matches = _permissionCatalog.Search(CatalogFilter.Text.Trim(), provider);
        const int renderLimit = 500;

        PermissionsGrid.ItemsSource = matches.Take(renderLimit).Select(entry => new PermissionRow(
            ActionDisplay.Short(entry.Action),
            entry.RiskLabel,
            RbacProviders.DisplayName(entry.Provider),
            entry.RoleCount,
            string.Join(", ", entry.GrantedByRoles.Take(4)) +
                (entry.RoleCount > 4 ? ", +" + (entry.RoleCount - 4) + " more" : "")
        )).ToList();

        var privileged = matches.Count(m => m.IsPrivileged);
        PermCountText.Text = matches.Count + " permission(s) — " + privileged + " privileged, " +
            (matches.Count - privileged) + " read-only" +
            (matches.Count > renderLimit
                ? "  (showing the first " + renderLimit + "; filter to narrow)" : "");
    }

    /// <summary>Double-click a permission to see exactly what it permits.</summary>
    private async void PermissionsGrid_MouseDoubleClick(
        object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (PermissionsGrid.SelectedItem is PermissionRow row)
            await ShowExplanationAsync(row.Action);
    }

    // ---------------- catalog ----------------

    private sealed record CatalogRow(string Service, string Name, string BuiltIn, int ActionCount, string Description)
    {
        public IReadOnlyList<string> Actions { get; init; } = Array.Empty<string>();
    }

    private List<CatalogRow> _catalogRows = new();
    private List<string> _lastSyncReport = new();

    private void SyncReport_Click(object sender, RoutedEventArgs e)
    {
        var text = _lastSyncReport.Count == 0
            ? "No sync has run yet in this session."
            : string.Join(Environment.NewLine + Environment.NewLine, _lastSyncReport) +
              Environment.NewLine + Environment.NewLine +
              "Notes:" + Environment.NewLine +
              "- 403 means the delegated permission isn't consented on the app registration, " +
              "or your signed-in account lacks the corresponding admin role." + Environment.NewLine +
              "- 404 means that RBAC provider doesn't exist in this cloud/tenant." + Environment.NewLine +
              "- A count of 0 means the endpoint answered but no roles are defined or licensed." +
              Environment.NewLine +
              "- Exchange/Purview via PowerShell need a PowerShell host plus " +
              "Install-Module ExchangeOnlineManagement.";

        var box = new TextBox
        {
            Text = text, IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            BorderThickness = new Thickness(0), Margin = new Thickness(12), FontSize = 12
        };
        new Window
        {
            Title = "Sync report", Width = 760, Height = 520, Owner = this,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, Content = box
        }.Show();
    }

    private async void Sync_Click(object sender, RoutedEventArgs e)
    {
        SyncButton.IsEnabled = false;
        try
        {
            var graph = GetGraph();
            var sync = new CatalogSync(graph);
            var (catalog, results) = await sync.SyncAllAsync(msg => Status(msg));

            // Richer role metadata from BETA — role-level isPrivileged, allowedPrincipalTypes,
            // categories, richDescription, and assignmentMode (undocumented but present, and
            // the most likely carrier of AU-scopability). A separate pass so a beta failure
            // cannot cost us a working v1.0 catalog.
            var enrichment = await new RoleMetadataEnricher(graph)
                .EnrichDirectoryAsync(catalog, msg => Status(msg));
            _lastSyncReport.Add("Role metadata: " + enrichment.Detail);
            var parts = results.Select(r =>
                RbacProviders.DisplayName(r.Provider) + ": " +
                (r.Error is null ? r.RoleCount.ToString() : "FAILED")).ToList();
            _lastSyncReport = results.Select(r => r.Summary).ToList();
            _lastSyncReport.Insert(0,
                "Signed in as " + (graph.Auth.SignedInAccount ?? "(unknown)") +
                Environment.NewLine + "Token scopes: " +
                string.Join(", ", graph.Auth.LastGrantedScopes
                    .Select(sc => sc.Contains('/') ? sc[(sc.LastIndexOf('/') + 1)..] : sc)));

            if (ExoSyncCheck.IsChecked == true)
            {
                var (runner, env, adminUpn) = GetPs();
                var deep = new ExoPurviewCatalogSync(runner, env, adminUpn);

                _lastSyncReport.Add("PowerShell host: " + PowerShellRunner.DescribeHost());
                // ONE session for both services. Two SyncAsync calls meant two PowerShell
                // PROCESSES and therefore two interactive sign-ins; Connect-IPPSSession in
                // the same session as an existing Connect-ExchangeOnline normally reuses
                // the token.
                var swDeep = System.Diagnostics.Stopwatch.StartNew();
                var lastBeat = DateTime.UtcNow;
                var lastMessage = "starting";

                void DeepProgress(string message)
                {
                    lastBeat = DateTime.UtcNow;
                    lastMessage = message;
                    var elapsed = swDeep.Elapsed;
                    var text = "PowerShell sync — " + message
                        + "   [" + (int)elapsed.TotalMinutes + "m "
                        + elapsed.Seconds.ToString("00") + "s elapsed]";
                    Dispatcher.Invoke(() => Status(text));
                }

                // A long sync and a hung one look identical without this. The timer keeps
                // the elapsed clock moving even while a single slow call is in flight, and
                // says plainly when nothing has happened for a while — including the most
                // likely cause, which is a sign-in prompt waiting behind the app.
                var stallTimer = new System.Windows.Threading.DispatcherTimer
                {
                    Interval = TimeSpan.FromSeconds(5)
                };
                stallTimer.Tick += (_, _) =>
                {
                    var quiet = DateTime.UtcNow - lastBeat;
                    var elapsed = swDeep.Elapsed;
                    var clock = "[" + (int)elapsed.TotalMinutes + "m "
                              + elapsed.Seconds.ToString("00") + "s elapsed]";

                    if (quiet > TimeSpan.FromSeconds(90))
                    {
                        Status("PowerShell sync — no progress for "
                            + (int)quiet.TotalSeconds + "s. Last step: " + lastMessage
                            + ".  " + clock + "  If a sign-in window opened behind this "
                            + "one, it is waiting for you. Otherwise a single call is just "
                            + "slow — the sync gives up on its own after 45 minutes.");
                    }
                    else
                    {
                        Status("PowerShell sync — " + lastMessage + "   " + clock);
                    }
                };
                stallTimer.Start();

                Status("Deep-syncing Exchange Online and Purview in ONE PowerShell session. "
                       + "This makes hundreds of round trips and can take several minutes — "
                       + "the status bar updates as it works.");
                try
                {
                    // A slow tenant read is never worth waiting for: Microsoft's
                    // documentation already says what these permissions ARE. The tenant is
                    // only needed for which roles EXIST here — including custom ones — and
                    // that part is a fast bulk call.
                    var budget = TimeSpan.FromMinutes(Math.Max(1, _config.PowerShellSyncMinutes));
                    using var budgetCts = new CancellationTokenSource(budget);

                    List<RoleDefinitionRecord> exoRoles;
                    List<RoleDefinitionRecord> purviewRoles;
                    try
                    {
                        (exoRoles, purviewRoles, _) =
                            await deep.SyncBothAsync(budgetCts.Token, DeepProgress);
                    }
                    // The runner kills the process and throws TimeoutException; a linked
                    // token can also surface OperationCanceledException. Both mean the same
                    // thing here: stop waiting and use the documented vocabulary.
                    catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
                    {
                        exoRoles = new List<RoleDefinitionRecord>();
                        purviewRoles = new List<RoleDefinitionRecord>();
                        _lastSyncReport.Add("Exchange/Purview (PS): exceeded the "
                            + budget.TotalMinutes + "-minute budget and was stopped. "
                            + "Permissions for these services come from Microsoft's "
                            + "documentation instead — which is where their definitions live "
                            + "anyway. Raise the budget in Settings if you want the full "
                            + "tenant read.");
                    }

                    catalog.ReplaceProvider(RbacProviders.Exchange, exoRoles);
                    parts.RemoveAll(p => p.StartsWith("Exchange Online:", StringComparison.Ordinal));
                    parts.Add("Exchange Online (PS): " + exoRoles.Count);
                    _lastSyncReport.Add("Exchange Online (PS): " + deep.LastExchangeDiagnostics);

                    if (purviewRoles.Count > 0)
                    {
                        catalog.ReplaceProvider(RbacProviders.Purview, purviewRoles);
                        parts.RemoveAll(p => p.StartsWith("Purview", StringComparison.Ordinal));
                        parts.Add("Purview (PS): " + purviewRoles.Count);
                    }
                    _lastSyncReport.Add("Purview (PS): " + deep.LastPurviewDiagnostics);

                    // Record the cmdlet surface each endpoint reported, so the script builder
                    // stops guessing which parameters exist where.
                    if (deep.LastCmdletCapabilities.Count > 0)
                    {
                        foreach (var cap in deep.LastCmdletCapabilities)
                        {
                            _cmdletCapabilities.Capabilities.RemoveAll(x =>
                                x.Cmdlet.Equals(cap.Cmdlet, StringComparison.OrdinalIgnoreCase) &&
                                x.Scope.Equals(cap.Scope, StringComparison.OrdinalIgnoreCase));
                            _cmdletCapabilities.Capabilities.Add(cap);
                        }
                        _cmdletCapabilities.LastSyncedUtc = DateTimeOffset.UtcNow;
                        try { _cmdletCapabilities.Save(CmdletCapabilityPath); }
                        catch (Exception) { /* cache only */ }

                        var absent = deep.LastCmdletCapabilities.Where(x => !x.Exists).ToList();
                        _lastSyncReport.Add("Cmdlet surface: probed "
                            + deep.LastCmdletCapabilities.Count + " cmdlet(s); "
                            + absent.Count + " not present at that endpoint"
                            + (absent.Count > 0
                                ? " (" + string.Join(", ", absent.Select(a => a.Cmdlet)) + ")"
                                : "") + ".");
                    }
                    _lastSyncReport.Add("PowerShell sync took "
                        + (int)swDeep.Elapsed.TotalMinutes + "m "
                        + swDeep.Elapsed.Seconds.ToString("00") + "s.");
                }
                catch (Exception ex)
                {
                    parts.Add("Exchange/Purview (PS): FAILED");
                    _lastSyncReport.Add("Exchange/Purview (PS): FAILED — " + ex.Message);
                }
                finally
                {
                    stallTimer.Stop();
                }
            }

            _catalog = catalog;
            catalog.Save(CatalogPath);
            SyncSummary.Text = string.Join("  |  ", parts);
            Status("Synced " + catalog.Roles.Count + " roles, " +
                   catalog.ActionCount + " distinct actions.");
            RefreshCatalogGrid();
        RebuildPermissionCatalog();
        RefreshForcedProviderList();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Sync failed", MessageBoxButton.OK, MessageBoxImage.Error);
            Status("Sync failed.");
        }
        finally { SyncButton.IsEnabled = true; }
    }

    private void RefreshCatalogGrid()
    {
        if (_catalog is null) return;
        _catalogRows = _catalog.Roles
            .OrderBy(r => r.Provider).ThenBy(r => r.DisplayName)
            .Select(r => new CatalogRow(
                RbacProviders.DisplayName(r.Provider), r.DisplayName,
                r.IsBuiltIn ? "yes" : (r.IsAccessCheckCreated ? "AL" : "no"),
                r.AllowedResourceActions.Count,
                r.Description) { Actions = r.AllowedResourceActions })
            .ToList();
        ApplyCatalogFilter();
    }

    private void CatalogFilter_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (CatalogPermsMode?.IsChecked == true) ApplyPermissionFilter();
        else ApplyCatalogFilter();
    }

    private void ApplyCatalogFilter()
    {
        var q = CatalogFilter.Text.Trim();
        CatalogGrid.ItemsSource = q.Length == 0
            ? _catalogRows
            : _catalogRows.Where(r =>
                r.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                r.Service.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                r.Actions.Any(a => a.Contains(q, StringComparison.OrdinalIgnoreCase))).ToList();
    }

    // ---------------- recommend ----------------

    private async void Recommend_Click(object sender, RoutedEventArgs e)
    {
        var function = FunctionText.Text.Trim();
        if (function.Length == 0) { Status("Describe the function first."); return; }
        if (_catalog is null)
        {
            MessageBox.Show("Sync the catalog first (Catalog tab).", "No catalog",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        RecommendButton.IsEnabled = false;
        OutcomesPanel.Children.Clear();
        GroupMatchPanel.Children.Clear();
        _cards.Clear();
        ExecutePanel.Visibility = Visibility.Collapsed;
        ReasoningText.Text = "";
        try
        {
            _lastFunction = function;
            _config = ReadConfigFromUi();

            AiSuggestion suggestion;
            string? promptSha = null;

            // If the request NAMES a permission, that is not a question for the model.
            // Asked for microsoft.directory/users/authenticationMethods.password/delete it
            // returned microsoft.directory/agentUsers/delete with a confident justification.
            // Substitution is the failure mode here, and the operator already said exactly
            // what they want.
            var literal = LiteralPermission.Detect(function, _catalog, _referenceStore.ActionNames());

            if (literal.Resolved.Count > 0)
            {
                suggestion = new AiSuggestion
                {
                    RequiredActions = literal.Resolved,
                    Reasoning = "You named " + literal.Resolved.Count
                        + " permission(s) directly, so they were used as written rather than "
                        + "interpreted."
                        + (literal.NotFound.Count > 0
                            ? "  " + literal.NotFound.Count
                              + " other named permission(s) do NOT exist and were not substituted."
                            : ""),
                    Confidence = SuggestionConfidence.High,
                    CandidatesConsidered = literal.Resolved.Count
                };
                Status("Used the permission(s) you named — no interpretation needed.");
            }
            else if (literal.NotFound.Count > 0)
            {
                // Named something permission-shaped that does not exist. Say so, rather
                // than letting the model hand back a plausible substitute.
                var didYouMean = string.Concat(literal.NotFound
                    .Where(n => literal.Suggestions.TryGetValue(n, out var sug) && sug.Count > 0)
                    .Select(n => "  Did you mean: "
                        + string.Join(", ", literal.Suggestions[n].Take(5)) + "?"));

                suggestion = new AiSuggestion
                {
                    RequiredActions = Array.Empty<string>(),
                    Confidence = SuggestionConfidence.None,
                    NoMatchExplanation =
                        "You named " + string.Join(", ", literal.NotFound)
                        + ", which exists in neither your catalog nor Microsoft's reference. "
                        + "Nothing was substituted: handing back a similar-looking permission "
                        + "is worse than saying it does not exist." + didYouMean
                };
                Status("Named permission does not exist — nothing substituted.");
            }
            else if (UseDemoCheck.IsChecked == true)
            {
                Status("Running offline demo suggester...");
                suggestion = await new DemoSuggester().SuggestAsync(function, _catalog);
            }
            else
            {
                var key = SecretStore.Load(_config.Ai.ApiKeyName);
                if (string.IsNullOrEmpty(key))
                    throw new InvalidOperationException(
                        "No AI key stored — set it in Settings, or tick the offline demo box.");
                Status("Asking AI endpoint (two-stage)...");
                using var provider = AiProviderFactory.Create(BuildAiConfig(), key);
                provider.PromptLogger = (stage, prompt) =>
                    File.AppendAllText(PromptLogPath,
                        "==== " + DateTimeOffset.UtcNow.ToString("o") + " [" + stage + "] ====\n" +
                        prompt + "\n");
                suggestion = await provider.SuggestAsync(function, _catalog, SelectedForcedProviders(), default, _referenceStore);
                promptSha = provider.LastPromptSha256;
            }

            _lastSuggestion = suggestion;
            _lastPromptSha = promptSha;
            _manualActions.Clear();
            _removedActions.Clear();
            ReasoningText.Text = "AI reasoning: " + suggestion.Reasoning;

            RunValidation();
            Status(_cards.Count == 0
                ? "The suggester returned no actions at all."
                : "Analysis complete — review each service verdict, click any permission for an explanation, add permissions if needed, then approve.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Analysis failed", MessageBoxButton.OK, MessageBoxImage.Error);
            Status("Analysis failed.");
        }
        finally { RecommendButton.IsEnabled = true; }
    }

    /// <summary>
    /// Re-runs deterministic validation over AI-suggested + human-added actions and
    /// rebuilds the verdict cards. Called after analysis and after every manual add.
    /// </summary>
    private void RunValidation()
    {
        if (_catalog is null || _lastSuggestion is null) return;
        OutcomesPanel.Children.Clear();
        _cards.Clear();
        _scopeEchoBlocks.Clear();

        var merged = _lastSuggestion.RequiredActions
            .Concat(_manualActions)
            .Where(a => !_removedActions.Contains(a, StringComparer.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var effective = _lastSuggestion with { RequiredActions = merged };

        _config = ReadConfigFromUi();
        var validator = new RecommendationValidator
        {
            MaxAcceptableExcessActions = _config.MaxAcceptableExcessActions,
            // Microsoft's list is authoritative: a permission it defines is real even when
            // no role in this tenant bundles it. Without this, valid permissions were
            // rejected as invented purely because the catalog is derived from roles.
            ReferenceActions = _referenceStore.ActionNames(),
            Ineligibility = _ineligibility,
            ReferenceDescriptions = _referenceStore.Entries
                .Where(e => e.Description.Length > 0)
                .GroupBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First().Description, StringComparer.OrdinalIgnoreCase)
        };
        var outcomes = validator.ValidateMulti(_catalog, effective, _lastFunction);

        // Guards render BEFORE the verdict, because they change how it should be read.
        // A recommendation under a red card is not a recommendation to act on. None of
        // these ask the model to grade its own answer — they are deterministic.
        RenderGuardCards(outcomes);

        foreach (var po in outcomes) AddOutcomeCard(po);

        ManualActionsText.Text = _manualActions.Count == 0
            ? ""
            : "Human-added (" + _manualActions.Count + "): " + string.Join(", ", _manualActions) +
              "  — recorded separately from AI suggestions in the audit trail.";
        RenderGroupMatches(outcomes
            .SelectMany(o => o.Outcome.ValidActions)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList());

        ExecutePanel.Visibility =
            _cards.Any(c => c.Options.Count > 0) ? Visibility.Visible : Visibility.Collapsed;
    }

    private void AddAction_Click(object sender, RoutedEventArgs e)
    {
        if (_catalog is null)
        {
            Status("Sync the catalog first (Catalog tab).");
            return;
        }
        // Allow building a purely manual request with no AI pass.
        if (_lastSuggestion is null)
        {
            _lastFunction = FunctionText.Text.Trim().Length > 0
                ? FunctionText.Text.Trim() : "(manual request)";
            _lastSuggestion = new AiSuggestion
            {
                RequiredActions = Array.Empty<string>(),
                Reasoning = "(no AI pass — request assembled manually by the approver)"
            };
            _lastPromptSha = null;
        }

        var query = ManualActionBox.Text.Trim();
        if (query.Length == 0) { Status("Type an action (or part of one) first."); return; }

        string? chosen = null;
        if (_catalog.ActionExists(query))
        {
            chosen = query;
        }
        else
        {
            var matches = _catalog.Roles
                .SelectMany(r => r.AllowedResourceActions)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Where(a => a.Contains(query, StringComparison.OrdinalIgnoreCase))
                .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
                .Take(200)
                .ToList();
            if (matches.Count == 0)
            {
                MessageBox.Show(
                    "No action in the synced catalog contains '" + query + "'. " +
                    "Only actions that exist in your tenant can be granted.",
                    "Not in catalog", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            chosen = matches.Count == 1 ? matches[0] : PickFromList(
                "Select the permission to add (" + matches.Count + " catalog matches)", matches);
            if (chosen is null) return;
        }

        bool already =
            _manualActions.Contains(chosen, StringComparer.OrdinalIgnoreCase) ||
            _lastSuggestion.RequiredActions.Contains(chosen, StringComparer.OrdinalIgnoreCase);
        if (already)
        {
            Status("'" + chosen + "' is already part of this request.");
            return;
        }

        _manualActions.Add(chosen);
        ManualActionBox.Clear();
        RunValidation();
        Status("Added '" + chosen + "' — request re-validated (selections reset).");
    }

    /// <summary>Minimal modal picker: ListBox + OK/Cancel, built in code.</summary>
    private string? PickFromList(string title, IReadOnlyList<string> items)
    {
        var list = new ListBox { ItemsSource = items, Margin = new Thickness(10) };
        var ok = new Button { Content = "Add selected", Margin = new Thickness(10, 0, 5, 10), IsDefault = true };
        var cancel = new Button { Content = "Cancel", Margin = new Thickness(5, 0, 10, 10), IsCancel = true };
        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right
        };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        var root = new DockPanel();
        DockPanel.SetDock(buttons, Dock.Bottom);
        root.Children.Add(buttons);
        root.Children.Add(list);
        var win = new Window
        {
            Title = title,
            Width = 640,
            Height = 480,
            Owner = this,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Content = root
        };
        ok.Click += (_, _) => { if (list.SelectedItem is not null) win.DialogResult = true; };
        list.MouseDoubleClick += (_, _) => { if (list.SelectedItem is not null) win.DialogResult = true; };
        return win.ShowDialog() == true ? list.SelectedItem as string : null;
    }

    /// <summary>Simple single-line text prompt (avoids a WinForms/VB dependency).</summary>
    private string? PromptForText(string title, string message, string initial)
    {
        var msg = new TextBlock
        {
            Text = message, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(12, 12, 12, 6)
        };
        var input = new TextBox { Text = initial, Margin = new Thickness(12, 0, 12, 8) };
        var ok = new Button { Content = "OK", Margin = new Thickness(0, 0, 6, 10), IsDefault = true, MinWidth = 70 };
        var cancel = new Button { Content = "Cancel", Margin = new Thickness(0, 0, 12, 10), IsCancel = true, MinWidth = 70 };
        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right
        };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        var stack = new StackPanel();
        stack.Children.Add(msg);
        stack.Children.Add(input);
        stack.Children.Add(buttons);
        var win = new Window
        {
            Title = title, Width = 460, SizeToContent = SizeToContent.Height,
            Owner = this, WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize, Content = stack
        };
        ok.Click += (_, _) => win.DialogResult = true;
        return win.ShowDialog() == true ? input.Text : null;
    }

    // ---------------- permission explanations ----------------

    /// <summary>Small clickable chip for one permission; click = explain.</summary>
    private Button MakeActionChip(string action)
    {
        // Exchange and Purview actions are full cmdlet SIGNATURES. Showing the whole
        // thing makes a card unreadable, so the chip shows the cmdlet and the tooltip
        // carries the parameters — nothing is hidden, just not shouted.
        var display = ActionDisplay.Short(action);
        var full = ActionDisplay.Detail(action);

        var chip = new Button
        {
            Content = display,
            Tag = action,
            Margin = new Thickness(0, 2, 6, 2),
            Padding = new Thickness(6, 2, 6, 2),
            Background = new SolidColorBrush(Color.FromRgb(0xE8, 0xEE, 0xF5)),
            Foreground = (Brush)FindResource("Steel"),
            BorderThickness = new Thickness(1),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xC3, 0xCB, 0xD6)),
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12,
            FontWeight = FontWeights.Normal,
            ToolTip = full is null
                ? "Click for an explanation of this permission"
                : full + "\n\nClick for an explanation of this permission."
        };
        chip.Click += async (_, _) => await ShowExplanationAsync(action);
        return chip;
    }

    private static WrapPanel MakeChipRow(string label, IEnumerable<string> actions,
        Func<string, Button> chipFactory)
    {
        var panel = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
        panel.Children.Add(new TextBlock
        {
            Text = label + " ",
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 4, 6, 0)
        });
        foreach (var a in actions) panel.Children.Add(chipFactory(a));
        return panel;
    }

    private async Task ShowExplanationAsync(string action)
    {
        // Deterministic context first: which roles in the tenant carry this action.
        var provider = _catalog?.ProviderOf(action);
        var carriers = _catalog is null
            ? new List<string>()
            : _catalog.Roles
                .Where(r => r.AllowedResourceActions.Contains(action, StringComparer.OrdinalIgnoreCase))
                .OrderBy(r => r.IsBuiltIn ? 0 : 1)
                .Take(8)
                .Select(r => r.DisplayName + (r.IsBuiltIn ? "" : " (custom)"))
                .ToList();

        var header =
            "Permission: " + action + Environment.NewLine +
            "Service: " + (provider is null ? "unknown" : RbacProviders.DisplayName(provider)) +
            Environment.NewLine +
            "Granted by (your tenant): " +
            (carriers.Count == 0 ? "no synced role carries it" : string.Join("; ", carriers)) +
            Environment.NewLine + Environment.NewLine;

        string body;
        if (_explainCache.TryGetValue(action, out var cached))
        {
            body = cached;
        }
        else if (UseDemoCheck.IsChecked == true ||
                 SecretStore.Load(_config.Ai.ApiKeyName) is null)
        {
            body = "(Offline: no AI endpoint in use. The tenant facts above are " +
                   "deterministic; configure the AI endpoint in Settings and untick " +
                   "the demo box for a plain-language explanation of what this " +
                   "permission allows and its risk profile.)";
        }
        else
        {
            Status("Asking AI to explain '" + action + "'...");
            try
            {
                _config = ReadConfigFromUi();
                var key = SecretStore.Load(_config.Ai.ApiKeyName)!;
                using var ai = AiProviderFactory.Create(BuildAiConfig(), key);
                ai.PromptLogger = (stage, prompt) =>
                    File.AppendAllText(PromptLogPath,
                        "==== " + DateTimeOffset.UtcNow.ToString("o") + " [" + stage + "] ====" +
                        Environment.NewLine + prompt + Environment.NewLine);
                const string system =
                    "You are a Microsoft 365 RBAC expert. Explain the given resource action " +
                    "or cmdlet in plain language for an approver deciding whether to grant it: " +
                    "what it permits, what it does NOT permit, its risk level (low/medium/high " +
                    "with one-line justification), and one typical legitimate use. Be concise " +
                    "(under 180 words), plain text, no markdown.";
                var user = "PERMISSION: " + action +
                           "\nSERVICE: " + (provider ?? "unknown") +
                           "\nROLES CONTAINING IT: " +
                           (carriers.Count == 0 ? "(none synced)" : string.Join("; ", carriers));
                body = await ai.CompleteAsync("explain", system, user);
                _explainCache[action] = body;
                Status("Ready.");
            }
            catch (Exception ex)
            {
                body = "(Explanation call failed: " + ex.Message + ")";
                Status("Explanation failed.");
            }
        }

        var textBox = new TextBox
        {
            Text = header + body,
            IsReadOnly = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            BorderThickness = new Thickness(0),
            Margin = new Thickness(12),
            FontSize = 13
        };
        var win = new Window
        {
            Title = "Permission explanation",
            Width = 620,
            Height = 420,
            Owner = this,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Content = textBox
        };
        win.Show();
    }

    /// <summary>
    /// The deterministic guards, in the order they change a decision: what the request
    /// asked for that permissions cannot express, what is not RBAC at all, a wrong
    /// resource, scope creep, then over-broad grants.
    /// </summary>
    private void RenderGuardCards(IReadOnlyList<ProviderOutcome> outcomes)
    {
        var validated = outcomes
            .SelectMany(o => o.Outcome.ValidActions)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // 1. Limits no permission can encode.
        var constraints = RequestConstraints.Detect(_lastFunction);
        if (constraints.Count > 0)
        {
            var stack = NewGuardCard("This request contains a limit permissions cannot express",
                                     (Brush)FindResource("Warn"));
            foreach (var finding in constraints)
            {
                stack.Children.Add(new TextBlock
                {
                    Text = finding.Title + " — \"" + finding.Phrase + "\"",
                    FontWeight = FontWeights.SemiBold,
                    Margin = new Thickness(0, 6, 0, 2)
                });
                stack.Children.Add(new TextBlock
                {
                    Text = finding.Guidance,
                    TextWrapping = TextWrapping.Wrap
                });
            }
            stack.Children.Add(new TextBlock
            {
                Text = "The permissions below cover the ACTION only. Applying the limit is a "
                     + "separate decision made at approval time.",
                Style = (Style)FindResource("Hint"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            });

            // Telling someone to use an administrative unit while the AU picker sits
            // unmentioned further down the page is advice, not help. Offer the control
            // where the need is stated.
            if (constraints.Any(c => c.Kind == RequestConstraints.Kind.Restriction
                                  || c.Kind == RequestConstraints.Kind.Exclusion))
            {
                var scopeNow = new Button
                {
                    Content = "Scope this grant to an administrative unit…",
                    HorizontalAlignment = HorizontalAlignment.Left,
                    Margin = new Thickness(0, 10, 0, 0)
                };
                scopeNow.Click += PickScope_Click;
                stack.Children.Add(scopeNow);

                var scopeEcho = new TextBlock
                {
                    Style = (Style)FindResource("Hint"),
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 4, 0, 0),
                    Text = _directoryScopeId == "/"
                        ? "Currently TENANT-WIDE — the limit above is not yet applied."
                        : "Currently scoped to " + ScopeDisplay.Text + "."
                };
                stack.Children.Add(scopeEcho);
                _scopeEchoBlocks.Add(scopeEcho);
            }
        }

        // 2. Capabilities RBAC does not grant at all.
        var nonRbac = NonRbacCapability.Findings(_lastFunction);
        if (nonRbac.Count > 0)
        {
            var stack = NewGuardCard("This is not granted by a permission at all",
                                     (Brush)FindResource("Bad"));
            foreach (var finding in nonRbac)
            {
                stack.Children.Add(new TextBlock
                {
                    Text = finding.Capability + " is configured in " + finding.Where,
                    FontWeight = FontWeights.SemiBold,
                    Margin = new Thickness(0, 6, 0, 2)
                });
                stack.Children.Add(new TextBlock
                {
                    Text = finding.Message,
                    TextWrapping = TextWrapping.Wrap
                });
            }
            stack.Children.Add(new TextBlock
            {
                Text = "Any permission recommended below would grant something BROADER than "
                     + "what was asked for. Configure the capability where it actually lives.",
                Style = (Style)FindResource("Hint"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            });
        }

        // 2a. The AI proposed permissions your catalog does not contain. Showing the
        // rejects without saying WHY they are missing leaves the operator assuming the
        // model hallucinated, when the commonest cause is a catalog that never synced
        // the service in question.
        var rejected = outcomes.SelectMany(o => o.Outcome.UnknownActionsRejected)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (rejected.Count > 0 && _catalog is not null)
        {
            var stack = NewGuardCard(
                rejected.Count + " proposed permission(s) are not in your catalog",
                (Brush)FindResource("Warn"));

            stack.Children.Add(new TextBlock
            {
                Text = "These were REJECTED and are not part of any recommendation below — "
                     + "the app never grants a permission it cannot find in your tenant. "
                     + "But there are two very different reasons this happens, and they "
                     + "need different fixes.",
                TextWrapping = TextWrapping.Wrap
            });

            stack.Children.Add(MakeChipRow("Rejected:", rejected.Take(15), MakeActionChip));

            // Which of the rejects LOOK like a service that simply is not synced?
            var likelyProviders = rejected
                .Select(a => CmdletServiceMap.OwnerOf(a)
                    ?? (a.Contains("Microsoft.Intune", StringComparison.OrdinalIgnoreCase)
                        ? RbacProviders.Intune
                        : a.StartsWith("microsoft.directory/", StringComparison.OrdinalIgnoreCase)
                            ? RbacProviders.Directory
                            : null))
                .Where(p => p is not null).Select(p => p!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Where(p => !_catalog.RolesFor(p).Any())
                .ToList();

            if (likelyProviders.Count > 0)
            {
                stack.Children.Add(new TextBlock
                {
                    Text = "MOST LIKELY A SYNC GAP. These look like "
                         + string.Join(", ", likelyProviders.Select(RbacProviders.DisplayName))
                         + " permissions, and your catalog has NO roles for "
                         + (likelyProviders.Count == 1 ? "that service" : "those services")
                         + ". Fix that first:",
                    FontWeight = FontWeights.SemiBold,
                    Foreground = (Brush)FindResource("Bad"),
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 8, 0, 2)
                });

                foreach (var provider in likelyProviders)
                {
                    stack.Children.Add(new TextBlock
                    {
                        Text = RbacProviders.DerivedRoleCapable.Contains(provider)
                            ? "  * " + RbacProviders.DisplayName(provider)
                              + " comes through PowerShell, not Graph. Catalog tab > tick "
                              + "\"Include Exchange & Purview via PowerShell\" > Sync all "
                              + "providers. If it still shows zero, open Sync report — the "
                              + "connection error is recorded there."
                            : "  * " + RbacProviders.DisplayName(provider)
                              + " comes through Graph. Home tab > Probe services to see "
                              + "whether it is readable, then Catalog tab > Sync all providers. "
                              + "A 403 usually means a missing consent or an unlicensed service.",
                        TextWrapping = TextWrapping.Wrap
                    });
                }
            }
            else
            {
                stack.Children.Add(new TextBlock
                {
                    Text = "PROBABLY NOT REAL PERMISSIONS. Every service these belong to IS "
                         + "synced, so the model most likely invented them — which is exactly "
                         + "what validation exists to catch. Check Catalog > Permissions for "
                         + "the real name, or restate the task in terms of the resource being "
                         + "read or changed.",
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 8, 0, 0)
                });
            }

            var resync = new Button
            {
                Content = "Re-sync the catalog now",
                HorizontalAlignment = HorizontalAlignment.Left,
                Margin = new Thickness(0, 8, 0, 0)
            };
            resync.Click += Sync_Click;
            stack.Children.Add(resync);
        }

        // 2b. The identified service has NO ROLES in the catalog at all. This is the
        // difference between "the app chose badly" and "the app had nothing to choose
        // from", and without it every downstream result looks like a reasoning failure.
        if (_lastSuggestion is not null && _catalog is not null)
        {
            // The question is whether the service has PERMISSIONS, not roles. Purview
            // synced 120 role NAMES with zero permission lists — plenty of roles, nothing
            // to recommend from — and a roles-only check passed it silently.
            var emptyServices = _lastSuggestion.IdentifiedServices
                .Where(p => !_catalog.RolesFor(p)
                    .SelectMany(r => r.AllowedResourceActions).Any())
                .ToList();

            if (emptyServices.Count > 0)
            {
                var stack = NewGuardCard(
                    "The right service has no roles in your catalog",
                    (Brush)FindResource("Bad"));

                foreach (var provider in emptyServices)
                {
                    var roleCount = _catalog.RolesFor(provider).Count();
                    stack.Children.Add(new TextBlock
                    {
                        Text = roleCount == 0
                            ? "This task belongs to " + RbacProviders.DisplayName(provider)
                              + ", but your synced catalog contains ZERO roles for it. The "
                              + "permissions proposed below therefore come from a DIFFERENT "
                              + "service and will not do the job."
                            : "This task belongs to " + RbacProviders.DisplayName(provider)
                              + ". Your catalog has " + roleCount + " role NAMES for it but "
                              + "NO permission lists — so nothing can be compared or "
                              + "recommended from that service, and the permissions below "
                              + "come from a DIFFERENT one. The Sync report says why the "
                              + "permission lists could not be read.",
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(0, 4, 0, 0)
                    });

                    if (provider == RbacProviders.Purview || provider == RbacProviders.Exchange)
                    {
                        stack.Children.Add(new TextBlock
                        {
                            Text = "Exchange and Purview roles are read through PowerShell, not "
                                 + "Graph. On the Catalog tab, tick \"Include Exchange & Purview "
                                 + "via PowerShell\" and sync again, then open the Sync report — "
                                 + "if that service failed, the reason is in there.",
                            Style = (Style)FindResource("Hint"),
                            TextWrapping = TextWrapping.Wrap,
                            Margin = new Thickness(0, 4, 0, 0)
                        });
                    }
                }
            }
        }

        // 2c. Does the proposal actually DO what was asked? Every other guard looks for
        // too MUCH; none notices too LITTLE. A purge request answered with search-only
        // permissions passes every existing check with zero excess.
        var coverageGaps = CapabilityCoverage.Gaps(
            _lastFunction,
            outcomes.SelectMany(o => o.Outcome.ValidActions)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToList());

        if (coverageGaps.Count > 0)
        {
            var stack = NewGuardCard(
                "This may not do what was asked", (Brush)FindResource("Warn"));

            foreach (var gap in coverageGaps)
            {
                stack.Children.Add(new TextBlock
                {
                    Text = gap.Message,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 4, 0, 0)
                });
            }

            stack.Children.Add(new TextBlock
            {
                Text = "Under-granting is safe — nothing extra is exposed — but the request "
                     + "will come back. Use \"Add permission\" below if you know the missing "
                     + "one, or restate the task naming the action explicitly.",
                Style = (Style)FindResource("Hint"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            });
        }

        // 3. Granted through the WRONG SERVICE. This is a correctness failure, not a
        // presentation one — the grant would execute against the wrong endpoint and the
        // task would fail.
        foreach (var providerOutcome in outcomes)
        {
            var wrongService = CmdletServiceMap.Findings(
                providerOutcome.Outcome.ValidActions, providerOutcome.Provider);
            if (wrongService.Count == 0) continue;

            var stack = NewGuardCard("Wrong service — this grant would not work",
                                     (Brush)FindResource("Bad"));
            foreach (var finding in wrongService)
            {
                stack.Children.Add(new TextBlock
                {
                    Text = finding.Message,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 4, 0, 0)
                });
            }
        }

        // 4. A resource whose name collides with what was asked for.
        var ambiguity = ResourceAmbiguity.Findings(validated, _lastFunction);
        if (ambiguity.Count > 0)
        {
            var stack = NewGuardCard("Possibly the wrong resource", (Brush)FindResource("Bad"));
            foreach (var finding in ambiguity)
            {
                stack.Children.Add(new TextBlock
                {
                    Text = finding.Message,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 4, 0, 0)
                });
            }
        }

        // 5. Permissions proposed that were never asked for.
        var inverse = InversePermissions.Findings(validated, _lastFunction);
        if (inverse.Count > 0)
        {
            var stack = NewGuardCard("Proposed but not requested", (Brush)FindResource("Bad"));
            foreach (var finding in inverse)
            {
                stack.Children.Add(new TextBlock
                {
                    Text = finding.Message,
                    TextWrapping = TextWrapping.Wrap
                });
            }
            stack.Children.Add(new TextBlock
            {
                Text = "Remove these before approving unless the task genuinely needs them — "
                     + "this is scope creep, and it is how least privilege erodes one grant "
                     + "at a time.",
                Style = (Style)FindResource("Hint"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            });
        }

        // 6. Grants that cover a whole service when something narrower exists.
        var breadth = PermissionBreadth.Findings(validated, _catalog!);
        if (breadth.Count > 0)
        {
            var stack = NewGuardCard("Not least privilege", (Brush)FindResource("Bad"));
            foreach (var finding in breadth)
            {
                stack.Children.Add(new TextBlock
                {
                    Text = finding.Message,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 4, 0, 2)
                });
                stack.Children.Add(new TextBlock
                {
                    Text = (finding.SameResource
                            ? "Narrower permissions on the SAME resource: "
                            : "No narrower permission exists on this resource. Others in the "
                              + "same namespace, as a lead only: ")
                         + string.Join(", ", finding.Examples.Select(ActionDisplay.Short)),
                    Style = (Style)FindResource("Hint"),
                    TextWrapping = TextWrapping.Wrap
                });
            }
        }

        // 7. Confidence, when the model was not sure it had the right service.
        if (_lastSuggestion is not null && _lastSuggestion.Confidence != SuggestionConfidence.High)
        {
            var stack = NewGuardCard(
                _lastSuggestion.Confidence == SuggestionConfidence.None
                    ? "No confident match"
                    : "LOW CONFIDENCE — verify before granting",
                (Brush)FindResource("Warn"));
            stack.Children.Add(new TextBlock
            {
                Text = _lastSuggestion.NoMatchExplanation
                    ?? "The owning service could not be confirmed, or the chosen permissions "
                     + "sit outside it. Treat this as a lead: check it in Catalog before "
                     + "granting anything.",
                TextWrapping = TextWrapping.Wrap
            });
            if (_lastSuggestion.CandidatesConsidered > 0)
            {
                stack.Children.Add(new TextBlock
                {
                    Text = _lastSuggestion.CandidatesConsidered
                         + " candidate permission(s) were offered to the model.",
                    Style = (Style)FindResource("Hint")
                });
            }
        }
    }

    /// <summary>Adds a titled card to the outcomes panel and returns its content stack.</summary>
    private StackPanel NewGuardCard(string title, Brush titleColour)
    {
        var stack = new StackPanel();
        stack.Children.Add(new TextBlock
        {
            Text = title,
            FontSize = 15,
            FontWeight = FontWeights.SemiBold,
            Foreground = titleColour,
            TextWrapping = TextWrapping.Wrap
        });
        OutcomesPanel.Children.Add(new Border
        {
            Style = (Style)FindResource("Card"),
            Child = stack
        });
        return stack;
    }

    private void AddOutcomeCard(ProviderOutcome po)
    {
        var outcome = po.Outcome;
        var card = new Border { Style = (Style)FindResource("Card") };
        var stack = new StackPanel();
        card.Child = stack;

        stack.Children.Add(new TextBlock
        {
            Text = RbacProviders.DisplayName(po.Provider),
            FontSize = 15,
            FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)FindResource("Steel")
        });

        stack.Children.Add(MakeChipRow(
            "Validated actions (" + outcome.ValidActions.Count + "):",
            outcome.ValidActions, MakeActionChip));

        if (!outcome.CustomRoleRecommended &&
            outcome.BestFit is not null && outcome.BestFit.ExcessCount > 0)
        {
            stack.Children.Add(MakeChipRow(
                "Excess granted by best fit '" + outcome.BestFit.DisplayName + "' (" +
                outcome.BestFit.ExcessLabel + "):",
                outcome.BestFit.ExcessActions.Take(30), MakeActionChip));
        }

        if (outcome.UnknownActionsRejected.Count > 0)
        {
            stack.Children.Add(new TextBlock
            {
                Text = "Rejected (not in your tenant catalog): " +
                       string.Join(", ", outcome.UnknownActionsRejected),
                TextWrapping = TextWrapping.Wrap,
                Foreground = (Brush)FindResource("Bad"),
                Margin = new Thickness(0, 4, 0, 0)
            });
        }

        var options = new List<object>();
        // Where each permission came from. Documentation says whether it is REAL; the
        // tenant says whether it is AVAILABLE HERE. Showing only one of those hides
        // whichever is missing, and they need different fixes.
        if (po.Outcome.Provenance.Count > 0)
        {
            var tenantVerified = po.Outcome.Provenance.Count(kv =>
                kv.Value == ActionProvenance.TenantVerified);
            var documentedOnly = po.Outcome.Provenance.Count(kv =>
                kv.Value == ActionProvenance.DocumentedOnly);
            var tenantOnly = po.Outcome.Provenance.Count(kv =>
                kv.Value == ActionProvenance.TenantOnly);

            var parts = new List<string>();
            if (tenantVerified > 0) parts.Add(tenantVerified + " documented AND in your tenant");
            if (documentedOnly > 0) parts.Add(documentedOnly + " documented but NOT in your tenant");
            if (tenantOnly > 0) parts.Add(tenantOnly + " in your tenant only (custom, or a service "
                                          + "with no published reference)");

            if (parts.Count > 0)
            {
                stack.Children.Add(new TextBlock
                {
                    // "Verified" used to sit in front of an existence check, which reads as
                    // "verified that these do the job". They are different claims.
                    Text = "Permission exists: " + string.Join("; ", parts) + ".",
                    Style = (Style)FindResource("Hint"),
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 4, 0, 0)
                });
            }
        }

        // WRONG RESOURCE. The operation check passes and the object is still wrong —
        // users/basic/update is a write, and for "reset MFA methods" it writes display
        // names. Third occurrence of this shape, so it gets its own guard.
        var wrongResource = ResourceFamily.Check(
            _lastFunction,
            po.Outcome.ValidActions,
            _catalog?.AllActions ?? Array.Empty<string>());

        if (wrongResource.Count > 0)
        {
            var stackR = NewGuardCard(
                "Right operation, wrong resource", (Brush)FindResource("Bad"));

            foreach (var f in wrongResource)
            {
                stackR.Children.Add(new TextBlock
                {
                    Text = f.Message,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 4, 0, 0)
                });

                if (f.Better is null) continue;

                stackR.Children.Add(new TextBlock
                {
                    Text = "This one does: " + ActionDisplay.Short(f.Better),
                    FontWeight = FontWeights.SemiBold,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 4, 0, 0)
                });

                // Naming the better candidate is the useful half; applying it should not
                // require retyping a permission string by hand.
                var useIt = new Button
                {
                    Content = "Use " + ActionDisplay.Short(f.Better) + " instead",
                    HorizontalAlignment = HorizontalAlignment.Left,
                    Margin = new Thickness(0, 6, 0, 0),
                    Tag = new[] { f.Action, f.Better }
                };
                useIt.Click += SwapPermission_Click;
                stackR.Children.Add(useIt);
            }
        }

        // TASK COVERAGE. A permission being real says nothing about whether it performs the
        // requested operation — a read-only action passes every existence check and cannot
        // delete anything.
        var contradicted = po.Outcome.Contradicted;
        if (contradicted.Count > 0)
        {
            var stack2 = NewGuardCard(
                "Excluded: cannot do what was asked", (Brush)FindResource("Warn"));

            foreach (var c2 in contradicted)
            {
                stack2.Children.Add(new TextBlock
                {
                    Text = ActionDisplay.Short(c2.Action) + " — " + c2.Reason,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 4, 0, 0)
                });
            }

            stack2.Children.Add(new TextBlock
            {
                Text = "These were EXCLUDED before role selection — they are not part of the "
                     + "recommendation below and did not influence which role was chosen. "
                     + "A read permission cannot perform a write task, so it never belonged "
                     + "in the proposal.",
                Style = (Style)FindResource("Hint"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            });
        }

        // Actions Microsoft will not accept in a custom role. Saying so up front stops the
        // operator wondering why no custom-role option appeared.
        if (po.Outcome.CustomRoleBlockedActions.Count > 0)
        {
            stack.Children.Add(new TextBlock
            {
                Text = po.Outcome.CustomRoleRefusedActions.Count > 0
                    ? "No custom role offered: Microsoft REFUSES "
                      + string.Join(", ", po.Outcome.CustomRoleRefusedActions.Select(ActionDisplay.Short))
                      + " in custom roles. Only a subset of directory actions are eligible, so a "
                      + "BUILT-IN role is the only route — the options below are ranked by how "
                      + "little extra they carry."
                    // UNPROVEN is not the same as refused, and saying so avoids implying
                    // Microsoft has ruled when it simply has not been asked.
                    : "No custom role offered: custom-role eligibility is UNVERIFIED for "
                      + string.Join(", ", po.Outcome.CustomRoleBlockedActions.Select(ActionDisplay.Short))
                      + ". Nothing in Microsoft's reference marks which actions are eligible, and "
                      + "this tenant has not yet accepted these in a custom role — so a custom "
                      + "role is not recommended automatically. A built-in role below is the safe "
                      + "route; approving one of those proves eligibility for next time.",
                Foreground = (Brush)FindResource("Warn"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 2)
            });
        }

        // Permissions validated against MICROSOFT rather than against this tenant's roles.
        // No existing role can cover them, so a custom role is the only route — and the
        // tenant, not the catalog, gets the final say on whether they work.
        if (po.Outcome.ReferenceOnlyActions.Count > 0)
        {
            stack.Children.Add(new TextBlock
            {
                Text = po.Outcome.ReferenceOnlyActions.Count
                     + " permission(s) exist in Microsoft's reference but are NOT granted by "
                     + "any role in your synced catalog. Tenant availability and custom-role "
                     + "eligibility are UNVERIFIED — this may be a sync gap, a preview "
                     + "permission, or one Microsoft does not allow in a custom role. "
                     + "Confirm before relying on it; any refusal is recorded in History.",
                Foreground = (Brush)FindResource("Warn"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 2)
            });
            stack.Children.Add(MakeChipRow("From Microsoft's reference:",
                po.Outcome.ReferenceOnlyActions.Take(12), MakeActionChip));
        }

        // For Exchange and Purview, show the composed ROLE GROUP plan. A single derived
        // role cannot span two parents, so this is the only shape that expresses "exactly
        // these cmdlets and nothing else" when the requirement crosses roles.
        if (po.Outcome.RoleGroupPlan is { Roles.Count: > 0 } plan)
        {
            stack.Children.Add(new TextBlock
            {
                Text = "Least-privilege plan: " + plan.Headline,
                FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource(plan.IsComplete ? "Ok" : "Warn"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 8, 0, 2)
            });

            foreach (var role in plan.Roles)
            {
                stack.Children.Add(new TextBlock
                {
                    Text = "  * " + role.Summary,
                    TextWrapping = TextWrapping.Wrap
                });
            }

            if (!plan.IsComplete)
            {
                stack.Children.Add(new TextBlock
                {
                    Text = "Not covered by any role in this service: "
                         + string.Join(", ", plan.Uncovered.Select(ActionDisplay.Short))
                         + ". Granting this would leave the task partly undone — check the "
                         + "service is right before proceeding.",
                    Foreground = (Brush)FindResource("Bad"),
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 2, 0, 0)
                });
            }

            var planDetail = new Button
            {
                Content = "Show the full plan…",
                HorizontalAlignment = HorizontalAlignment.Left,
                Margin = new Thickness(0, 6, 0, 4)
            };
            var planText = plan.Describe();
            planDetail.Click += (_, _) => ShowTextWindow("Least-privilege role plan", planText);
            stack.Children.Add(planDetail);
        }

        var combo = new ComboBox
        {
            Margin = new Thickness(0, 8, 0, 0),
            MaxWidth = 780,
            HorizontalAlignment = HorizontalAlignment.Left
        };

        if (outcome.CustomRoleRecommended && outcome.CustomRole is not null)
        {
            options.Add(outcome.CustomRole);
            var d = outcome.CustomRole;
            combo.Items.Add(d.ParentRoleName is null
                ? "RECOMMENDED — create custom role '" + d.DisplayName + "' with exactly " +
                  d.AllowedResourceActions.Count + " action(s), zero excess"
                : "RECOMMENDED — derive custom role '" + d.DisplayName + "' from '" +
                  d.ParentRoleName + "', stripping " + (d.EntriesToRemove?.Count ?? 0) +
                  " excess cmdlet(s) -> exactly " + d.AllowedResourceActions.Count + " remain");
        }
        foreach (var fit in outcome.RankedFits.Take(6))
        {
            options.Add(fit);
            var tag = options.Count == 1 ? "RECOMMENDED — " : "";
            combo.Items.Add(tag + (fit.IsBuiltIn ? "built-in" : "custom") + " role '" +
                            fit.DisplayName + "'  (" + fit.ExcessLabel + ")" +
                            (fit.IsPartial
                                ? "  — does NOT grant: " + string.Join(", ",
                                      fit.MissingActions.Select(ActionDisplay.Short))
                                : ""));
        }

        // A complete ROLE-GROUP PLAN is a selectable answer in its own right. Without this
        // it rendered as text only — no combo, no include checkbox, no way to approve —
        // because a multi-role plan has no single CustomRoleDraft and no covering RoleFit.
        // The plan WAS executable and the UI gave no way to choose it.
        if (options.Count == 0
            && po.Outcome.RoleGroupPlan is { Roles.Count: > 0, IsComplete: true } selectablePlan)
        {
            options.Add(selectablePlan);
            combo.Items.Add("RECOMMENDED — role group '" + selectablePlan.RoleGroupName
                + "' carrying " + selectablePlan.Roles.Count + " role(s)"
                + (selectablePlan.TotalExcess == 0
                    ? ", exactly the needed cmdlets"
                    : ", " + selectablePlan.TotalExcess + " excess stripped by derivation"));
        }

        CheckBox include;
        if (options.Count == 0)
        {
            // A complete role-group plan IS the answer for Exchange-model services, so
            // saying "no single role covers these actions, split the request" underneath
            // one contradicts it. The single-role message only applies when no plan exists.
            var planCovers = po.Outcome.RoleGroupPlan is { Roles.Count: > 0, IsComplete: true };

            stack.Children.Add(new TextBlock
            {
                Text = outcome.ValidActions.Count == 0
                    ? "Nothing actionable for this service."
                    : planCovers
                        ? "No SINGLE role covers these actions — the plan above spans "
                          + po.Outcome.RoleGroupPlan!.Roles.Count
                          + " roles, which is the least-privilege answer here."
                        : "No single role covers these actions" +
                          (RbacProviders.DerivedRoleCapable.Contains(po.Provider)
                            ? ", so no parent exists to derive a custom role from. Split the request."
                            : po.Outcome.CustomRoleBlockedActions.Count > 0
                                // This service DOES support custom roles — Microsoft just
                                // will not accept this particular action in one. Saying the
                                // service lacks the feature was simply wrong.
                                ? ". A custom role cannot be used here because Microsoft refuses "
                                  + string.Join(", ", po.Outcome.CustomRoleBlockedActions
                                        .Select(ActionDisplay.Short))
                                  + " in custom roles, so pick a built-in role below — each shows "
                                  + "what it covers and what it leaves out."
                                : ". Pick a role below and handle the remainder separately, or "
                                  + "split the request."),
                Foreground = (Brush)FindResource(planCovers ? "Ok" : "Warn"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0)
            });
            include = new CheckBox { IsChecked = false, Visibility = Visibility.Collapsed };
        }
        else
        {
            combo.SelectedIndex = 0;
            stack.Children.Add(combo);

            if (RbacProviders.DerivedRoleCapable.Contains(po.Provider))
            {
                stack.Children.Add(new TextBlock
                {
                    Text = "Runs as PowerShell (" +
                           (po.Provider == RbacProviders.Exchange
                               ? "Exchange Online" : "Security & Compliance") +
                           "): the exact script is shown for review before anything executes. " +
                           "The grant flows through an ACG- role group; enter the principal's UPN below.",
                    Style = (Style)FindResource("Hint"),
                    Margin = new Thickness(0, 6, 0, 0)
                });
            }

            include = new CheckBox
            {
                Content = "Include this grant in approval",
                IsChecked = true,
                Margin = new Thickness(0, 10, 0, 0)
            };
            stack.Children.Add(include);
        }

        OutcomesPanel.Children.Add(card);
        _cards.Add(new OutcomeCard
        {
            Provider = po.Provider,
            Outcome = outcome,
            Include = include,
            Choice = combo,
            Options = options
        });
    }

    // ---------------- user picker / duration / PIM setup / autocomplete ----------------

    private async void FindUser_Click(object sender, RoutedEventArgs e)
    {
        var hit = await PickUserAsync();
        if (hit is null) return;
        PrincipalBox.Text = hit.Id;
        if (!string.IsNullOrWhiteSpace(hit.Upn)) UpnBox.Text = hit.Upn;
        PrincipalDisplay.Text = hit.DisplayName;
        Status("Selected " + hit.DisplayName + " — object ID and UPN filled.");
    }

    /// <summary>
    /// Shared people picker used by New Request and Access Review. The token is warmed
    /// up BEFORE the modal opens: an MSAL sign-in raised from inside a modal can land
    /// behind it and look like a hang.
    /// </summary>
    private async Task<UserHit?> PickUserAsync()
    {
        GraphClient graph;
        try
        {
            Status("Connecting to Graph (sign in if prompted)...");
            graph = GetGraph();
            await graph.Auth.WarmUpOrToken();
            Status("Ready.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Sign-in failed", MessageBoxButton.OK, MessageBoxImage.Error);
            Status("Sign-in failed.");
            return null;
        }

        var searchBox = new TextBox { Margin = new Thickness(10, 10, 10, 0) };
        var searchBtn = new Button
        {
            Content = "Search", Margin = new Thickness(0, 10, 10, 0), IsDefault = true, MinWidth = 80
        };
        var top = new DockPanel();
        DockPanel.SetDock(searchBtn, Dock.Right);
        top.Children.Add(searchBtn);
        top.Children.Add(searchBox);

        var statusText = new TextBlock
        {
            Margin = new Thickness(12, 6, 12, 0),
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)FindResource("Steel"),
            Text = "Type at least 2 characters, then Search."
        };
        var list = new ListBox { Margin = new Thickness(10) };
        var ok = new Button { Content = "Select", Margin = new Thickness(10, 0, 5, 10), MinWidth = 80 };
        var cancel = new Button
        {
            Content = "Cancel", Margin = new Thickness(5, 0, 10, 10), IsCancel = true, MinWidth = 80
        };
        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right
        };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);

        var header = new StackPanel();
        header.Children.Add(top);
        header.Children.Add(statusText);

        var root = new DockPanel();
        DockPanel.SetDock(header, Dock.Top);
        DockPanel.SetDock(buttons, Dock.Bottom);
        root.Children.Add(header);
        root.Children.Add(buttons);
        root.Children.Add(list);

        var win = new Window
        {
            Title = "Find user (name or UPN)",
            Width = 620, Height = 480, Owner = this,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Content = root
        };

        async Task RunSearch()
        {
            var q = searchBox.Text.Trim();
            if (q.Length < 2) { statusText.Text = "Type at least 2 characters."; return; }
            searchBtn.IsEnabled = false;
            statusText.Text = "Searching for '" + q + "'...";
            list.ItemsSource = null;
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(45));
                var lookup = new DirectoryLookup(graph);
                var hits = await lookup.SearchUsersAsync(q, cts.Token);
                list.ItemsSource = hits;
                statusText.Text = hits.Count > 0
                    ? hits.Count + " match(es). " + lookup.LastDiagnostics
                    : "No matches for '" + q + "'. " + lookup.LastDiagnostics;
            }
            catch (OperationCanceledException)
            {
                statusText.Text = "Search timed out after 45s — check network/VPN to the Graph endpoint.";
            }
            catch (Exception ex)
            {
                statusText.Text = "Search failed: " + ex.Message;
            }
            finally { searchBtn.IsEnabled = true; }
        }

        searchBtn.Click += async (_, _) => await RunSearch();
        searchBox.KeyDown += async (_, args) =>
        {
            if (args.Key == System.Windows.Input.Key.Enter) await RunSearch();
        };
        ok.Click += (_, _) => { if (list.SelectedItem is not null) win.DialogResult = true; };
        list.MouseDoubleClick += (_, _) => { if (list.SelectedItem is not null) win.DialogResult = true; };
        win.Loaded += (_, _) => searchBox.Focus();

        return win.ShowDialog() == true ? list.SelectedItem as UserHit : null;
    }

    /// <summary>
    /// Direct membership has no server-side expiry, so a duration on it would promise an
    /// enforcement that doesn't exist. Switching to Direct sets the duration to 'never';
    /// switching back to PIM restores a bounded default.
    /// </summary>
    private void GroupMode_Changed(object sender, RoutedEventArgs e)
    {
        if (DurationBox is null || GroupDirectRadio is null) return;
        if (GroupDirectRadio.IsChecked == true)
        {
            DurationBox.Text = "never";
        }
        else if (string.Equals(DurationBox.Text.Trim(), "never", StringComparison.OrdinalIgnoreCase))
        {
            DurationBox.Text = "14 days";
        }
        Duration_TextChanged(DurationBox, null!);
    }

    private void Duration_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (DurationPreview is null) return; // during InitializeComponent
        if (DurationParser.TryParseSpec(DurationBox.Text, out var spec))
        {
            DurationPreview.Text = spec.Describe();
            DurationPreview.Foreground = spec.Permanent
                ? (Brush)FindResource("Bad")
                : (Brush)FindResource("Steel");
        }
        else
        {
            DurationPreview.Text =
                "unrecognized — try '14 days', '8 hours', '2 weeks', ISO like P14D, or 'never'";
            DurationPreview.Foreground = (Brush)FindResource("Warn");
        }
    }

    /// <summary>Returns the parsed duration or null (with a status message) if invalid.</summary>
    private DurationParser.DurationSpec? GetDurationOrWarn()
    {
        if (DurationParser.TryParseSpec(DurationBox.Text, out var spec))
            return spec;
        Status("Duration '" + DurationBox.Text +
               "' not recognized — use '14 days', '8 hours', ISO (P14D), or 'never' for no expiry.");
        return null;
    }

    private async void FindGroup_Click(object sender, RoutedEventArgs e)
    {
        GraphClient graph;
        try
        {
            FindGroupButton.IsEnabled = false;
            Status("Connecting to Graph (sign in if prompted)...");
            graph = GetGraph();
            await graph.Auth.WarmUpOrToken();
            Status("Ready.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Sign-in failed", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        finally { FindGroupButton.IsEnabled = true; }

        var searchBox = new TextBox { Margin = new Thickness(10, 10, 10, 0) };
        var searchBtn = new Button
        { Content = "Search", Margin = new Thickness(0, 10, 10, 0), IsDefault = true, MinWidth = 80 };
        var top = new DockPanel();
        DockPanel.SetDock(searchBtn, Dock.Right);
        top.Children.Add(searchBtn);
        top.Children.Add(searchBox);
        var statusText = new TextBlock
        {
            Margin = new Thickness(12, 6, 12, 0), TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)FindResource("Steel"),
            Text = "Search by group name. '[role-assignable]' groups can carry Entra directory roles."
        };
        var list = new ListBox { Margin = new Thickness(10) };
        var ok = new Button { Content = "Select", Margin = new Thickness(10, 0, 5, 10), MinWidth = 80 };
        var cancel = new Button
        { Content = "Cancel", Margin = new Thickness(5, 0, 10, 10), IsCancel = true, MinWidth = 80 };
        var buttons = new StackPanel
        { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        var header = new StackPanel();
        header.Children.Add(top);
        header.Children.Add(statusText);
        var root = new DockPanel();
        DockPanel.SetDock(header, Dock.Top);
        DockPanel.SetDock(buttons, Dock.Bottom);
        root.Children.Add(header);
        root.Children.Add(buttons);
        root.Children.Add(list);
        var win = new Window
        {
            Title = "Find group", Width = 640, Height = 460, Owner = this,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, Content = root
        };

        async Task RunSearch()
        {
            var q = searchBox.Text.Trim();
            if (q.Length < 2) { statusText.Text = "Type at least 2 characters."; return; }
            searchBtn.IsEnabled = false;
            statusText.Text = "Searching...";
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(45));
                var hits = await new DirectoryLookup(graph).SearchGroupsAsync(q, cts.Token);
                list.ItemsSource = hits;
                statusText.Text = hits.Count > 0
                    ? hits.Count + " match(es)."
                    : "No groups start with '" + q + "'.";
            }
            catch (Exception ex) { statusText.Text = "Search failed: " + ex.Message; }
            finally { searchBtn.IsEnabled = true; }
        }

        searchBtn.Click += async (_, _) => await RunSearch();
        searchBox.KeyDown += async (_, args) =>
        { if (args.Key == System.Windows.Input.Key.Enter) await RunSearch(); };
        ok.Click += (_, _) => { if (list.SelectedItem is not null) win.DialogResult = true; };
        list.MouseDoubleClick += (_, _) => { if (list.SelectedItem is not null) win.DialogResult = true; };
        win.Loaded += (_, _) => searchBox.Focus();

        if (win.ShowDialog() == true && list.SelectedItem is GroupHit hit)
        {
            PimGroupBox.Text = hit.Id;
            Status("Selected group '" + hit.DisplayName + "'" +
                   (hit.IsRoleAssignable ? " (role-assignable)." : "."));
        }
    }

    /// <summary>
    /// Turns whatever is in the PIM group box into an object id. A GUID passes through;
    /// anything else is resolved by exact display name so a typed group NAME still works.
    /// </summary>
    private async Task<string?> ResolvePimGroupAsync(string raw)
    {
        var text = raw.Trim();
        if (text.Length == 0) return "";
        if (Guid.TryParse(text, out _)) return text;

        Status("Resolving group '" + text + "'...");
        var hit = await new DirectoryLookup(GetGraph()).ResolveGroupByNameAsync(text);
        if (hit is null)
        {
            MessageBox.Show(
                "'" + text + "' is not a group object ID, and no single group has exactly " +
                "that display name.\n\nUse 'Find group…' to pick one, or paste the group's " +
                "object ID (GUID).",
                "Group not resolved", MessageBoxButton.OK, MessageBoxImage.Warning);
            return null;
        }
        PimGroupBox.Text = hit.Id;
        Status("Resolved '" + hit.DisplayName + "' to " + hit.Id + ".");
        return hit.Id;
    }

    /// <summary>
    /// Creates an empty security group and fills the group box.
    ///
    /// Separate from "Set up PIM group", which also attaches a role. Sometimes you just
    /// need the container first — and isAssignableToRole is the reason this cannot be an
    /// afterthought: it is fixed at creation and can NEVER be changed, so a group made
    /// without it can never carry an Entra directory role no matter what you do later.
    /// </summary>
    private async void NewGroup_Click(object sender, RoutedEventArgs e)
    {
        var suggested = "ACP - " + (string.IsNullOrWhiteSpace(_lastFunction)
            ? "access group"
            : new string(_lastFunction.Trim().Take(48).ToArray()));

        var roleAssignable = MessageBox.Show(
            "Will this group ever carry an Entra DIRECTORY role?\n\n"
            + "Yes  — creates it as ROLE-ASSIGNABLE. Required for directory roles, and it "
            + "cannot be turned on later: the flag is set at creation and is immutable. "
            + "Needs Privileged Role Administrator.\n\n"
            + "No   — a plain security group. Fine for Intune, Windows 365 and Defender, "
            + "which assign roles to ordinary security groups.\n\n"
            + "If unsure, choose No — you can create another group, but you can never "
            + "change this flag on an existing one.",
            "Create security group", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);

        if (roleAssignable == MessageBoxResult.Cancel) return;

        NewGroupButton.IsEnabled = false;
        try
        {
            Status("Creating security group...");
            var executor = new RoleExecutor(GetGraph());
            var groupId = await executor.CreateSecurityGroupAsync(
                suggested,
                "Created by AccessCheck for: " + (_lastFunction ?? "an access grant"),
                roleAssignable == MessageBoxResult.Yes);

            PimGroupBox.Text = groupId;
            Status("Created '" + suggested + "'"
                   + (roleAssignable == MessageBoxResult.Yes ? " (role-assignable)" : "")
                   + " — the group is EMPTY and holds no role yet.");

            MessageBox.Show(
                "Group created and its ID filled in.\n\nName: " + suggested
                + "\nRole-assignable: " + (roleAssignable == MessageBoxResult.Yes ? "yes" : "no")
                + "\n\nIt is empty and carries no role. Approving a grant will attach the "
                + "role and add the member.",
                "Group created", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(ExplainGrantFailure(ex), "Group creation failed",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Status("Group creation failed.");
        }
        finally { NewGroupButton.IsEnabled = true; }
    }

    private async void SetupPimGroup_Click(object sender, RoutedEventArgs e)
    {
        // Applies to the first included Intune/CloudPC/Defender card's selected role.
        var card = _cards.FirstOrDefault(c =>
            c.Include.IsChecked == true && c.Options.Count > 0 &&
            c.Provider != RbacProviders.Directory &&
            !RbacProviders.DerivedRoleCapable.Contains(c.Provider));
        if (card is null)
        {
            Status("Include an Intune / Windows 365 / Defender grant first — directory grants have PIM natively.");
            return;
        }
        var choice = card.Options[Math.Max(0, card.Choice.SelectedIndex)];

        // A CUSTOM ROLE is the commonest recommendation, and refusing to stage a group for
        // one meant "approve the grant, then come back and do this" — two passes for what
        // is conceptually one action. Create the role here instead.
        var draftChoice = choice as CustomRoleDraft;
        var fit = choice as RoleFit;
        if (draftChoice is null && fit is null)
        {
            Status("Select a role option on the " + RbacProviders.DisplayName(card.Provider)
                   + " card first.");
            return;
        }

        var roleLabel = draftChoice?.DisplayName ?? fit!.DisplayName;
        var groupName = "ACP - " + roleLabel + " (" + RbacProviders.DisplayName(card.Provider) + ")";

        var steps = draftChoice is null
            ? "1. Create security group '" + groupName + "'\n"
              + "2. Assign the EXISTING role '" + roleLabel + "' to that group\n"
              + "3. Fill the PIM group box with its ID"
            : "1. Create the custom role '" + roleLabel + "' with exactly "
              + draftChoice.AllowedResourceActions.Count + " permission(s)\n"
              + "2. Create security group '" + groupName + "'\n"
              + "3. Assign that role to the group\n"
              + "4. Fill the PIM group box with its ID";

        var confirm = MessageBox.Show(
            "This will:\n" + steps + "\n\n"
            + "The group onboards to PIM for Groups automatically at the first time-bound "
            + "membership grant. Proceed?",
            "Set up PIM group", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) return;

        SetupPimButton.IsEnabled = false;
        try
        {
            var executor = new RoleExecutor(GetGraph());

            // Create the role first when the recommendation is a custom one — the group has
            // nothing to carry otherwise.
            string roleId;
            if (draftChoice is not null)
            {
                Status("Creating custom role '" + roleLabel + "'...");
                roleId = await executor.CreateCustomRoleAsync(card.Provider, draftChoice);
                await VerifyAndLearnAsync(card.Provider, roleId,
                                          draftChoice.AllowedResourceActions);
            }
            else
            {
                roleId = fit!.RoleId;
            }

            Status("Creating security group...");
            var groupId = await executor.CreateSecurityGroupAsync(groupName,
                "AccessCheck PIM grant group for role '" + roleLabel + "'.");

            Status("Attaching role to group...");
            RoleExecutor.IntuneAssignmentScope? setupScope = null;
            if (card.Provider == RbacProviders.Intune)
            {
                setupScope = await ChooseIntuneScopeAsync(roleLabel);
                if (setupScope is null) { Status("Cancelled at scope selection."); return; }
            }
            await executor.AssignMultiAsync(card.Provider, groupId, roleId,
                "AccessCheck PIM group pre-staging for '" + roleLabel + "'", setupScope);
            PimGroupBox.Text = groupId;
            Status("PIM group ready (" + groupName + ") — grants will now use time-bound membership.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "PIM group setup failed",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Status("PIM group setup failed.");
        }
        finally { SetupPimButton.IsEnabled = true; }
    }

    private void ManualAction_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (ActionSuggestList is null || _catalog is null) return;
        var q = ManualActionBox.Text.Trim();
        if (q.Length < 2)
        {
            ActionSuggestList.Visibility = Visibility.Collapsed;
            return;
        }
        var matches = _catalog.Roles
            .SelectMany(r => r.AllowedResourceActions)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(a => a.Contains(q, StringComparison.OrdinalIgnoreCase))
            .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .ToList();
        ActionSuggestList.ItemsSource = matches;
        ActionSuggestList.Visibility =
            matches.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ActionSuggestList_MouseUp(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (ActionSuggestList.SelectedItem is string chosen)
        {
            ManualActionBox.TextChanged -= ManualAction_TextChanged;
            ManualActionBox.Text = chosen;
            ManualActionBox.TextChanged += ManualAction_TextChanged;
            ActionSuggestList.Visibility = Visibility.Collapsed;
        }
    }

    private async void AskAiAction_Click(object sender, RoutedEventArgs e)
    {
        if (_catalog is null) { Status("Sync the catalog first."); return; }
        if (UseDemoCheck.IsChecked == true ||
            SecretStore.Load(_config.Ai.ApiKeyName) is null)
        {
            Status("Ask AI needs a configured provider — set one in Settings and untick the demo box.");
            return;
        }

        var need = PromptForText(
            "Ask AI for permissions",
            "Describe what the person needs to do (plain language). The AI proposes " +
            "matching permissions from your synced catalog only.",
            ManualActionBox.Text);
        if (string.IsNullOrWhiteSpace(need)) return;

        Status("Asking AI for matching permissions...");
        try
        {
            _config = ReadConfigFromUi();
            var key = SecretStore.Load(_config.Ai.ApiKeyName)!;
            using var ai = AiProviderFactory.Create(BuildAiConfig(), key);
            ai.PromptLogger = (stage, prompt) =>
                File.AppendAllText(PromptLogPath,
                    "==== " + DateTimeOffset.UtcNow.ToString("o") + " [" + stage + "] ====" +
                    Environment.NewLine + prompt + Environment.NewLine);

            // Candidate pool: keyword-filtered catalog actions; fall back to a broad sample.
            var words = need.ToLowerInvariant()
                .Split(new[] { ' ', ',', '.', ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Where(w => w.Length > 3)
                .ToList();
            var all = _catalog.Roles
                .SelectMany(r => r.AllowedResourceActions)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var candidates = all
                .Where(a => words.Any(w => a.Contains(w, StringComparison.OrdinalIgnoreCase)))
                .Take(300)
                .ToList();
            if (candidates.Count == 0) candidates = all.Take(300).ToList();

            const string system =
                "You are a Microsoft 365 RBAC expert. From the CANDIDATE ACTIONS list, pick " +
                "the permissions that best match the described need — minimal set, most " +
                "specific first. You may ONLY return strings that appear verbatim in the " +
                "candidates. Return ONLY JSON: {\"actions\":[\"...\"]}. No prose, no fences.";
            var user = "NEED: " + need + "\nCANDIDATE ACTIONS:\n" +
                       string.Join("\n", candidates);
            var raw = await ai.CompleteAsync("find-actions", system, user);

            var proposed = new List<string>();
            using (var doc = System.Text.Json.JsonDocument.Parse(raw))
            {
                if (doc.RootElement.TryGetProperty("actions", out var arr) &&
                    arr.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    foreach (var el in arr.EnumerateArray())
                    {
                        var a = el.GetString();
                        if (!string.IsNullOrWhiteSpace(a) && _catalog.ActionExists(a) &&
                            !proposed.Contains(a, StringComparer.OrdinalIgnoreCase))
                            proposed.Add(a);
                    }
                }
            }
            Status("Ready.");
            if (proposed.Count == 0)
            {
                MessageBox.Show("The AI found no catalog permissions matching that description.",
                    "No matches", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            var chosen = PickFromList(
                "AI-proposed permissions for: " + need + "  (validated against your catalog)",
                proposed);
            if (chosen is not null)
            {
                ManualActionBox.TextChanged -= ManualAction_TextChanged;
                ManualActionBox.Text = chosen;
                ManualActionBox.TextChanged += ManualAction_TextChanged;
                ActionSuggestList.Visibility = Visibility.Collapsed;
                Status("Selected '" + chosen + "' — click Add & re-validate to include it.");
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Ask AI failed", MessageBoxButton.OK, MessageBoxImage.Error);
            Status("Ask AI failed.");
        }
    }

    // ---------------- PIM policy pre-flight ----------------

    /// <summary>
    /// Checks the requested duration against the role's PIM policy BEFORE submitting.
    /// Returns the duration to actually use (possibly clamped), or null to abort.
    /// A policy that requires expiry rejects "never" with
    /// 400 RoleAssignmentRequestPolicyValidationFailed ["ExpirationRule"].
    /// </summary>
    private async Task<(bool Permanent, string Iso, TimeSpan Span)?> PreflightDirectoryPolicyAsync(
        string roleDefinitionId, string roleDisplayName, bool eligible,
        bool permanent, string iso, TimeSpan span)
    {
        RolePolicyLimits limits;
        try
        {
            Status("Checking PIM policy for '" + roleDisplayName + "'...");
            limits = await new PolicyReader(GetGraph())
                .GetDirectoryLimitsAsync(roleDefinitionId, eligible);
        }
        catch (Exception ex)
        {
            limits = RolePolicyLimits.UnknownLimits(ex.Message);
        }
        Status("Ready.");

        if (limits.Unknown) return (permanent, iso, span); // can't check — let Graph decide

        // 1. Permanent requested but the policy requires an expiry.
        if (permanent && !limits.PermanentAllowed)
        {
            var max = limits.MaximumDuration ?? "P180D";
            var maxSpan = limits.MaximumSpan ?? TimeSpan.FromDays(180);
            var answer = MessageBox.Show(
                "The PIM policy for '" + roleDisplayName + "' does NOT allow permanent " +
                (eligible ? "eligibility" : "assignment") + ".\n\n" +
                "Submitting 'never' would fail with:\n" +
                "  400 RoleAssignmentRequestPolicyValidationFailed [\"ExpirationRule\"]\n\n" +
                "The policy's maximum is " + max + ".\n\n" +
                "Use " + max + " instead?\n" +
                "(Choose No to cancel and either pick a shorter duration, or raise the limit in " +
                "Entra → PIM → Microsoft Entra roles → Settings for this role.)",
                "PIM policy forbids permanent access",
                MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (answer != MessageBoxResult.Yes) return null;
            return (false, max, maxSpan);
        }

        // 2. Duration exceeds the policy maximum.
        if (!permanent && limits.MaximumSpan is TimeSpan cap && span > cap)
        {
            var max = limits.MaximumDuration!;
            var answer = MessageBox.Show(
                "The requested duration (" + iso + ") exceeds the PIM policy maximum for '" +
                roleDisplayName + "', which is " + max + ".\n\n" +
                "Submitting it would fail with:\n" +
                "  400 RoleAssignmentRequestPolicyValidationFailed [\"ExpirationRule\"]\n\n" +
                "Use the policy maximum (" + max + ") instead?",
                "Duration exceeds PIM policy",
                MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (answer != MessageBoxResult.Yes) return null;
            return (false, max, cap);
        }

        return (permanent, iso, span);
    }

    /// <summary>Turns PIM's opaque policy rejection into something actionable.</summary>
    /// <summary>
    /// Reads back a role we just created and teaches the catalog from the result.
    ///
    /// Creating a role returning success is an ATTEMPT; reading it back is the RESULT —
    /// and the tenant accepting an action is stronger evidence that the action exists here
    /// than any catalog snapshot or documentation. So a permission the catalog could not
    /// confirm, attempted anyway and then read back, becomes PROVEN and stops being
    /// doubted next time. Anything the tenant silently dropped is reported, because that
    /// is the honest answer to "does this permission exist in my tenant".
    /// </summary>
    /// <summary>Ledgers from the most recent approval, one per service.</summary>
    private readonly List<GrantLedger> _lastLedgers = new();

    /// <summary>
    /// Create the role, then READ IT BACK before anything else is attempted.
    ///
    /// Creation returning an id is an ATTEMPT. If the role is not actually there with the
    /// actions requested, the group and assignment steps that follow would build on
    /// nothing — and the failure would surface two steps later, pointing at the wrong thing.
    /// </summary>
    private async Task<string> CreateAndVerifyRoleAsync(
        GrantLedger ledger, RoleExecutor executor, string provider, CustomRoleDraft draft)
    {
        var step = ledger.Begin("Create custom role '" + draft.DisplayName + "'");
        Status("Creating custom role in " + provider + "...");

        string roleId;
        try
        {
            roleId = await executor.CreateCustomRoleAsync(provider, draft);
            step.State = GrantLedger.StepState.Succeeded;
            step.Artifact = "role '" + draft.DisplayName + "' (" + provider + ")";
        }
        catch (Exception ex)
        {
            step.State = GrantLedger.StepState.Failed;
            step.Detail = Trim(ex.Message);
            throw;   // nothing was created; the caller reports with the ledger attached
        }

        var check = ledger.Begin("Verify the role exists and carries "
                                 + draft.AllowedResourceActions.Count + " action(s)");
        try
        {
            Status("Verifying the role...");
            var verifier = new GrantVerification(GetGraph());
            var result = await verifier.VerifyRoleAsync(
                provider, roleId, draft.AllowedResourceActions);

            check.State = result.Confirmed
                ? GrantLedger.StepState.Verified
                : GrantLedger.StepState.Failed;
            check.Detail = result.Detail;

            if (result.ProvenActions.Count > 0 && _catalog is not null)
            {
                var learned = _catalog.RecordProvenActions(provider, result.ProvenActions);
                if (learned > 0)
                {
                    try { _catalog.Save(CatalogPath); } catch (Exception) { }
                }
            }

            if (!result.Confirmed)
            {
                throw new InvalidOperationException(
                    "The role was created but did not verify: " + result.Detail);
            }
        }
        catch (InvalidOperationException) { throw; }
        catch (Exception ex)
        {
            // Verification is a READ. It failing does not mean the grant failed, so record
            // and continue rather than abandoning a role that may be perfectly good.
            check.State = GrantLedger.StepState.Succeeded;
            check.Detail = "could not verify: " + Trim(ex.Message);
        }

        return roleId;
    }

    /// <summary>
    /// Assign the role, then CONFIRM the principal actually holds it.
    ///
    /// A 200 from the assignment call is not the same as the principal having the role —
    /// PIM in particular accepts a request that is still pending. Recording the difference
    /// is what stops "granted" appearing next to access nobody has yet.
    /// </summary>
    private async Task AssignAndVerifyAsync(
        GrantLedger ledger, RoleExecutor executor, string provider,
        string principalId, string roleId, string justification,
        RoleExecutor.IntuneAssignmentScope? scope)
    {
        var step = ledger.Begin("Assign the role to the principal");
        try
        {
            await executor.AssignMultiAsync(provider, principalId, roleId, justification, scope);
            step.State = GrantLedger.StepState.Succeeded;
            step.Artifact = "assignment (" + RbacProviders.DisplayName(provider) + ")";
        }
        catch (Exception ex)
        {
            step.State = GrantLedger.StepState.Failed;
            step.Detail = Trim(ex.Message);
            throw;
        }

        var check = ledger.Begin("Confirm the principal now holds the role");
        try
        {
            var holds = await executor.DoesPrincipalHoldRoleAsync(provider, principalId, roleId);
            check.State = holds ? GrantLedger.StepState.Verified : GrantLedger.StepState.Succeeded;
            check.Detail = holds
                ? null
                : "submitted but not yet held — normal while a PIM request is pending or "
                  + "awaiting approval; check PIM > Pending requests";
        }
        catch (Exception ex)
        {
            check.State = GrantLedger.StepState.Succeeded;
            check.Detail = "could not confirm: " + Trim(ex.Message);
        }
    }

    private async Task VerifyAndLearnAsync(
        string provider, string roleId, IReadOnlyList<string> requestedActions)
    {
        if (_catalog is null || string.IsNullOrWhiteSpace(roleId)) return;

        try
        {
            Status("Verifying the role was created as requested...");
            var verifier = new GrantVerification(GetGraph());
            var result = await verifier.VerifyRoleAsync(provider, roleId, requestedActions);

            if (result.ProvenActions.Count > 0)
            {
                var learned = _catalog.RecordProvenActions(provider, result.ProvenActions);
                if (learned > 0)
                {
                    try { _catalog.Save(CatalogPath); } catch (Exception) { /* cache only */ }
                    _lastSyncReport.Add("Learned " + learned + " permission(s) for "
                        + RbacProviders.DisplayName(provider)
                        + " from a successful grant — the tenant accepted them, so they are "
                        + "no longer treated as unverified.");
                }
            }

            Status(result.Confirmed
                ? "Verified: " + result.Detail
                : "NOT fully verified — " + result.Detail);

            if (!result.Confirmed)
            {
                MessageBox.Show(result.Detail, "Grant verification",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            // Verification is a read. It must never undo or obscure a grant that worked.
            Status("Grant completed; verification could not run: " + Trim(ex.Message));
        }
    }

    /// <summary>
    /// Learns from a refusal and explains the route that DOES work.
    ///
    /// "Action 'X' is not supported for Custom Role creation" means X is real and granted
    /// by built-in roles but cannot go in a custom one. Recording it means the app never
    /// proposes that custom role again — the tenant should only have to refuse once.
    /// </summary>
    private string ExplainCustomRoleRefusal(string message)
    {
        var refused = CustomRoleEligibility.ParseRefusedAction(message);
        if (refused is null) return message;

        if (_ineligibility.RecordIneligible(refused))
        {
            try { _ineligibility.Save(IneligibilityPath); } catch (Exception) { /* cache */ }
        }

        // Which built-in roles DO grant it? That is the actionable part.
        var granting = _catalog is null
            ? new List<string>()
            : _catalog.Roles
                .Where(r => r.AllowedResourceActions.Contains(refused, StringComparer.OrdinalIgnoreCase))
                .Select(r => r.DisplayName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(6)
                .ToList();

        return "'" + refused + "' cannot go in a CUSTOM role."
             + Environment.NewLine + Environment.NewLine
             + "Microsoft allows only a subset of directory actions in custom roles. This one "
             + "is real, and built-in roles grant it, but custom role creation refuses it. "
             + "Nothing was created."
             + Environment.NewLine + Environment.NewLine
             + (granting.Count > 0
                ? "Built-in roles in your tenant that DO grant it:" + Environment.NewLine
                  + "  " + string.Join(Environment.NewLine + "  ", granting)
                  + Environment.NewLine + Environment.NewLine
                  + "Re-run and choose one of those instead — the dropdown will now offer them, "
                  + "because this refusal has been recorded and a custom role will no longer be "
                  + "proposed for it."
                : "Re-run to see which built-in roles cover it. This refusal has been recorded, "
                  + "so a custom role will no longer be proposed for this action.")
             + Environment.NewLine + Environment.NewLine
             + "Original error: " + message;
    }

    /// <summary>
    /// First value that is neither null NOR blank. `??` alone is not enough here: an empty
    /// string is a perfectly good non-null value and will stop the chain, which is how an
    /// empty role-group name reached Exchange.
    /// </summary>
    /// <summary>
    /// Replaces a wrongly-chosen permission with the one that matches, then re-validates.
    /// The guard names the better candidate; this saves retyping it.
    /// </summary>
    private void SwapPermission_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button b || b.Tag is not string[] pair || pair.Length != 2) return;

        var (wrong, right) = (pair[0], pair[1]);

        _manualActions.RemoveAll(a => a.Equals(wrong, StringComparison.OrdinalIgnoreCase));
        if (!_manualActions.Contains(right, StringComparer.OrdinalIgnoreCase))
            _manualActions.Add(right);

        _removedActions.Add(wrong);

        Status("Swapped " + ActionDisplay.Short(wrong) + " for "
               + ActionDisplay.Short(right) + " — re-validating.");
        RunValidation();
    }

    /// <summary>
    /// A fixed-size, SCROLLABLE review of an emitted script.
    ///
    /// The plain MessageBox sized itself to its content, and a derived Exchange role strips
    /// hundreds of cmdlets — so the window grew past the bottom of the screen and the
    /// Yes/No buttons became unreachable. Here the script scrolls inside a fixed window and
    /// the buttons are always visible.
    /// </summary>
    private bool ShowScriptReview(string header, string script)
    {
        var win = new Window
        {
            Title = "Review PowerShell",
            Width = 820,
            Height = 560,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = this,
            ResizeMode = ResizeMode.CanResize,
            ShowInTaskbar = false
        };

        var grid = new Grid { Margin = new Thickness(14) };
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var head = new TextBlock
        {
            Text = header,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 10),
            FontWeight = FontWeights.SemiBold
        };
        Grid.SetRow(head, 0);
        grid.Children.Add(head);

        // The script: monospace, read-only, selectable so it can be copied, and scrolling
        // both ways rather than forcing the window to grow.
        var box = new TextBox
        {
            Text = script,
            IsReadOnly = true,
            FontFamily = new System.Windows.Media.FontFamily("Consolas, Courier New, monospace"),
            FontSize = 12,
            TextWrapping = TextWrapping.NoWrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            AcceptsReturn = true,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(8)
        };
        Grid.SetRow(box, 1);
        grid.Children.Add(box);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 12, 0, 0)
        };

        var result = false;

        var copy = new Button
        {
            Content = "Copy",
            MinWidth = 90,
            Margin = new Thickness(0, 0, 8, 0),
            Padding = new Thickness(10, 4, 10, 4)
        };
        copy.Click += (_, _) =>
        {
            try { Clipboard.SetText(script); Status("Script copied to clipboard."); }
            catch (Exception) { /* clipboard can transiently fail; not worth interrupting */ }
        };

        var run = new Button
        {
            Content = "Run this script",
            MinWidth = 130,
            Margin = new Thickness(0, 0, 8, 0),
            Padding = new Thickness(10, 4, 10, 4),
            IsDefault = true
        };
        run.Click += (_, _) => { result = true; win.Close(); };

        var cancel = new Button
        {
            Content = "Cancel",
            MinWidth = 90,
            Padding = new Thickness(10, 4, 10, 4),
            IsCancel = true
        };
        cancel.Click += (_, _) => { result = false; win.Close(); };

        buttons.Children.Add(copy);
        buttons.Children.Add(run);
        buttons.Children.Add(cancel);
        Grid.SetRow(buttons, 2);
        grid.Children.Add(buttons);

        win.Content = grid;
        win.ShowDialog();
        return result;
    }

    private static string FirstNonBlank(params string?[] candidates)
    {
        foreach (var c in candidates)
            if (!string.IsNullOrWhiteSpace(c)) return c!;
        return "";
    }

    private string ExplainGrantFailure(Exception ex)
    {
        var msg = ex.Message;

        if (msg.Contains("not supported for Custom Role creation", StringComparison.OrdinalIgnoreCase))
            return ExplainCustomRoleRefusal(msg);

        // A role created moments ago may not be visible to PIM yet — directory replication,
        // not a missing role. Retrying after a pause usually succeeds.
        if (msg.Contains("RoleNotFound", StringComparison.OrdinalIgnoreCase))
        {
            return "The role was not found when the assignment was filed."
                 + Environment.NewLine + Environment.NewLine
                 + "If the role was created seconds earlier, this is almost always DIRECTORY "
                 + "REPLICATION rather than a missing role — PIM has not seen it yet. Wait a "
                 + "minute and re-run; the app reuses an existing role rather than creating a "
                 + "second one."
                 + Environment.NewLine + Environment.NewLine
                 + "If it persists, check Entra > Roles & admins for the role by name."
                 + Environment.NewLine + Environment.NewLine + "Original error: " + msg;
        }

        // A pending request is NOT a rejection, and reading it as one leads to exactly the
        // wrong next move: retrying, which fails identically. Entra refuses a second
        // request while one is outstanding.
        if (msg.Contains("PendingRoleAssignmentRequest", StringComparison.OrdinalIgnoreCase))
        {
            return "A request for this principal and role is ALREADY PENDING in PIM."
                 + Environment.NewLine + Environment.NewLine
                 + "This usually means an earlier submission is still being processed, or it "
                 + "is waiting on approval because the role's PIM policy requires one. It is "
                 + "not a rejection, and retrying will fail the same way."
                 + Environment.NewLine + Environment.NewLine
                 + "What to check: Entra admin center > Identity Governance > Privileged "
                 + "Identity Management > Microsoft Entra roles > Pending requests."
                 + Environment.NewLine
                 + "  * If the earlier request already grants what you wanted, nothing "
                 + "further is needed." + Environment.NewLine
                 + "  * Cancel it there first if you want to submit different terms."
                 + Environment.NewLine + Environment.NewLine
                 + "Original error: " + msg;
        }

        if (msg.Contains("RoleAssignmentExists", StringComparison.OrdinalIgnoreCase))
        {
            return "This principal ALREADY HOLDS this role — nothing was changed."
                 + Environment.NewLine + Environment.NewLine
                 + "Run Access Review on them to see the existing assignment and its expiry."
                 + Environment.NewLine + Environment.NewLine + "Original error: " + msg;
        }

        if (msg.Contains("SubjectNotFound", StringComparison.OrdinalIgnoreCase))
        {
            return "The principal could not be found. For a newly created user or group, "
                 + "directory replication can take a few minutes."
                 + Environment.NewLine + Environment.NewLine + "Original error: " + msg;
        }

        if (!msg.Contains("RoleAssignmentRequestPolicyValidationFailed", StringComparison.OrdinalIgnoreCase))
            return msg;

        var detail = msg.Contains("ExpirationRule", StringComparison.OrdinalIgnoreCase)
            ? "The ExpirationRule failed: the role's PIM policy either forbids permanent " +
              "assignments or caps the duration below what was requested."
            : msg.Contains("Enablement", StringComparison.OrdinalIgnoreCase)
                ? "An Enablement rule failed: the policy requires something the request " +
                  "didn't supply (typically MFA, justification, or ticket information)."
                : msg.Contains("Approval", StringComparison.OrdinalIgnoreCase)
                    ? "An Approval rule failed: this role requires approval, so the request " +
                      "must go through the PIM approval workflow rather than a direct assign."
                    : "A PIM role management policy rule rejected the request.";

        return detail + Environment.NewLine + Environment.NewLine +
               "Fix it either way:" + Environment.NewLine +
               "  • Adjust the request (shorter duration, or not permanent), or" + Environment.NewLine +
               "  • Change the rule in Entra → Identity Governance → PIM → Microsoft Entra roles" +
               Environment.NewLine + "    → Settings → the role in question." +
               Environment.NewLine + Environment.NewLine +
               "Raw error: " + msg;
    }

    // ---------------- execute ----------------

    private async void Execute_Click(object sender, RoutedEventArgs e)
    {
        if (_lastSuggestion is null || _catalog is null) return;
        var principal = PrincipalBox.Text.Trim();
        var principalUpn = UpnBox.Text.Trim();
        var spec = GetDurationOrWarn();
        if (spec is null) return;
        var permanent = spec.Permanent;
        var duration = permanent ? "" : spec.Iso;
        var durationSpan = spec.Approx;
        var eligible = EligibleRadio.IsChecked == true;
        var groupDirectMode = GroupDirectRadio.IsChecked == true;
        var pimGroupRaw = PimGroupBox.Text.Trim();
        var pimGroupResolved = await ResolvePimGroupAsync(pimGroupRaw);
        if (pimGroupResolved is null) return; // could not resolve — message already shown
        var pimGroup = pimGroupResolved;

        var selected = _cards
            .Where(c => c.Include.IsChecked == true && c.Options.Count > 0)
            .ToList();
        // Group-only path: no role cards ticked, but a group is chosen — the user is simply
        // added to a group that already carries the right roles.
        if (selected.Count == 0 && pimGroup.Length > 0)
        {
            await ExecuteGroupOnlyAsync(principal, pimGroup, groupDirectMode,
                permanent, duration, durationSpan);
            return;
        }
        if (selected.Count == 0) { Status("No grants selected."); return; }

        bool anyGraph = selected.Any(c => !RbacProviders.DerivedRoleCapable.Contains(c.Provider));
        bool anyPs = selected.Any(c => RbacProviders.DerivedRoleCapable.Contains(c.Provider));
        if (anyGraph && principal.Length == 0)
        {
            Status("Enter the principal object ID (Graph grants).");
            return;
        }
        if (anyPs && principalUpn.Length == 0)
        {
            Status("Enter the principal UPN (Exchange/Purview grants).");
            return;
        }

        // Statement of exactly what will happen — this text IS the approval.
        // PRE-FLIGHT EVERY SERVICE BEFORE CREATING ANYTHING.
        //
        // Creating the Intune role and then failing on Entra left a real role in the tenant
        // with no assignment and an error dialog implying nothing worked. Whatever can be
        // known in advance must be checked in advance.
        // A permission that cannot perform the requested operation must never reach
        // execution, however real it is.
        foreach (var c0 in selected)
        {
            var bad0 = c0.Outcome.Contradicted;
            if (bad0.Count == 0) continue;
            MessageBox.Show(
                RbacProviders.DisplayName(c0.Provider) + ": "
                + string.Join(Environment.NewLine + Environment.NewLine,
                              bad0.Select(b => ActionDisplay.Short(b.Action) + " — " + b.Reason))
                + Environment.NewLine + Environment.NewLine
                + "Nothing was changed. Restate the task, or add the permission that performs "
                + "the operation, then re-analyze.",
                "Permission cannot do what was asked",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        var blocked = new List<string>();
        foreach (var c in selected)
        {
            var acts = c.Outcome.ValidActions;
            var refused = acts.Where(a => _ineligibility.IsIneligible(a)).ToList();
            if (refused.Count == 0) continue;

            var choiceForCheck = c.Options.Count > 0
                ? c.Options[Math.Max(0, c.Choice.SelectedIndex)] : null;
            if (choiceForCheck is CustomRoleDraft)
            {
                blocked.Add(RbacProviders.DisplayName(c.Provider) + ": "
                    + string.Join(", ", refused.Select(ActionDisplay.Short))
                    + " cannot go in a custom role — pick a built-in role on that card.");
            }
        }

        if (blocked.Count > 0)
        {
            MessageBox.Show(
                "Nothing has been created yet. These grants would fail:"
                + Environment.NewLine + Environment.NewLine
                + "  " + string.Join(Environment.NewLine + "  ", blocked)
                + Environment.NewLine + Environment.NewLine
                + "Change those cards to a built-in role and approve again.",
                "Blocked before creating anything",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var planLines = new List<string>();
        foreach (var c in selected)
        {
            var choice = c.Options[Math.Max(0, c.Choice.SelectedIndex)];
            var label = choice is CustomRoleDraft d
                ? (d.ParentRoleName is null
                    ? "create custom role '" + d.DisplayName + "' (" +
                      d.AllowedResourceActions.Count + " exact actions)"
                    : "derive role '" + d.DisplayName + "' from '" + d.ParentRoleName +
                      "' (strip " + (d.EntriesToRemove?.Count ?? 0) + ", keep " +
                      d.AllowedResourceActions.Count + ")")
                : choice is RoleGroupPlan p
                    ? "role group '" + p.RoleGroupName + "' carrying " + p.Roles.Count
                      + " role(s): " + string.Join(", ", p.Roles.Select(r => r.Summary))
                    : choice is RoleFit rf
                        ? "use role '" + rf.DisplayName + "' (" + rf.ExcessLabel + ")"
                        // A hard cast here threw InvalidCastException the moment a plan
                        // became selectable. Pattern-match every case the combo can hold.
                        : "the selected option";
            var scopeNote = c.Provider == RbacProviders.Directory && _directoryScopeId != "/"
                ? " [scoped to " + ScopeDisplay.Text + "]" : "";
            var mech = c.Provider == RbacProviders.Directory
                ? (eligible
                    ? "PIM ELIGIBLE (self-activate)" + (permanent ? ", NO EXPIRY" : ", expires " + duration)
                    : permanent ? "PIM ACTIVE, NO EXPIRY" : "PIM ACTIVE afterDuration " + duration)
                : RbacProviders.DerivedRoleCapable.Contains(c.Provider)
                    ? "PowerShell role-group grant to " + principalUpn +
                      (permanent ? ", NO EXPIRY (never auto-removed)" : ", app-tracked expiry " + duration)
                    : pimGroup.Length > 0
                        ? (groupDirectMode
                            ? "DIRECT membership of group " + pimGroup +
                              (permanent ? ", NO EXPIRY (never auto-removed)"
                                         : ", app-tracked expiry " + duration + " (Housekeeping removes)")
                            : "PIM-for-Groups membership in " + pimGroup +
                              (permanent ? ", NO EXPIRY" : " afterDuration " + duration))
                        : "DIRECT assignment" +
                          (permanent ? ", NO EXPIRY (never auto-removed)"
                                     : ", app-tracked expiry " + duration + " (housekeeping removes)");
            planLines.Add(RbacProviders.DisplayName(c.Provider) + ": " + label +
                          " -> " + mech + scopeNote);
        }

        var permanentWarning = permanent
            ? "\n\nPERMANENT GRANT — this access will NEVER expire automatically.\n" +
              "Nothing will remove it: not PIM, not Housekeeping. It stays until someone\n" +
              "revokes it by hand. This is recorded as a permanent grant in the audit history.\n"
            : "";
        var confirm = MessageBox.Show(
            (anyGraph ? "Principal (Graph): " + principal + "\n" : "") +
            (anyPs ? "Principal (PS): " + principalUpn + "\n" : "") +
            "\n" + string.Join("\n", planLines) + permanentWarning + "\n\nExecute these grants?",
            permanent ? "Approve PERMANENT grants" : "Approve grants",
            MessageBoxButton.YesNo,
            permanent ? MessageBoxImage.Warning : MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) { Status("Cancelled — nothing executed."); return; }

        ExecuteButton.IsEnabled = false;
        var store = new RequestHistoryStore(HistoryPath);
        try
        {
            RoleExecutor? graphExecutor = null;
            var failures = new List<string>();
            var successes = new List<string>();
            foreach (var c in selected)
            {
                // ONE SERVICE FAILING MUST NOT ABORT THE REST. Intune's role was created,
                // Entra threw, and the whole batch stopped — leaving a real role in the
                // tenant with no assignment and a dialog implying nothing had worked.
                // A LEDGER PER SERVICE. Each step verifies before the next begins, so a
                // failure can say exactly what exists now rather than leaving the operator
                // to work it out from the portal.
                var ledger = new GrantLedger { Provider = c.Provider };
                _lastLedgers.Add(ledger);

                // DECLARED OUTSIDE THE TRY. The catch block writes a failure record with it,
                // and a variable declared inside a try is not in scope in its catch — so
                // isolating per-service failures broke the build until this moved out.
                var record = RequestRecordBuilder
                    .FromOutcome(_lastFunction, _lastSuggestion, c.Outcome, _lastPromptSha,
                                 _manualActions.ToList())
                    with { Provider = c.Provider };

                try
                {
                    var choice = c.Options[Math.Max(0, c.Choice.SelectedIndex)];
                    var justification = "AccessCheck least-privilege grant: " + _lastFunction;
    
                    if (RbacProviders.DerivedRoleCapable.Contains(c.Provider))
                    {
                        // ---- Exchange / Purview via PowerShell ----
                        var scope = c.Provider == RbacProviders.Exchange
                            ? RbacScope.Exchange : RbacScope.Purview;
                        var (runner, env, adminUpn) = GetPs();
                        var psExec = new ExoPurviewExecutor(runner, env, adminUpn);
    
                        CustomRoleDraft? draft = choice as CustomRoleDraft;
    
                        // The choice can now BE the plan. A one-role plan still needs a covering
                        // role name for the single-parent path, or it would build a script that
                        // grants nothing.
                        var chosenPlan = choice as RoleGroupPlan;

                        // `??` only falls through on NULL, and ParentRoleName is an empty
                        // STRING when there is no parent — so the chain stopped there and
                        // handed an empty name downstream, which Exchange rejected with
                        // "The property DisplayName can't be empty."
                        var covering = FirstNonBlank(
                            draft?.ParentRoleName,
                            (choice as RoleFit)?.DisplayName,
                            chosenPlan?.Roles.FirstOrDefault()?.RoleName,
                            draft?.DisplayName);
    
                        // A plan spanning MORE THAN ONE role cannot be executed as a single
                        // derivation. Search-and-purge needs Compliance Search for the search
                        // and Search And Purge for the -Purge switch; running the single-parent
                        // path would have granted the search and silently dropped the purge.
                        var plan = c.Outcome.RoleGroupPlan;
                        var multiRole = plan is { IsComplete: true, Roles.Count: > 1 };
    
                        psExec.Capabilities = _cmdletCapabilities;
    
                        // Refuse BEFORE the script is shown, not halfway through it. Every
                        // Exchange-vs-SCC surprise so far surfaced as a mid-script failure with
                        // a partial grant behind it.
                        var needed = multiRole
                            ? new[] { "New-RoleGroup", "Get-RoleGroup", "Add-RoleGroupMember" }
                            : new[] { "New-RoleGroup", "Get-RoleGroup", "Add-RoleGroupMember" };
                        var missing = psExec.MissingCmdlets(scope, needed);
                        if (missing.Count > 0)
                        {
                            MessageBox.Show(
                                RbacProviders.DisplayName(c.Provider) + " does not have: "
                                + string.Join(", ", missing)
                                + "\n\nThese were probed during the last catalog sync and are not "
                                + "present at that endpoint, so this grant cannot run. Nothing was "
                                + "changed.",
                                "Cmdlet not available", MessageBoxButton.OK, MessageBoxImage.Warning);
                            store.Append(record with
                            {
                                PrincipalId = principalUpn,
                                Notes = "Blocked: endpoint lacks " + string.Join(", ", missing)
                            });
                            continue;
                        }
    
                        // Record what actually resolved, so a blank one is visible in the
                        // History row rather than having to be inferred from the service's
                        // complaint two layers down.
                        record = record with
                        {
                            Notes = (record.Notes ?? "")
                                + "[names: choice=" + choice.GetType().Name
                                + "; covering='" + covering
                                + "'; draft='" + (draft?.DisplayName ?? "-")
                                + "'; plan=" + (plan is null ? "-" : plan.Roles.Count + " role(s)")
                                + "] "
                        };

                        // Honour the operator's chosen object name. The AC-/ACG- prefixes are
                        // still applied by the builder; this replaces the auto-generated stem.
                        var chosenName = GrantNameBox?.Text?.Trim();
                        if (!string.IsNullOrWhiteSpace(chosenName))
                        {
                            if (draft is not null)
                                draft = draft with { DisplayName = "AC - " + chosenName };
                        }

                        var script = multiRole
                            ? psExec.BuildMultiRoleGrantScript(scope, plan!, principalUpn, justification,
                                                               chosenName)
                            : psExec.BuildGrantScript(scope, draft, covering, principalUpn, justification,
                                                      chosenName);
    
                        if (multiRole)
                        {
                            Status("Multi-role plan: " + plan!.Roles.Count
                                   + " roles will be carried by one role group.");
                        }
    
                        var scriptOk = ShowScriptReview(
                            "This exact script will run against "
                            + RbacProviders.DisplayName(c.Provider) + ":",
                            script)
                            ? MessageBoxResult.Yes : MessageBoxResult.No;
                        if (scriptOk != MessageBoxResult.Yes)
                        {
                            store.Append(record with
                            {
                                PrincipalId = principalUpn,
                                Notes = "Declined at script review."
                            });
                            continue;
                        }
    
                        Status("Running PowerShell grant (" + c.Provider + ") — sign in if prompted...");
                        using var resultDoc = await psExec.RunAsync(script);
                        var groupName = resultDoc.RootElement.TryGetProperty("roleGroup", out var g)
                            ? g.GetString() : null;
                        // BOTH PATHS REPORT WHAT THE TENANT ACTUALLY CARRIES.
                        //
                        // The single-role script used to echo back the role it was ASKED to
                        // grant; it now reads the group and returns what is really in it, the
                        // same as the multi-role path. Reading "roles" only when multiRole left
                        // single-role grants with a null role name in the audit record — an
                        // approved, executed Exchange grant whose record could not say which
                        // role was involved.
                        var landed = new List<string>();
                        if (resultDoc.RootElement.TryGetProperty("roles", out var rolesEl)
                            && rolesEl.ValueKind == System.Text.Json.JsonValueKind.Array)
                        {
                            landed = rolesEl.EnumerateArray()
                                .Select(e => e.GetString() ?? "")
                                .Where(x => x.Length > 0).ToList();
                        }
                        var roleName = landed.Count > 0
                            ? string.Join(" + ", landed)
                            // Fallback for an older script shape, so a mid-upgrade run still
                            // records something rather than silently nothing.
                            : (resultDoc.RootElement.TryGetProperty("role", out var rn)
                                ? rn.GetString() : null);
    
                        if (multiRole && landed.Count > 0)
                        {
                            var wanted = plan!.Roles.Count;
                            Status("Role group '" + groupName + "' carries " + landed.Count
                                   + " of " + wanted + " planned role(s).");
    
                            if (landed.Count < wanted)
                            {
                                MessageBox.Show(
                                    "The role group was created but carries only " + landed.Count
                                    + " of the " + wanted + " roles the plan needed.\n\n"
                                    + "Carrying: " + string.Join(", ", landed)
                                    + "\n\nThe missing role(s) were not accepted by the service, so "
                                    + "part of the task will not work. Check the role names exist "
                                    + "in " + RbacProviders.DisplayName(c.Provider) + ".",
                                    "Partial grant", MessageBoxButton.OK, MessageBoxImage.Warning);
                            }
                            else if (_catalog is not null)
                            {
                                // The tenant accepted every role — the permissions behind them
                                // are proven to exist here.
                                var proven = plan.Roles.SelectMany(r => r.Covers).Distinct().ToList();
                                var learned = _catalog.RecordProvenActions(c.Provider, proven);
                                if (learned > 0)
                                {
                                    try { _catalog.Save(CatalogPath); } catch (Exception) { }
                                    _lastSyncReport.Add("Learned " + learned + " "
                                        + RbacProviders.DisplayName(c.Provider)
                                        + " permission(s) proven by this grant.");
                                }
                            }
                        }
                        DateTimeOffset? expires = permanent
                            ? null : DateTimeOffset.UtcNow + durationSpan;
                        store.Append(record with
                        {
                            PrincipalId = principalUpn,
                            Approved = true, ApprovedBy = Environment.UserName,
                            ApprovedUtc = DateTimeOffset.UtcNow,
                            AssignmentTypeUsed = "PsRoleGroup",
                            Duration = permanent ? "PERMANENT" : duration,
                            PermanentGrant = permanent,
                            ChosenRoleId = roleName, ChosenRoleDisplay = roleName,
                            CustomRoleCreated = draft is not null,
                            GroupIdUsed = groupName, TrackedExpiryUtc = expires,
                            // THE DEDICATED FIELDS, POPULATED AT LAST. Both existed from the
                            // start and were never written, so every Exchange and Purview
                            // record carried its role group in GroupIdUsed — a field named for
                            // Entra groups — and its role name only in ChosenRoleDisplay.
                            // Anything reading history for "what did we create in Exchange"
                            // had to parse prose. Housekeeping and grant reuse both need this
                            // structured.
                            ExoRoleGroup = groupName,
                            ExoRoleName = roleName
                        });
                        continue;
                    }
    
                    // ---- Graph providers ----
                    graphExecutor ??= new RoleExecutor(GetGraph());
                    string roleId;
                    bool createdCustom = false;
                    if (choice is CustomRoleDraft graphDraft)
                    {
                        // Reuse before creating: an equivalent role may already exist from an
                        // earlier run, and duplicating it just multiplies what has to be governed.
                        RoleDefinitionRecord? existingRole = _catalog is null
                            ? null
                            : RoleExecutor.FindEquivalentRole(_catalog, c.Provider, graphDraft);
                        if (existingRole is not null &&
                            _staleRoleIdsIgnored.Contains(existingRole.Id))
                            existingRole = null;   // already proven dead this session
    
                        // A matched role that Intune cannot see (or that no longer exists) is
                        // simply not a reuse candidate. Ignore it and create a fresh one — the
                        // catalog LIST endpoint can still return roles that GET-by-id 404s, so
                        // aborting here would loop forever on the same phantom entry.
                        if (existingRole is not null && c.Provider == RbacProviders.Intune)
                        {
                            var matchState = await graphExecutor.GetIntuneRoleStateAsync(existingRole.Id);
                            if (matchState != RoleExecutor.IntuneRoleState.Usable)
                            {
                                Status("Ignoring stale catalog match '" + existingRole.DisplayName +
                                       "' (" + matchState + ") — creating a fresh role instead.");
                                _staleRoleIdsIgnored.Add(existingRole.Id);
                                existingRole = null;
                            }
                        }
    
                        if (existingRole is not null)
                        {
                            var reuse = MessageBox.Show(
                                "A role that already grants this exact permission set exists:" +
                                Environment.NewLine + Environment.NewLine +
                                "  " + existingRole.DisplayName + "  (" +
                                existingRole.AllowedResourceActions.Count + " permissions, " +
                                (existingRole.IsBuiltIn ? "built-in" : "custom") + ")" +
                                Environment.NewLine + Environment.NewLine +
                                "Reuse it instead of creating '" + graphDraft.DisplayName + "'?" +
                                Environment.NewLine + Environment.NewLine +
                                "Yes = use the existing role, and attach the group to it if needed " +
                                "(recommended — fewer objects to govern)." + Environment.NewLine +
                                "No  = create a new custom role anyway." + Environment.NewLine +
                                "Cancel = skip this grant.",
                                "An equivalent role already exists",
                                MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
    
                            if (reuse == MessageBoxResult.Cancel)
                            {
                                store.Append(record with
                                {
                                    PrincipalId = principal,
                                    Notes = "Cancelled at duplicate-role prompt."
                                });
                                Status("Cancelled — an equivalent role already exists.");
                                continue;
                            }
                            if (reuse == MessageBoxResult.Yes)
                            {
                                roleId = existingRole.Id;
                            }
                            else
                            {
                                roleId = await CreateAndVerifyRoleAsync(
                                    ledger, graphExecutor, c.Provider, graphDraft);
                                createdCustom = true;
                            }
                        }
                        else
                        {
                            roleId = await CreateAndVerifyRoleAsync(
                                ledger, graphExecutor, c.Provider, graphDraft);
                            createdCustom = true;
                        }
                    }
                    else if (choice is RoleFit chosenFit)
                    {
                        roleId = chosenFit.RoleId;
                    }
                    else
                    {
                        // Only Exchange-model providers produce a plan choice, and they take the
                        // PowerShell branch above — but a clear message beats an
                        // InvalidCastException if that ever stops being true.
                        store.Append(record with
                        {
                            PrincipalId = principal,
                            Notes = "Skipped: the selected option is not a role this service can "
                                  + "grant directly (" + choice.GetType().Name + ")."
                        });
                        continue;
                    }
    
                    if (c.Provider == RbacProviders.Directory)
                    {
                        // Pre-flight against the role's PIM policy so a rejection is caught
                        // and explained here rather than as an opaque 400.
                        var roleLabel = outcomeRoleLabel(c, choice);
                        var checkedDuration = await PreflightDirectoryPolicyAsync(
                            roleId, roleLabel, eligible, permanent, duration, durationSpan);
                        if (checkedDuration is null)
                        {
                            store.Append(record with
                            { PrincipalId = principal, Notes = "Cancelled at PIM policy pre-flight." });
                            Status("Cancelled at PIM policy check — nothing executed for " + roleLabel + ".");
                            continue;
                        }
                        var effPermanent = checkedDuration.Value.Permanent;
                        var effDuration = checkedDuration.Value.Iso;
    
                        var p = new AssignmentPlan
                        {
                            PrincipalId = principal,
                            RoleDefinitionId = roleId,
                            Justification = justification,
                            Type = eligible ? AssignmentType.Eligible : AssignmentType.Active,
                            Duration = effPermanent ? "P365D" : effDuration,
                            Permanent = effPermanent,
                            DirectoryScopeId = _directoryScopeId
                        };
                        Status("Filing PIM schedule request...");
                        var scheduleId = await graphExecutor.AssignDirectoryAsync(p);
                        store.Append(record with
                        {
                            PrincipalId = principal,
                            Approved = true, ApprovedBy = Environment.UserName,
                            ApprovedUtc = DateTimeOffset.UtcNow,
                            AssignmentTypeUsed = p.Type.ToString(),
                            Duration = effPermanent ? "PERMANENT" : effDuration,
                            PermanentGrant = effPermanent,
                            ChosenRoleId = roleId, CustomRoleCreated = createdCustom,
                            GraphScheduleRequestId = scheduleId
                        });
                    }
                    else if (pimGroup.Length > 0 && groupDirectMode)
                    {
                        if (!await EnsureGroupCarriesRoleAsync(graphExecutor, c.Provider, pimGroup,
                                roleId, outcomeRoleLabel(c, choice), createdCustom))
                        {
                            store.Append(record with
                            {
                                PrincipalId = principal,
                                Notes = "Skipped — group does not carry the role and attaching was declined."
                            });
                            Status("Skipped " + RbacProviders.DisplayName(c.Provider) +
                                   " — group does not carry the role.");
                            continue;
                        }
                        Status("Adding to group (direct membership)...");
                        if (await graphExecutor.IsGroupMemberAsync(pimGroup, principal))
                        {
                            Status("Already a member of that group — nothing to add.");
                        }
                        else
                        {
                            await graphExecutor.AddGroupMemberAsync(pimGroup, principal);
                        }
                        DateTimeOffset? gExpires = permanent
                            ? null : DateTimeOffset.UtcNow + durationSpan;
                        store.Append(record with
                        {
                            PrincipalId = principal,
                            Approved = true, ApprovedBy = Environment.UserName,
                            ApprovedUtc = DateTimeOffset.UtcNow,
                            AssignmentTypeUsed = "DirectGroupMember",
                            Duration = permanent ? "PERMANENT" : duration,
                            PermanentGrant = permanent,
                            ChosenRoleId = roleId, CustomRoleCreated = createdCustom,
                            GroupIdUsed = pimGroup, TrackedExpiryUtc = gExpires
                        });
                    }
                    else if (pimGroup.Length > 0)
                    {
                        if (!await EnsureGroupCarriesRoleAsync(graphExecutor, c.Provider, pimGroup,
                                roleId, outcomeRoleLabel(c, choice), createdCustom))
                        {
                            store.Append(record with
                            {
                                PrincipalId = principal,
                                Notes = "Skipped — group does not carry the role and attaching was declined."
                            });
                            Status("Skipped " + RbacProviders.DisplayName(c.Provider) +
                                   " — group does not carry the role.");
                            continue;
                        }
                        Status("Granting PIM-for-Groups membership...");
                        var reqId = await graphExecutor.AssignGroupMembershipAsync(
                            pimGroup, principal, duration, justification, permanent);
                        store.Append(record with
                        {
                            PrincipalId = principal,
                            Approved = true, ApprovedBy = Environment.UserName,
                            ApprovedUtc = DateTimeOffset.UtcNow,
                            AssignmentTypeUsed = "PimGroup",
                            Duration = permanent ? "PERMANENT" : duration,
                            PermanentGrant = permanent,
                            ChosenRoleId = roleId, CustomRoleCreated = createdCustom,
                            GroupIdUsed = pimGroup, GraphScheduleRequestId = reqId
                        });
                    }
                    else
                    {
                        Status("Creating direct assignment (" + c.Provider + ")...");
                        RoleExecutor.IntuneAssignmentScope? directScope = null;
                        if (c.Provider == RbacProviders.Intune)
                        {
                            directScope = await ChooseIntuneScopeAsync(outcomeRoleLabel(c, choice));
                            if (directScope is null)
                            {
                                store.Append(record with
                                { PrincipalId = principal, Notes = "Cancelled at Intune scope selection." });
                                Status("Cancelled at scope selection.");
                                continue;
                            }
                        }
                        var assignmentId = await graphExecutor.AssignMultiAsync(
                            c.Provider, principal, roleId, justification, directScope);
                        DateTimeOffset? expires = permanent
                            ? null : DateTimeOffset.UtcNow + durationSpan;
                        store.Append(record with
                        {
                            PrincipalId = principal,
                            Approved = true, ApprovedBy = Environment.UserName,
                            ApprovedUtc = DateTimeOffset.UtcNow,
                            AssignmentTypeUsed = "DirectMulti",
                            Duration = permanent ? "PERMANENT" : duration,
                            PermanentGrant = permanent,
                            ChosenRoleId = roleId, CustomRoleCreated = createdCustom,
                            MultiAssignmentId = assignmentId, TrackedExpiryUtc = expires
                        });
                    }
                
                }
                catch (Exception serviceEx)
                {
                    // The ledger says exactly which steps ran and what they left behind —
                    // the difference between "it failed" and "it failed, and here is the
                    // role now sitting in your tenant".
                    failures.Add(RbacProviders.DisplayName(c.Provider) + ": "
                                 + ExplainGrantFailure(serviceEx)
                                 + (ledger.Steps.Count > 0
                                     ? Environment.NewLine + Environment.NewLine + ledger.Report()
                                     : ""));
                    store.Append(record with
                    {
                        PrincipalId = principal,
                        Notes = "FAILED: " + Trim(serviceEx.Message)
                    });
                    Status(RbacProviders.DisplayName(c.Provider) + " failed — continuing.");
                    continue;
                }
}
            Status("Executed. See History tab.");
            RefreshHistoryGrid();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ExplainGrantFailure(ex), "Execution failed",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Status("Execution failed — see error.");
        }
        finally { ExecuteButton.IsEnabled = true; }
    }

    /// <summary>
    /// Adds the principal to an existing group that already carries the needed roles.
    /// No role is created or assigned — this is the "join a proven group" path.
    /// </summary>
    private async Task ExecuteGroupOnlyAsync(
        string principal, string groupId, bool directMode,
        bool permanent, string duration, TimeSpan durationSpan)
    {
        if (principal.Length == 0) { Status("Enter or find the recipient first."); return; }
        if (_lastSuggestion is null) return;

        var mech = directMode
            ? "DIRECT membership" +
              (permanent ? ", NO EXPIRY (never auto-removed)"
                         : ", app-tracked expiry " + duration + " (Housekeeping removes)")
            : "PIM-for-Groups membership" + (permanent ? ", NO EXPIRY" : " afterDuration " + duration);

        var confirm = MessageBox.Show(
            "Principal: " + principal + Environment.NewLine +
            "Group: " + groupId + Environment.NewLine + Environment.NewLine +
            "No new role will be created or assigned — the user is added to a group that " +
            "already carries the required roles." + Environment.NewLine + Environment.NewLine +
            mech + Environment.NewLine + Environment.NewLine + "Proceed?",
            permanent ? "Approve PERMANENT group membership" : "Approve group membership",
            MessageBoxButton.YesNo,
            permanent ? MessageBoxImage.Warning : MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) { Status("Cancelled — nothing executed."); return; }

        ExecuteButton.IsEnabled = false;
        var store = new RequestHistoryStore(HistoryPath);
        try
        {
            var executor = new RoleExecutor(GetGraph());
            var record = RequestRecordBuilder
                .FromOutcome(_lastFunction, _lastSuggestion,
                    new ValidationOutcome
                    {
                        ValidActions = Array.Empty<string>(),
                        UnknownActionsRejected = Array.Empty<string>(),
                        RankedFits = Array.Empty<RoleFit>(),
                        CustomRoleRecommended = false
                    },
                    _lastPromptSha, _manualActions.ToList())
                with { PrincipalId = principal, ChosenRoleDisplay = "(existing group)" };

            if (directMode)
            {
                Status("Adding to group (direct membership)...");
                if (!await executor.IsGroupMemberAsync(groupId, principal))
                    await executor.AddGroupMemberAsync(groupId, principal);
                store.Append(record with
                {
                    Approved = true, ApprovedBy = Environment.UserName,
                    ApprovedUtc = DateTimeOffset.UtcNow,
                    AssignmentTypeUsed = "DirectGroupMember",
                    Duration = permanent ? "PERMANENT" : duration,
                    PermanentGrant = permanent,
                    GroupIdUsed = groupId,
                    TrackedExpiryUtc = permanent ? null : DateTimeOffset.UtcNow + durationSpan,
                    Notes = "Joined existing group carrying the required roles."
                });
            }
            else
            {
                Status("Granting PIM-for-Groups membership...");
                var reqId = await executor.AssignGroupMembershipAsync(
                    groupId, principal, duration,
                    "AccessCheck: join existing group for " + _lastFunction, permanent);
                store.Append(record with
                {
                    Approved = true, ApprovedBy = Environment.UserName,
                    ApprovedUtc = DateTimeOffset.UtcNow,
                    AssignmentTypeUsed = "PimGroup",
                    Duration = permanent ? "PERMANENT" : duration,
                    PermanentGrant = permanent,
                    GroupIdUsed = groupId, GraphScheduleRequestId = reqId,
                    Notes = "Joined existing group carrying the required roles."
                });
            }
            Status("Added to group. See History tab.");
            RefreshHistoryGrid();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ExplainGrantFailure(ex), "Group membership failed",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Status("Group membership failed.");
        }
        finally { ExecuteButton.IsEnabled = true; }
    }

    /// <summary>
    /// An Intune role created through the unified endpoint is invisible to Intune itself
    /// and can never be assigned. Detects that, and offers to DELETE the dead role so the
    /// next run is clean — the error alone told the operator to do it but gave no way to.
    /// Returns true when the role is usable.
    /// </summary>
    private async Task<bool> EnsureIntuneRoleUsableAsync(
        RoleExecutor executor, string roleId, string roleName)
    {
        Status("Locating '" + roleName + "' in Intune...");
        var state = await executor.GetIntuneRoleStateAsync(roleId);
        if (state == RoleExecutor.IntuneRoleState.Usable) return true;

        if (state == RoleExecutor.IntuneRoleState.Missing)
        {
            // THE ROLE IS NOT THERE. That is not a problem to escalate — it is precisely
            // the condition under which creating one is correct. The old behaviour asked
            // permission to re-sync and then aborted either way, so a stale cache entry
            // blocked a grant that would have worked. Drop the dead entry and carry on.
            _catalog?.RemoveRole(roleId);
            try { _catalog?.Save(CatalogPath); } catch (Exception) { /* cache only */ }
            RefreshCatalogGrid();
            RebuildPermissionCatalog();

            Status("'" + roleName + "' was a stale catalog entry — removed; creating a fresh role.");
            return false;   // caller creates rather than reusing; see StaleEntryCleared
        }

        // UnifiedOnly: the role really is there, just at the endpoint Intune can't use.
        var answer = MessageBox.Show(
            "'" + roleName + "' (" + roleId + ") exists only under the unified " +
            "/roleManagement path, which Intune itself cannot see — so it can never be " +
            "assigned to anything." + Environment.NewLine + Environment.NewLine +
            "Delete it now?" + Environment.NewLine + Environment.NewLine +
            "Yes = delete the unusable role, then re-run to create a working one." +
            Environment.NewLine + "No  = leave it and abort this grant.",
            "Unusable Intune role", MessageBoxButton.YesNo, MessageBoxImage.Warning);

        if (answer == MessageBoxResult.Yes)
        {
            try
            {
                Status("Deleting unusable role...");
                await executor.DeleteRoleAsync(RbacProviders.Intune, roleId);
                Status("Deleted — re-syncing catalog...");
                var (catalog, _) = await new CatalogSync(GetGraph()).SyncAllAsync(msg => Status(msg));
                _catalog = catalog;
                catalog.Save(CatalogPath);
                RefreshCatalogGrid();
        RebuildPermissionCatalog();
        RefreshForcedProviderList();
                MessageBox.Show(
                    "Deleted and catalog refreshed. Re-run the request — role creation now " +
                    "uses Intune's own endpoint only, so the new role will be assignable.",
                    "Removed", MessageBoxButton.OK, MessageBoxImage.Information);
                Status("Unusable role deleted — re-run the request.");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Delete failed: " + ex.Message,
                    "Delete failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        return false;
    }

    /// <summary>
    /// Intune requires a scope on every role assignment. Asks which one, because the
    /// difference matters: "all devices and licensed users" is the broadest possible
    /// scope, while scope groups confine the role to specific devices/users.
    /// Returns null if the operator cancels.
    /// </summary>
    private async Task<RoleExecutor.IntuneAssignmentScope?> ChooseIntuneScopeAsync(string roleName)
    {
        var answer = MessageBox.Show(
            "Intune requires a SCOPE for '" + roleName + "'. This decides which devices and " +
            "users the role can act on." + Environment.NewLine + Environment.NewLine +
            "Yes  = scope to specific group(s) — least privilege, pick a scope group next." +
            Environment.NewLine +
            "No   = ALL devices and ALL licensed users — the broadest scope Intune offers." +
            Environment.NewLine +
            "Cancel = abort this assignment.",
            "Choose the Intune scope", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);

        if (answer == MessageBoxResult.Cancel) return null;
        if (answer == MessageBoxResult.No)
            return RoleExecutor.IntuneAssignmentScope.AllDevicesAndUsers;

        var typed = PromptForText("Intune scope group",
            "Name or object ID of the security group defining the SCOPE " +
            "(which devices/users this role may act on):", "");
        if (string.IsNullOrWhiteSpace(typed)) return null;

        var resolved = await ResolvePimGroupAsync(typed.Trim());
        if (string.IsNullOrWhiteSpace(resolved)) return null;
        return RoleExecutor.IntuneAssignmentScope.ForGroups(new[] { resolved });
    }

    /// <summary>
    /// Membership in a group only grants something if the GROUP carries the role.
    /// Verifies that, and offers to attach the role when it doesn't — otherwise the
    /// grant is a silent no-op (and any freshly created custom role is orphaned).
    /// Returns false if the operator declines, so the caller can skip that grant.
    /// </summary>
    private async Task<bool> EnsureGroupCarriesRoleAsync(
        RoleExecutor executor, string provider, string groupId,
        string roleId, string roleName, bool roleWasJustCreated)
    {
        Status("Checking whether the group carries '" + roleName + "'...");
        var holds = roleWasJustCreated
            ? false // brand-new role cannot already be attached
            : await executor.DoesPrincipalHoldRoleAsync(provider, groupId, roleId);
        if (holds)
        {
            Status("Group already carries '" + roleName + "'.");
            return true;
        }

        var answer = MessageBox.Show(
            "The group does NOT carry '" + roleName + "' (" +
            RbacProviders.DisplayName(provider) + ")." +
            (roleWasJustCreated
                ? "\n\nThis role was just created, so nothing holds it yet."
                : "") +
            "\n\nAdding the user to the group would grant them NOTHING, because a group " +
            "only confers what it has been assigned." +
            "\n\nAttach '" + roleName + "' to the group now?" +
            "\n\nYes  = assign the role to the group (permanent — the group is the carrier), " +
            "then add the member." +
            "\nNo   = skip this grant entirely so nothing misleading is recorded.",
            "Group does not carry this role",
            MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (answer != MessageBoxResult.Yes) return false;

        RoleExecutor.IntuneAssignmentScope? scope = null;
        if (provider == RbacProviders.Intune)
        {
            // A role created moments ago through Intune's own endpoint is usable by
            // definition; only pre-existing roles need proving.
            if (!roleWasJustCreated &&
                !await EnsureIntuneRoleUsableAsync(executor, roleId, roleName)) return false;
            scope = await ChooseIntuneScopeAsync(roleName);
            if (scope is null) return false;
        }

        Status("Attaching '" + roleName + "' to the group...");
        if (provider == RbacProviders.Directory)
            await executor.AssignDirectoryRoleToPrincipalAsync(groupId, roleId);
        else
            await executor.AssignMultiAsync(provider, groupId, roleId,
                "AccessCheck: group carries this role for delegated access", scope);
        Status("Role attached to the group.");
        return true;
    }

    /// <summary>Human label for the role a card will grant, for policy messages.</summary>
    private static string outcomeRoleLabel(object card, object choice) =>
        choice is CustomRoleDraft d ? d.DisplayName
        : choice is RoleFit f ? f.DisplayName
        : choice is RoleGroupPlan p ? p.RoleGroupName
        : "the selected role";

    private static TimeSpan ParseIsoDuration(string iso)
    {
        try { return System.Xml.XmlConvert.ToTimeSpan(iso); }
        catch { return TimeSpan.FromDays(14); }
    }

    private static string Trim(string s) => s.Length <= 160 ? s : s[..160];

    // ---------------- history ----------------

    private sealed record HistoryRow(
        string When, string Function, string Service, string Role,
        string Delta, string Added, string Approved, string Expiry, string Notes);

    private void HistoryRefresh_Click(object sender, RoutedEventArgs e) => RefreshHistoryGrid();

    /// <summary>
    /// Opens the FULL request log in a scrollable window, with a highlight box and an AI
    /// lookup over either a highlighted section or the whole log.
    /// </summary>
    private async void HistoryFullLog_Click(object sender, RoutedEventArgs e)
    {
        string log;
        try
        {
            log = File.Exists(HistoryPath) ? File.ReadAllText(HistoryPath) : "";
        }
        catch (Exception ex)
        {
            MessageBox.Show("Could not read the history log: " + ex.Message,
                "Full log", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (string.IsNullOrWhiteSpace(log))
        {
            MessageBox.Show("The history log is empty — no requests have been recorded yet.",
                "Full log", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var win = new Window
        {
            Title = "Full request log",
            Width = 900,
            Height = 640,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = this,
            ResizeMode = ResizeMode.CanResize,
            ShowInTaskbar = false
        };

        var grid = new Grid { Margin = new Thickness(14) };
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var hint = new TextBlock
        {
            Text = "The complete request log. Select any part and use \"Look up selection\" to "
                 + "ask the AI about it, or \"Look up whole log\" to summarise everything.",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 10)
        };
        Grid.SetRow(hint, 0);
        grid.Children.Add(hint);

        var logBox = new TextBox
        {
            Text = log,
            IsReadOnly = true,
            FontFamily = new System.Windows.Media.FontFamily("Consolas, Courier New, monospace"),
            FontSize = 12,
            TextWrapping = TextWrapping.NoWrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            AcceptsReturn = true,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(8)
        };
        Grid.SetRow(logBox, 1);
        grid.Children.Add(logBox);

        var answer = new TextBox
        {
            IsReadOnly = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            MinHeight = 80,
            MaxHeight = 160,
            Margin = new Thickness(0, 10, 0, 0),
            Padding = new Thickness(8),
            Visibility = Visibility.Collapsed,
            Background = (Brush)FindResource("CardBg")
        };
        Grid.SetRow(answer, 2);
        grid.Children.Add(answer);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 12, 0, 0)
        };

        async Task Lookup(string scope, string content)
        {
            if (string.IsNullOrWhiteSpace(content))
            {
                answer.Visibility = Visibility.Visible;
                answer.Text = "Nothing to look up — select some text first.";
                return;
            }

            answer.Visibility = Visibility.Visible;
            answer.Text = "Asking the AI about the " + scope + "...";

            try
            {
                var key = SecretStore.Load(_config.Ai.ApiKeyName);
                if (string.IsNullOrEmpty(key))
                {
                    answer.Text = "No AI key is stored. Set one under Settings to use log lookup.";
                    return;
                }

                // Same channel the recommendation flow uses. The provider only ever sees the
                // log content the operator chose to send.
                using var provider = AiProviderFactory.Create(BuildAiConfig(), key);
                provider.PromptLogger = LogPrompt;

                var result = await provider.SuggestAsync(
                    "Explain this AccessCheck request-log content in plain language, "
                    + "including what was requested, what was granted, and any failures:\n\n"
                    + content,
                    _catalog ?? new RoleCatalog(),
                    null, default, _referenceStore);

                answer.Text = string.IsNullOrWhiteSpace(result.Reasoning)
                    ? "The AI returned no explanation."
                    : result.Reasoning;
            }
            catch (Exception ex)
            {
                answer.Text = "Lookup failed: " + ex.Message;
            }
        }

        var lookupSel = new Button
        {
            Content = "Look up selection",
            MinWidth = 130,
            Margin = new Thickness(0, 0, 8, 0),
            Padding = new Thickness(10, 4, 10, 4)
        };
        lookupSel.Click += async (_, _) => await Lookup("selected section", logBox.SelectedText);

        var lookupAll = new Button
        {
            Content = "Look up whole log",
            MinWidth = 130,
            Margin = new Thickness(0, 0, 8, 0),
            Padding = new Thickness(10, 4, 10, 4)
        };
        lookupAll.Click += async (_, _) => await Lookup("whole log", logBox.Text);

        var copy = new Button
        {
            Content = "Copy",
            MinWidth = 90,
            Margin = new Thickness(0, 0, 8, 0),
            Padding = new Thickness(10, 4, 10, 4)
        };
        copy.Click += (_, _) =>
        {
            try { Clipboard.SetText(logBox.SelectedText.Length > 0 ? logBox.SelectedText : logBox.Text); }
            catch (Exception) { }
        };

        var close = new Button
        {
            Content = "Close",
            MinWidth = 90,
            Padding = new Thickness(10, 4, 10, 4),
            IsCancel = true
        };
        close.Click += (_, _) => win.Close();

        buttons.Children.Add(lookupSel);
        buttons.Children.Add(lookupAll);
        buttons.Children.Add(copy);
        buttons.Children.Add(close);
        Grid.SetRow(buttons, 3);
        grid.Children.Add(buttons);

        win.Content = grid;
        win.ShowDialog();
        await Task.CompletedTask;
    }

    private void RefreshHistoryGrid()
    {
        var rows = new RequestHistoryStore(HistoryPath).LoadLatest()
            .Select(r => new HistoryRow(
                r.CreatedUtc.ToString("yyyy-MM-dd HH:mm"),
                r.FunctionDescription,
                r.Provider is null ? "" : RbacProviders.DisplayName(r.Provider),
                r.ChosenRoleDisplay ?? "",
                r.ExcessActionsAccepted.Count.ToString(),
                r.HumanAddedActions.Count.ToString(),
                r.Approved ? "yes (" + (r.ApprovedBy ?? "?") + ")" : "no",
                r.PermanentGrant
                    ? "PERMANENT (no expiry)"
                    : r.TrackedExpiryUtc?.ToString("yyyy-MM-dd HH:mm") ??
                      (r.GraphScheduleRequestId is not null ? "PIM (server-side)" : ""),
                r.Notes ?? ""))
            .ToList();
        HistoryGrid.ItemsSource = rows;
    }

    // ---------------- housekeeping ----------------

    // ---------------- housekeeping (scan-only; removal is explicit) ----------------

    /// <summary>One thing housekeeping COULD remove. Nothing happens until it is ticked.</summary>
    private sealed class HousekeepingItem : System.ComponentModel.INotifyPropertyChanged
    {
        private bool _selected;
        public bool Selected
        {
            get => _selected;
            set
            {
                if (_selected == value) return;
                _selected = value;
                PropertyChanged?.Invoke(this,
                    new System.ComponentModel.PropertyChangedEventArgs(nameof(Selected)));
            }
        }
        public string Kind { get; init; } = "";
        public string Description { get; init; } = "";
        public string Expired { get; init; } = "";
        /// <summary>Performs the removal. Only ever invoked for ticked items.</summary>
        public Func<Task>? RemoveAsync { get; init; }
        public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
    }

    private readonly System.Collections.ObjectModel.ObservableCollection<HousekeepingItem>
        _housekeepingItems = new();

    private async void Housekeeping_Click(object sender, RoutedEventArgs e)
    {
        HousekeepingButton.IsEnabled = false;
        HousekeepingLog.Clear();
        _housekeepingItems.Clear();
        HousekeepingGrid.ItemsSource = _housekeepingItems;
        void Log(string s2) => HousekeepingLog.AppendText(s2 + Environment.NewLine);

        try
        {
            var store = new RequestHistoryStore(HistoryPath);
            var records = store.LoadLatest();
            RoleExecutor? graphExecutor = null;

            Log("SCAN ONLY — nothing is removed by this pass.");
            Log("");

            // --- expired direct Graph assignments (Intune / W365 / Defender) ---
            foreach (var rec in records)
            {
                if (rec.MultiAssignmentId is null || rec.RemovedByHousekeeping) continue;
                if (rec.TrackedExpiryUtc is null || rec.TrackedExpiryUtc > DateTimeOffset.UtcNow) continue;
                var captured = rec;
                _housekeepingItems.Add(new HousekeepingItem
                {
                    Kind = "Expired role assignment",
                    Description = (captured.ChosenRoleDisplay ?? captured.ChosenRoleId ?? "role") +
                                  " for " + captured.PrincipalId +
                                  " (" + RbacProviders.DisplayName(captured.Provider ?? "") + ")",
                    Expired = captured.TrackedExpiryUtc?.ToString("yyyy-MM-dd HH:mm") ?? "",
                    RemoveAsync = async () =>
                    {
                        graphExecutor ??= new RoleExecutor(GetGraph());
                        await graphExecutor.RemoveMultiAssignmentAsync(
                            captured.Provider!, captured.MultiAssignmentId!);
                        store.Append(captured with
                        { RemovedByHousekeeping = true, Notes = "Removed at expiry (operator-selected)." });
                    }
                });
            }

            // --- expired direct group memberships ---
            foreach (var rec in records)
            {
                if (rec.RemovedByHousekeeping) continue;
                if (!string.Equals(rec.AssignmentTypeUsed, "DirectGroupMember",
                        StringComparison.OrdinalIgnoreCase)) continue;
                if (rec.GroupIdUsed is null || rec.PrincipalId is null) continue;
                if (rec.TrackedExpiryUtc is null || rec.TrackedExpiryUtc > DateTimeOffset.UtcNow) continue;
                var captured = rec;
                _housekeepingItems.Add(new HousekeepingItem
                {
                    Kind = "Expired group membership",
                    Description = captured.PrincipalId + " in group " + captured.GroupIdUsed,
                    Expired = captured.TrackedExpiryUtc?.ToString("yyyy-MM-dd HH:mm") ?? "",
                    RemoveAsync = async () =>
                    {
                        graphExecutor ??= new RoleExecutor(GetGraph());
                        await graphExecutor.RemoveGroupMemberAsync(
                            captured.GroupIdUsed!, captured.PrincipalId!);
                        store.Append(captured with
                        { RemovedByHousekeeping = true, Notes = "Membership removed at expiry (operator-selected)." });
                    }
                });
            }

            // --- expired Exchange / Purview role-group memberships ---
            foreach (var rec in records)
            {
                if (rec.GroupIdUsed is null || rec.RemovedByHousekeeping) continue;
                if (string.Equals(rec.AssignmentTypeUsed, "DirectGroupMember",
                        StringComparison.OrdinalIgnoreCase)) continue;
                if (rec.Provider is null ||
                    !RbacProviders.DerivedRoleCapable.Contains(rec.Provider)) continue;
                if (rec.TrackedExpiryUtc is null || rec.TrackedExpiryUtc > DateTimeOffset.UtcNow) continue;
                var captured = rec;
                _housekeepingItems.Add(new HousekeepingItem
                {
                    Kind = "Expired " + RbacProviders.DisplayName(captured.Provider) + " membership",
                    Description = captured.PrincipalId + " in role group '" + captured.GroupIdUsed + "'",
                    Expired = captured.TrackedExpiryUtc?.ToString("yyyy-MM-dd HH:mm") ?? "",
                    RemoveAsync = async () =>
                    {
                        var scope = captured.Provider == RbacProviders.Exchange
                            ? RbacScope.Exchange : RbacScope.Purview;
                        var (runner, env, adminUpn) = GetPs();
                        var psExec = new ExoPurviewExecutor(runner, env, adminUpn);
                        var script = psExec.BuildRemoveMemberScript(
                            scope, captured.GroupIdUsed!, captured.PrincipalId ?? "");
                        using var _ = await psExec.RunAsync(script);
                        store.Append(captured with
                        { RemovedByHousekeeping = true, Notes = "Membership removed at expiry (operator-selected)." });
                    }
                });
            }

            // --- orphaned AccessCheck-created roles (Graph) ---
            Log("Re-syncing the role catalog to find orphaned AccessCheck roles...");
            graphExecutor ??= new RoleExecutor(GetGraph());
            var (catalog, _) = await new CatalogSync(GetGraph()).SyncAllAsync(Log);
            _catalog = catalog;
            catalog.Save(CatalogPath);
            RefreshCatalogGrid();
        RebuildPermissionCatalog();
        RefreshForcedProviderList();

            foreach (var role in catalog.Roles.Where(r =>
                r.IsAccessCheckCreated && !RbacProviders.DerivedRoleCapable.Contains(r.Provider)))
            {
                var empty = await graphExecutor.RoleHasNoAssignmentsAsync(role.Provider, role.Id);
                if (!empty) continue;
                var captured = role;
                _housekeepingItems.Add(new HousekeepingItem
                {
                    Kind = "Unused AccessCheck role",
                    Description = captured.DisplayName + " (" +
                                  RbacProviders.DisplayName(captured.Provider) +
                                  ", " + captured.AllowedResourceActions.Count + " permissions) — " +
                                  "no assignments remain",
                    Expired = "n/a",
                    RemoveAsync = async () =>
                    {
                        graphExecutor ??= new RoleExecutor(GetGraph());
                        await graphExecutor.DeleteRoleAsync(captured.Provider, captured.Id);
                    }
                });
            }

            // --- empty AccessCheck role groups (Exchange / Purview) ---
            foreach (var scope in new[] { RbacScope.Exchange, RbacScope.Purview })
            {
                try
                {
                    var (runner, env, adminUpn) = GetPs();
                    var psExec = new ExoPurviewExecutor(runner, env, adminUpn);
                    using var doc = await psExec.RunAsync(psExec.BuildListAlGroupsScript(scope));
                    if (!doc.RootElement.TryGetProperty("groups", out var groups)) continue;
                    foreach (var g in groups.EnumerateArray())
                    {
                        var name = g.GetProperty("name").GetString() ?? "";
                        var memberCount = g.TryGetProperty("members", out var ms) ? ms.GetArrayLength() : 0;
                        if (memberCount > 0) continue;
                        string? derivedRole = null;
                        if (g.TryGetProperty("roles", out var rl) && rl.GetArrayLength() > 0)
                        {
                            var r0 = rl[0].GetString();
                            if (r0 is not null && r0.StartsWith("AC - ", StringComparison.OrdinalIgnoreCase))
                                derivedRole = r0;
                        }
                        var capturedScope = scope;
                        var capturedName = name;
                        var capturedRole = derivedRole;
                        _housekeepingItems.Add(new HousekeepingItem
                        {
                            Kind = "Empty AccessCheck role group",
                            Description = capturedName + " (" + capturedScope + ")" +
                                          (capturedRole is not null
                                              ? " and its derived role '" + capturedRole + "'" : "") +
                                          " — no members",
                            Expired = "n/a",
                            RemoveAsync = async () =>
                            {
                                var (r2, e2, u2) = GetPs();
                                var px = new ExoPurviewExecutor(r2, e2, u2);
                                using var __ = await px.RunAsync(
                                    px.BuildDeleteGroupAndRoleScript(capturedScope, capturedName, capturedRole));
                            }
                        });
                    }
                }
                catch (Exception ex) { Log("  " + scope + " role-group scan skipped: " + Trim(ex.Message)); }
            }

            Log("");
            Log("Scan complete: " + _housekeepingItems.Count + " candidate(s) found. Nothing removed.");
            HousekeepingSummary.Text = _housekeepingItems.Count == 0
                ? "Nothing to clean up."
                : _housekeepingItems.Count + " candidate(s) — tick what you want removed, then " +
                  "'Remove selected…'. Nothing is deleted until you do.";
            var any = _housekeepingItems.Count > 0;
            HousekeepingRemoveButton.IsEnabled = any;
            HousekeepingSelectAllButton.IsEnabled = any;
            HousekeepingSelectNoneButton.IsEnabled = any;
            RefreshHistoryGrid();
        }
        catch (Exception ex)
        {
            Log("Scan failed: " + ex.Message);
        }
        finally { HousekeepingButton.IsEnabled = true; }
    }

    private void HousekeepingSelectAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var i in _housekeepingItems) i.Selected = true;
    }

    private void HousekeepingSelectNone_Click(object sender, RoutedEventArgs e)
    {
        foreach (var i in _housekeepingItems) i.Selected = false;
    }

    private async void HousekeepingRemove_Click(object sender, RoutedEventArgs e)
    {
        var chosen = _housekeepingItems.Where(i => i.Selected && i.RemoveAsync is not null).ToList();
        if (chosen.Count == 0)
        {
            Status("Nothing ticked — nothing to remove.");
            return;
        }

        var list = string.Join(Environment.NewLine,
            chosen.Take(25).Select(i => "  • [" + i.Kind + "] " + i.Description));
        if (chosen.Count > 25) list += Environment.NewLine + "  ... and " + (chosen.Count - 25) + " more";

        var confirm = MessageBox.Show(
            "Remove these " + chosen.Count + " item(s)?" + Environment.NewLine + Environment.NewLine +
            list + Environment.NewLine + Environment.NewLine +
            "This is the only destructive step. Nothing else will be touched.",
            "Confirm removal", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) { Status("Cancelled — nothing removed."); return; }

        HousekeepingRemoveButton.IsEnabled = false;
        void Log(string s2) => HousekeepingLog.AppendText(s2 + Environment.NewLine);
        int done = 0, failed = 0;
        foreach (var item in chosen)
        {
            try
            {
                Status("Removing: " + item.Description);
                await item.RemoveAsync!();
                Log("REMOVED [" + item.Kind + "] " + item.Description);
                done++;
            }
            catch (Exception ex)
            {
                Log("FAILED  [" + item.Kind + "] " + item.Description + " — " + ex.Message);
                failed++;
            }
        }
        foreach (var item in chosen) _housekeepingItems.Remove(item);

        Log("");
        Log("Removal finished: " + done + " removed, " + failed + " failed.");
        HousekeepingSummary.Text = done + " removed, " + failed + " failed. " +
                                   _housekeepingItems.Count + " candidate(s) still listed.";
        Status("Housekeeping removal complete.");
        HousekeepingRemoveButton.IsEnabled = _housekeepingItems.Count > 0;
        RefreshHistoryGrid();
    }

    // ================= JOB DESCRIPTION TAB =================

    /// <summary>
    /// The last plan, kept so "Copy plan" does not have to re-run the analysis.
    /// </summary>
    private PortfolioComposer.Portfolio? _jdPortfolio;

    private void JdLoad_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open a job description",
            Filter = "Text and Markdown (*.txt;*.md)|*.txt;*.md|All files (*.*)|*.*"
        };
        if (dialog.ShowDialog() != true) return;

        try { JdText.Text = File.ReadAllText(dialog.FileName); }
        catch (Exception ex)
        {
            MessageBox.Show("Could not read that file.\n\n" + ex.Message,
                "Open failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void JdCopy_Click(object sender, RoutedEventArgs e)
    {
        if (_jdPortfolio is null) return;
        try
        {
            Clipboard.SetText(PortfolioComposer.Describe(_jdPortfolio));
            JdStatus.Text = "Plan copied to the clipboard.";
        }
        catch (Exception)
        {
            // Another process can hold the clipboard open. Not worth a dialog.
            JdStatus.Text = "Could not access the clipboard.";
        }
    }

    private async void JdAnalyze_Click(object sender, RoutedEventArgs e)
    {
        var document = JdText.Text?.Trim() ?? "";
        if (document.Length == 0)
        {
            MessageBox.Show("Paste a job description first.", "Nothing to analyse",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (_catalog is null || _catalog.Roles.Count == 0)
        {
            MessageBox.Show("Sync the catalog first — there is no permission vocabulary to "
                + "choose from, so every duty would come back unanswered.",
                "No catalog", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var key = SecretStore.Load(_config.Ai.ApiKeyName);
        if (string.IsNullOrEmpty(key))
        {
            MessageBox.Show("No AI key is stored under '" + _config.Ai.ApiKeyName +
                "'. Store one on the Settings tab.", "No key",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        JdPlanPanel.Children.Clear();
        JdDutyPanel.Children.Clear();
        JdAnalyzeButton.IsEnabled = false;
        JdCopyButton.IsEnabled = false;
        _jdPortfolio = null;

        try
        {
            // ONE PROVIDER FOR THE WHOLE DOCUMENT. Decomposition and every per-duty analysis
            // share it, so a twenty-duty description opens one connection rather than
            // twenty-one.
            using var provider = AiProviderFactory.Create(BuildAiConfig(), key);

            // SAME DOCUMENT, SAME PLAN. The endpoint is not deterministic even at
            // temperature 0 with a fixed seed — re-running one job description produced a
            // different split of the duties and therefore different answers throughout.
            var promptCache = new PromptCache(PromptCachePath);
            provider.Cache = promptCache;

            provider.PromptLogger = (stage, prompt) =>
                File.AppendAllText(PromptLogPath,
                    "==== " + DateTimeOffset.UtcNow.ToString("o") + " [" + stage + "] ====" +
                    Environment.NewLine + prompt + Environment.NewLine);

            JdStatus.Text = "Splitting into duties...";
            Status("Splitting the job description into discrete duties...");
            var functions = await provider.DecomposeAsync(document);

            var validator = new RecommendationValidator
            {
                MaxAcceptableExcessActions = _config.MaxAcceptableExcessActions,
                ReferenceActions = _referenceStore.ActionNames(),
                Ineligibility = _ineligibility,
                ReferenceDescriptions = _referenceStore.Descriptions()
            };

            var store = new RequestHistoryStore(HistoryPath);
            var analyses = new List<DutyAnalysis>();
            var skipped = 0;
            var analysed = 0;

            foreach (var fn in functions)
            {
                // NOT EVERY DUTY IS AN ACCESS REQUEST. "Mentors junior staff" has no permission,
                // and forcing one is how unrelated access gets granted. Shown and skipped.
                if (fn.NotAccessRelated)
                {
                    skipped++;
                    JdDutyPanel.Children.Add(JdCard(
                        "SKIPPED — not an access question", fn.Text,
                        fn.Note.Length > 0 ? fn.Note : "No permission grants this.",
                        "#6B7A8F"));
                    continue;
                }

                analysed++;
                JdStatus.Text = "Analysing duty " + analysed + "...";
                Status("Analysing: " + fn.Text);
                // Let the UI paint between duties — each one is several endpoint round trips.
                await Task.Yield();

                try
                {
                    var suggestion = await provider.SuggestAsync(
                        fn.Text, _catalog, null, default, _referenceStore);
                    var outcomes = validator.ValidateMulti(_catalog, suggestion, fn.Text);

                    if (outcomes.Count == 0)
                    {
                        // A DUTY THAT PRODUCED NOTHING STILL HAPPENED. Dropping it here would
                        // leave the plan quietly counting fewer duties than the document holds.
                        analyses.Add(new DutyAnalysis
                        {
                            Duty = fn.Text,
                            Provider = RbacProviders.Directory,
                            Actions = Array.Empty<string>(),
                            DeclaredReadOnly = fn.ReadOnly
                        });
                        JdDutyPanel.Children.Add(JdCard("NO VERDICT", fn.Text,
                            "Nothing validated for this duty.", "#B45309"));
                        continue;
                    }

                    foreach (var po in outcomes)
                    {
                        var label = po.Outcome.CustomRoleRecommended
                            ? po.Outcome.CustomRole?.DisplayName
                            : po.Outcome.BestFit?.DisplayName;

                        analyses.Add(new DutyAnalysis
                        {
                            Duty = fn.Text,
                            Provider = po.Provider,
                            Actions = po.Outcome.ValidActions,
                            RoleLabel = label,
                            CustomRole = po.Outcome.CustomRoleRecommended,
                            DeclaredReadOnly = fn.ReadOnly
                        });

                        store.Append(RequestRecordBuilder.FromOutcome(
                            fn.Text, suggestion, po.Outcome, provider.LastPromptSha256)
                            with { Provider = po.Provider });

                        JdDutyPanel.Children.Add(JdCard(
                            RbacProviders.DisplayName(po.Provider) + " — " +
                                (label ?? "no covering role"),
                            fn.Text,
                            po.Outcome.ValidActions.Count + " permission(s): " +
                                string.Join(", ", po.Outcome.ValidActions.Take(6)) +
                                (po.Outcome.ValidActions.Count > 6 ? ", ..." : ""),
                            "#1F4E79"));
                    }
                }
                catch (Exception ex)
                {
                    // ONE DUTY FAILING MUST NOT LOSE THE REST OF THE DOCUMENT — NOR ITSELF.
                    analyses.Add(new DutyAnalysis
                    {
                        Duty = fn.Text,
                        Provider = RbacProviders.Directory,
                        Actions = Array.Empty<string>(),
                        DeclaredReadOnly = fn.ReadOnly
                    });
                    JdDutyPanel.Children.Add(JdCard("ANALYSIS FAILED", fn.Text, ex.Message, "#B91C1C"));
                }
            }

            promptCache.Save();
        _jdPortfolio = PortfolioComposer.Compose(analyses);
            RenderJdPlan(_jdPortfolio, skipped);

            JdCopyButton.IsEnabled = true;
            JdStatus.Text = analysed + " duty(ies) analysed, " + skipped + " skipped.";
            Status("Job description analysis complete — review the plan above.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Analysis failed",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Status("Job description analysis failed.");
        }
        finally
        {
            JdAnalyzeButton.IsEnabled = true;
        }
    }

    /// <summary>
    /// The PLAN goes above the per-duty transcript. The transcript is working; the plan is
    /// what someone approves, and burying it under twenty cards means it is not read.
    /// </summary>
    private void RenderJdPlan(PortfolioComposer.Portfolio portfolio, int skipped)
    {
        JdPlanPanel.Children.Clear();

        var header = new StackPanel();
        header.Children.Add(new TextBlock
        {
            Style = (Style)FindResource("H1"),
            Text = "The plan"
        });
        header.Children.Add(new TextBlock
        {
            Style = (Style)FindResource("Hint"),
            TextWrapping = TextWrapping.Wrap,
            Text = portfolio.Summary +
                   (skipped > 0 ? "  " + skipped + " duty(ies) skipped as not access-related." : "")
        });
        JdPlanPanel.Children.Add(new Border
        {
            Style = (Style)FindResource("Card"),
            Child = header
        });

        foreach (var grant in portfolio.Grants)
        {
            var body = new StackPanel();
            body.Children.Add(new TextBlock
            {
                Text = grant.Headline,
                FontWeight = FontWeights.Bold,
                TextWrapping = TextWrapping.Wrap,
                Foreground = (Brush)FindResource("Steel")
            });

            foreach (var duty in grant.Duties)
                body.Children.Add(new TextBlock
                {
                    Style = (Style)FindResource("Hint"),
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(12, 4, 0, 0),
                    Text = "• " + duty
                });

            body.Children.Add(new TextBlock
            {
                Style = (Style)FindResource("Hint"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0),
                Text = grant.Actions.Count + " permission(s), risk score " + grant.RiskScore
                     + "  —  " + grant.Rationale
            });

            JdPlanPanel.Children.Add(new Border
            {
                Style = (Style)FindResource("Card"),
                Child = body
            });
        }

        if (portfolio.Unresolved.Count > 0)
        {
            var body = new StackPanel();
            body.Children.Add(new TextBlock
            {
                Text = "No permission found",
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0xB4, 0x53, 0x09))
            });
            foreach (var duty in portfolio.Unresolved)
                body.Children.Add(new TextBlock
                {
                    Style = (Style)FindResource("Hint"),
                    TextWrapping = TextWrapping.Wrap,
                    Text = "• " + duty
                });
            JdPlanPanel.Children.Add(new Border
            {
                Style = (Style)FindResource("Card"),
                Child = body
            });
        }

        // THE CONCERNS ARE THE POINT OF COMPOSING AT ALL. Each grant above can be individually
        // defensible while the union is an escalation path, and no per-duty verdict can see it.
        foreach (var concern in portfolio.Concerns)
        {
            var body = new StackPanel();
            body.Children.Add(new TextBlock
            {
                Text = (concern.Blocking ? "[BLOCKING]  " : "") + concern.Title,
                FontWeight = FontWeights.Bold,
                TextWrapping = TextWrapping.Wrap,
                Foreground = new SolidColorBrush(concern.Blocking
                    ? Color.FromRgb(0xB9, 0x1C, 0x1C)
                    : Color.FromRgb(0xB4, 0x53, 0x09))
            });
            body.Children.Add(new TextBlock
            {
                Style = (Style)FindResource("Hint"),
                TextWrapping = TextWrapping.Wrap,
                Text = concern.Detail
            });
            JdPlanPanel.Children.Add(new Border
            {
                Style = (Style)FindResource("Card"),
                Child = body
            });
        }

        JdPlanPanel.Children.Add(new TextBlock
        {
            Style = (Style)FindResource("Hint"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 6, 0, 14),
            Text = "This is a portfolio, not a role. Grant the parts you accept one at a time "
                 + "on the New Request tab — paste the duty text there and approve it as usual."
        });
    }

    /// <summary>One duty's outcome, in the same card idiom as the rest of the app.</summary>
    private Border JdCard(string title, string duty, string detail, string hex)
    {
        var body = new StackPanel();
        body.Children.Add(new TextBlock
        {
            Text = title,
            FontWeight = FontWeights.Bold,
            TextWrapping = TextWrapping.Wrap,
            Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(hex))
        });
        body.Children.Add(new TextBlock
        {
            Style = (Style)FindResource("Hint"),
            TextWrapping = TextWrapping.Wrap,
            Text = duty
        });
        body.Children.Add(new TextBlock
        {
            Style = (Style)FindResource("Hint"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 4, 0, 0),
            Text = detail
        });

        return new Border { Style = (Style)FindResource("Card"), Child = body };
    }
}

/// <summary>Offline keyword suggester so the GUI works with no AI endpoint configured.</summary>
internal sealed class DemoSuggester : IRecommendationProvider
{
    public Task<AiSuggestion> SuggestAsync(
        string functionDescription,
        RoleCatalog catalog,
        IReadOnlyCollection<string>? forcedProviders = null,
        CancellationToken ct = default,
        ReferenceStore? reference = null)
    {
        var catalogRoles = catalog.Roles;
        var words = functionDescription
            .ToLowerInvariant()
            .Split(new[] { ' ', ',', '.', ';' }, StringSplitOptions.RemoveEmptyEntries)
            .Where(w => w.Length > 3)
            .ToHashSet();

        var matched = catalogRoles
            .SelectMany(r => r.AllowedResourceActions)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(action => words.Any(w => action.Contains(w, StringComparison.OrdinalIgnoreCase)))
            .Take(8)
            .ToList();

        return Task.FromResult(new AiSuggestion
        {
            RequiredActions = matched,
            Reasoning = "OFFLINE DEMO: naive keyword match — configure the AI endpoint for real analysis."
        });
    }
}
