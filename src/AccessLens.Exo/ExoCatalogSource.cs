using System.Text.Json;
using AccessLens.Core.Catalog;

namespace AccessLens.Exo;

/// <summary>
/// Sources cmdlet-level truth for Exchange and Purview role models via PowerShell:
/// Get-ManagementRole + Get-ManagementRoleEntry. This REPLACES the Graph beta
/// exchange provider entries in the catalog because the derived custom-role model
/// (New-ManagementRole -Parent / Remove-ManagementRoleEntry) operates on cmdlets,
/// so recommendations must be computed in the same vocabulary that execution uses.
/// AL- prefix marks AccessLens-created roles/role groups for housekeeping.
/// </summary>
public sealed class ExoCatalogSource
{
    public const string Marker = "AL-";
    private readonly PwshRunner _runner;
    public ExoCatalogSource(PwshRunner runner) => _runner = runner;

    private const string JsonSentinel = "===ALJSON===";

    private static string CatalogBody => """
        $roles = Get-ManagementRole
        $out = foreach ($r in $roles) {
            $entries = @(Get-ManagementRoleEntry ("{0}\*" -f $r.Name) -ErrorAction SilentlyContinue |
                         Select-Object -ExpandProperty Name)
            [pscustomobject]@{
                name        = $r.Name
                description = "$($r.Description)"
                entries     = $entries
            }
        }
        Write-Output '===ALJSON==='
        $out | ConvertTo-Json -Depth 4 -Compress
        """;

    public string BuildExchangeCatalogScript(ExoEnvironment env) =>
        "$ErrorActionPreference = 'Stop'\n" +
        "Import-Module ExchangeOnlineManagement\n" +
        env.ExoConnectLine() + "\n" +
        CatalogBody + "\n" +
        "Disconnect-ExchangeOnline -Confirm:$false | Out-Null\n";

    public string BuildPurviewCatalogScript(ExoEnvironment env) =>
        "$ErrorActionPreference = 'Stop'\n" +
        "Import-Module ExchangeOnlineManagement\n" +
        env.IppsConnectLine() + "\n" +
        CatalogBody + "\n" +
        "Disconnect-ExchangeOnline -Confirm:$false | Out-Null\n";

    public async Task<List<RoleDefinitionRecord>> SyncAsync(
        ExoEnvironment env, string provider, CancellationToken ct = default)
    {
        var script = provider == RbacProviders.Purview
            ? BuildPurviewCatalogScript(env)
            : BuildExchangeCatalogScript(env);

        var result = await _runner.RunAsync(script, TimeSpan.FromMinutes(20), ct);
        if (!result.Succeeded)
            throw new InvalidOperationException(
                "PowerShell catalog sync failed (" + provider + "): " + Trim(result.StdErr));

        return Parse(result.StdOut, provider);
    }

    public static List<RoleDefinitionRecord> Parse(string stdout, string provider)
    {
        var idx = stdout.LastIndexOf(JsonSentinel, StringComparison.Ordinal);
        if (idx < 0)
            throw new InvalidDataException(
                "PowerShell output did not contain the JSON sentinel; got: " + Trim(stdout));
        var json = stdout[(idx + JsonSentinel.Length)..].Trim();

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var items = root.ValueKind == JsonValueKind.Array
            ? root.EnumerateArray().ToList()
            : new List<JsonElement> { root }; // single role serializes as an object

        var roles = new List<RoleDefinitionRecord>();
        foreach (var el in items)
        {
            var name = el.GetProperty("name").GetString() ?? "";
            if (name.Length == 0) continue;
            var entries = new List<string>();
            if (el.TryGetProperty("entries", out var arr) && arr.ValueKind == JsonValueKind.Array)
                foreach (var a in arr.EnumerateArray())
                {
                    var s = a.GetString();
                    if (!string.IsNullOrWhiteSpace(s)) entries.Add(s);
                }
            roles.Add(new RoleDefinitionRecord
            {
                Id = provider + ":" + name,
                DisplayName = name,
                Description = el.TryGetProperty("description", out var d) ? d.GetString() ?? "" : "",
                IsBuiltIn = !name.StartsWith(Marker, StringComparison.OrdinalIgnoreCase),
                IsAccessLensCreated = name.StartsWith(Marker, StringComparison.OrdinalIgnoreCase),
                Provider = provider,
                AllowedResourceActions = entries
            });
        }
        return roles;
    }

    private static string Trim(string s) => s.Length <= 400 ? s : s[..400];
}
