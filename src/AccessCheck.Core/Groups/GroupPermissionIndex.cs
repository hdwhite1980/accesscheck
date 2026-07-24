using AccessCheck.Core.Catalog;
using AccessCheck.Core.Recommendation;

namespace AccessCheck.Core.Groups;

/// <summary>One permission a group grants, and which of its roles supply it.</summary>
public sealed record GroupPermissionEntry(
    string Action, string Provider, IReadOnlyList<string> ViaRoles)
{
    public bool IsPrivileged => ActionRisk.IsPrivileged(Action);
    public string RiskLabel => IsPrivileged ? "privileged" : "read";
    public string ViaRolesLabel => string.Join(", ", ViaRoles);
}

/// <summary>One group that grants a given permission, and how.</summary>
public sealed record PermissionSource(
    string GroupId, string GroupName, IReadOnlyList<string> ViaRoles, int GroupTotalPermissions)
{
    public string ViaRolesLabel => string.Join(", ", ViaRoles);
}

/// <summary>
/// Two-way index over the group catalog. Forward answers "what does joining this group
/// actually grant?"; reverse answers "who else already has this permission, and through
/// what?" — the question that turns a single grant into a picture of blast radius.
/// </summary>
public sealed class GroupPermissionIndex
{
    private readonly Dictionary<string, List<PermissionSource>> _byAction =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<GroupPermissionEntry>> _byGroup =
        new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<string> AllActions =>
        _byAction.Keys.OrderBy(a => a, StringComparer.OrdinalIgnoreCase).ToList();

    public static GroupPermissionIndex Build(GroupCatalog groups, RoleCatalog roles)
    {
        var index = new GroupPermissionIndex();

        foreach (var group in groups.Groups)
        {
            // action -> the roles in THIS group that grant it
            var attribution = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            var providerOf = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var holding in group.Holdings)
            {
                var def = roles.Find(holding.RoleId);
                if (def is null) continue;
                foreach (var action in def.AllowedResourceActions)
                {
                    if (!attribution.TryGetValue(action, out var list))
                        attribution[action] = list = new List<string>();
                    if (!list.Contains(holding.Label)) list.Add(holding.Label);
                    providerOf[action] = holding.Provider;
                }
            }

            // Actions the group grants whose role isn't resolvable stay visible rather
            // than silently vanishing — an unresolved role is itself worth seeing.
            foreach (var action in group.GrantedActions)
            {
                if (attribution.ContainsKey(action)) continue;
                attribution[action] = new List<string> { "(role not in catalog)" };
                providerOf[action] = group.Providers.FirstOrDefault() ?? RbacProviders.Directory;
            }

            var entries = attribution
                .Select(kv => new GroupPermissionEntry(
                    kv.Key,
                    providerOf.TryGetValue(kv.Key, out var p) ? p : RbacProviders.Directory,
                    kv.Value))
                .OrderByDescending(e => e.IsPrivileged)
                .ThenBy(e => e.Action, StringComparer.OrdinalIgnoreCase)
                .ToList();

            index._byGroup[group.GroupId] = entries;

            foreach (var entry in entries)
            {
                if (!index._byAction.TryGetValue(entry.Action, out var sources))
                    index._byAction[entry.Action] = sources = new List<PermissionSource>();
                sources.Add(new PermissionSource(
                    group.GroupId, group.DisplayName, entry.ViaRoles, group.GrantedActions.Count));
            }
        }

        return index;
    }

    /// <summary>Everything a group grants, privileged permissions first.</summary>
    public IReadOnlyList<GroupPermissionEntry> PermissionsOf(string groupId) =>
        _byGroup.TryGetValue(groupId, out var list)
            ? list : Array.Empty<GroupPermissionEntry>();

    /// <summary>Every group that grants a permission — the reverse lookup.</summary>
    public IReadOnlyList<PermissionSource> GroupsGranting(string action) =>
        _byAction.TryGetValue(action, out var list)
            ? list.OrderBy(s => s.GroupName, StringComparer.OrdinalIgnoreCase).ToList()
            : Array.Empty<PermissionSource>();

    /// <summary>Permissions granted by more than one group — duplication worth consolidating.</summary>
    public IReadOnlyList<string> ActionsGrantedByMultipleGroups =>
        _byAction.Where(kv => kv.Value.Select(v => v.GroupId)
                .Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1)
            .Select(kv => kv.Key)
            .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
            .ToList();
}
