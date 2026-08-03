using AccessCheck.Core.Recommendation;

namespace AccessCheck.Core.Catalog;

/// <summary>
/// Checks a freshly synced catalog for the ways it can be broken WITHOUT anything failing.
///
/// Every expensive bug in this application has had the same shape: two halves that both
/// work, no error anywhere, and a silent fall back to data nothing downstream can use.
///
///   Purview reported 120 roles holding zero permissions between them, and every Purview
///   recommendation was made against an empty dictionary for weeks.
///
///   Exchange held two action formats at once — 2,734 fully-qualified strings and 466 bare
///   cmdlet names — because one of three entry paths did not normalise. Whether an Exchange
///   request worked depended on which path had supplied that role.
///
///   A single role, Mail Recipients, stored 1 cmdlet of the 178 the tenant reports, after a
///   transient error that the per-role try/catch swallowed. Add-MailboxPermission was
///   therefore reported as a permission Microsoft does not define.
///
/// None of these raised anything. Each was found only when someone eventually went looking,
/// and each had been producing wrong recommendations in the meantime. A sync that succeeds
/// while producing an unusable catalog is worse than one that fails, because failure is
/// visible and this is not.
///
/// So this asks the questions no individual sync step is in a position to ask: does the
/// data LOOK like data, and does it look like it did last time.
/// </summary>
public static class CatalogHealth
{
    public enum Severity
    {
        /// <summary>Worth knowing. Does not by itself mean anything is wrong.</summary>
        Note = 0,
        /// <summary>Recommendations for something will be degraded.</summary>
        Warning = 1,
        /// <summary>Recommendations for a whole service cannot work.</summary>
        Broken = 2
    }

    public sealed record Finding
    {
        public required Severity Severity { get; init; }
        public required string Provider { get; init; }
        public required string Title { get; init; }
        public required string Detail { get; init; }
    }

    /// <summary>
    /// Inspects a catalog, optionally against the one it replaced.
    ///
    /// The previous catalog is what makes a COLLAPSE detectable. A role holding one cmdlet
    /// is unremarkable on its own — plenty legitimately do — and alarming if it held a
    /// hundred and seventy-eight an hour ago.
    /// </summary>
    public static IReadOnlyList<Finding> Check(RoleCatalog catalog, RoleCatalog? previous = null)
    {
        var findings = new List<Finding>();

        var providers = catalog.Roles
            .Select(r => r.Provider)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var provider in providers)
        {
            var roles = catalog.Roles
                .Where(r => r.Provider.Equals(provider, StringComparison.OrdinalIgnoreCase))
                .ToList();

            var withActions = roles.Count(r => r.AllowedResourceActions.Count > 0);
            var display = RbacProviders.DisplayName(provider);

            // 1. A PROVIDER WITH ROLES AND NO VOCABULARY. The catalog reports a healthy
            //    count and answers nothing, which is the most expensive shape of all because
            //    the count is the thing people check.
            if (withActions == 0)
            {
                findings.Add(new Finding
                {
                    Severity = Severity.Broken,
                    Provider = provider,
                    Title = display + ": " + roles.Count + " role(s), NO permissions",
                    Detail = "Every role for this service is an empty shell, so no request "
                           + "can be answered from it — and a request that belongs here will "
                           + "be answered from a DIFFERENT service instead, which is how a "
                           + "mailbox request was once answered with a backup permission. "
                           + "Check the service's own sync step actually ran."
                });
                continue;
            }

            // 2. MOSTLY EMPTY. Purview is legitimately like this — Microsoft exposes no role
            //    contents — so it is a warning rather than a break, but the operator should
            //    know how much of the service is unreachable.
            if (withActions < roles.Count / 2)
            {
                findings.Add(new Finding
                {
                    Severity = Severity.Warning,
                    Provider = provider,
                    Title = display + ": only " + withActions + " of " + roles.Count +
                            " role(s) have permissions",
                    Detail = "The rest cannot be recommended. If this service publishes its "
                           + "role contents, the sync is incomplete; if it does not, the "
                           + "documented role list is the only route and may need importing."
                });
            }

            // 3. TWO SHAPES IN ONE PROVIDER. Actions within a service should look alike.
            //    Exchange held path-shaped and cmdlet-shaped strings simultaneously because
            //    one entry path did not normalise, and nothing could match half of them.
            var actions = roles.SelectMany(r => r.AllowedResourceActions)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var qualified = actions.Count(a => a.StartsWith('('));
            if (qualified > 0 && qualified < actions.Count)
            {
                findings.Add(new Finding
                {
                    Severity = Severity.Broken,
                    Provider = provider,
                    Title = display + ": two action formats in one service",
                    Detail = qualified + " of " + actions.Count + " action(s) carry a module "
                           + "qualifier and the rest do not. Nothing downstream can match "
                           + "both, so roughly " + (qualified * 100 / actions.Count) +
                           "% of this service's vocabulary is unreachable. One entry path is "
                           + "not normalising."
                });
            }

            // 4. A ROLE THAT COLLAPSED. Needs the previous catalog: one cmdlet is normal,
            //    one cmdlet where there were 178 is a swallowed transient error.
            if (previous is null) continue;

            foreach (var role in roles)
            {
                var before = previous.Roles.FirstOrDefault(r =>
                    r.Id.Equals(role.Id, StringComparison.OrdinalIgnoreCase) &&
                    r.Provider.Equals(role.Provider, StringComparison.OrdinalIgnoreCase));

                if (before is null) continue;

                var was = before.AllowedResourceActions.Count;
                var now = role.AllowedResourceActions.Count;

                // Ten-fold, and more than a handful lost. A role trimmed by an administrator
                // shrinks a little; a fetch that failed halfway loses nearly everything.
                if (was >= 10 && now * 10 <= was)
                {
                    findings.Add(new Finding
                    {
                        Severity = Severity.Warning,
                        Provider = provider,
                        Title = display + ": '" + role.DisplayName + "' collapsed from " +
                                was + " to " + now + " permission(s)",
                        Detail = "A tenth of what it held last sync. Roles do not usually "
                               + "shrink like this, and a transient failure during the entry "
                               + "fetch produces exactly this result while reporting success. "
                               + "Re-run the sync before trusting recommendations that "
                               + "involve this role."
                    });
                }
            }
        }

        return findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Provider, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>Plain text for a console or a sync report.</summary>
    public static string Describe(IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0) return "";

        var lines = new List<string> { "CATALOG HEALTH:" };
        foreach (var f in findings)
        {
            var marker = f.Severity switch
            {
                Severity.Broken => "  !! ",
                Severity.Warning => "   ! ",
                _ => "     "
            };
            lines.Add(marker + f.Title);
            lines.Add("       " + f.Detail);
        }
        return string.Join(Environment.NewLine, lines);
    }
}
