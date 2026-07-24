namespace AccessCheck.Core.Recommendation;

/// <summary>
/// Constraints a request expresses that PERMISSIONS CANNOT ENCODE.
///
/// "Reset passwords for standard users but not administrators" names a real, common,
/// entirely reasonable requirement — and no permission string expresses it.
/// microsoft.directory/users/password/update resets anyone. The exclusion is achieved by
/// SCOPE (an administrative unit) or by a role whose restriction is built into the product
/// (Password Administrator cannot touch privileged accounts), never by choosing a
/// different permission.
///
/// Without this the app returns the permission and implies the whole request is satisfied
/// — the quiet over-grant it exists to prevent.
/// </summary>
public static class RequestConstraints
{
    public enum Kind { Exclusion, Restriction, ReadOnlyIntent }

    public sealed record Finding
    {
        public required Kind Kind { get; init; }
        public required string Phrase { get; init; }
        public required string Guidance { get; init; }

        public string Title => Kind switch
        {
            Kind.Exclusion => "Exclusion requested",
            Kind.Restriction => "Scope restriction requested",
            _ => "Read-only intent stated"
        };
    }

    private static readonly string[] ExclusionMarkers =
    {
        "but not", "except", "excluding", "other than", "apart from",
        "should not be able", "must not be able", "cannot touch", "not for admin",
        "no admin", "non-admin", "not administrators", "not privileged"
    };

    private static readonly string[] RestrictionMarkers =
    {
        "only for", "only in", "limited to", "restricted to", "scoped to",
        "just for", "just the", "confined to", "within the", "for the team",
        "for their department", "for their site", "for their region",
        // "their own team" is how anyone actually phrases a scope limit.
        "their own", "his own", "her own", "own team", "own department",
        "own users", "own devices", "own site", "themselves", "their team",
        "their department", "their users", "their devices", "that they own",
        "they manage", "they own", "assigned to them", "in their group"
    };

    private static readonly string[] ReadOnlyMarkers =
    {
        "without being able to change", "without changing", "without modifying",
        "read only", "read-only", "view only", "view-only", "cannot edit",
        "not be able to edit", "not be able to modify", "look but not"
    };

    public static IReadOnlyList<Finding> Detect(string functionDescription)
    {
        var text = functionDescription.ToLowerInvariant();
        var findings = new List<Finding>();

        var exclusion = ExclusionMarkers.FirstOrDefault(m => text.Contains(m, StringComparison.Ordinal));
        if (exclusion is not null)
        {
            findings.Add(new Finding
            {
                Kind = Kind.Exclusion,
                Phrase = exclusion,
                Guidance =
                    "No permission can express an exclusion. Granting the permission grants it " +
                    "for every object it covers.\n\n" +
                    "Achieve the exclusion one of these ways instead:\n" +
                    "* A RESTRICTED BUILT-IN ROLE, where the limit is enforced by the product. " +
                    "Password Administrator can reset passwords for non-administrators but is " +
                    "blocked from privileged accounts — a custom role built from the raw " +
                    "password permission has no such restriction and would be MORE privileged " +
                    "than the built-in role.\n" +
                    "* An ADMINISTRATIVE UNIT containing only the objects in scope, with the " +
                    "role assigned over that AU rather than the whole tenant.\n" +
                    "* For Intune, SCOPE TAGS limiting which objects the role can act on."
            });
        }

        var restriction = RestrictionMarkers.FirstOrDefault(m => text.Contains(m, StringComparison.Ordinal));
        if (restriction is not null)
        {
            findings.Add(new Finding
            {
                Kind = Kind.Restriction,
                Phrase = restriction,
                Guidance =
                    "A \"who or what can this apply to\" limit is SCOPE, not permission. The " +
                    "permissions say what may be done; they do not say to whom.\n\n" +
                    "Set the scope when the grant is approved:\n" +
                    "* Entra directory roles — assign over an ADMINISTRATIVE UNIT rather than " +
                    "tenant-wide (the Directory scope control on the approve panel).\n" +
                    "* Intune — SCOPE TAGS on the role assignment.\n" +
                    "* Azure resources — assign at the resource group or resource, not the " +
                    "subscription.\n\n" +
                    "\"Their own team\" specifically usually means a DYNAMIC administrative unit " +
                    "whose membership rule matches the manager's department, or one AU per team. " +
                    "It is per-person scope, so one tenant-wide grant cannot express it however " +
                    "the permissions are chosen."
            });
        }

        var readOnly = ReadOnlyMarkers.FirstOrDefault(m => text.Contains(m, StringComparison.Ordinal));
        if (readOnly is not null)
        {
            findings.Add(new Finding
            {
                Kind = Kind.ReadOnlyIntent,
                Phrase = readOnly,
                Guidance =
                    "Read-only was stated explicitly. Check the proposal contains no create, " +
                    "update, delete or allTasks permission — if it does, it exceeds what was " +
                    "asked for."
            });
        }

        return findings;
    }
}

/// <summary>
/// Permissions that appear together but were not both asked for.
///
/// A request to disable an account does not ask for the ability to re-enable it. Padding a
/// proposal with the inverse verb is the commonest quiet over-grant, and it is detectable
/// without asking the model to grade its own work.
/// </summary>
public static class InversePermissions
{
    private static readonly (string Left, string Right)[] Pairs =
    {
        ("disable", "enable"), ("block", "unblock"), ("revoke", "grant"),
        ("remove", "create"), ("delete", "create"), ("archive", "restore"),
        ("suspend", "resume"), ("retire", "enroll"), ("wipe", "provision")
    };

    public sealed record Finding
    {
        public required string Present { get; init; }
        public required string Inverse { get; init; }
        public required string Message { get; init; }
    }

    public static IReadOnlyList<Finding> Findings(
        IReadOnlyCollection<string> actions, string functionDescription)
    {
        var text = functionDescription.ToLowerInvariant();
        var results = new List<Finding>();

        foreach (var action in actions)
        {
            var a = action.ToLowerInvariant();
            foreach (var (left, right) in Pairs)
            {
                foreach (var (verb, opposite) in new[] { (left, right), (right, left) })
                {
                    if (!a.Contains(verb, StringComparison.Ordinal)) continue;
                    // The request asked for this verb — fine.
                    if (text.Contains(verb, StringComparison.Ordinal)) continue;
                    // The proposal contains the OPPOSITE of something that was asked for.
                    if (!text.Contains(opposite, StringComparison.Ordinal)) continue;

                    results.Add(new Finding
                    {
                        Present = action,
                        Inverse = opposite,
                        Message =
                            $"'{action}' was not asked for. The request mentions '{opposite}', " +
                            "and this is its inverse — granting both is broader than the task requires."
                    });
                }
            }
        }
        return results;
    }
}

/// <summary>
/// Resources whose names collide on a common word, where the wrong pick is plausible and
/// the consequences are very different. "Manage app protection policies" and App Control
/// for Business both contain "app", but app protection is MAM (ManagedApps) while App
/// Control is application allowlisting (formerly WDAC).
/// </summary>
public static class ResourceAmbiguity
{
    public sealed record Finding
    {
        public required string Chosen { get; init; }
        public required string Alternative { get; init; }
        public required string Message { get; init; }
    }

    private static readonly (string Trigger, string Chosen, string Other, string Note)[] Collisions =
    {
        ("app protection", "AppControlPolicy", "ManagedApps",
         "App protection policies are MAM and live under ManagedApps. AppControlPolicy is " +
         "App Control for Business (formerly WDAC) — application allowlisting, a different " +
         "product solving a different problem."),
        ("app control", "ManagedApps", "AppControlPolicy",
         "App Control for Business is application allowlisting (AppControlPolicy). " +
         "ManagedApps is app protection / MAM."),
        ("compliance polic", "SecurityBaselines", "DeviceCompliancePolic",
         "Device compliance policies are DeviceCompliancePolicies. Security baselines are a " +
         "separate resource — a bundle of recommended settings, not a compliance rule."),
        ("configuration profile", "SecurityBaselines", "DeviceConfigurations",
         "Configuration profiles are DeviceConfigurations. Security baselines are a different resource."),
        ("conditional access", "conditionalAccessPolicies", "namedLocations",
         "Conditional Access policies and named locations are separate resources; a policy " +
         "read does not include location management."),
        ("mobile app", "AppControlPolicy", "MobileApps",
         "Mobile app deployment is MobileApps. AppControlPolicy is application allowlisting " +
         "on Windows endpoints.")
    };

    /// <summary>Guidance for the model BEFORE it chooses. Preventing beats correcting.</summary>
    public static IReadOnlyList<string> PromptHints(string functionDescription)
    {
        var text = functionDescription.ToLowerInvariant();
        return Collisions
            .Where(c => text.Contains(c.Trigger, StringComparison.Ordinal))
            .Select(c => $"- The request mentions \"{c.Trigger}\". {c.Note} Choose permissions " +
                         $"on {c.Other}, NOT {c.Chosen}.")
            .ToList();
    }

    /// <summary>ONE finding per collision, listing every affected action.</summary>
    public static IReadOnlyList<Finding> Findings(
        IReadOnlyCollection<string> actions, string functionDescription)
    {
        var text = functionDescription.ToLowerInvariant();
        var results = new List<Finding>();

        foreach (var rule in Collisions)
        {
            if (!text.Contains(rule.Trigger, StringComparison.Ordinal)) continue;

            // Only complain if the RIGHT resource was not also chosen.
            if (actions.Any(a => a.Contains(rule.Other, StringComparison.OrdinalIgnoreCase))) continue;

            var affected = actions
                .Where(a => a.Contains(rule.Chosen, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (affected.Count == 0) continue;

            var list = affected.Count == 1
                ? $"'{affected[0]}'"
                : $"{affected.Count} permissions on {rule.Chosen}";

            results.Add(new Finding
            {
                Chosen = string.Join(", ", affected),
                Alternative = rule.Other,
                Message =
                    $"The request says \"{rule.Trigger}\", but {list} target a different " +
                    $"resource. {rule.Note} Look for permissions on {rule.Other} instead." +
                    (affected.Count > 1 ? "\n\nAffected: " + string.Join(", ", affected) : "")
            });
        }
        return results;
    }
}

/// <summary>
/// Capabilities configured somewhere other than RBAC entirely. Approvers in entitlement
/// management are named per access-package policy; no permission grant makes someone an
/// approver. Returning a plausible-looking permission for these is worse than saying so —
/// it grants something broader than was asked for.
/// </summary>
public static class NonRbacCapability
{
    public sealed record Finding
    {
        public required string Capability { get; init; }
        public required string Where { get; init; }
        public required string Message { get; init; }
    }

    private static readonly (string[] Markers, string Capability, string Where, string Note)[] Rules =
    {
        (new[] { "approve access request", "approver", "approve requests", "approval workflow" },
         "Being an approver", "the access package policy",
         "Approvers are named IN THE ACCESS PACKAGE POLICY (Identity Governance > Entitlement " +
         "management > the package > Policies > Requests). No RBAC permission makes someone an " +
         "approver. Granting entitlement management permissions instead would let them " +
         "ADMINISTER packages — far more than approving requests for their own team."),

        (new[] { "access review", "review campaign", "certify access" },
         "Running an access review", "the access review definition",
         "Reviewers are named in the ACCESS REVIEW DEFINITION itself. An RBAC permission grants " +
         "the ability to CREATE and manage reviews, which is broader than being a reviewer on one."),

        (new[] { "break glass", "emergency account", "break-glass" },
         "Break-glass access", "a permanently assigned excluded account",
         "Break-glass accounts are deliberately excluded from Conditional Access and hold " +
         "standing Global Administrator. That is a design decision, not a grant this tool " +
         "should broker."),

        (new[] { "self-service password reset", "sspr", "reset their own password" },
         "Self-service password reset", "the SSPR policy",
         "SSPR is enabled by policy for a group of users; it is not an admin permission.")
    };

    public static IReadOnlyList<Finding> Findings(string functionDescription)
    {
        var text = functionDescription.ToLowerInvariant();
        return Rules
            .Where(r => r.Markers.Any(m => text.Contains(m, StringComparison.Ordinal)))
            .Select(r => new Finding { Capability = r.Capability, Where = r.Where, Message = r.Note })
            .ToList();
    }
}
