using AccessCheck.Core.Catalog;

namespace AccessCheck.Core.Recommendation;

/// <summary>How much a finding should change what the operator does next.</summary>
public enum GuardSeverity
{
    /// <summary>Worth knowing. Does not by itself argue against approving.</summary>
    Note = 0,
    /// <summary>The grant may not do the job, or does more than was asked.</summary>
    Warning = 1,
    /// <summary>The proposal acts on something other than what was requested.</summary>
    Serious = 2
}

/// <summary>One deterministic finding about a proposal.</summary>
public sealed record GuardFinding
{
    public required GuardSeverity Severity { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; init; }
    /// <summary>The action this concerns, where it concerns one. Empty otherwise.</summary>
    public string Action { get; init; } = "";
    /// <summary>Narrower or more appropriate permissions, where the guard knows of any.</summary>
    public IReadOnlyList<string> Alternatives { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Runs every deterministic guard and returns what they found.
///
/// WHY THIS EXISTS. The guards themselves have always been in Core. What was not was the
/// decision of WHICH to run, in what order, and against what — that lived in the desktop
/// app's code-behind, so only the desktop app ever ran them. Everything else got the
/// verdict without the checks: the CLI, the job-description pipeline, and the tests.
///
/// That cost real findings. A request to remove malicious MESSAGES was answered with
/// Remove-Mailbox — which deletes the mailbox and the user account with it — and passed
/// without comment, because ResourceAmbiguity, the guard whose entire purpose is to notice
/// the right operation on the wrong object, was unreachable from the path that produced it.
/// The same gap let a group-membership duty be answered with access-review permissions.
///
/// ORDER IS PART OF THE ANSWER. Findings are returned in the order they change a decision:
/// what the request asked for that no permission can express, what is not RBAC at all, a
/// wrong resource, a permission nobody asked for, then breadth. An operator who reads only
/// the first line should be reading the one most likely to stop them.
/// </summary>
public static class GuardReport
{
    /// <summary>
    /// Every guard, against one request and its validated outcomes.
    ///
    /// Deliberately takes only what the guards need. It cannot reach a catalog it was not
    /// given, cannot call an endpoint, and returns findings rather than rendering them —
    /// which is what makes it testable, and what stopped it being testable before.
    /// </summary>
    public static IReadOnlyList<GuardFinding> Build(
        string functionDescription,
        IReadOnlyList<ProviderOutcome> outcomes,
        RoleCatalog catalog,
        IReadOnlyDictionary<string, string>? descriptions = null,
        SuggestionConfidence confidence = SuggestionConfidence.High)
    {
        var findings = new List<GuardFinding>();

        var validated = outcomes
            .SelectMany(o => o.Outcome.ValidActions)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // 1. LIMITS NO PERMISSION CAN ENCODE. First because it is the only one that can be
        //    true of a correct proposal — "reset passwords but not for administrators" is a
        //    reasonable request that RBAC cannot express, and approving the permissions
        //    without applying the limit elsewhere grants more than was agreed.
        foreach (var c in RequestConstraints.Detect(functionDescription))
        {
            findings.Add(new GuardFinding
            {
                Severity = GuardSeverity.Warning,
                Title = c.Title + " — \"" + c.Phrase + "\"",
                Detail = c.Guidance
            });
        }

        // 2. NOT AN RBAC QUESTION AT ALL.
        foreach (var f in NonRbacCapability.Findings(functionDescription))
        {
            findings.Add(new GuardFinding
            {
                Severity = GuardSeverity.Warning,
                Title = "Not granted by any role: " + f.Capability,
                Detail = f.Message
            });
        }

        // 3. RIGHT OPERATION, WRONG OBJECT. The most dangerous shape of wrong answer,
        //    because it executes successfully — Remove-Mailbox for a request about deleting
        //    messages does exactly what it says and destroys the mailbox.
        foreach (var a in ResourceAmbiguity.Findings(validated, functionDescription))
        {
            findings.Add(new GuardFinding
            {
                Severity = GuardSeverity.Serious,
                Title = "Possibly the wrong resource: " + a.Chosen,
                Detail = a.Message,
                Action = a.Chosen,
                Alternatives = a.Alternative.Length > 0
                    ? new[] { a.Alternative } : Array.Empty<string>()
            });
        }

        // 4. THE OPPOSITE OF WHAT WAS ASKED — enable offered for a disable request.
        foreach (var i in InversePermissions.Findings(validated, functionDescription))
        {
            findings.Add(new GuardFinding
            {
                Severity = GuardSeverity.Serious,
                Title = "Opposite operation: " + i.Present,
                Detail = i.Message,
                Action = i.Present,
                Alternatives = i.Inverse.Length > 0
                    ? new[] { i.Inverse } : Array.Empty<string>()
            });
        }

        // 5. DOES THE PROPOSAL ACTUALLY DO THE JOB? The only guard looking for too LITTLE.
        //    Under-granting is safe but wastes a grant cycle and erodes trust in the verdict.
        var described = descriptions is null
            ? validated.Select(a => (a, "")).ToList()
            : validated.Select(a => (a, descriptions.TryGetValue(a, out var d) ? d : "")).ToList();

        foreach (var g in CapabilityCoverage.Gaps(functionDescription, described))
        {
            findings.Add(new GuardFinding
            {
                Severity = g.NamesOnly ? GuardSeverity.Note : GuardSeverity.Warning,
                Title = "Cannot " + g.Capability + (g.NamesOnly ? " (unconfirmed)" : ""),
                Detail = g.Message
            });
        }

        // 6. GRANTED THROUGH THE WRONG SERVICE. Per outcome, because the question is whether
        //    THIS provider owns the cmdlet, not whether any of them does.
        foreach (var po in outcomes)
        {
            foreach (var w in CmdletServiceMap.Findings(po.Outcome.ValidActions, po.Provider))
            {
                // Only Message is read here. The desktop app renders nothing else from
                // these findings, and inventing a field the type may not carry would trade
                // a working guard for a compile error.
                findings.Add(new GuardFinding
                {
                    Severity = GuardSeverity.Serious,
                    Title = "Wrong service for a chosen permission ("
                          + RbacProviders.DisplayName(po.Provider) + ")",
                    Detail = w.Message
                });
            }
        }

        // 7. BREADTH. Last because "zero excess" is already reassuring by the time an
        //    operator reaches it, and this is what makes that reassurance false: an action
        //    that IS the whole service needs no excess to grant everything.
        foreach (var b in PermissionBreadth.Findings(validated, catalog))
        {
            findings.Add(new GuardFinding
            {
                Severity = GuardSeverity.Warning,
                Title = "Too broad: " + b.Action,
                Detail = b.Message,
                Action = b.Action,
                Alternatives = b.Examples
            });
        }

        // 8. LOW CONFIDENCE IS A FINDING, NOT A FOOTNOTE. "No confident match" is a real
        //    answer, and burying it under a verdict that looks like every other verdict is
        //    how it stops being read.
        if (confidence != SuggestionConfidence.High)
        {
            findings.Add(new GuardFinding
            {
                Severity = confidence == SuggestionConfidence.None
                    ? GuardSeverity.Serious : GuardSeverity.Warning,
                Title = "Low confidence in this suggestion",
                Detail = confidence == SuggestionConfidence.None
                    ? "Nothing was proposed with any confidence. Treat this as 'no answer "
                      + "found' rather than as a recommendation to review."
                    : "The suggestion did not reach high confidence. Check it against what "
                      + "the person actually needs to do before approving."
            });
        }

        // Most serious first, so reading stops in the right place.
        return findings
            .OrderByDescending(f => f.Severity)
            .ToList();
    }

    /// <summary>Plain text for a console, an email, or the audit record.</summary>
    public static string Describe(IReadOnlyList<GuardFinding> findings)
    {
        if (findings.Count == 0) return "";

        var lines = new List<string>();
        foreach (var f in findings)
        {
            var marker = f.Severity switch
            {
                GuardSeverity.Serious => "!!",
                GuardSeverity.Warning => " !",
                _ => "  "
            };
            lines.Add("  " + marker + " " + f.Title);
            foreach (var line in f.Detail.Split('\n'))
                lines.Add("     " + line.Trim());
            if (f.Alternatives.Count > 0)
                lines.Add("     consider instead: " + string.Join(", ", f.Alternatives.Take(4)));
            lines.Add("");
        }
        return string.Join(Environment.NewLine, lines);
    }
}
