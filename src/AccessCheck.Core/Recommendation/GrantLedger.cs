namespace AccessCheck.Core.Recommendation;

/// <summary>
/// An ordered, verified record of what a grant actually did.
///
/// WHY. A grant is several writes: create or reuse a role, create or reuse a group, attach
/// the role, add the member. Firing them in sequence and throwing on the first failure
/// leaves real objects in the tenant with no record of which ones — an Intune role created,
/// an Entra role created, no assignment, and a dialog implying nothing happened.
///
/// So every step VERIFIES before the next one starts, and every outcome is recorded.
/// When something fails the operator is told exactly what exists now, what does not, and
/// what to do about it — rather than being left to work it out from the portal.
/// </summary>
public sealed class GrantLedger
{
    public enum StepState { NotReached, Skipped, Succeeded, Verified, Failed }

    public sealed record Step
    {
        public required string Name { get; init; }
        public required StepState State { get; set; }
        /// <summary>What now exists because of this step, if anything.</summary>
        public string? Artifact { get; set; }
        public string? Detail { get; set; }

        public string Describe() => State switch
        {
            StepState.Verified  => "  [verified] " + Name
                                   + (Artifact is null ? "" : " -> " + Artifact),
            StepState.Succeeded => "  [done, unverified] " + Name
                                   + (Artifact is null ? "" : " -> " + Artifact)
                                   + (Detail is null ? "" : "  (" + Detail + ")"),
            StepState.Skipped   => "  [skipped] " + Name
                                   + (Detail is null ? "" : "  (" + Detail + ")"),
            StepState.Failed    => "  [FAILED] " + Name
                                   + (Detail is null ? "" : "  " + Detail),
            _                   => "  [not reached] " + Name
        };
    }

    public string Provider { get; init; } = "";
    public List<Step> Steps { get; } = new();

    public Step Begin(string name)
    {
        var step = new Step { Name = name, State = StepState.NotReached };
        Steps.Add(step);
        return step;
    }

    public bool AnyFailed => Steps.Any(s => s.State == StepState.Failed);

    /// <summary>Objects that now exist in the tenant because of this attempt.</summary>
    public IReadOnlyList<string> Created =>
        Steps.Where(s => s.Artifact is not null &&
                         (s.State == StepState.Verified || s.State == StepState.Succeeded))
             .Select(s => s.Artifact!)
             .ToList();

    /// <summary>
    /// The whole story, for a dialog or the history record. Deliberately includes the
    /// steps that SUCCEEDED — those are the ones that left something behind.
    /// </summary>
    public string Report()
    {
        var lines = new List<string> { "Steps attempted:" };
        lines.AddRange(Steps.Select(s => s.Describe()));

        var created = Created;
        if (created.Count > 0)
        {
            lines.Add("");
            lines.Add(AnyFailed
                ? "These were created before the failure and STILL EXIST in your tenant:"
                : "Created:");
            lines.AddRange(created.Select(c => "  * " + c));
            if (AnyFailed)
            {
                lines.Add("");
                lines.Add("They carry the AC- / ACG- prefix and are listed on the Housekeeping "
                          + "tab. Re-running reuses them rather than creating duplicates.");
            }
        }
        return string.Join(Environment.NewLine, lines);
    }
}
