namespace AccessCheck.Core.Recommendation;

/// <summary>
/// Does this permission actually DO what was asked?
///
/// Existence checks prove a permission is real. They say nothing about whether it performs
/// the requested operation — so a read-only action can pass every guard and be granted for
/// a delete task. authenticationMethods/standard/restrictedRead is real, documented, and
/// present in built-in roles, and it cannot delete anything.
///
/// This is the mechanical half of task coverage: the OPERATION implied by the request
/// versus the operation the permission performs. It deliberately does not attempt semantic
/// judgement beyond that — a wrong answer here would be worse than silence, so anything
/// unclear returns Unknown rather than a guess.
/// </summary>
public static class TaskCoverage
{
    public enum Status { Verified, Partial, Contradicted, Unknown }

    public sealed record Result
    {
        public required string Action { get; init; }
        public required Status Status { get; init; }
        public required string Reason { get; init; }
    }

    /// <summary>Operations a request can ask for, and the words that signal each.</summary>
    private static readonly (string Op, string[] Words)[] RequestedOperations =
    {
        ("delete",  new[] { "delete", "remove", "purge", "wipe", "destroy", "erase", "revoke" }),
        ("create",  new[] { "create", "add", "provision", "onboard", "register" }),
        ("update",  new[] { "update", "change", "modify", "edit", "reset", "configure", "set ",
                            "enable", "disable", "assign", "approve" }),
        ("read",    new[] { "read", "view", "see", "inspect", "investigate", "audit", "report",
                            "list", "check", "look" })
    };

    /// <summary>Markers in the ACTION NAME or its description that indicate read-only.</summary>
    private static readonly string[] ReadOnlyMarkers =
        { "/read", "read", "restrictedread", "getslist", "_read", "view", "standard/read" };

    private static readonly string[] WriteMarkers =
        { "create", "update", "delete", "write", "manage", "alltasks", "allproperties",
          "remove", "reset", "set", "add", "wipe", "revoke", "purge", "enable", "disable",
          "retire", "assign", "execute", "start", "invoke", "new-", "remove-", "set-" };

    /// <summary>
    /// Compares the operation the REQUEST asks for against what the ACTION performs.
    /// Only returns Contradicted when both sides are clear and they conflict.
    /// </summary>
    public static Result Evaluate(string? functionDescription, string? action, string? description)
    {
        // Normalise ONCE into non-null locals. Guarding with `?? ""` at the point of use
        // told the compiler the parameter might be null and then assigned it straight into
        // a required non-null property — hence CS8601 four times over.
        var safeAction = action ?? "";
        var text = (functionDescription ?? "").ToLowerInvariant();
        var name = safeAction.ToLowerInvariant();
        var desc = (description ?? "").ToLowerInvariant();

        var requested = RequestedOperations
            .Where(o => o.Words.Any(w => text.Contains(w, StringComparison.Ordinal)))
            .Select(o => o.Op)
            .ToList();

        var wantsChange = requested.Any(o => o is "delete" or "create" or "update");
        if (!wantsChange)
        {
            // A read request satisfied by anything is fine; a read request satisfied by a
            // WRITE permission is over-granting, which other guards already cover.
            return new Result
            {
                Action = safeAction,
                Status = Status.Unknown,
                Reason = "The request does not clearly ask for a state change, so operation "
                       + "matching cannot decide this either way."
            };
        }

        // Is the action read-only? Judge on the name first — it is structured — then the
        // description, which is prose and less reliable.
        var looksWrite = WriteMarkers.Any(m => name.Contains(m, StringComparison.Ordinal));
        var looksRead = !looksWrite && ReadOnlyMarkers.Any(m =>
            name.Contains(m, StringComparison.Ordinal));

        if (looksRead)
        {
            var op = requested.First(o => o is "delete" or "create" or "update");
            return new Result
            {
                Action = safeAction,
                Status = Status.Contradicted,
                Reason = $"The request asks to {op}, but this permission is READ-ONLY — it "
                       + "cannot perform that operation. Granting it would not achieve the task."
            };
        }

        if (looksWrite)
        {
            return new Result
            {
                Action = safeAction,
                Status = Status.Verified,
                Reason = "The permission performs a state change, matching the operation the "
                       + "request asks for."
            };
        }

        return new Result
        {
            Action = safeAction,
            Status = Status.Unknown,
            Reason = string.IsNullOrWhiteSpace(desc)
                ? "No Microsoft description is available for this permission, so its "
                  + "operation could not be confirmed."
                : "The permission's operation could not be determined from its name or "
                  + "description."
        };
    }

    public static IReadOnlyList<Result> EvaluateAll(
        string? functionDescription,
        IEnumerable<(string Action, string Description)> actions) =>
        actions.Select(a => Evaluate(functionDescription, a.Action, a.Description)).ToList();
}
