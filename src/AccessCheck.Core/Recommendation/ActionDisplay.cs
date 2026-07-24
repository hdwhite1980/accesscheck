namespace AccessCheck.Core.Recommendation;

/// <summary>
/// Turns a raw catalog action into something readable.
///
/// Exchange and Purview role entries arrive as full cmdlet signatures:
///   (Microsoft.Exchange.Management.PowerShell.E2010) New-ComplianceSearch -AllowNotFound...
/// That is correct to STORE — it is what the tenant returned, and the derived-role recipe
/// needs it — but displaying it makes a card unreadable, and using it in a role name
/// produces a tenant object named after a parameter list. Storage keeps the signature;
/// display and naming use the cmdlet alone.
/// </summary>
public static class ActionDisplay
{
    /// <summary>The cmdlet name alone: "New-ComplianceSearch".</summary>
    public static string? CmdletName(string action)
    {
        var text = action.Trim();

        // Strip a leading "(Namespace)" qualifier.
        if (text.StartsWith("(", StringComparison.Ordinal))
        {
            var close = text.IndexOf(')');
            if (close >= 0) text = text[(close + 1)..].Trim();
        }

        var first = text.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        if (first is null || !first.Contains('-') || first.Contains('/')) return null;

        // Verb-Noun, both starting with a letter — excludes "-AllowNotFound" style parameters.
        var parts = first.Split('-', 2);
        if (parts.Length != 2 || parts[0].Length == 0 || parts[1].Length == 0) return null;
        if (!char.IsLetter(parts[0][0]) || !char.IsLetter(parts[1][0])) return null;

        return first;
    }

    /// <summary>What to put on screen. Resource actions pass through untouched.</summary>
    public static string Short(string action) => CmdletName(action) ?? action;

    /// <summary>The full signature, when it differs — so nothing is silently hidden.</summary>
    public static string? Detail(string action)
    {
        var name = CmdletName(action);
        return name is null || name == action ? null : action;
    }

    /// <summary>A readable subject for naming a role after what it grants.</summary>
    public static string Subject(string action)
    {
        var cmdlet = CmdletName(action);
        if (cmdlet is not null)
        {
            var parts = cmdlet.Split('-', 2);
            return parts.Length == 2 ? parts[1] : cmdlet;
        }

        const string intunePrefix = "Microsoft.Intune_";
        var index = action.IndexOf(intunePrefix, StringComparison.OrdinalIgnoreCase);
        if (index >= 0)
        {
            var rest = action[(index + intunePrefix.Length)..];
            return rest.Split('_').FirstOrDefault() ?? rest;
        }

        if (action.Contains('/'))
        {
            var segments = action.Split('/', StringSplitOptions.RemoveEmptyEntries);
            return segments.Length >= 2 ? segments[1] : (segments.FirstOrDefault() ?? action);
        }
        return action;
    }

    /// <summary>
    /// Resolves what the MODEL said back to the exact catalog string.
    ///
    /// Candidates are sent as stored, so a model naturally replies "New-ComplianceSearch"
    /// rather than the full signature. An exact-match filter then rejects a CORRECT answer
    /// and reports "no match" — worse than useless, because it hides a right answer behind
    /// a wrong verdict.
    /// </summary>
    public static string? Resolve(string proposed, IReadOnlyCollection<string> candidates)
    {
        var wanted = proposed.Trim();
        if (wanted.Length == 0) return null;

        var exact = candidates.FirstOrDefault(c => c.Equals(wanted, StringComparison.OrdinalIgnoreCase));
        if (exact is not null) return exact;

        var byCmdlet = candidates.FirstOrDefault(c =>
            string.Equals(CmdletName(c), wanted, StringComparison.OrdinalIgnoreCase));
        if (byCmdlet is not null) return byCmdlet;

        var proposedCmdlet = CmdletName(proposed);
        if (proposedCmdlet is not null)
        {
            var both = candidates.FirstOrDefault(c =>
                string.Equals(CmdletName(c), proposedCmdlet, StringComparison.OrdinalIgnoreCase));
            if (both is not null) return both;
        }

        return null;
    }
}
