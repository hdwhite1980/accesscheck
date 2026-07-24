using System.Globalization;
using System.Text.RegularExpressions;

namespace AccessCheck.Core.Execution;

/// <summary>
/// Accepts human-friendly durations ("14 days", "8 hours", "2 weeks", "30d",
/// "1 month") as well as raw ISO 8601 ("P14D", "PT8H"), and produces both the
/// ISO string the Graph/PIM APIs need and an approximate TimeSpan for
/// app-tracked expiry (months approximated as 30 days).
/// </summary>
public static partial class DurationParser
{
    /// <summary>
    /// A parsed duration. Permanent means no automatic removal at all: PIM gets
    /// expiration type "noExpiration" and non-PIM grants get no tracked expiry, so
    /// housekeeping will never revoke them.
    /// </summary>
    public sealed record DurationSpec(bool Permanent, string Iso, TimeSpan Approx)
    {
        public static DurationSpec Forever => new(true, "", TimeSpan.Zero);

        public string Describe() => Permanent
            ? "PERMANENT — no expiry, access remains until removed by hand"
            : Iso + "  (expires ~" +
              (DateTimeOffset.UtcNow + Approx).ToString("yyyy-MM-dd HH:mm 'UTC'") + ")";
    }

    private static readonly string[] PermanentWords =
    {
        "never", "permanent", "permanently", "none", "no expiry", "no expiration",
        "noexpiry", "noexpiration", "forever", "indefinite", "indefinitely", "always"
    };

    /// <summary>Parses a duration, including the permanent forms ("never", "permanent", "no expiry").</summary>
    public static bool TryParseSpec(string input, out DurationSpec spec)
    {
        var s = (input ?? "").Trim();
        if (PermanentWords.Contains(s, StringComparer.OrdinalIgnoreCase))
        {
            spec = DurationSpec.Forever;
            return true;
        }
        if (TryParse(s, out var iso, out var approx))
        {
            spec = new DurationSpec(false, iso, approx);
            return true;
        }
        spec = DurationSpec.Forever;
        return false;
    }

    public static bool TryParse(string input, out string iso, out TimeSpan approx)
    {
        iso = "";
        approx = TimeSpan.Zero;
        var s = (input ?? "").Trim();
        if (s.Length == 0) return false;

        // Raw ISO 8601 passes through after validation.
        if (s.StartsWith("P", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                approx = System.Xml.XmlConvert.ToTimeSpan(s.ToUpperInvariant());
                iso = s.ToUpperInvariant();
                return approx > TimeSpan.Zero;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        var m = FriendlyPattern().Match(s.ToLowerInvariant());
        if (!m.Success) return false;
        if (!int.TryParse(m.Groups["n"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var n)
            || n <= 0) return false;

        switch (m.Groups["unit"].Value)
        {
            case "minute": case "minutes": case "min": case "mins": case "m":
                iso = "PT" + n + "M"; approx = TimeSpan.FromMinutes(n); return true;
            case "hour": case "hours": case "hr": case "hrs": case "h":
                iso = "PT" + n + "H"; approx = TimeSpan.FromHours(n); return true;
            case "day": case "days": case "d":
                iso = "P" + n + "D"; approx = TimeSpan.FromDays(n); return true;
            case "week": case "weeks": case "wk": case "wks": case "w":
                iso = "P" + (n * 7) + "D"; approx = TimeSpan.FromDays(n * 7); return true;
            case "month": case "months": case "mo": case "mos":
                iso = "P" + n + "M"; approx = TimeSpan.FromDays(n * 30); return true;
            default:
                return false;
        }
    }

    /// <summary>Short human description of a parsed duration, for UI previews.</summary>
    public static string Describe(string iso, TimeSpan approx) =>
        iso + "  (expires ~" +
        (DateTimeOffset.UtcNow + approx).ToString("yyyy-MM-dd HH:mm 'UTC'") + ")";

    [GeneratedRegex(@"^(?<n>\d{1,4})\s*(?<unit>[a-z]+)$")]
    private static partial Regex FriendlyPattern();
}
