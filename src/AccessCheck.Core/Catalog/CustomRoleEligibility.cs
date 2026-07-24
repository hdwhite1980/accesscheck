using System.Text.Json;

namespace AccessCheck.Core.Catalog;

/// <summary>
/// Actions Microsoft REFUSES to put in a custom role.
///
/// Only a subset of directory actions are custom-role eligible. The rest exist, are
/// documented, are granted by built-in roles — and still fail role creation with
/// "Action 'X' is not supported for Custom Role creation". microsoft.directory/users/disable
/// is one: real, in the reference, in built-in roles, and not custom-role eligible.
///
/// Nothing in the resourceActions reference marks this, so it cannot be known in advance.
/// It CAN be learned: the tenant refusing an action is as informative as the tenant
/// accepting one, and it should only ever have to refuse once.
/// </summary>
public sealed class CustomRoleEligibility
{
    public List<string> IneligibleActions { get; set; } = new();
    public DateTimeOffset? LastUpdatedUtc { get; set; }

    /// <summary>Actions a tenant has ACCEPTED in a custom role — proof, not assumption.</summary>
    public List<string> ProvenEligibleActions { get; set; } = new();

    public enum Status { Supported, Unsupported, Unknown }

    /// <summary>
    /// Three states, because "not on the refused list" is not the same as "allowed".
    ///
    /// Only a subset of directory actions are custom-role eligible and NOTHING in the
    /// reference marks which. Treating silence as permission is how a grant gets proposed,
    /// approved, half-executed, and then refused by Microsoft — leaving a real role behind.
    /// Unknown must therefore block a custom-role RECOMMENDATION, not just report it.
    /// </summary>
    public Status Eligibility(string action)
    {
        if (IsIneligible(action)) return Status.Unsupported;
        if (ProvenEligibleActions.Any(a => a.Equals(action, StringComparison.OrdinalIgnoreCase)))
            return Status.Supported;
        return Status.Unknown;
    }

    /// <summary>Records an action the tenant accepted in a custom role it actually created.</summary>
    public bool RecordEligible(string action)
    {
        if (string.IsNullOrWhiteSpace(action)) return false;
        if (IsIneligible(action)) return false;   // a refusal outranks an assumption
        if (ProvenEligibleActions.Any(a => a.Equals(action, StringComparison.OrdinalIgnoreCase)))
            return false;
        ProvenEligibleActions.Add(action.Trim());
        LastUpdatedUtc = DateTimeOffset.UtcNow;
        return true;
    }

    public bool IsIneligible(string action) =>
        IneligibleActions.Any(a => a.Equals(action, StringComparison.OrdinalIgnoreCase));

    /// <summary>Records a refusal. Returns true when this is news.</summary>
    public bool RecordIneligible(string action)
    {
        if (string.IsNullOrWhiteSpace(action) || IsIneligible(action)) return false;
        IneligibleActions.Add(action.Trim());
        LastUpdatedUtc = DateTimeOffset.UtcNow;
        return true;
    }

    /// <summary>
    /// Pulls the action name out of Microsoft's refusal so the app learns the specific
    /// action rather than just that "something" failed.
    /// </summary>
    public static string? ParseRefusedAction(string errorMessage)
    {
        if (string.IsNullOrWhiteSpace(errorMessage)) return null;
        if (!errorMessage.Contains("not supported for Custom Role creation",
                                   StringComparison.OrdinalIgnoreCase)) return null;

        // "Action 'microsoft.directory/users/disable' is not supported for Custom Role creation."
        var open = errorMessage.IndexOf('\'');
        if (open < 0) return null;
        var close = errorMessage.IndexOf('\'', open + 1);
        if (close <= open) return null;

        var action = errorMessage[(open + 1)..close].Trim();
        return action.Length > 0 ? action : null;
    }

    public static CustomRoleEligibility Load(string path)
    {
        if (!File.Exists(path)) return new CustomRoleEligibility();
        try
        {
            var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            return JsonSerializer.Deserialize<CustomRoleEligibility>(File.ReadAllText(path), opts)
                   ?? new CustomRoleEligibility();
        }
        catch (Exception) { return new CustomRoleEligibility(); }
    }

    public void Save(string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(
            this, new JsonSerializerOptions { WriteIndented = true }));
}
