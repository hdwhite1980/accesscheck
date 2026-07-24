using System.Text.Json;

namespace AccessCheck.Core.Catalog;

/// <summary>
/// What a provider can actually do IN THIS TENANT, learned rather than assumed.
///
/// RbacProviders.CustomRoleCapable is a hardcoded list of provider NAMES. A name is not
/// proof: custom-role support also depends on the endpoint being reachable, the tenant
/// being licensed, the cloud supporting it, and the specific permission set being
/// eligible. Windows 365 sits in that list and returns 403 on this tenant for want of a
/// licence — the name said yes and the tenant said no.
///
/// So capability is three-state and observed, in the same shape as CmdletCapability for
/// PowerShell and CustomRoleEligibility for individual actions.
/// </summary>
public sealed class ProviderCapability
{
    public enum State { Supported, Unsupported, Unknown }

    public sealed class Observation
    {
        public string Provider { get; set; } = "";
        /// <summary>Did a custom-role creation actually succeed here?</summary>
        public bool? CustomRoleCreated { get; set; }
        /// <summary>Did the provider's role endpoint answer at all?</summary>
        public bool? EndpointReachable { get; set; }
        public string LastError { get; set; } = "";
        public DateTimeOffset? ObservedUtc { get; set; }
    }

    public List<Observation> Observations { get; set; } = new();

    public Observation For(string provider)
    {
        var existing = Observations.FirstOrDefault(o =>
            o.Provider.Equals(provider, StringComparison.OrdinalIgnoreCase));
        if (existing is not null) return existing;

        var fresh = new Observation { Provider = provider };
        Observations.Add(fresh);
        return fresh;
    }

    /// <summary>
    /// Can this provider create a custom role here?
    ///
    /// Supported only on OBSERVED success. Unsupported on an observed refusal or an
    /// unreachable endpoint. Unknown otherwise — and Unknown must not be read as yes.
    /// </summary>
    public State CanCreateCustomRole(string provider)
    {
        // A provider that does not support custom roles by design is settled without asking.
        if (!RbacProviders.CustomRoleCapable.Contains(provider)
            && !RbacProviders.DerivationCapable.Contains(provider))
            return State.Unsupported;

        var o = Observations.FirstOrDefault(x =>
            x.Provider.Equals(provider, StringComparison.OrdinalIgnoreCase));
        if (o is null) return State.Unknown;

        if (o.EndpointReachable == false) return State.Unsupported;
        if (o.CustomRoleCreated == true) return State.Supported;
        if (o.CustomRoleCreated == false) return State.Unsupported;
        return State.Unknown;
    }

    public void RecordCreation(string provider, bool succeeded, string error = "")
    {
        var o = For(provider);
        o.CustomRoleCreated = succeeded;
        o.EndpointReachable = true;   // it answered, even to refuse
        o.LastError = succeeded ? "" : error;
        o.ObservedUtc = DateTimeOffset.UtcNow;
    }

    public void RecordEndpointFailure(string provider, string error)
    {
        var o = For(provider);
        o.EndpointReachable = false;
        o.LastError = error;
        o.ObservedUtc = DateTimeOffset.UtcNow;
    }

    /// <summary>A line for the operator when capability is not Supported.</summary>
    public string Explain(string provider) => CanCreateCustomRole(provider) switch
    {
        State.Supported => "",
        State.Unsupported =>
            RbacProviders.DisplayName(provider) + " cannot create custom roles here"
            + (For(provider).LastError.Length > 0
                ? " — " + For(provider).LastError : "") + ".",
        _ =>
            "Custom-role support for " + RbacProviders.DisplayName(provider)
            + " has not been confirmed in this tenant, so a custom role is not recommended "
            + "automatically. A built-in role below is the verified route."
    };

    public static ProviderCapability Load(string path)
    {
        if (!File.Exists(path)) return new ProviderCapability();
        try
        {
            var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            return JsonSerializer.Deserialize<ProviderCapability>(File.ReadAllText(path), opts)
                   ?? new ProviderCapability();
        }
        catch (Exception) { return new ProviderCapability(); }
    }

    public void Save(string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(
            this, new JsonSerializerOptions { WriteIndented = true }));
}
