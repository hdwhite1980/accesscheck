namespace AccessLens.Core.Execution;

public enum AssignmentType
{
    /// <summary>Time-boxed active assignment: access is live immediately and PIM removes it at expiry.</summary>
    Active,
    /// <summary>Eligible assignment: user self-activates via PIM per policy (max 8h per activation).</summary>
    Eligible
}

/// <summary>
/// The approved, execution-ready plan. Built ONLY after a human clicks Approve.
/// Maps to POST /roleManagement/directory/roleAssignmentScheduleRequests (Active)
/// or /roleEligibilityScheduleRequests (Eligible) with scheduleInfo.expiration afterDuration.
/// </summary>
public sealed record AssignmentPlan
{
    public required string PrincipalId { get; init; }
    public required string RoleDefinitionId { get; init; }
    public required string Justification { get; init; }
    public AssignmentType Type { get; init; } = AssignmentType.Active;
    /// <summary>ISO 8601 duration, e.g. "P14D", "PT8H". PIM enforces expiry server-side.</summary>
    public required string Duration { get; init; }
    public string DirectoryScopeId { get; init; } = "/";
}
