using System;
using System.Collections.Generic;
using System.Linq;

namespace AccessCheck.Core.Recommendation;

/// <summary>
/// Guards the RESOURCE half of a permission choice.
///
/// TaskCoverage answers "is this the right operation?" — read vs write. Nothing answered
/// "is this the right object?". Three observed failures had the same shape: the permission
/// was real, the verb was right, and the object was wrong
/// (agentUsers instead of users, twice; users/basic instead of users/authenticationMethods).
///
/// Two checks:
///   1. RequestedFamilyNotCovered — the request names a resource family (MFA, password,
///      manager, sessions, licences, UPN) and NOTHING chosen acts on that path segment.
///   2. DistinctObjectType — a chosen action acts on an object type that merely RESEMBLES
///      the requested one. agentUsers is not a narrower users; it is a different object.
///
/// Suggestions are only ever drawn from the candidate list (Microsoft reference UNION tenant).
/// This class never constructs an action string that was not handed to it.
/// </summary>
public static class ResourceFamily
{
    // ---- public shape -------------------------------------------------------------

    public enum FindingKind
    {
        RequestedFamilyNotCovered,
        DistinctObjectType
    }

    public sealed record Finding(
        FindingKind Kind,
        string Family,
        string? OffendingAction,
        string Explanation,
        string? SuggestedAction,
        string SuggestionNote);

    public sealed record Outcome(IReadOnlyList<Finding> Findings)
    {
        public bool HasFindings => Findings.Count > 0;

        public static Outcome None { get; } = new(Array.Empty<Finding>());
    }

    // ---- family table -------------------------------------------------------------

    private sealed record FamilyDefinition(
        string Name,
        string[] RequestKeywords,
        string[] PathSegments,
        bool SegmentsSeenInTenant);

    /// <remarks>
    /// SegmentsSeenInTenant=true means the segment appears verbatim in a synced catalog role
    /// on his tenant. false means the segment name is documented-or-assumed and has NOT been
    /// confirmed against ReferenceStore — a false entry can only ever cause a MISSED finding,
    /// never a wrong one, because a family with no matching candidate produces a finding with
    /// no suggestion rather than an invented action.
    /// </remarks>
    private static readonly FamilyDefinition[] Families =
    {
        new("authentication methods",
            new[]
            {
                "mfa", "multifactor", "multi-factor", "multi factor", "2fa",
                "authentication method", "authenticator", "fido", "security key",
                "passkey", "one-time passcode", "phone sign-in", "re-register", "reregister"
            },
            new[] { "authenticationMethods" },
            true),

        new("password",
            new[] { "password", "passwd" },
            new[] { "password" },
            true),

        new("manager attribute",
            new[]
            {
                "their manager", "manager attribute", "reporting manager",
                "reporting line", "change the manager", "set the manager", "assign a manager"
            },
            new[] { "manager" },
            true),

        new("sign-in sessions",
            new[]
            {
                "session", "sign out", "signout", "sign-out",
                "revoke token", "refresh token", "revoke access"
            },
            new[] { "invalidateAllRefreshTokens" },
            true),

        new("licences",
            new[] { "licence", "license", "sku" },
            new[] { "licenses", "licenseAssignments", "assignLicense" },
            false),

        new("user principal name",
            new[] { "upn", "user principal name", "sign-in name", "rename the account" },
            new[] { "userPrincipalName" },
            false)
    };

    // ---- object types the request can name ----------------------------------------

    private static readonly (string Token, string[] Words)[] ObjectTypes =
    {
        ("users", new[] { "user", "users", "employee", "employees", "staff", "person", "people", "account", "accounts" }),
        ("groups", new[] { "group", "groups", "distribution list", "security group" }),
        ("devices", new[] { "device", "devices", "workstation", "workstations", "laptop", "laptops" }),
        ("applications", new[] { "application", "applications", "app registration", "enterprise app" }),
        ("servicePrincipals", new[] { "service principal", "service principals", "managed identity" })
    };

    // ---- verbs ---------------------------------------------------------------------

    private static readonly (string Verb, string[] Words)[] VerbWords =
    {
        ("update", new[] { "reset", "update", "change", "set", "modify", "edit", "rotate", "manage" }),
        ("create", new[] { "create", "add", "register", "enroll", "enrol", "provision" }),
        ("delete", new[] { "delete", "remove", "revoke", "deregister", "unregister", "deprovision" }),
        ("read", new[] { "read", "view", "see", "list", "audit", "inspect", "report on" })
    };

    private static readonly string[] BreadthOrder = { "basic", "standard", "allProperties", "full" };

    // ---- entry point ---------------------------------------------------------------

    public static Outcome Evaluate(
        string requestText,
        IReadOnlyList<string> chosenActions,
        IReadOnlyList<string> candidateActions)
    {
        if (string.IsNullOrWhiteSpace(requestText) || chosenActions is null || chosenActions.Count == 0)
            return Outcome.None;

        var candidates = candidateActions ?? Array.Empty<string>();
        var text = " " + requestText.ToLowerInvariant() + " ";
        var findings = new List<Finding>();

        var requestedObject = RequestedObjectType(text);
        var intendedVerb = IntendedVerb(text);

        // --- check 1: a named family that nothing chosen acts on ---
        foreach (var family in Families)
        {
            if (!family.RequestKeywords.Any(k => text.Contains(k, StringComparison.Ordinal)))
                continue;

            var covered = chosenActions.Any(a => ActsOnFamily(a, family));
            if (covered)
                continue;

            var suggestion = BestCandidate(candidates, family, requestedObject, intendedVerb);

            var offender = chosenActions.FirstOrDefault(a =>
                requestedObject is not null &&
                string.Equals(ObjectTypeOf(a), requestedObject, StringComparison.OrdinalIgnoreCase) &&
                IsWriteVerb(VerbOf(a)));

            var explanation = offender is null
                ? $"The request is about {family.Name}, and none of the chosen permissions act on that resource."
                : $"The request is about {family.Name}, but {offender} does not act on that resource. " +
                  "It is a write, so the operation check passes — it simply changes something else.";

            findings.Add(new Finding(
                FindingKind.RequestedFamilyNotCovered,
                family.Name,
                offender,
                explanation,
                suggestion,
                suggestion is null
                    ? "No permission acting on that resource was found in the candidate list."
                    : "Found in the candidate list."));
        }

        // --- check 2: an object type that merely resembles the requested one ---
        if (requestedObject is not null)
        {
            foreach (var action in chosenActions)
            {
                var objectType = ObjectTypeOf(action);
                if (objectType is null)
                    continue;
                if (string.Equals(objectType, requestedObject, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!Resembles(objectType, requestedObject))
                    continue;

                var swapped = SwapObjectType(action, objectType, requestedObject);
                var suggestion = swapped is not null && ContainsAction(candidates, swapped) ? swapped : null;

                findings.Add(new Finding(
                    FindingKind.DistinctObjectType,
                    requestedObject,
                    action,
                    $"{action} acts on {objectType}, which is a different object type from {requestedObject} — " +
                    "not a narrower scope of it.",
                    suggestion,
                    suggestion is null
                        ? $"No equivalent {requestedObject} permission was found in the candidate list."
                        : "Found in the candidate list."));
            }
        }

        return findings.Count == 0 ? Outcome.None : new Outcome(findings);
    }

    // ---- action parsing -------------------------------------------------------------

    /// <summary>Segments after the namespace. Null for anything not slash-delimited
    /// (Intune underscore operations, Exchange cmdlet signatures) — those are not judged.</summary>
    private static string[]? PathSegments(string action)
    {
        if (string.IsNullOrWhiteSpace(action))
            return null;

        var parts = action.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
            return null;
        if (!parts[0].Contains('.', StringComparison.Ordinal))
            return null;

        return parts.Skip(1).ToArray();
    }

    private static string? ObjectTypeOf(string action)
    {
        var segments = PathSegments(action);
        return segments is null ? null : segments[0];
    }

    private static string? VerbOf(string action)
    {
        var segments = PathSegments(action);
        return segments is null ? null : segments[^1];
    }

    private static bool ActsOnFamily(string action, FamilyDefinition family)
    {
        var segments = PathSegments(action);
        if (segments is null)
            return false;

        return segments.Any(s => family.PathSegments.Any(f => string.Equals(s, f, StringComparison.OrdinalIgnoreCase)));
    }

    private static bool IsWriteVerb(string? verb)
    {
        if (verb is null)
            return false;
        return !verb.EndsWith("read", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsAction(IReadOnlyList<string> candidates, string action)
    {
        return candidates.Any(c => string.Equals(c, action, StringComparison.OrdinalIgnoreCase));
    }

    // ---- request parsing --------------------------------------------------------------

    private static string? RequestedObjectType(string loweredPaddedText)
    {
        foreach (var (token, words) in ObjectTypes)
        {
            foreach (var w in words)
            {
                if (loweredPaddedText.Contains(" " + w + " ", StringComparison.Ordinal) ||
                    loweredPaddedText.Contains(" " + w + "'", StringComparison.Ordinal) ||
                    loweredPaddedText.Contains(" " + w + ",", StringComparison.Ordinal) ||
                    loweredPaddedText.Contains(" " + w + ".", StringComparison.Ordinal))
                {
                    return token;
                }
            }
        }

        return null;
    }

    private static string? IntendedVerb(string loweredPaddedText)
    {
        foreach (var (verb, words) in VerbWords)
        {
            if (words.Any(w => loweredPaddedText.Contains(" " + w + " ", StringComparison.Ordinal)))
                return verb;
        }

        return null;
    }

    // ---- resemblance ------------------------------------------------------------------

    /// <summary>
    /// True when two object types differ but one is a decorated form of the other —
    /// agentUsers/users, deviceUsers/users. A general rule, not a curated list: the whole
    /// point is that the NEXT collision has not been seen yet.
    /// </summary>
    private static bool Resembles(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase))
            return false;

        var longer = a.Length >= b.Length ? a : b;
        var shorter = a.Length >= b.Length ? b : a;

        if (shorter.Length < 4)
            return false;

        return longer.EndsWith(shorter, StringComparison.OrdinalIgnoreCase) ||
               longer.StartsWith(shorter, StringComparison.OrdinalIgnoreCase);
    }

    private static string? SwapObjectType(string action, string from, string to)
    {
        var parts = action.Split('/');
        for (var i = 0; i < parts.Length; i++)
        {
            if (string.Equals(parts[i], from, StringComparison.OrdinalIgnoreCase))
            {
                parts[i] = to;
                return string.Join("/", parts);
            }
        }

        return null;
    }

    // ---- suggestion ranking -------------------------------------------------------------

    private static string? BestCandidate(
        IReadOnlyList<string> candidates,
        FamilyDefinition family,
        string? requestedObject,
        string? intendedVerb)
    {
        var pool = candidates.Where(c => ActsOnFamily(c, family)).ToList();

        if (requestedObject is not null)
        {
            var narrowed = pool
                .Where(c => string.Equals(ObjectTypeOf(c), requestedObject, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (narrowed.Count > 0)
                pool = narrowed;
        }

        if (intendedVerb is not null)
        {
            var wantsWrite = !string.Equals(intendedVerb, "read", StringComparison.OrdinalIgnoreCase);

            var exact = pool
                .Where(c => string.Equals(VerbOf(c), intendedVerb, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (exact.Count > 0)
            {
                pool = exact;
            }
            else if (wantsWrite)
            {
                var writes = pool.Where(c => IsWriteVerb(VerbOf(c))).ToList();
                if (writes.Count > 0)
                    pool = writes;
            }
        }

        if (pool.Count == 0)
            return null;

        return pool
            .OrderBy(BreadthRank)
            .ThenBy(c => c.Length)
            .ThenBy(c => c, StringComparer.OrdinalIgnoreCase)
            .First();
    }

    private static int BreadthRank(string action)
    {
        var segments = PathSegments(action);
        if (segments is null)
            return BreadthOrder.Length;

        for (var i = 0; i < BreadthOrder.Length; i++)
        {
            if (segments.Any(s => string.Equals(s, BreadthOrder[i], StringComparison.OrdinalIgnoreCase)))
                return i;
        }

        return BreadthOrder.Length;
    }
}
