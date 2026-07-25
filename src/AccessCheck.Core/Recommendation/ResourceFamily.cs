// BUILD MARKER: ResourceFamily r4 — Check + Correct + Swap + read-does-not-cover-family.
// Verify the file on disk is this one:
//   Select-String -Path ResourceFamily.cs -Pattern "public sealed record Swap"
// If that returns nothing, you have an older copy and RecommendationModels.cs will not
// compile (CS0426: the type name 'Swap' does not exist in the type 'ResourceFamily').

namespace AccessCheck.Core.Recommendation;

/// <summary>
/// Guards the RESOURCE half of a permission choice.
///
/// TaskCoverage answers "is this the right OPERATION?" — read versus write. Nothing
/// answered "is this the right OBJECT?". Three observed failures had the same shape:
/// the permission was real, the verb was right, and the object was wrong —
/// agentUsers instead of users (twice), then users/basic instead of
/// users/authenticationMethods. users/basic/update IS a write, so the operation check
/// passes; it simply writes display names and phone numbers.
///
/// Two checks:
///   1. FamilyNotCovered — the request names a resource family (authentication methods,
///      password, manager, sessions, licences, UPN) and NOTHING chosen acts on it.
///   2. DistinctObject — a chosen action acts on an object type that merely RESEMBLES
///      the requested one. agentUsers is not a narrower users; it is a different object.
///
/// The valuable half is naming the better candidate, which is usually findable because
/// it sits in the same catalog — in the MFA case it was in the excess list of the very
/// role the app then recommended. Suggestions are drawn ONLY from the candidate pool
/// passed in; this class never constructs an action string it was not handed.
/// </summary>
public static class ResourceFamily
{
    public enum FindingKind
    {
        FamilyNotCovered,
        DistinctObject
    }

    /// <summary>
    /// One wrong-resource finding. <see cref="Action"/> is the permission to swap OUT and
    /// is empty when nothing chosen was close enough to blame; <see cref="Better"/> is the
    /// permission to swap IN, null when the candidate pool held nothing that fits.
    /// </summary>
    public sealed record Finding
    {
        public required FindingKind Kind { get; init; }
        public required string Family { get; init; }
        public required string Action { get; init; }
        public required string Message { get; init; }
        public string? Better { get; init; }
    }

    // ---- family table --------------------------------------------------------------

    private sealed record FamilyDefinition(
        string Name,
        string[] RequestKeywords,
        string[] PathSegments);

    /// <remarks>
    /// PathSegments are matched against the action path, never against a curated list of
    /// whole action names — so a family whose segment name is wrong can only ever cause a
    /// MISSED finding, never a false one: with no matching candidate the finding carries a
    /// null Better rather than an invented permission.
    /// authenticationMethods / password / manager / invalidateAllRefreshTokens are verbatim
    /// from the synced catalog. The licence and UPN segments are NOT confirmed against
    /// ReferenceStore.
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
            new[] { "authenticationMethods" }),

        new("password",
            new[] { "password", "passwd" },
            new[] { "password" }),

        new("manager attribute",
            new[]
            {
                "their manager", "manager attribute", "reporting manager", "reporting line",
                "change the manager", "set the manager", "assign a manager"
            },
            new[] { "manager" }),

        new("sign-in sessions",
            new[]
            {
                "session", "sign out", "signout", "sign-out",
                "revoke token", "refresh token", "revoke access"
            },
            // A family is covered by ANY segment that acts on it. Listing only
            // invalidateAllRefreshTokens made agentUsers/revokeSignInSessions read as "does
            // not act on sessions", which is false — it acts on sessions, just on the wrong
            // object. That is check 2's job to report, not check 1's.
            new[] { "invalidateAllRefreshTokens", "revokeSignInSessions", "signInSessions" }),

        new("licences",
            new[] { "licence", "license", "sku" },
            new[] { "licenses", "licenseAssignments", "assignLicense" }),

        new("user principal name",
            new[] { "upn", "user principal name", "sign-in name", "rename the account" },
            new[] { "userPrincipalName" })
    };

    private static readonly (string Token, string[] Words)[] ObjectTypes =
    {
        ("users", new[] { "user", "users", "employee", "employees", "staff", "person", "people", "account", "accounts" }),
        ("groups", new[] { "group", "groups", "distribution list", "security group" }),
        ("devices", new[] { "device", "devices", "workstation", "workstations", "laptop", "laptops" }),
        ("applications", new[] { "application", "applications", "app registration", "enterprise app" }),
        ("servicePrincipals", new[] { "service principal", "service principals", "managed identity" })
    };

    private static readonly (string Verb, string[] Words)[] VerbWords =
    {
        ("update", new[] { "reset", "update", "change", "set", "modify", "edit", "rotate", "manage" }),
        ("create", new[] { "create", "add", "register", "enroll", "enrol", "provision" }),
        ("delete", new[] { "delete", "remove", "revoke", "deregister", "unregister", "deprovision" }),
        ("read", new[] { "read", "view", "see", "list", "audit", "inspect" })
    };

    /// <summary>Narrower write scopes first, so a swap never widens privilege.</summary>
    private static readonly string[] BreadthOrder = { "basic", "standard", "allProperties", "full" };

    // ---- entry point ----------------------------------------------------------------

    public static IReadOnlyList<Finding> Check(
        string requestText,
        IEnumerable<string> chosenActions,
        IEnumerable<string> candidateActions)
    {
        var findings = new List<Finding>();
        if (string.IsNullOrWhiteSpace(requestText)) return findings;

        var chosen = (chosenActions ?? Enumerable.Empty<string>())
            .Where(a => !string.IsNullOrWhiteSpace(a)).ToList();
        if (chosen.Count == 0) return findings;

        var candidates = (candidateActions ?? Enumerable.Empty<string>())
            .Where(a => !string.IsNullOrWhiteSpace(a)).ToList();

        // A FORBIDDEN RESOURCE IS NOT A REQUIRED ONE — and this guard does not merely warn,
        // it CHANGES THE PERMISSION SET. On "They should not be able to create normal user
        // accounts or manage anyone's licences", the word "licences" appears only in the
        // prohibition, and Correct() responded by ADDING users/assignLicense. The app granted
        // exactly what the operator had excluded, which is the one failure mode worse than a
        // false warning.
        var text = " " + RequestNegation.Positive(requestText).ToLowerInvariant() + " ";
        var requestedObject = RequestedObjectType(text);
        var intendedVerb = IntendedVerb(text);
        var wantsStateChange = intendedVerb is not null
            && !intendedVerb.Equals("read", StringComparison.OrdinalIgnoreCase);

        // --- 1. a named family that nothing chosen acts on ---
        foreach (var family in Families)
        {
            if (!family.RequestKeywords.Any(k => text.Contains(k, StringComparison.Ordinal)))
                continue;
            // A READ ACTION DOES NOT COVER THE FAMILY FOR A WRITE TASK.
            //
            // This is what made the guard silent on "reset MFA methods": the model chose
            // authenticationMethods/standard/restrictedRead alongside users/basic/update.
            // restrictedRead DOES act on authentication methods, so the family read as
            // covered and nothing was flagged — then TaskCoverage stripped the read action
            // afterwards, leaving a requirement set with nothing on the family at all.
            // The same rule TaskCoverage applies has to apply here, or a read permission
            // masks the missing write until it is too late to correct it.
            if (chosen.Any(a => ActsOnFamily(a, family)
                                && (!wantsStateChange || IsWriteVerb(VerbOf(a)))))
                continue;

            // Blame the closest thing chosen: same object, and a WRITE, because that is the
            // one that slipped past the operation check.
            var offender = chosen.FirstOrDefault(a =>
                requestedObject is not null
                && string.Equals(ObjectTypeOf(a), requestedObject, StringComparison.OrdinalIgnoreCase)
                && IsWriteVerb(VerbOf(a))
                // ...and is NOT already doing a job the request explicitly named. A compound
                // request ("disable their account, revoke their sessions, wipe their laptop")
                // is several tasks; blaming users/disable for not revoking sessions punishes
                // a permission that was chosen correctly for a different clause.
                && !DoesAJobTheRequestNamed(a, text));

            var message = offender is null
                ? "The request is about " + family.Name +
                  ", and none of the chosen permissions act on that resource."
                : "The request is about " + family.Name + ", but " + offender +
                  " does not act on that resource. It is a write, so the operation check " +
                  "passes — it simply changes something else.";

            findings.Add(new Finding
            {
                Kind = FindingKind.FamilyNotCovered,
                Family = family.Name,
                Action = offender ?? "",
                Message = message,
                Better = BestCandidate(candidates, family, requestedObject, intendedVerb)
            });
        }

        // --- 2. an object type that merely resembles the requested one ---
        if (requestedObject is not null)
        {
            foreach (var action in chosen)
            {
                var objectType = ObjectTypeOf(action);
                if (objectType is null) continue;
                if (string.Equals(objectType, requestedObject, StringComparison.OrdinalIgnoreCase)) continue;
                if (!Resembles(objectType, requestedObject)) continue;

                var swapped = SwapObjectType(action, objectType, requestedObject);
                var better = swapped is not null
                             && candidates.Any(c => string.Equals(c, swapped, StringComparison.OrdinalIgnoreCase))
                    ? swapped
                    : null;

                // The same operation on the right object is often named differently rather
                // than absent: users/revokeSignInSessions does not exist, but
                // users/invalidateAllRefreshTokens does the job. Fall back to the family the
                // offending action belongs to and find the right-object member of it.
                if (better is null)
                {
                    var ownFamily = Families.FirstOrDefault(fam => ActsOnFamily(action, fam));
                    if (ownFamily is not null)
                        better = BestCandidate(candidates, ownFamily, requestedObject, intendedVerb);
                }

                findings.Add(new Finding
                {
                    Kind = FindingKind.DistinctObject,
                    Family = requestedObject,
                    Action = action,
                    Message = action + " acts on " + objectType + ", which is a different object type "
                              + "from " + requestedObject + " — not a narrower scope of it.",
                    Better = better
                });
            }
        }

        return findings;
    }

    /// <summary>
    /// One wrong-resource correction: what was swapped, what was dropped, and why.
    /// </summary>
    public sealed record Correction
    {
        /// <summary>The action list to actually use — corrected.</summary>
        public required IReadOnlyList<string> Actions { get; init; }
        public required IReadOnlyList<Swap> Substituted { get; init; }
        /// <summary>Wrong for the requested resource with no replacement in the catalog.</summary>
        public required IReadOnlyList<string> Removed { get; init; }
        public required IReadOnlyList<Finding> Findings { get; init; }

        public bool Changed => Substituted.Count > 0 || Removed.Count > 0;
    }

    public sealed record Swap
    {
        public required string Wrong { get; init; }
        public required string Right { get; init; }
        public required string Why { get; init; }
    }

    /// <summary>
    /// APPLIES what <see cref="Check"/> finds, instead of only reporting it.
    ///
    /// Detecting the wrong permission and then ranking roles against it anyway is how a
    /// request that named the right role ended up "covers part only": the requirement set
    /// still contained an action nothing could satisfy. Where the catalog holds the correct
    /// permission, substitute it; where it does not, drop the wrong one rather than let it
    /// shape the recommendation. Both are reported so nothing changes silently.
    ///
    /// MUST run on the WHOLE request, before actions are split by provider — a family owned
    /// by one service looks uncovered from inside another service's slice.
    /// </summary>
    public static Correction Correct(
        string requestText,
        IEnumerable<string> chosenActions,
        IEnumerable<string> candidateActions)
    {
        var actions = (chosenActions ?? Enumerable.Empty<string>())
            .Where(a => !string.IsNullOrWhiteSpace(a)).ToList();

        var findings = Check(requestText, actions, candidateActions);
        if (findings.Count == 0)
        {
            return new Correction
            {
                Actions = actions,
                Substituted = Array.Empty<Swap>(),
                Removed = Array.Empty<string>(),
                Findings = findings
            };
        }

        var swaps = new List<Swap>();
        var removed = new List<string>();
        var result = new List<string>(actions);

        foreach (var f in findings)
        {
            // Nothing chosen was blamable — the finding names a gap, not a wrong pick. Add
            // the right permission rather than removing something that was never wrong.
            if (string.IsNullOrWhiteSpace(f.Action))
            {
                if (f.Better is not null
                    && !result.Contains(f.Better, StringComparer.OrdinalIgnoreCase))
                {
                    result.Add(f.Better);
                    swaps.Add(new Swap { Wrong = "", Right = f.Better, Why = f.Message });
                }
                continue;
            }

            result.RemoveAll(a => a.Equals(f.Action, StringComparison.OrdinalIgnoreCase));

            if (f.Better is null)
            {
                removed.Add(f.Action);
                continue;
            }

            if (!result.Contains(f.Better, StringComparer.OrdinalIgnoreCase))
                result.Add(f.Better);
            swaps.Add(new Swap { Wrong = f.Action, Right = f.Better, Why = f.Message });
        }

        return new Correction
        {
            Actions = result,
            Substituted = swaps,
            Removed = removed,
            Findings = findings
        };
    }

    // ---- action parsing ---------------------------------------------------------------

    /// <summary>
    /// Segments after the namespace, or null for anything not slash-delimited — Intune
    /// underscore operations and Exchange cmdlet signatures are not judged here rather than
    /// judged wrongly.
    /// </summary>
    private static string[]? PathSegments(string action)
    {
        if (string.IsNullOrWhiteSpace(action)) return null;
        var parts = action.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3) return null;
        if (!parts[0].Contains('.', StringComparison.Ordinal)) return null;
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
        if (segments is null) return false;
        return segments.Any(s =>
            family.PathSegments.Any(f => string.Equals(s, f, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// True when the action's own operation is one the request asked for by name, so it is
    /// answering some clause of a compound request rather than missing the point.
    /// </summary>
    private static bool DoesAJobTheRequestNamed(string action, string paddedText)
    {
        var verb = VerbOf(action);
        if (string.IsNullOrWhiteSpace(verb)) return false;
        return paddedText.Contains(" " + verb.ToLowerInvariant(), StringComparison.Ordinal);
    }

    private static bool IsWriteVerb(string? verb) =>
        verb is not null && !verb.EndsWith("read", StringComparison.OrdinalIgnoreCase);

    // ---- request parsing ----------------------------------------------------------------

    private static string? RequestedObjectType(string padded)
    {
        foreach (var (token, words) in ObjectTypes)
            foreach (var w in words)
                if (padded.Contains(" " + w + " ", StringComparison.Ordinal)
                    || padded.Contains(" " + w + "'", StringComparison.Ordinal)
                    || padded.Contains(" " + w + ",", StringComparison.Ordinal)
                    || padded.Contains(" " + w + ".", StringComparison.Ordinal))
                    return token;
        return null;
    }

    private static string? IntendedVerb(string padded)
    {
        foreach (var (verb, words) in VerbWords)
            if (words.Any(w => padded.Contains(" " + w + " ", StringComparison.Ordinal)))
                return verb;
        return null;
    }

    // ---- resemblance ----------------------------------------------------------------------

    /// <summary>
    /// True when two object types differ but one is a decorated form of the other —
    /// agentUsers/users, deviceUsers/users. A GENERAL rule rather than a curated pair list,
    /// because the next collision has not happened yet.
    /// </summary>
    private static bool Resembles(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase)) return false;

        var longer = a.Length >= b.Length ? a : b;
        var shorter = a.Length >= b.Length ? b : a;
        if (shorter.Length < 4) return false;

        return longer.EndsWith(shorter, StringComparison.OrdinalIgnoreCase)
               || longer.StartsWith(shorter, StringComparison.OrdinalIgnoreCase);
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

    // ---- suggestion ranking -----------------------------------------------------------------

    private static string? BestCandidate(
        List<string> candidates,
        FamilyDefinition family,
        string? requestedObject,
        string? intendedVerb)
    {
        var pool = candidates.Where(c => ActsOnFamily(c, family)).ToList();
        if (pool.Count == 0) return null;

        if (requestedObject is not null)
        {
            var sameObject = pool
                .Where(c => string.Equals(ObjectTypeOf(c), requestedObject, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (sameObject.Count > 0) pool = sameObject;
        }

        if (intendedVerb is not null)
        {
            var exact = pool
                .Where(c => string.Equals(VerbOf(c), intendedVerb, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (exact.Count > 0)
            {
                pool = exact;
            }
            else if (!string.Equals(intendedVerb, "read", StringComparison.OrdinalIgnoreCase))
            {
                // Never offer a READ as the fix for a write task — that is the exact class
                // of mistake the coverage guard exists to stop.
                var writes = pool.Where(c => IsWriteVerb(VerbOf(c))).ToList();
                if (writes.Count == 0) return null;
                pool = writes;
            }
        }

        return pool
            .OrderBy(BreadthRank)
            .ThenBy(c => c.Length)
            .ThenBy(c => c, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
    }

    private static int BreadthRank(string action)
    {
        var segments = PathSegments(action);
        if (segments is null) return BreadthOrder.Length;

        for (var i = 0; i < BreadthOrder.Length; i++)
            if (segments.Any(s => string.Equals(s, BreadthOrder[i], StringComparison.OrdinalIgnoreCase)))
                return i;

        return BreadthOrder.Length;
    }
}
