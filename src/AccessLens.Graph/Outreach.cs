namespace AccessLens.Graph;

/// <summary>
/// OPTIONAL courtesy check-ins ("still need this access?"). Expiry never depends
/// on these — PIM removes access server-side regardless. Only compiled-in email
/// for now; Teams chat can be added behind the same interface later.
/// </summary>
public sealed class Outreach
{
    private readonly GraphClient _graph;
    public Outreach(GraphClient graph) => _graph = graph;

    /// <summary>POST /me/sendMail as the signed-in admin.</summary>
    public async Task SendRenewalCheckAsync(
        string toAddress, string roleDisplay, DateTimeOffset expiresUtc,
        CancellationToken ct = default)
    {
        var body = new
        {
            message = new
            {
                subject = "Access check-in: " + roleDisplay + " expires " +
                          expiresUtc.ToString("yyyy-MM-dd HH:mm 'UTC'"),
                body = new
                {
                    contentType = "Text",
                    content =
                        "Your temporary access (" + roleDisplay + ") is scheduled to expire on " +
                        expiresUtc.ToString("yyyy-MM-dd HH:mm 'UTC'") + ".\n\n" +
                        "No action is needed if you are done — it will be removed automatically.\n" +
                        "If you still need this access, reply to this message with a brief justification " +
                        "and your admin can extend it."
                },
                toRecipients = new object[]
                {
                    new { emailAddress = new { address = toAddress } }
                }
            },
            saveToSentItems = true
        };
        using var _ = await _graph.PostAsync("/v1.0/me/sendMail", body, ct);
    }
}
