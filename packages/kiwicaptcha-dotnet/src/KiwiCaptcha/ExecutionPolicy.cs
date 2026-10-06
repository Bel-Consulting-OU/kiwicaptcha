using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;

namespace KiwiCaptcha;

/// <summary>
/// The execution delegation plane of the dotnet SDK: an execution-armed
/// record demands the browser-trace walker, an oracle this SDK does not
/// carry. The default policy fails every armed record closed
/// (<c>execution_mismatch</c>, documented). The sidecar policy
/// delegates that single verification to a co-located
/// kiwicaptcha-verifier sidecar over HTTP: the sidecar carries the full
/// Rust core with the real execution verifier, consumes the record
/// (single-use semantics preserved: the sidecar consumes, this SDK
/// never double-consumes) and answers the provider-shaped verdict
/// mapped back into this SDK's vocabulary.
///
/// Trust boundary: the sidecar decides acceptances, so it must be
/// co-located and trusted to the same standard as the verifier itself.
/// The bearer credential is sent per request, and a refused credential
/// denies instead of retrying into an untrusted verifier.
/// </summary>
public sealed class ExecutionPolicy
{
    private static readonly Regex KiwiCodeRegex =
        new("\"kiwi-code\"\\s*:\\s*\"([a-z0-9_]+)\"", RegexOptions.Compiled);

    private static readonly Regex SuccessRegex =
        new("\"success\"\\s*:\\s*(true|false)", RegexOptions.Compiled);

    /// <summary>The kiwicaptcha-verifier base URL; empty keeps fail-closed.</summary>
    public string SidecarUrl { get; init; } = "";

    /// <summary>The sidecar's own credential, sent as the bearer.</summary>
    public string BearerToken { get; init; } = "";

    /// <summary>The bounded budget of one delegation call in ms (default 5000).</summary>
    public int TimeoutMs { get; init; } = 5000;

    /// <summary>Whether the policy delegates the execution-armed dimension.</summary>
    public bool Enabled() => !string.IsNullOrWhiteSpace(SidecarUrl);

    /// <summary>
    /// Hands one execution-armed verification to the sidecar. Answers
    /// (ok, code): ok means the sidecar's full-core pass accepted; a
    /// failure maps the sidecar's kiwi-code (the shared wire vocabulary)
    /// through verbatim, with the transport failures fail-closed
    /// (storage_unavailable keeps the retry disposition with the record
    /// intact).
    /// </summary>
    public (bool Ok, string Code) Delegate(string rawToken, string scope, string clientIp)
    {
        var body = new StringBuilder();
        body.Append("{\"token\":\"").Append(JsonEscape(rawToken));
        body.Append("\",\"scope\":\"").Append(JsonEscape(scope)).Append("\"");
        if (!string.IsNullOrEmpty(clientIp))
        {
            body.Append(",\"remoteip\":\"").Append(JsonEscape(clientIp)).Append("\"");
        }
        body.Append("}");

        using var client = new HttpClient(new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromMilliseconds(TimeoutMs),
        });
        client.Timeout = TimeSpan.FromMilliseconds(TimeoutMs);
        using var request = new HttpRequestMessage(HttpMethod.Post,
            SidecarUrl.Trim().TrimEnd('/') + "/verify");
        request.Content = new StringContent(body.ToString(), Encoding.UTF8, "application/json");
        if (!string.IsNullOrEmpty(BearerToken))
        {
            request.Headers.Add("authorization", "Bearer " + BearerToken);
        }

        HttpResponseMessage response;
        try
        {
            response = client.SendAsync(request).GetAwaiter().GetResult();
        }
        catch (Exception)
        {
            return (false, "storage_unavailable");
        }
        using (response)
        {
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized
                || response.StatusCode == System.Net.HttpStatusCode.Forbidden)
            {
                // The sidecar refused the credential: never retry into
                // an untrusted verifier, fail closed with a deny.
                return (false, "execution_mismatch");
            }
            if ((int)response.StatusCode >= 500)
            {
                return (false, "storage_unavailable");
            }
            if ((int)response.StatusCode != 200)
            {
                return (false, "execution_mismatch");
            }
            var text = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            var success = SuccessRegex.Match(text);
            if (success.Success && success.Groups[1].Value == "true")
            {
                return (true, "ok");
            }
            var code = KiwiCodeRegex.Match(text);
            return code.Success
                ? (false, code.Groups[1].Value)
                : (false, "execution_mismatch");
        }
    }

    private static string JsonEscape(string value)
    {
        var outp = new StringBuilder(value.Length + 8);
        foreach (var c in value)
        {
            switch (c)
            {
                case '"': outp.Append("\\\""); break;
                case '\\': outp.Append("\\\\"); break;
                case '\n': outp.Append("\\n"); break;
                case '\r': outp.Append("\\r"); break;
                case '\t': outp.Append("\\t"); break;
                default:
                    if (c < 0x20)
                    {
                        outp.Append("\\u").Append(((int)c).ToString("x4"));
                    }
                    else
                    {
                        outp.Append(c);
                    }
                    break;
            }
        }
        return outp.ToString();
    }
}
