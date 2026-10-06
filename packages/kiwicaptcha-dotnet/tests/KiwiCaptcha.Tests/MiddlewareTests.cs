using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Xunit;

namespace KiwiCaptcha.Tests;

/// <summary>
/// The ASP.NET Core auto-verify pipeline over a DefaultHttpContext
/// harness, plus the Razor tag helper.
/// </summary>
public class MiddlewareTests
{
    private const string Secret = "0123456789abcdef0123456789abcdef";
    private const long IssuedAt = 1_800_000_000L;

    private static Verifier NewVerifier() => new(new MemoryStore(), new Verifier.Config
    {
        NowSecs = () => IssuedAt,
    });

    private static (ChallengeRecord Record, string Token) Mint()
    {
        var nonceBytes = new byte[Kiwi.NonceB64Bytes];
        var saltBytes = new byte[Kiwi.SaltB64Bytes];
        for (var i = 0; i < nonceBytes.Length; i++)
        {
            nonceBytes[i] = (byte)i;
        }
        for (var i = 0; i < saltBytes.Length; i++)
        {
            saltBytes[i] = (byte)(i + 100);
        }
        var nonce = Convert.ToBase64String(nonceBytes);
        var salt = Convert.ToBase64String(saltBytes);
        var expiresAt = IssuedAt + 120;
        var payload = Canonical.CanonicalPayloadChecked(2, nonce, "login", "", IssuedAt,
            expiresAt, "sha256", 1, 1, 1, 1, salt, 0, "", 1, "", "", 1, "", 0, "", "", false);
        var signature = Canonical.SignPayloadV2(payload, Secret, "");
        var challenge = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload)) + "." + signature;
        var record = new ChallengeRecord
        {
            Nonce = nonce,
            Scope = "login",
            IssuedAt = IssuedAt,
            ExpiresAt = expiresAt,
            IssuedAtNs = IssuedAt * 1_000_000,
            Algorithm = "sha256",
            MKib = 1,
            T = 1,
            P = 1,
            TargetBits = 1,
            Salt = salt,
            Prefix = challenge + "|" + salt + "|",
            Challenge = challenge,
            ProtocolVersion = 2,
            PolicyVersion = 1,
            Kid = 1,
        };
        // Search the counter to the target the way the widget does.
        long counter = 0;
        var saltBytesDecoded = Convert.FromBase64String(salt);
        while (true)
        {
            var prefixBytes = Encoding.UTF8.GetBytes(record.Prefix + counter);
            var input = new byte[prefixBytes.Length + saltBytesDecoded.Length];
            Array.Copy(prefixBytes, input, prefixBytes.Length);
            Array.Copy(saltBytesDecoded, 0, input, prefixBytes.Length, saltBytesDecoded.Length);
            if (Canonical.LeadingZeroBits(Canonical.Sha256(input)) >= record.TargetBits)
            {
                break;
            }
            counter++;
        }
        return (record, SolutionToken.Create(nonce, counter, 1500,
            JsonObject.Of(("v", new JsonNumber("1")))).Encode());
    }

    private static async Task<(int Status, string Body, bool Proceeded, Decision? Decision)> Run(
        DefaultHttpContext context, Verifier? verifier = null, string expectedScope = "login",
        Func<PathString, bool>? pathPredicate = null,
        Func<HttpContext, Decision, Task>? denied = null)
    {
        var proceeded = false;
        var middleware = new KiwiCaptchaMiddleware(_ =>
        {
            proceeded = true;
            return Task.CompletedTask;
        }, verifier ?? NewVerifier(), Secret, expectedScope, pathPredicate, null, denied);
        await middleware.InvokeAsync(context);
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(context.Response.Body);
        var body = await reader.ReadToEndAsync();
        var decision = context.Items.TryGetValue(KiwiCaptchaMiddleware.DecisionItem, out var value)
            ? (Decision?)value
            : null;
        return (context.Response.StatusCode, body, proceeded, decision);
    }

    private static DefaultHttpContext NewContext(string method = "POST", string path = "/api/submit")
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        return context;
    }

    [Fact]
    public async Task ValidTokenProceedsAndRidesTheDecision()
    {
        var verifier = NewVerifier();
        var (record, token) = Mint();
        Support.StoreRecord(verifier.Storage(), record);
        var context = NewContext();
        context.Request.Headers[KiwiCaptchaMiddleware.TokenHeader] = token;
        var (status, _, proceeded, decision) = await Run(context, verifier);
        Assert.True(proceeded);
        Assert.Equal(200, status);
        Assert.NotNull(decision);
        Assert.Equal(Decision.DispositionAllow, decision!.Disposition);
    }

    [Fact]
    public async Task MissingTokenIsForbidden()
    {
        var context = NewContext();
        var (status, body, proceeded, _) = await Run(context);
        Assert.False(proceeded);
        Assert.Equal(403, status);
        Assert.Contains("malformed_token", body);
        Assert.Contains("\"disposition\":\"deny\"", body);
    }

    [Fact]
    public async Task QueryTokenSourceResolves()
    {
        var verifier = NewVerifier();
        var (record, token) = Mint();
        Support.StoreRecord(verifier.Storage(), record);
        var context = NewContext();
        context.Request.QueryString = new QueryString("?kiwi_token=" + Uri.EscapeDataString(token));
        var (status, _, proceeded, _) = await Run(context, verifier);
        Assert.True(proceeded);
        Assert.Equal(200, status);
    }

    [Fact]
    public async Task FormTokenSourceResolves()
    {
        var verifier = NewVerifier();
        var (record, token) = Mint();
        Support.StoreRecord(verifier.Storage(), record);
        var context = NewContext();
        context.Request.ContentType = "application/x-www-form-urlencoded";
        var form = "kiwi_token=" + Uri.EscapeDataString(token);
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(form));
        context.Request.ContentLength = form.Length;
        var (status, _, proceeded, _) = await Run(context, verifier);
        Assert.True(proceeded);
        Assert.Equal(200, status);
        // The consumed record: a replay is a 403 deny.
        var context2 = NewContext();
        context2.Request.ContentType = "application/x-www-form-urlencoded";
        context2.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(form));
        context2.Request.ContentLength = form.Length;
        var (status2, body2, _, _) = await Run(context2, verifier);
        Assert.Equal(403, status2);
        Assert.Contains("already_consumed", body2);
    }

    private sealed class FailingStore : Store.IStoreAdapter
    {
        public ChallengeRecord? Find(string nonce) => throw new Store.StorageUnavailableException("down");

        public bool Delete(string nonce) => throw new Store.StorageUnavailableException("down");

        public Store.ConsumedRecord? Consume(string nonce) =>
            throw new Store.StorageUnavailableException("down");

        public bool CommitResult(string nonce, bool valid, string binding) =>
            throw new Store.StorageUnavailableException("down");
    }

    [Fact]
    public async Task RetryDispositionAnswersServiceUnavailable()
    {
        var (_, token) = Mint();
        var context = NewContext();
        context.Request.Headers[KiwiCaptchaMiddleware.TokenHeader] = token;
        var (status, body, _, _) = await Run(context, new Verifier(new FailingStore(),
            new Verifier.Config()));
        Assert.Equal(503, status);
        Assert.Contains("storage_unavailable", body);
        Assert.Contains("\"disposition\":\"retry\"", body);
    }

    [Fact]
    public async Task PathPredicateSkipsUnprotectedRoutes()
    {
        var context = NewContext("GET", "/api/open");
        var (_, _, proceeded, _) = await Run(context, pathPredicate: path =>
            path.StartsWithSegments("/api/protected"));
        Assert.True(proceeded);
    }

    [Fact]
    public async Task CustomDenialRendererWins()
    {
        var context = NewContext();
        var (_, _, proceeded, _) = await Run(context, denied: (ctx, decision) =>
        {
            ctx.Response.Redirect("/login");
            return Task.CompletedTask;
        });
        Assert.False(proceeded);
        Assert.Equal(302, context.Response.StatusCode);
        Assert.Equal("/login", context.Response.Headers.Location);
    }

    [Fact]
    public void ClientIpResolution()
    {
        var direct = new DefaultHttpContext();
        direct.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        Assert.Equal("127.0.0.1", KiwiCaptchaMiddleware.ClientIpFromRequest(direct, null));
        var forwarded = new DefaultHttpContext();
        forwarded.Connection.RemoteIpAddress = IPAddress.Parse("10.0.0.1");
        forwarded.Request.Headers["X-Forwarded-For"] = "203.0.113.9, 10.0.0.9";
        // The peer must sit inside the trust list before any
        // forwarded header is read at all.
        Assert.Equal("10.0.0.1", KiwiCaptchaMiddleware.ClientIpFromRequest(forwarded, null));
        Assert.Equal("203.0.113.9",
            KiwiCaptchaMiddleware.ClientIpFromRequest(forwarded, new[] { "10.0.0.0/24" }));
    }

    [Fact]
    public async Task TagHelperRendersTheWidgetAnchor()
    {
        var helper = new KiwiCaptchaTagHelper
        {
            SiteKey = "test-site-key",
            Scope = "login",
            Theme = "dark",
        };
        var context = new Microsoft.AspNetCore.Razor.TagHelpers.TagHelperContext(
            "kiwi-captcha", new TagHelperAttributeList(), new Dictionary<object, object>(), "id");
        var output = new Microsoft.AspNetCore.Razor.TagHelpers.TagHelperOutput("kiwi-captcha",
            new TagHelperAttributeList(),
            (_, _) => Task.FromResult<TagHelperContent>(new DefaultTagHelperContent()));
        helper.Process(context, output);
        Assert.Equal("div", output.TagName);
        Assert.Equal("kiwi-captcha kiwi-captcha-dark",
            Convert.ToString(output.Attributes.First(a => a.Name == "class").Value));
        Assert.Equal("test-site-key",
            Convert.ToString(output.Attributes.First(a => a.Name == "data-sitekey").Value));
        Assert.Equal("login",
            Convert.ToString(output.Attributes.First(a => a.Name == "data-scope").Value));
        Assert.Contains("/kiwicaptcha/kiwi-widget.js", output.Content.GetContent());
    }

    [Fact]
    public void HealthEndpointCheck()
    {
        // The health mapper runs the doctor's store roundtrip inline,
        // so the shipped wiring stays honest about store readiness.
        var check = Doctor.CheckStore("memory://");
        Assert.True(check.Ok, check.Detail);
    }
}
