using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.AspNetCore.Routing;

namespace KiwiCaptcha;

/// <summary>
/// Framework middleware for the ASP.NET Core stack: one verification
/// pipeline the Razor views, minimal APIs and Blazor Server endpoints
/// all share.
///
/// The contract: a request carrying a valid, unconsumed token
/// proceeds; anything else is answered with a 403 Forbidden carrying
/// the machine-readable error code, and a retry disposition (a storage
/// outage or capacity exhaustion) answers with a 503 Service
/// Unavailable. The token source order is the x-kiwi-token header,
/// then the kiwi_token form field, then the kiwi_token query
/// parameter. The verified decision rides the HttpContext.Items entry
/// <see cref="KiwiCaptchaMiddleware.DecisionItem"/> for the wrapped
/// handler.
/// </summary>
public sealed class KiwiCaptchaMiddleware
{
    /// <summary>Token source header of the shared order.</summary>
    public const string TokenHeader = "X-Kiwi-Token";

    /// <summary>Token source field of the shared order.</summary>
    public const string TokenField = "kiwi_token";

    /// <summary>The HttpContext.Items key the verified decision is stored under.</summary>
    public const string DecisionItem = "KiwiCaptcha.Decision";

    private readonly RequestDelegate _next;
    private readonly Verifier _verifier;
    private readonly string _secretKey;
    private readonly string _expectedScope;
    private readonly Func<PathString, bool>? _pathPredicate;
    private readonly bool _realIp;
    private readonly Func<HttpContext, Decision, Task>? _denied;

    /// <summary>Builds the middleware over a verifier and the options.</summary>
    public KiwiCaptchaMiddleware(RequestDelegate next, Verifier verifier, string secretKey,
        string? expectedScope = null, Func<PathString, bool>? pathPredicate = null,
        bool realIp = false, Func<HttpContext, Decision, Task>? denied = null)
    {
        _next = next;
        _verifier = verifier;
        _secretKey = secretKey;
        _expectedScope = expectedScope ?? "";
        _pathPredicate = pathPredicate;
        _realIp = realIp;
        _denied = denied;
    }

    /// <summary>Runs the verify pipeline for one request.</summary>
    public async Task InvokeAsync(HttpContext context)
    {
        var pathScope = context.Request.Path.Value?.Trim('/') ?? "";
        if (pathScope.Length == 0)
        {
            pathScope = "default";
        }
        if (_pathPredicate != null && !_pathPredicate(context.Request.Path))
        {
            await _next(context);
            return;
        }
        var token = context.Request.Headers.TryGetValue(TokenHeader, out var header)
            && header.Count > 0 && !string.IsNullOrEmpty(header[0])
            ? header[0]
            : null;
        if (token == null && HttpMethods.IsPost(context.Request.Method)
            && context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync();
            token = form[TokenField].FirstOrDefault();
        }
        if (token == null)
        {
            token = context.Request.Query[TokenField].FirstOrDefault();
        }
        if (string.IsNullOrEmpty(token))
        {
            await RenderDenialAsync(context,
                Decision.FromOutcome(VerifyOutcome.MalformedTokenOutcome("malformed"), ""));
            return;
        }
        var options = new Verifier.Options
        {
            SecretKey = _secretKey,
            ExpectedScope = _expectedScope,
            ClientIp = ClientIpFromRequest(context, _realIp),
        };
        var outcome = _verifier.Verify(token, options);
        var decision = Decision.FromOutcome(outcome, "");
        if (decision.Ok)
        {
            context.Items[DecisionItem] = decision;
            await _next(context);
            return;
        }
        await RenderDenialAsync(context, decision);
    }

    private async Task RenderDenialAsync(HttpContext context, Decision decision)
    {
        if (_denied != null)
        {
            await _denied(context, decision);
            return;
        }
        var status = decision.Disposition == Decision.DispositionRetry ? 503 : 403;
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(
            "{\"ok\":false,\"error\":\"" + decision.Error
            + "\",\"disposition\":\"" + decision.Disposition + "\"}");
    }

    /// <summary>
    /// Resolves the client ip: the forwarded header's first hop when
    /// trusted, else the remote address.
    /// </summary>
    public static string ClientIpFromRequest(HttpContext context, bool trustForwarded)
    {
        if (trustForwarded && context.Request.Headers.TryGetValue("X-Forwarded-For", out var forwarded))
        {
            var first = forwarded.ToString().Split(',')[0].Trim();
            if (first.Length > 0)
            {
                return first;
            }
        }
        return context.Connection.RemoteIpAddress?.ToString() ?? "";
    }
}

/// <summary>The use-site extension for the middleware pipeline.</summary>
public static class KiwiCaptchaApplicationBuilderExtensions
{
    /// <summary>
    /// Registers the auto-verify middleware. Call after UseRouting and
    /// before the endpoint handlers it should protect.
    /// </summary>
    public static IApplicationBuilder UseKiwiCaptcha(this IApplicationBuilder app,
        Verifier verifier, string secretKey, string? expectedScope = null,
        Func<PathString, bool>? pathPredicate = null, bool realIp = false,
        Func<HttpContext, Decision, Task>? denied = null)
    {
        return app.UseMiddleware<KiwiCaptchaMiddleware>(
            verifier, secretKey, expectedScope, pathPredicate, realIp, denied);
    }
}

/// <summary>
/// The Razor tag helper: a form tag the widget anchors to, mirroring
/// the reCAPTCHA field ergonomics. The widget script renders into the
/// element by id, and the wrapper div carries the site key and the
/// optional action binding.
/// </summary>
[HtmlTargetElement("kiwi-captcha", TagStructure = TagStructure.WithoutEndTag)]
public sealed class KiwiCaptchaTagHelper : TagHelper
{
    /// <summary>The widget site key the issuance endpoint publishes.</summary>
    public string SiteKey { get; set; } = "";

    /// <summary>The challenge scope the widget requests, empty for the default.</summary>
    public string? Scope { get; set; }

    /// <summary>The theme: light or dark.</summary>
    public string? Theme { get; set; }

    /// <summary>The script source; defaults to the bundled widget path.</summary>
    public string? ScriptSrc { get; set; }

    /// <summary>Renders the widget anchor element with its data attributes.</summary>
    public override void Process(TagHelperContext context, TagHelperOutput output)
    {
        output.TagName = "div";
        output.TagMode = TagMode.StartTagAndEndTag;
        output.Attributes.SetAttribute("class", "kiwi-captcha" +
            (Theme == "dark" ? " kiwi-captcha-dark" : ""));
        output.Attributes.SetAttribute("data-sitekey", SiteKey);
        if (!string.IsNullOrEmpty(Scope))
        {
            output.Attributes.SetAttribute("data-scope", Scope);
        }
        var scriptSrc = ScriptSrc ?? "/kiwicaptcha/kiwi-widget.js";
        var child = new TagBuilder("script");
        child.Attributes["src"] = scriptSrc;
        child.Attributes["async"] = "async";
        child.Attributes["defer"] = "defer";
        output.Content.AppendHtml(child);
    }
}

/// <summary>
/// The endpoint mapper for the widget assets and the issuance route
/// the tag helper and the Blazor component point at. The issuance
/// handler delegates to the deployment's own issuer; the SDK ships
/// the wiring, not the issuance policy.
/// </summary>
public static class KiwiCaptchaEndpoints
{
    /// <summary>
    /// Maps GET /kiwicaptcha/health to a plain-text readiness probe
    /// over the verifier's store, the doctor's one-shot roundtrip in
    /// miniature.
    /// </summary>
    public static IEndpointConventionBuilder MapKiwiCaptchaHealth(this IEndpointRouteBuilder endpoints,
        Verifier verifier)
    {
        return endpoints.MapGet("/kiwicaptcha/health", () =>
        {
            var check = Doctor.CheckStore("memory://");
            return Results.Text(check.Ok ? "ok" : "degraded: " + check.Detail);
        });
    }
}
