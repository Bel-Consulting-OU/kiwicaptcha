package ee.bel.kiwi.keycloak;

import jakarta.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * The KiwiCaptcha authenticator: one flow execution that verifies the
 * proof-of-work token server-to-server against the kiwi deployment.
 * Attach it to a flow (for example a copy of the browser flow, on the
 * registration path) as REQUIRED; a missing or failed challenge stops
 * the flow with the challenge error page, and an unreachable
 * deployment fails the flow closed.
 *
 * Configuration rides the authenticator's config model:
 * kiwi.verify.url, kiwi.bearer, kiwi.scope, kiwi.trust.proxy.cidrs.
 * The trusted-proxy list is empty by default: the bound client IP is
 * then the socket peer that Keycloak's own KC_PROXY configuration
 * adjusted, and no forwarding header is parsed. When CIDRs are
 * configured, the immediate socket peer must sit inside one of them
 * before the X-Forwarded-For chain is walked right to left through
 * trusted hops (the shared SDK trusted-proxy walk), with X-Real-IP as
 * the no-chain fallback.
 */
public class KiwiAuthenticator implements Authenticator {

    public static final String CONFIG_VERIFY_URL = "kiwi.verify.url";
    public static final String CONFIG_BEARER = "kiwi.bearer";
    public static final String CONFIG_SCOPE = "kiwi.scope";
    public static final String CONFIG_TRUST_PROXY_CIDRS = "kiwi.trust.proxy.cidrs";

    public static final String VERIFY_URL_DEFAULT = "http://127.0.0.1:7371/verify";

    private static final Logger LOG = Logger.getLogger(KiwiAuthenticator.class);

    private final KiwiVerifyClient client;

    public KiwiAuthenticator() {
        this(new KiwiVerifyClient());
    }

    public KiwiAuthenticator(KiwiVerifyClient client) {
        this.client = client;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        HttpRequest request = context.getHttpRequest();
        var httpHeaders = request.getHttpHeaders();

        // The token authority rule (protocol/decision-v1/corpus.json):
        // every non-empty value from every source is collected — every
        // X-Kiwi-Token header line, every value of the incumbent form
        // fields and of the same-named query parameters, repeated
        // values included — and all collected values must agree. Two
        // distinct values refuse the request with the typed
        // token_source_conflict code before any token is verified, so
        // a trusted gateway's header can never be shadowed by an
        // attacker-controlled form field or query string.
        List<String> headerTokenValues = KiwiVerifyClient.splitTokenHeaderLines(
                httpHeaders == null ? null : httpHeaders.getRequestHeaders().get("X-Kiwi-Token"));
        List<String> formTokenValues = new ArrayList<>();
        MultivaluedMap<String, String> form = request.getDecodedFormParameters();
        if (form != null) {
            for (String field : KiwiVerifyClient.tokenFieldNames()) {
                addAll(formTokenValues, form.get(field));
            }
        }
        List<String> queryTokenValues = new ArrayList<>();
        var queryParameters = request.getUri() == null ? null : request.getUri().getQueryParameters();
        if (queryParameters != null) {
            for (String field : KiwiVerifyClient.tokenFieldNames()) {
                addAll(queryTokenValues, queryParameters.get(field));
            }
        }
        var resolution = KiwiVerifyClient.resolveTokenValues(headerTokenValues, formTokenValues, queryTokenValues);
        if (resolution.code() != null) {
            // malformed_token keeps the incumbent missing_token event
            // detail; a conflict carries the corpus code verbatim.
            boolean conflict = KiwiVerifyClient.CODE_TOKEN_SOURCE_CONFLICT.equals(resolution.code());
            context.getEvent().detail("kiwi_captcha", conflict ? resolution.code() : "missing_token");
            if (isAlternative(context)) {
                // ALTERNATIVE: this execution is optional, so let the
                // flow continue with its other alternatives instead of
                // blocking on a challenge that will never be answered.
                context.attempted();
                return;
            }
            challenge(context, conflict
                    ? "The security check could not be verified. Solve the challenge and try again."
                    : "The security check did not run. Solve the challenge and try again.");
            return;
        }
        String token = resolution.token();

        var config = context.getAuthenticatorConfig();
        var configModel = config == null ? null : config.getConfig();
        String verifyUrl = configValue(configModel, CONFIG_VERIFY_URL, VERIFY_URL_DEFAULT);
        String bearer = configValue(configModel, CONFIG_BEARER, "");
        String scope = configValue(configModel, CONFIG_SCOPE, "login");
        // Default: the socket peer (the value Keycloak's own KC_PROXY
        // configuration adjusted); forwarding headers are never read.
        // With trusted CIDRs configured, the resolver requires the
        // immediate socket peer to sit inside one of them before it
        // walks the X-Forwarded-For chain right to left through the
        // trusted hops (the shared SDK trusted-proxy walk of
        // tools/client-ip/test-vectors.json), with X-Real-IP as the
        // no-chain fallback. A missing peer fails closed: never invent
        // 127.0.0.1 (the remoteip is the challenge's binding key).
        var requestHeaders = httpHeaders == null ? null : httpHeaders.getRequestHeaders();
        List<String> forwardedFor = requestHeaders == null ? List.of() : orEmpty(requestHeaders.get("X-Forwarded-For"));
        List<String> realIp = requestHeaders == null ? List.of() : orEmpty(requestHeaders.get("X-Real-IP"));
        String remoteAddr = context.getConnection() == null ? null : context.getConnection().getRemoteAddr();
        String ip = KiwiVerifyClient.resolveClientIp(remoteAddr, forwardedFor, realIp, trustedCidrs(configModel));
        if (ip.isEmpty()) {
            LOG.warn("kiwicaptcha: no socket peer for the verify binding; failing the flow closed");
            context.getEvent().detail("kiwicaptcha", "missing_client_ip");
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }

        KiwiVerifyClient.Result result = client.verify(verifyUrl, bearer, token, scope, ip);
        if (result.ok()) {
            context.success();
            return;
        }
        if ("verify_unavailable".equals(result.code())) {
            LOG.warnf("kiwicaptcha verify endpoint unavailable (%s); failing the flow closed", verifyUrl);
            context.getEvent().detail("kiwi_captcha", "verify_unavailable");
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }
        context.getEvent().detail("kiwi_captcha", result.code());
        if (isAlternative(context)) {
            // A failed or missing challenge under ALTERNATIVE must not
            // block the flow's other alternatives; the execution is
            // marked attempted and the flow moves on. A success above
            // still required a verified token.
            context.attempted();
            return;
        }
        challenge(context, "The security check did not pass. Solve the challenge and try again.");
    }

    /**
     * The trusted-proxy CIDR list from the config model: one
     * comma-separated string, empty entries dropped, empty by default
     * (trust nobody, headers ignored). Malformed entries are dropped
     * inside the resolver, so a typo can never widen the boundary.
     */
    private static List<String> trustedCidrs(java.util.Map<String, String> config) {
        String value = configValue(config, CONFIG_TRUST_PROXY_CIDRS, "");
        List<String> cidrs = new ArrayList<>();
        for (String candidate : value.split(",")) {
            String trimmed = candidate.trim();
            if (!trimmed.isEmpty()) {
                cidrs.add(trimmed);
            }
        }
        return cidrs;
    }

    private static void addAll(List<String> target, List<String> values) {
        if (values != null) {
            for (String value : values) {
                if (value != null) {
                    target.add(value);
                }
            }
        }
    }

    private static List<String> orEmpty(List<String> values) {
        return values == null ? List.of() : values;
    }

    /**
     * Whether this execution is configured ALTERNATIVE. Under that
     * requirement a missing or failed challenge continues the flow;
     * under REQUIRED it blocks (and an outage always fails closed).
     */
    private static boolean isAlternative(AuthenticationFlowContext context) {
        return context.getExecution() != null
                && context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.ALTERNATIVE;
    }

    private void challenge(AuthenticationFlowContext context, String message) {
        context.challenge(
                context.form().setError(message).createErrorPage(jakarta.ws.rs.core.Response.Status.BAD_REQUEST)
        );
    }

    private static String configValue(java.util.Map<String, String> config, String key, String fallback) {
        if (config == null) {
            return fallback;
        }
        String value = config.get(key);
        return value == null || value.isBlank() ? fallback : value;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No interactive form: any submission that lands here is
        // re-verified against the same contract as authenticate(), and
        // nothing else. The previous attempted() marked this execution
        // done without verifying, which let an ALTERNATIVE-flow
        // request continue to the next alternative and skip the check
        // entirely; a REQUIRED execution then "failed closed" only by
        // accident. Re-verification (not attempted()) is the one
        // behavior that is correct under both requirements.
        authenticate(context);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions.
    }

    @Override
    public void close() {
        // No resources to release.
    }
}
