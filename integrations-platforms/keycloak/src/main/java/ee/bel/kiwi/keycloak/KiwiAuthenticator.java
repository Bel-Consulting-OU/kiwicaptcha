package ee.bel.kiwi.keycloak;

import jakarta.ws.rs.core.MultivaluedMap;
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
 * kiwi.verify.url, kiwi.bearer, kiwi.scope, kiwi.trust.proxy. The
 * trust-proxy switch is off by default: the bound client IP is then
 * the socket peer that Keycloak's own KC_PROXY configuration
 * adjusted, and no forwarding header is parsed. When it is on, the
 * rightmost X-Forwarded-For hop (the value the nearest trusted proxy
 * appended) is the binding, with X-Real-IP as the no-chain fallback.
 */
public class KiwiAuthenticator implements Authenticator {

    public static final String CONFIG_VERIFY_URL = "kiwi.verify.url";
    public static final String CONFIG_BEARER = "kiwi.bearer";
    public static final String CONFIG_SCOPE = "kiwi.scope";
    public static final String CONFIG_TRUST_PROXY = "kiwi.trust.proxy";

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
        String headerToken = httpHeaders == null ? null : httpHeaders.getRequestHeaders().getFirst("X-Kiwi-Token");

        MultivaluedMap<String, String> form = request.getDecodedFormParameters();
        String token = KiwiVerifyClient.extractToken(
                headerToken,
                KiwiVerifyClient.tokenFieldNames(),
                field -> form == null ? null : form.getFirst(field)
        );
        if (token == null) {
            context.getEvent().detail("kiwi_captcha", "missing_token");
            if (isAlternative(context)) {
                // ALTERNATIVE: this execution is optional, so let the
                // flow continue with its other alternatives instead of
                // blocking on a challenge that will never be answered.
                context.attempted();
                return;
            }
            challenge(context, "The security check did not run. Solve the challenge and try again.");
            return;
        }

        var config = context.getAuthenticatorConfig();
        var configModel = config == null ? null : config.getConfig();
        String verifyUrl = configValue(configModel, CONFIG_VERIFY_URL, VERIFY_URL_DEFAULT);
        String bearer = configValue(configModel, CONFIG_BEARER, "");
        String scope = configValue(configModel, CONFIG_SCOPE, "login");
        boolean trustProxy = Boolean.parseBoolean(configValue(configModel, CONFIG_TRUST_PROXY, "false"));
        // Default: the socket peer (the value Keycloak's own KC_PROXY
        // configuration adjusted); forwarding headers are never read.
        // With the trust-proxy switch on, the resolver takes the
        // rightmost X-Forwarded-For hop appended by the nearest trusted
        // proxy (a client-supplied leftmost entry is ignored), with
        // X-Real-IP as the no-chain fallback. A missing peer fails
        // closed: never invent 127.0.0.1 (the remoteip is the
        // challenge's binding key).
        var requestHeaders = httpHeaders == null ? null : httpHeaders.getRequestHeaders();
        String forwardedFor = requestHeaders == null ? null : requestHeaders.getFirst("X-Forwarded-For");
        String realIp = requestHeaders == null ? null : requestHeaders.getFirst("X-Real-IP");
        String remoteAddr = context.getConnection() == null ? null : context.getConnection().getRemoteAddr();
        String ip = KiwiVerifyClient.resolveClientIp(remoteAddr, forwardedFor, realIp, trustProxy);
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
