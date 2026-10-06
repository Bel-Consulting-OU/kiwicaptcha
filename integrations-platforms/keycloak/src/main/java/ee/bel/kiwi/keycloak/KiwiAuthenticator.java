package ee.bel.kiwi.keycloak;

import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.http.HttpRequest;
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
 * kiwi.verify.url, kiwi.bearer, kiwi.scope, kiwi.trust.proxy.
 */
public class KiwiAuthenticator implements Authenticator {

    public static final String CONFIG_VERIFY_URL = "kiwi.verify.url";
    public static final String CONFIG_BEARER = "kiwi.bearer";
    public static final String CONFIG_SCOPE = "kiwi.scope";
    public static final String CONFIG_TRUSTED_PROXIES = "kiwi.trusted.proxies";

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
            challenge(context, "The security check did not run. Solve the challenge and try again.");
            return;
        }

        var config = context.getAuthenticatorConfig();
        var configModel = config == null ? null : config.getConfig();
        String verifyUrl = configValue(configModel, CONFIG_VERIFY_URL, VERIFY_URL_DEFAULT);
        String bearer = configValue(configModel, CONFIG_BEARER, "");
        String scope = configValue(configModel, CONFIG_SCOPE, "login");
        String trustedProxies = configValue(configModel, CONFIG_TRUSTED_PROXIES, "");

        var headers = request.getHttpHeaders();
        String forwarded = headers == null ? null : headers.getRequestHeaders().getFirst("X-Forwarded-For");
        String realIp = headers == null ? null : headers.getRequestHeaders().getFirst("X-Real-IP");
        String ip = KiwiVerifyClient.clientIp(
                context.getConnection() == null ? null : context.getConnection().getRemoteAddr(),
                forwarded,
                realIp,
                trustedProxies
        );

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
        challenge(context, "The security check did not pass. Solve the challenge and try again.");
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
        // No interactive action: the authenticator decides in authenticate().
        context.attempted();
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
