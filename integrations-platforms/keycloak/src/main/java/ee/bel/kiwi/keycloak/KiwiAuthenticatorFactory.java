package ee.bel.kiwi.keycloak;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * The factory Keycloak instantiates the authenticator through. The
 * service entry (META-INF/services) is what makes it appear in the
 * flow editor after the jar lands in providers/ and the server is
 * rebuilt.
 */
public class KiwiAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "kiwi-captcha";

    private static final KiwiAuthenticator SINGLETON = new KiwiAuthenticator();

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.REQUIRED,
            Requirement.DISABLED,
    };

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Scope config) {
        // No provider-level configuration.
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-init wiring.
    }

    @Override
    public void close() {
        // No resources to release.
    }

    @Override
    public String getDisplayType() {
        return "KiwiCaptcha";
    }

    @Override
    public String getHelpText() {
        return "Verifies a KiwiCaptcha proof-of-work token server-to-server against your self-hosted deployment.";
    }

    @Override
    public String getReferenceCategory() {
        return "captcha";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> properties = new ArrayList<>();
        properties.add(new ProviderConfigProperty(
                KiwiAuthenticator.CONFIG_VERIFY_URL, "Verify URL",
                "The kiwi verify endpoint (the sidecar's /verify or a siteverify route).",
                ProviderConfigProperty.STRING_TYPE, KiwiAuthenticator.VERIFY_URL_DEFAULT));
        properties.add(new ProviderConfigProperty(
                KiwiAuthenticator.CONFIG_BEARER, "Bearer secret",
                "The deployment's bearer credential, empty for none.",
                ProviderConfigProperty.PASSWORD, ""));
        properties.add(new ProviderConfigProperty(
                KiwiAuthenticator.CONFIG_SCOPE, "Scope",
                "The challenge scope this flow sends.",
                ProviderConfigProperty.STRING_TYPE, "login"));
        return properties;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }
}
