package ee.bel.kiwi.keycloak;

import java.util.Arrays;
import java.util.List;

import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * The plain-JDK test of the factory surface: the flow-editor
 * requirement choices (REQUIRED, ALTERNATIVE, DISABLED) and the
 * config properties (verify URL, bearer, scope, trust-proxy switch).
 * It needs the Keycloak SPI jars on the classpath, unlike the pure
 * KiwiVerifyClientTest; see README.md for the command.
 */
public final class KiwiAuthenticatorFactoryTest {

    private static int failures = 0;
    private static int checks = 0;

    private static void check(String name, boolean condition) {
        checks++;
        if (!condition) {
            failures++;
            System.err.println("FAIL: " + name);
        }
    }

    private static ProviderConfigProperty property(List<ProviderConfigProperty> properties, String name) {
        return properties.stream().filter(p -> name.equals(p.getName())).findFirst().orElse(null);
    }

    public static void main(String[] args) {
        KiwiAuthenticatorFactory factory = new KiwiAuthenticatorFactory();
        List<Requirement> choices = Arrays.asList(factory.getRequirementChoices());
        check("REQUIRED is offered", choices.contains(Requirement.REQUIRED));
        check("ALTERNATIVE is offered", choices.contains(Requirement.ALTERNATIVE));
        check("DISABLED is offered", choices.contains(Requirement.DISABLED));

        List<ProviderConfigProperty> properties = factory.getConfigProperties();
        check("verify url is configurable", property(properties, KiwiAuthenticator.CONFIG_VERIFY_URL) != null);
        check("bearer is configurable", property(properties, KiwiAuthenticator.CONFIG_BEARER) != null);
        check("scope is configurable", property(properties, KiwiAuthenticator.CONFIG_SCOPE) != null);

        ProviderConfigProperty trustProxy = property(properties, KiwiAuthenticator.CONFIG_TRUST_PROXY);
        check("trust-proxy switch is configurable", trustProxy != null);
        check("trust-proxy switch is boolean",
                trustProxy != null && ProviderConfigProperty.BOOLEAN_TYPE.equals(trustProxy.getType()));
        check("trust-proxy switch defaults off",
                trustProxy != null && "false".equals(String.valueOf(trustProxy.getDefaultValue())));

        System.out.println(checks + " checks, " + failures + " failures");
        System.exit(failures == 0 ? 0 : 1);
    }
}
