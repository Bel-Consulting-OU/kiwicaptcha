# KiwiCaptcha for Keycloak (Authenticator SPI)

Native Keycloak extension: an authenticator that verifies a
KiwiCaptcha proof-of-work token server-to-server against the kiwi
deployment. Attach it to any flow (a copy of the browser flow, or a
direct grant flow) as REQUIRED, and the flow stops when the challenge
is missing or failed. An unreachable deployment fails the flow closed.

## Mechanism

- `src/main/java/ee/bel/kiwi/keycloak/KiwiAuthenticator.java`: the
  Authenticator SPI class. `authenticate()` reads the token from the
  `X-Kiwi-Token` header or the incumbent form fields
  (`kiwi__token`, `g-recaptcha-response`, `h-captcha-response`,
  `cf-turnstile-response`, `frc-captcha-solution`, `altcha`), calls
  the sidecar-shaped verify endpoint, `context.success()` on pass, a
  challenge error page on deny, `failure(INTERNAL_ERROR)` when the
  deployment is unreachable.
- `KiwiAuthenticatorFactory.java` registers it (id `kiwi-captcha`)
  with the flow-editor config: verify URL, bearer, scope,
  trust-proxy switch.
- `KiwiVerifyClient.java` is the dependency-free client (java.net.http
  plus a hand-rolled JSON encoder and body scanner), so the decision
  surface compiles and tests with the JDK alone.
- The service entry `META-INF/services/org.keycloak.authentication.AuthenticatorFactory`
  makes the factory discoverable.

## Build and deployment steps

1. Build: `mvn package` produces `target/kiwicaptcha-spi.jar`
   (Keycloak 23.x, Java 17; the dependencies are `provided`).
2. Copy the jar to `providers/` and rebuild:
   `bin/kc.sh build && bin/kc.sh start` (or restart the container).
3. Admin console, Authentication, Flows: copy the browser flow, add
   the "KiwiCaptcha" execution where the protection belongs
   (registration path or login), set it REQUIRED, and configure the
   verify URL (default `http://127.0.0.1:7371/verify`), the bearer
   and the scope.
4. Bind the flow to the relevant action (browser or direct grant).
5. The client side: Keycloak's login theme needs the shim. Drop the
   deployment's script tag into your theme's `footer.ftl` (or a
   `terms.ftl` on the registration page) and a small script that
   writes the solved token into the hidden `kiwi__token` input the
   authenticator reads; the shims do exactly that for the incumbent
   markup conventions.

## Test status

`KiwiVerifyClientTest.java` (20 checks) is a plain-JDK test compiled
and run here:

```
javac -d /tmp/kiwi-kc-classes src/main/java/ee/bel/kiwi/keycloak/KiwiVerifyClient.java \
  src/test/java/ee/bel/kiwi/keycloak/KiwiVerifyClientTest.java
java -cp /tmp/kiwi-kc-classes ee.bel.kiwi.keycloak.KiwiVerifyClientTest
```

It covers the decision surface (status mapping, body scanning), token
extraction, ip binding, JSON escaping and live round trips against a
local HTTP stub (success, failure, 5xx fail closed, unreachable fail
closed). `mvn package` was run on this host (Java 17, Keycloak 23
artifacts from Central) and produces the jar; exercising the
authenticator inside a running Keycloak (flow editor, login theme)
needs a server, which this repository does not ship.
