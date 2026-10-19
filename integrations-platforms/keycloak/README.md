# KiwiCaptcha for Keycloak (Authenticator SPI)

Native Keycloak extension: an authenticator that verifies a
KiwiCaptcha proof-of-work token server-to-server against the kiwi
deployment. Attach it to any flow (a copy of the browser flow, or a
direct grant flow) as REQUIRED, and the flow stops when the challenge
is missing or failed. An unreachable deployment fails the flow closed.

## Mechanism

- `src/main/java/ee/bel/kiwi/keycloak/KiwiAuthenticator.java`: the
  Authenticator SPI class. `authenticate()` applies the shared token
  authority rule: every non-empty value from every source — every
  `X-Kiwi-Token` header line, every value of the incumbent form fields
  (`kiwi__token`, `g-recaptcha-response`, `h-captcha-response`,
  `cf-turnstile-response`, `frc-captcha-solution`, `altcha`) and of the
  same-named query parameters — is collected and must agree. One
  distinct value verifies however many sources carry it; two or more
  distinct values fail the authentication with the typed
  `token_source_conflict` event before any token is verified. The call
  goes to the sidecar-shaped verify endpoint, `context.success()` on
  pass, a challenge error page on deny, `failure(INTERNAL_ERROR)` when
  the deployment is unreachable.
- `KiwiAuthenticatorFactory.java` registers it (id `kiwi-captcha`)
  with the flow-editor config: verify URL, bearer, scope and the
  trusted-proxy CIDR list (`kiwi.trust.proxy.cidrs`, comma-separated,
  empty by default). The socket peer binds the challenge unless it
  sits inside one of the configured prefixes; only then is the
  `X-Forwarded-For` chain walked right to left through trusted hops
  (the first untrusted hop wins, a malformed hop or a repeated
  forwarding header fails closed to the peer), with `X-Real-IP` as the
  no-chain fallback. An empty list trusts nobody: forwarding headers
  are ignored entirely. Malformed CIDR entries are skipped, so a typo
  can never widen the trust boundary.
- The factory offers REQUIRED, ALTERNATIVE and DISABLED. Under
  ALTERNATIVE a missing, conflicting or failed challenge calls
  `attempted()`, so the flow can continue with its other alternatives;
  success still requires a verified token, and an unreachable
  deployment fails the flow closed under either requirement.
- `KiwiVerifyClient.java` is the dependency-free client (java.net.http
  plus a hand-rolled JSON encoder) and `Json.java` is its strict
  RFC 8259 parser: the verify response is parsed as real JSON and
  `success` must be the JSON boolean `true`, so the decision surface
  compiles and tests with the JDK alone without a substring scanner.
- The service entry `META-INF/services/org.keycloak.authentication.AuthenticatorFactory`
  makes the factory discoverable.

## Build and deployment steps

1. Build: `mvn package` produces `target/kiwicaptcha-spi.jar`
   (Keycloak 23.x, Java 17; the dependencies are `provided`).
2. Copy the jar to `providers/` and rebuild:
   `bin/kc.sh build && bin/kc.sh start` (or restart the container).
3. Admin console, Authentication, Flows: copy the browser flow, add
   the "KiwiCaptcha" execution where the protection belongs
   (registration path or login), set it REQUIRED. ALTERNATIVE is also
   supported: a missing, conflicting or failed challenge marks the
   execution attempted so the flow's other alternatives can satisfy
   it, while this execution never reaches `success()` without a
   verified token. Configure the verify URL (default
   `http://127.0.0.1:7371/verify`), the bearer, the scope and — only
   behind a reverse proxy — the trusted-proxy CIDR list
   (`kiwi.trust.proxy.cidrs`, e.g. `10.0.0.0/24, 2001:db8::/64`; the
   proxy must be the immediate socket peer for the headers to be
   honored).
4. Bind the flow to the relevant action (browser or direct grant).
5. The client side: Keycloak's login theme needs the shim. Drop the
   deployment's script tag into your theme's `footer.ftl` (or a
   `terms.ftl` on the registration page) and a small script that
   writes the solved token into the hidden `kiwi__token` input the
   authenticator reads; the shims do exactly that for the incumbent
   markup conventions.

## Test status

`KiwiVerifyClientTest.java` (121 checks) is a plain-JDK test compiled
and run here:

```
javac -d /tmp/kiwi-kc-classes src/main/java/ee/bel/kiwi/keycloak/KiwiVerifyClient.java \
  src/main/java/ee/bel/kiwi/keycloak/Json.java \
  src/test/java/ee/bel/kiwi/keycloak/KiwiVerifyClientTest.java
java -Dkiwi.test.vectors=../../tools/client-ip/test-vectors.json \
  -cp /tmp/kiwi-kc-classes ee.bel.kiwi.keycloak.KiwiVerifyClientTest
```

(It also finds the vectors by searching upward from the working
directory when the property is absent; `tests/run-all.sh` passes it
explicitly so the cwd never matters.)

It covers the decision surface (status mapping, real-JSON body
parsing — truncated documents, trailing garbage, string lookalikes and
duplicate keys all fail closed), the token authority rule (the
collect/distinct/conflict matrix of
`protocol/decision-v1/corpus.json`: no token, exactly one value, two
distinct values across sources, two distinct repeated header lines,
the same value twice), the client-ip resolver parameterized over the
ENTIRE shared `tools/client-ip/test-vectors.json` matrix (every CIDR
case and every scenario, exactly like the go and dotnet SDK suites)
plus direct-reachability checks (an untrusted peer never unlocks
forwarding headers, not even when other ranges are configured), and
JSON escaping and live round trips against a local HTTP stub (success,
failure, 5xx fail closed, unreachable fail closed).

`KiwiAuthenticatorFactoryTest.java` (9 checks) pins the flow-editor
surface: REQUIRED, ALTERNATIVE and DISABLED are offered, and the
config properties are the verify URL, bearer, scope and the
trusted-proxy CIDR list defaulting to empty. It compiles against
`target/classes` plus the Keycloak SPI jars (`mvn -o compile` first).

`mvn -o compile` was run on this host (Java 17, Keycloak 23
artifacts from the local repository); `mvn package` produces the jar.
Exercising the authenticator inside a running Keycloak (flow editor,
login theme) needs a server, which this repository does not ship.
