# KiwiCaptcha platform integrations

Self-hosted platform plugins and gateway gates for KiwiCaptcha. Every
integration here is complete against the platform's documented stable
extension surface and the kiwi deployment's two server surfaces:

- the client shims: the incumbent globals (`grecaptcha`, `hcaptcha`,
  `turnstile`) and the Altcha and Friendly Captcha element
  conventions, served by the kiwi deployment (`/kiwi-captcha/api.js`
  compat route, `widget-shims.js` asset);
- the verify surface: the verifier sidecar's `POST /verify` with the
  JSON body `{"token", "scope", "remoteip"}` and an optional bearer,
  or the symfony bundle's provider-shaped `POST /kiwi-captcha/siteverify`
  (`response`, `secret`, `remoteip`). Both answer the provider siteverify
  JSON shape (`success`, `challenge_ts`, `hostname`, `error-codes`).

## Directories

| Directory | Platform | Mechanism | Routing decision |
|---|---|---|---|
| `nginx/`, `caddy/`, `traefik/` | gateways | auth_request / forward_auth / forwardAuth | native to the layer; gates arbitrary routes |
| `wordpress/` | WordPress | plugin: hooks, shortcode, settings API | native plugin |
| `drupal/` | Drupal 10 | module: form_alter, service, settings form | native module |
| `joomla/` | Joomla 4/5 | package: captcha plugin contract | native plugin |
| `discourse/` | Discourse | plugin: middleware + sign-up hook | native plugin |
| `phpbb/` | phpBB 3.3 | extension: captcha plugin service | native extension |
| `flarum/` | Flarum 1.x | extension: PSR-15 middleware extender | native extension |
| `gitea-forgejo/` | Gitea, Forgejo | reverse proxy gate on the sign-up route | proxy layer, on purpose |
| `gitlab/` | GitLab CE | reverse proxy gate on the sign-up route | proxy layer, on purpose |
| `keycloak/` | Keycloak | authenticator SPI (Java, maven) | native SPI |
| `authentik/` | Authentik | custom flow stage (Python) | native stage |
| `zitadel/` | Zitadel | action script (JS) + API flow | native action |

The Gitea/Forgejo and GitLab rows say it plainly: those servers have
no stable plugin surface for captcha, and a core patch would not
survive an update. The gate therefore lives in the reverse proxy in
front of them, reusing the nginx/Caddy bundles from this directory,
and guards exactly the sign-up endpoint.

## The shared gateway contract

`kiwi-verify.php` (shipped at the top level and copied into each
gateway directory) is the one companion every gateway needs. All
three gateways answer the same contract:

- verify URL: `KIWI_VERIFY_URL` (default the sidecar at
  `http://127.0.0.1:7371/verify`; `KIWI_VERIFY_MODE=compat` switches
  the wire format to a provider siteverify endpoint);
- secret bearer: `KIWI_BEARER`, sent only server-to-server;
- token sources: the `X-Kiwi-Token` header, the incumbent form fields,
  a JSON body, or the `kiwi_token` cookie;
- deny: 403 with `X-Kiwi-Deny: 1`, or 302 to `KIWI_REDIRECT` with
  `KIWI_DENY=302` (nginx turns the 403 into the redirect itself via
  `error_page`, since auth_request passes only 2xx);
- gate fault: 503 when the kiwi deployment is unreachable. Fail closed.

## Tests

`tests/run.sh` runs everything the local toolchain allows: PHP unit
tests of the endpoint logic, a live matrix (php -S plus curl) against
a stub kiwi deployment, `nginx -t` on the example config, byte
equality of the endpoint copies, and `php -l` over every PHP file.
Caddy and Traefik are documented for `caddy validate` and the Traefik
dashboard check; neither binary is assumed on the host.
