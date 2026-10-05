# KiwiCaptcha for Discourse

Native Discourse plugin: sign-up protection through a Rack middleware,
the same mechanism official plugins use for request-level work
(discourse-prometheus). No core patch, so it survives updates.

## Mechanism

- `plugin.rb` registers `KiwiSignupGate`, a Rack middleware inserted
  ahead of the app. It guards the sign-up POSTs (configurable path
  list, default `/u`, `/u.json`, `/users`), reads the token from the
  `X-Kiwi-Token` header or the `kiwi_token` cookie, and verifies it
  server-to-server against the kiwi deployment. Failures answer 403
  with a provider-shaped JSON body; an unreachable deployment answers
  503 (fail closed).
- `config/settings.yml` adds the site settings: `kiwi_captcha_enabled`,
  `kiwi_verify_url`, `kiwi_bearer` (secret), `kiwi_signup_scope`,
  `kiwi_signup_paths`, `kiwi_trust_proxy`.
- `lib/kiwi_captcha/verifier.rb` is the framework-free client (pure,
  injected transport).
- `assets/javascripts/kiwi-signup-header.js` adds the `X-Kiwi-Token`
  header to sign-up fetches, reading the token the shim widget wrote.

## Deployment steps

1. Copy this directory to `var/discourse/shared/stack/kiwi-captcha`
   (or your plugins path), add it to the container's `plugins` list,
   and rebuild: `./launcher rebuild app`.
2. Serve the shim on the signup page: Admin, Customize, Themes, edit
   the common `</head>` section and add the deployment's script tag:

   ```html
   <script src="https://kiwi.example.com/kiwi-captcha/api.js?compat=recaptcha" defer></script>
   ```

3. In Admin, Settings, find the kiwi settings: enable the plugin, set
   `kiwi verify url` to the deployment's verify endpoint and the
   bearer when one is required.
4. Verify: a sign-up POST without a solved challenge gets 403; the
   production logs record nothing extra.

## Test status

`tests/verifier_test.rb` (12 checks, plain `ruby`) covers the pure
client: token extraction, the trusted-proxy ip, the wire request
shape, the decision table over a fake transport, and a real Net::HTTP
round trip against a handcrafted local HTTP server. The middleware
and the plugin bootstrap follow the documented Discourse surfaces
(SiteSetting from settings.yml, Rack middleware insertion,
register_asset) but need a live Discourse container to exercise; this
repository does not ship one.
