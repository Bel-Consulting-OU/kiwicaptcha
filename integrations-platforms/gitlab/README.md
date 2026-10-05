# KiwiCaptcha for GitLab CE (self-hosted)

## Routing decision (stated plainly)

GitLab CE has no captcha plugin surface for a self-hosted deployment
(the built-in reCAPTCHA support binds to Google's reCAPTCHA service,
which defeats the self-hosted premise), and patching the Rails
controllers would not survive an update. The gate therefore lives in
the reverse proxy in front of GitLab and covers exactly the sign-up
endpoint. The proxy-vs-native decision is the deliverable: the
artifact is the tested gateway bundle, not a fork.

## Mechanism

- `nginx-signup-gate.conf`: the auth_request fragment for the
  registration POST (`/users/sign_up`, format suffixes included). It
  reuses the shared companion `kiwi-verify.php` from `../nginx/` and
  the same contract (verify URL, bearer, token from header/cookie,
  deny 403 with an nginx-side redirect, 503 fail closed).
- Caddy instead of nginx: the same `forward_auth` block as
  `../caddy/Caddyfile` applied to `path /users/sign_up*`.

## Deployment steps

1. Run `kiwi-verify.php` (copy it from `../nginx/`) behind an FPM
   pool on the GitLab host.
2. Put a plain nginx (or Caddy) in front of the Omnibus instance (or
   include the pieces through the Omnibus
   `nginx['custom_nginx_config']` hook). Include the fragment in the
   server block; point `proxy_pass` at the workhorse (default
   `127.0.0.1:8181`).
3. Serve the shim on the sign-up page. GitLab has no admin script-tag
   setting, so inject it through a small
   `custom_html_head`-style approach: Omnibus has
   `gitlab_rails['extra_sign_in_text']` (renders on the sign-in
   screen, not the sign-up form), so the practical path is the proxy:
   `sub_filter '</head>' '<script src="https://kiwi.example.com/kiwi-captcha/api.js?compat=recaptcha" defer></script></head>';`
   with `proxy_set_header Accept-Encoding "";` on the sign-up route,
   plus a small inline script that turns the solved token into the
   `X-Kiwi-Token` header or the `kiwi_token` cookie on submit.
4. `nginx -t` and reload.

## Test status

The shared endpoint and the nginx example config are tested on this
host (`../tests/run.sh`: the live matrix plus `nginx -t`), and the
gitea-forgejo fragment (the same directive set) is composed and
linted in the suite. The GitLab fragment uses the identical
directives with a regex location; lint it with your real server block
(`nginx -t`) after dropping it in.
