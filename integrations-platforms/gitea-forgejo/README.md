# KiwiCaptcha for Gitea and Forgejo

## Routing decision (stated plainly)

Gitea and Forgejo have no plugin or hook surface for captcha, and a
core patch would not survive an update. The gate therefore lives in
the reverse proxy in front of the server and covers exactly the
sign-up endpoint; everything else reaches Gitea or Forgejo untouched.
This proxy-vs-native decision is deliberate: the artifact is the
tested gateway bundle, not a fork.

## Mechanism

- `nginx-signup-gate.conf`: the auth_request fragment for the
  registration POST (`/user/sign_up` on both servers). It reuses the
  shared companion `kiwi-verify.php` from `../nginx/` and the same
  contract (verify URL, bearer, token from header/cookie, deny 403
  with an nginx-side redirect, 503 fail closed).
- The Caddy equivalent is the same `forward_auth` block as
  `../caddy/Caddyfile` with `uri /kiwi-verify.php` applied to
  `path /user/sign_up`.

## Deployment steps (nginx)

1. Run `kiwi-verify.php` (copy it from `../nginx/`) behind an FPM
   pool, and serve the shim on the sign-up page. Gitea has no admin
   script-tag setting, so add the tag through a custom
   `templates/base/head_script.tmpl` in `$GITEA_CUSTOM` (or Forgejo's
   `custom/templates/base/head_script.tmpl`):

   ```html
   <script src="https://kiwi.example.com/kiwi-captcha/api.js?compat=recaptcha" defer></script>
   ```

   plus a tiny inline script that sets the token cookie or injects
   the `X-Kiwi-Token` header on the registration submit (the shim
   writes the token into the `kiwi__token` hidden field; a five line
   submit handler turns it into the header or the cookie).

2. Include `nginx-signup-gate.conf` into the server block that
   proxies Gitea (the fragment defines the auth location, the gated
   route and the two outcome redirects). Point `fastcgi_pass` and
   `SCRIPT_FILENAME` at your pool and the copied endpoint.
3. `nginx -t` and reload.

## Test status

The shared endpoint and the nginx example config are tested on this
host (`../tests/run.sh` runs the live matrix and `nginx -t`). The
sign-up fragment uses the identical directives; lint it with your
real server block (`nginx -t`) after dropping it in, since the
fragment alone is not a complete config (an nginx fragment cannot be
linted standalone).
