# nginx auth_request gate

Gates arbitrary nginx routes on a KiwiCaptcha token. The mechanism is
nginx's own `auth_request` module: each gated route fires an internal
subrequest to PHP running `kiwi-verify.php` (shipped next to this
file), and only a 204 lets the request through.

## Pieces

- `kiwi-verify.php`: a shim to the canonical endpoint at
  `../kiwi-verify.php`. In a deployment, copy the CANONICAL
  `../kiwi-verify.php` to the web root that PHP serves (outside any
  public document root when you can; the location below reaches it
  through FPM directly) — do not copy the shim alone.
- `kiwi-gate.conf.example`: a complete, lintable config with the three
  pieces marked: the auth location, the `auth_request` + `error_page`
  pair, and the deny/fault outcomes.

## Deployment steps

1. Serve the shim on the pages that post to the gated route. The
   script tag is the kiwi deployment's compat route, for example:

   ```html
   <script src="https://kiwi.example.com/kiwi-captcha/api.js?compat=recaptcha" defer></script>
   <div class="g-recaptcha" data-sitekey="login"></div>
   ```

2. Deliver the token to the gate. The `auth_request` subrequest
   carries request headers and cookies, never the body. Either have
   the page send the header (a fetch wrapper that adds
   `X-Kiwi-Token: <token>` from the shim's response field), or set
   the `kiwi_token` cookie from the page after the widget solves:

   ```js
   document.cookie = 'kiwi_token=' + encodeURIComponent(token) + '; Path=/; Secure; SameSite=Strict';
   ```

3. Copy the marked pieces of `kiwi-gate.conf.example` into your
   server block. Point `fastcgi_pass` at your FPM socket and
   `SCRIPT_FILENAME` at the copied `kiwi-verify.php`. Set the knobs
   (`KIWI_VERIFY_URL`, `KIWI_SCOPE`, `KIWI_TRUSTED_PROXIES`, a
   comma-separated trusted-proxy CIDR list whose default empty value
   never trusts a forwarded header). Keep
   `KIWI_BEARER` in the FPM pool environment, never in the config.

4. The redirect knob: nginx `auth_request` passes only 2xx, so keep
   `KIWI_DENY=403` on the endpoint and let nginx do the redirect with
   `error_page 403 = @kiwi_denied;` exactly as the example shows.

5. Lint and reload:

   ```
   nginx -t -c /etc/nginx/nginx.conf
   nginx -s reload
   ```

## Scope per route

Duplicate the auth location per scope when different gates protect
different forms (`KIWI_SCOPE=login` for sign-in, `signup` for
registration, `comment` for comments). One scope per `location` block
keeps the mapping reviewable.

## Test status

`../tests/run.sh` lints this example config with `nginx -t` on this
host (nginx 1.31) and exercises the endpoint itself live. The full
proxy chain (a real FPM pool behind a real server block) is documented
here but not driven by the automated tests.
