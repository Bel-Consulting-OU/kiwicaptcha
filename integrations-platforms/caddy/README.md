# Caddy forward_auth gate

Gates arbitrary Caddy routes on a KiwiCaptcha token with Caddy's own
`forward_auth` directive (a reverse_proxy shortcut for an auth
subrequest).

## Pieces

- `kiwi-verify.php`: the companion endpoint (byte-identical with the
  top-level copy). Run it with PHP's built-in server, an FPM pool or
  a tiny container; the Caddyfile dials `127.0.0.1:8788`.
- `Caddyfile`: the site block with the `forward_auth` directive and a
  gated route.

## Deployment steps

1. Serve the shim on the pages that post to the gated route (see
   `../nginx/README.md` step 1; the tag and markup are identical).

2. Run the endpoint with the gate knobs in its environment:

   ```
   KIWI_VERIFY_URL=http://127.0.0.1:7371/verify \
   KIWI_SCOPE=login \
   KIWI_BEARER=$(cat /etc/kiwi/bearer) \
   php -S 127.0.0.1:8788 /srv/kiwi/kiwi-verify.php
   ```

   Under `php -S` every path lands in the script, so Caddy's
   `/kiwi-verify.php` uri works as written.

3. Copy the `forward_auth` block into your Caddyfile and attach it to
   the routes that must carry a captcha (a directive at site level
   guards every route; scope it with `@gated` matchers when only some
   routes are protected).

4. Deliver the token in the `X-Kiwi-Token` header or the
   `kiwi_token` cookie: the forward_auth subrequest carries the
   original method and headers, not the body.

5. The redirect knob: on a deny with `KIWI_DENY=302` and
   `KIWI_REDIRECT=https://example.com/captcha-required`, Caddy copies
   the endpoint's 302 and Location to the browser natively; keep
   `KIWI_DENY=403` for API routes.

6. Validate and reload:

   ```
   caddy validate --config Caddyfile
   caddy reload --config Caddyfile
   ```

## Test status

Caddy is not installed on this host, so the automated suite covers the
shared endpoint (`../tests/run.sh`, live matrix) and documents this
file for `caddy validate` (2.7+). The directive usage follows the
documented forward_auth contract: 2xx passes, other statuses are
copied back to the client.
