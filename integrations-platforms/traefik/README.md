# Traefik forwardAuth gate

Gates arbitrary Traefik routers on a KiwiCaptcha token with the
`forwardAuth` middleware.

## Pieces

- `kiwi-verify.php`: a shim to the canonical endpoint at
  `../kiwi-verify.php` (one shared endpoint, no per-gateway drift).
  Deploy the canonical file. Run it on `127.0.0.1:8788`.
- `kiwi-forwardauth.yml`: the dynamic configuration with the
  `kiwi-captcha` middleware and one gated router.

## Deployment steps

1. Serve the shim on the pages that post to the gated route (see
   `../nginx/README.md` step 1).

2. Run the endpoint with the gate knobs in its environment:

   ```
   KIWI_VERIFY_URL=http://127.0.0.1:7371/verify \
   KIWI_SCOPE=signup \
   KIWI_TRUSTED_PROXIES=127.0.0.0/8 \
   KIWI_BEARER=$(cat /etc/kiwi/bearer) \
   php -S 127.0.0.1:8788 /srv/kiwi/kiwi-verify.php
   ```

   Set `KIWI_TRUSTED_PROXIES=127.0.0.0/8` when Traefik is the only
   thing that can set X-Forwarded-For on this hop (the default
   entryPoint behavior). With the default empty value the gate binds
   the socket peer, so a client-supplied forwarding header can never
   move the binding.

3. Drop `kiwi-forwardauth.yml` into the directory your static config
   watches:

   ```yaml
   providers:
     file:
       directory: /etc/traefik/dynamic
       watch: true
   ```

4. Attach the `kiwi-captcha` middleware to every router that must
   carry a captcha, exactly as the example router does.

5. Token sources: forwardAuth preserves the original method and body,
   so the header, the cookie, a form field and a JSON body all work
   on this layer.

6. The redirect knob: with `KIWI_DENY=302` plus `KIWI_REDIRECT`,
   Traefik returns the endpoint's 302 with its Location to the
   browser; API routes keep the plain 403.

7. Check the config in the dashboard (the middleware appears under
   HTTP, middlewares) or with `traefik --configFile=... --dry-run` on
   a host that has the binary.

## Test status

Traefik is not installed on this host, so the automated suite covers
the shared endpoint (`../tests/run.sh`) and the YAML is documented for
the dashboard check. The middleware fields follow the documented
forwardAuth contract: 2xx continues, anything else is returned to the
client.
