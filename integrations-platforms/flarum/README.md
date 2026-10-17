# KiwiCaptcha for Flarum 1.x

A Flarum extension that guards registrations: the extender wires a
PSR-15 middleware into the api frontend, and every `POST /register`
must carry a kiwi proof-of-work token verified against the deployment
before Flarum's RegisterController runs.

## Mechanism

- `extend.php` wires `(new Extend\Middleware('api'))->add(VerifySignupMiddleware::class)`
  and ships the forum JS asset through `Extend\Frontend('forum')->js`.
- `src/Api/Middleware/VerifySignupMiddleware.php` is the PSR-15
  middleware (Flarum resolves `SettingsRepositoryInterface` and the
  Guzzle client from the container): non-register requests pass
  through untouched; a register request without a token answers 403
  JSON; a failed challenge answers 403; an unreachable deployment
  answers 503 (fail closed).
- `src/Api/KiwiVerifier.php` is the framework-free verify client.
- `js/dist/forum.js` is a plain, hand-maintained asset (the extension
  ships no JS build toolchain): it patches fetch so registration
  calls carry the `X-Kiwi-Token` header read from the shim widget's
  hidden field or the `kiwi_token` cookie.
- The extension has no admin settings UI. Its settings are ordinary
  rows in Flarum's settings table, read by the middleware; set them
  with `flarum config` (which writes the table) or a SQL insert. No
  locale keys or serialized settings are shipped for a modal that
  does not exist.

## Deployment steps

1. `composer require kiwi/flarum-captcha:*` with this directory as a
   path repository (or copy it to the extensions path), then enable
   the extension in the admin panel.
2. Set the settings (`kiwi-enabled`, `kiwi-verify-url`,
   `kiwi-bearer`, `kiwi-signup-scope`, `kiwi-trusted-proxies`) in
   Flarum's settings table with `flarum config` or a SQL insert. The
   extension deliberately ships no admin UI: there is no settings
   modal, and no locale file claims one.
3. Serve the deployment's shim script on the forum (a header/footer
   HTML block or your theme):

   ```html
   <script src="https://kiwi.example.com/kiwi-captcha/api.js?compat=recaptcha" defer></script>
   ```

4. Sign-up without a solved challenge now gets 403 before any user
   row is created.

## Test status

`tests/test-middleware.php` (27 checks, plain `php`) declares the
framework interfaces the extension references (Flarum settings, Guzzle
client, PSR-7/15, the diactoros JSON response) and loads the real
middleware: pass-through for non-register requests, the 403/503 deny
paths, the pass path through header and form tokens, and the disable
switch, plus the pure verifier. It also pins the honest packaging:
`extend.php` serializes no dead admin setting and no admin locale file
is shipped. A live Flarum install remains the place where the
extension boot gets its final verification.
