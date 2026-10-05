# KiwiCaptcha for WordPress

Native WordPress plugin: login, registration, comments and WooCommerce
checkout protection, a forms API and a settings page, all verified
server-to-server against your own kiwi deployment.

## Mechanism

| Form | Hook | Failure shape |
|---|---|---|
| wp-login.php | `authenticate` filter, priority 30 | WP_Error `kiwi_captcha_failed` |
| wp-signup.php / wp-register.php | `registration_errors` | appended WP_Error |
| comments | `pre_comment_on_post` | `wp_die` with a back link |
| WooCommerce checkout | `woocommerce_checkout_process` | `wc_add_notice(..., 'error')` |
| any form | `[kiwi_captcha scope="..."]` shortcode | the widget container |

Verification is one `wp_remote_post` to the deployment: json mode
speaks the sidecar (`{"token","scope","remoteip"}` plus the bearer
header), compat mode speaks a siteverify route (`response`, `secret`,
`remoteip` form encoding). The response keeps the provider shape, so
the decision table is: success true passes, a 5xx or transport failure
is a gate fault (deny, 503-shaped), everything else denies.

The client side is the deployment's shim script (settings field
`shim_url`, e.g. `https://kiwi.example.com/kiwi-captcha/api.js?compat=recaptcha`).
It renders the incumbent containers and writes the solved token into
the hidden `kiwi__token` field the plugin's markup carries, so a page
cache never serves a stale token.

## Deployment steps

1. Copy this directory to `wp-content/plugins/kiwicaptcha` and
   activate the plugin.
2. Deploy KiwiCaptcha (the symfony bundle or the verifier sidecar) and
   open Settings, KiwiCaptcha.
3. Fill in the verify URL (default `http://127.0.0.1:7371/verify`),
   the shim script URL and the bearer secret; pick the wire format.
4. Enable the forms you want protected; set each form's scope
   (`login`, `signup`, `comment`, `checkout` by default).
5. For custom forms, place `[kiwi_captcha scope="guestbook"]` in the
   content or call `KiwiCaptcha_Form::markup('guestbook', $shimUrl)`
   from a template, and verify `kiwi__token` with
   `KiwiCaptcha_Client::evaluate()` in your own handler.

## Test status

`tests/test-wordpress-plugin.php` (52 checks, run with plain `php`)
exercises the plugin through a WordPress function shim layer: the
options store, the filter/action registry, a recording
`wp_remote_post`, a throwing `wp_die` and a `wc_add_notice` collector.
Covered: the settings schema and sanitization, token extraction
(header, native and incumbent fields, JSON body, cookie), the full
decision table, the wire formats on the recorded requests, every guard
hook's pass and deny path, the shortcode, the scope resolution and the
markup. Not covered here: the browser rendering of the shim (covered
by the wasm package's browser suite) and a live WooCommerce install.
