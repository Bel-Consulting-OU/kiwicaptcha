=== KiwiCaptcha ===
Contributors: kiwicaptcha
Tags: captcha, proof of work, security, spam, woocommerce
Requires at least: 5.8
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.0.0
License: MIT

Proof-of-work CAPTCHA for login, registration, comments and WooCommerce checkout, verified against your self-hosted KiwiCaptcha deployment.

== Description ==

KiwiCaptcha protects the WordPress forms you choose with a
proof-of-work challenge. There is no third-party captcha host, no
tracking and no external calls: verification is a server-to-server
call to your own KiwiCaptcha deployment.

* Login protection through the authenticate filter (priority 30, after
  the core credential check).
* Registration protection through registration_errors.
* Comment protection through pre_comment_on_post (wp_die with a back
  link).
* WooCommerce checkout protection through woocommerce_checkout_process,
  registered inert unless WooCommerce is active.
* A forms API: the [kiwi_captcha scope="comment"] shortcode prints the
  widget container anywhere.
* A settings page under Settings, KiwiCaptcha: the deployment verify
  URL, the shim script URL, the bearer secret, the wire format and a
  scope plus enable switch per form.

The client side loads the deployment's shim script, so pages can also
keep incumbent reCAPTCHA, hCaptcha, Turnstile, ALTCHA or Friendly
Captcha markup: the shims render those containers against your own
deployment.

== Installation ==

1. Copy the wordpress/ directory to wp-content/plugins/kiwicaptcha.
2. Deploy KiwiCaptcha (the symfony bundle or the verifier sidecar) and
   note its verify URL and shim script URL.
3. Activate the plugin and open Settings, KiwiCaptcha.
4. Fill in the verify URL (default http://127.0.0.1:7371/verify for a
   sidecar on the same host), the shim script URL, and the bearer
   secret when the deployment requires one.
5. Enable the forms you want protected and set their scopes.

== Frequently Asked Questions ==

= Does the token survive a page cache? =

The widget runs in the browser at submit time and writes a fresh token
into the hidden kiwi__token field, so cached pages are fine.

= Can I use one deployment for several sites? =

Yes. Give each form its own scope so the deployment's per-scope policy
applies.

== Changelog ==

= 1.0.0 =
First release: login, registration, comment and checkout guards, the
shortcode forms API and the settings page.
