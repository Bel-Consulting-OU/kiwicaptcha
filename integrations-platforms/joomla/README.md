# KiwiCaptcha for Joomla 4/5

A Joomla package (`pkg_kiwicaptcha`) that installs one captcha plugin
(`plg_captcha_kiwicaptcha`) implementing Joomla's captcha plugin
contract: the `onInit` / `onDisplay` / `onCheckAnswer` event methods
the core Captcha factory invokes on the active captcha plugin. Once
the plugin is published and selected (System, Manage, Captcha, or the
form's captcha attribute), every form that renders a captcha gets the
kiwi widget and the server-side verification.

## Mechanism

- `onInit()` emits the deployment's shim script tag into the document
  head (params field `shim_url`), so the page can also keep incumbent
  reCAPTCHA, hCaptcha, Turnstile, ALTCHA or Friendly Captcha markup.
- `onDisplay()` returns the widget container: a `data-kiwi-scope`
  scoped div with the hidden `kiwi__token` field the form submits.
- `onCheckAnswer()` verifies: token extraction (header, the native and
  incumbent form fields, the dispatcher's answer value, cookie) and
  the server-to-server call through
  `Joomla\Plugin\Captcha\Kiwicaptcha\KiwiClient` (src/KiwiClient.php,
  framework-free). Boolean answer, the contract's shape.
- Params (the plugin's Basic tab): verify URL, shim URL, bearer
  secret, wire format (sidecar json or siteverify compat), the form
  scope, and the trust-proxy switch.

## Deployment steps

1. Zip `pkg_kiwicaptcha/` (or install the plugin directory directly
   under `plugins/captcha/kiwicaptcha`).
2. Install the package through System, Install, Extensions.
3. Publish the KiwiCaptcha captcha plugin and set its params: the
   deployment verify URL, the shim script URL, the bearer secret.
4. Select the captcha: System, Manage, Captcha (Basic Captcha
   provider) or per-form.
5. Sign-up, contact, and any extension form that honors the captcha
   contract is now protected with the scope from the params.

## Test status

`tests/test-kiwicaptcha-plugin.php` (23 checks, plain `php`) boots a
Joomla shim layer (CMSPlugin with the params registry, a recording
document, an application with raw input) and loads the real plugin
file: the three contract methods pass and deny against a stubbed
transport, and the framework-free client is covered (extraction,
scopes, both wire formats, the decision table). The shim layer is a
test double, so a live Joomla install remains the place where the
installer path and the captcha dispatcher wiring get their final
verification.
