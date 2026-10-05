# KiwiCaptcha for Drupal 10/11

Native Drupal module: form protection through `hook_form_alter`, one
validate handler, a verifier service and a settings form. No drush is
needed for any of it.

## Mechanism

- `kiwicaptcha_form_alter()` matches the core form ids
  (`user_login_form`, `user_login_block`, `user_register_form`,
  `comment_form`, any `contact_message_*` form), attaches the widget
  element (a scoped container with the hidden `kiwi__token` field),
  adds the shared validate handler and attaches the deployment's shim
  script through `html_head`.
- The validate handler delegates token extraction to
  `Drupal\kiwicaptcha\KiwiVerifyLogic` and verification to the
  `kiwicaptcha.verifier` service (the pure decision table plus Guzzle
  through the `http_client` service).
- `src/Form/SettingsForm.php` is the ConfigFormBase page at
  /admin/config/people/kiwicaptcha: verify URL, shim URL, bearer,
  wire format (sidecar json or siteverify compat), trust-proxy switch
  and a scope plus enable switch per form.
- Config lives in `kiwicaptcha.settings` with the install defaults in
  `config/install/` and the schema in `config/schema/`.

## Deployment steps

1. Copy this directory to `modules/kiwicaptcha`.
2. Enable it: extend the admin UI (`/admin/modules`) or
   `drush en kiwicaptcha` if drush exists in your workflow.
3. Open Configuration, People, KiwiCaptcha; fill in the deployment
   verify URL, the shim script URL and the bearer; enable the forms.
4. The widget renders at the bottom of each protected form
   (`#weight` 100); a theme can override the `kiwicaptcha_widget`
   theme entry for different placement.

## Test status

`tests/test-kiwicaptcha-pure.php` (27 checks, plain `php`) loads
`src/KiwiVerifyLogic.php` and `src/KiwiMarkup.php` directly; neither
file references a Drupal class, so the token extraction, the scope
resolution over the settings shape, both wire formats, the full
decision table over a fake transport and the markup element are
covered outside Drupal. The thin Drupal glue (the `.module` hooks,
the service constructor, the ConfigFormBase form) is `php -l` checked
here and follows the documented Drupal 10 conventions; exercising it
end to end needs a Drupal install, which this repository does not
carry.
