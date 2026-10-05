# KiwiCaptcha for phpBB 3.3

A phpBB extension (`ext/kiwi/captcha`) that registers a captcha plugin
service, the platform's own captcha mechanism: the board's captcha
factory (`phpbb\captcha\factory`) resolves the configured plugin by
the service name `captcha.plugins.<name>`, and this extension
registers `captcha.plugins.kiwi`.

## Mechanism

- `captcha/kiwi.php` implements the captcha plugin contract:
  `init()`, `confirm()` (the verification), `get_attempt_count()`,
  `reset()`, `get_name()`, `has_config()`, plus the template feed
  (`captcha_kiwi.html` with the widget markup and the shim URL).
- `captcha/client.php` is the verify client: mode `json` speaks the
  sidecar (`{"token","scope","remoteip"}` with the bearer header),
  mode `compat` speaks a siteverify route (`response`, `secret`,
  `remoteip` form encoding). The transport is phpBB's `http_client`
  service (Guzzle).
- `config/services.yml` wires both; `language/en/info_acp_kiwi.php`
  carries the ACP strings; the config keys are `kiwi_verify_url`,
  `kiwi_bearer`, `kiwi_shim_url`, `kiwi_scope`, `kiwi_mode`,
  `kiwi_trust_proxy` (set them through a small ACP page or an SQL
  insert; the plugin reads them from the board config table).

## Deployment steps

1. Copy `ext/kiwi/captcha` to `<board>/ext/kiwi/captcha`.
2. Enable in ACP, Customise, Manage extensions.
3. Select the captcha: ACP, General, Board configuration, User
   registration, "Spambot countermeasures" (or the form's captcha
   setting), choose KiwiCaptcha.
4. Set the config keys (verify URL, shim URL, scope `signup`) so the
   widget and the verifier find the deployment.

## Test status

`ext/kiwi/captcha/tests/test-client.php` (20 checks, plain `php`)
stubs the two framework types (`phpbb\config\config` as an array
accessory, `GuzzleHttp\ClientInterface` as a one-method interface),
then loads the real extension classes: both wire formats, the decision
table, token extraction, the confirm() pass and deny paths, the
attempt counter and the template feed. A live board install remains
the place where the ACP flow and the style rendering get their final
verification; the phpBB version constraint (>=3.3, <4.0) is declared
in composer.json.
