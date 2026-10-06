<?php

declare(strict_types=1);

/**
 * The plugin test runner: boots the WordPress shim layer, loads the
 * plugin, and exercises the pure surfaces (settings schema and
 * sanitization, token extraction, the gate decision table, markup,
 * shortcode, scope resolution) plus every hook guard against the
 * recorded shim state. Run: php tests/test-wordpress-plugin.php
 */

require __DIR__.'/wp-shim.php';

require dirname(__DIR__).'/kiwicaptcha.php';

$failures = 0;
$checks = 0;
function check(string $name, bool $condition): void
{
    global $failures, $checks;
    ++$checks;
    if (!$condition) {
        ++$failures;
        fwrite(STDERR, "FAIL: {$name}\n");
    }
}

function resetState(array $options = []): void
{
    $GLOBALS['kiwi_test']['options'] = ['kiwicaptcha_options' => $options];
    $GLOBALS['kiwi_test']['http'] = [];
    $GLOBALS['kiwi_test']['http_log'] = [];
    $GLOBALS['kiwi_test']['die'] = null;
    $GLOBALS['kiwi_test']['notices'] = [];
    $_SERVER = ['REMOTE_ADDR' => '198.51.100.23'];
    $_POST = [];
    $_COOKIE = [];
}

$defaults = KiwiCaptcha_Settings::defaults();
check('defaults carry the deployment knobs', $defaults['verify_url'] === 'http://127.0.0.1:7371/verify' && $defaults['mode'] === 'json');
check('defaults protect login and signup only', $defaults['enabled_login'] === true && $defaults['enabled_comment'] === false);

// The hooks registered on load.
$actions = $GLOBALS['kiwi_test']['actions'];
$filters = $GLOBALS['kiwi_test']['filters'];
check('authenticate filter registered', isset($filters['authenticate']));
check('registration_errors filter registered', isset($filters['registration_errors']));
check('pre_comment_on_post action registered', isset($actions['pre_comment_on_post']));
check('woocommerce_checkout_process action registered', isset($actions['woocommerce_checkout_process']));
check('shortcode registered on init', isset($actions['init']));
check('settings page registered', isset($actions['admin_menu'], $actions['admin_init']));

// Token extraction.
$server = ['HTTP_X_KIWI_TOKEN' => ' hdr '];
check('header token wins', KiwiCaptcha_Client::extractToken($server, [], []) === 'hdr');
$post = ['kiwi__token' => 'native', 'g-recaptcha-response' => 'legacy'];
check('native field wins over incumbent', KiwiCaptcha_Client::extractToken([], $post, []) === 'native');
check('incumbent field found alone', KiwiCaptcha_Client::extractToken([], ['cf-turnstile-response' => 'cf'], []) === 'cf');
check('json body token', KiwiCaptcha_Client::extractToken(['CONTENT_TYPE' => 'application/json'], [], [], '{"token":"jt"}') === 'jt');
check('cookie token', KiwiCaptcha_Client::extractToken([], [], ['kiwi_token' => 'ck']) === 'ck');
check('no token is null', KiwiCaptcha_Client::extractToken([], [], []) === null);

// Client ip.
check('peer ip when proxies untrusted', KiwiCaptcha_Client::clientIp(['REMOTE_ADDR' => '10.9.9.9', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4']) === '10.9.9.9');
check('trusted lb takes next left', KiwiCaptcha_Client::clientIp(['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4, 10.0.0.1'], ['trusted_proxies' => '10.0.0.0/8']) === '1.2.3.4');
check('garbage hop fails closed', KiwiCaptcha_Client::clientIp(['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4, garbage!!, 10.0.0.1'], ['trusted_proxies' => '10.0.0.0/8']) === '10.0.0.1');
check('real ip when trusted and no xff', KiwiCaptcha_Client::clientIp(['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_REAL_IP' => '198.51.100.7'], ['trusted_proxies' => '10.0.0.0/8']) === '198.51.100.7');

// The decision table against a canned deployment.
resetState();
$settings = KiwiCaptcha_Settings::all();
$GLOBALS['kiwi_test']['http'][$settings['verify_url']] = [
    'response' => ['code' => 200],
    'body' => json_encode(['success' => true, 'error-codes' => []]),
];
$outcome = KiwiCaptcha_Client::evaluate($settings, 'login', ['REMOTE_ADDR' => '1.2.3.4'], ['kiwi__token' => 'good']);
check('success evaluates ok', $outcome['ok'] === true && $outcome['code'] === 'verified' && $outcome['status'] === 200);
$request = $GLOBALS['kiwi_test']['http_log'][0] ?? null;
$body = json_decode((string) ($request['args']['body'] ?? ''), true);
check('sidecar wire format sent', is_array($body) && ($body['token'] ?? '') === 'good' && ($body['scope'] ?? '') === 'login' && ($body['remoteip'] ?? '') === '1.2.3.4');
check('bearer header absent without a secret', !isset($request['args']['headers']['Authorization']));

resetState(['bearer' => 'sekrit']);
$GLOBALS['kiwi_test']['http'][KiwiCaptcha_Settings::all()['verify_url']] = [
    'response' => ['code' => 200],
    'body' => json_encode(['success' => true, 'error-codes' => []]),
];
KiwiCaptcha_Client::evaluate(KiwiCaptcha_Settings::all(), 'login', [], ['kiwi__token' => 'good']);
$request = $GLOBALS['kiwi_test']['http_log'][0] ?? null;
check('bearer rides the json authorization header', ($request['args']['headers']['Authorization'] ?? '') === 'Bearer sekrit');

$GLOBALS['kiwi_test']['http'][$settings['verify_url']] = [
    'response' => ['code' => 200],
    'body' => json_encode(['success' => false, 'error-codes' => ['timeout-or-duplicate']]),
];
$outcome = KiwiCaptcha_Client::evaluate($settings, 'login', [], ['kiwi__token' => 'stale']);
check('failed challenge denies 403', $outcome['ok'] === false && $outcome['code'] === 'challenge_failed' && $outcome['status'] === 403);

$outcome = KiwiCaptcha_Client::evaluate($settings, 'login', [], []);
check('missing token denies 403', $outcome['code'] === 'missing_token' && $outcome['status'] === 403);

$GLOBALS['kiwi_test']['http'][$settings['verify_url']] = ['response' => ['code' => 503], 'body' => ''];
$outcome = KiwiCaptcha_Client::evaluate($settings, 'login', [], ['kiwi__token' => 'good']);
check('deployment 503 is a gate fault', $outcome['code'] === 'verify_unavailable' && $outcome['status'] === 503);

$GLOBALS['kiwi_test']['http'][$settings['verify_url']] = null;
$outcome = KiwiCaptcha_Client::evaluate($settings, 'login', [], ['kiwi__token' => 'good']);
check('transport failure is a gate fault', $outcome['code'] === 'verify_unavailable' && $outcome['status'] === 503);

// Compat mode wire format.
resetState(['mode' => 'compat', 'bearer' => 'the-secret', 'verify_url' => 'https://kiwi.test/siteverify']);
$GLOBALS['kiwi_test']['http']['https://kiwi.test/siteverify'] = ['response' => ['code' => 200], 'body' => json_encode(['success' => true])];
$outcome = KiwiCaptcha_Client::evaluate(KiwiCaptcha_Settings::all(), 'login', [], ['g-recaptcha-response' => 'good']);
check('compat mode evaluates ok', $outcome['ok'] === true);
$request = $GLOBALS['kiwi_test']['http_log'][0] ?? null;
check('compat request hits the siteverify route', ($request['url'] ?? '') === 'https://kiwi.test/siteverify');
check('compat body carries response and secret', strpos((string) ($request['args']['body'] ?? ''), 'response=good') !== false && strpos((string) ($request['args']['body'] ?? ''), 'secret=the-secret') !== false);

// The guards.
resetState(['enabled_comment' => true, 'enabled_checkout' => true]);
$user = new WP_User();
$GLOBALS['kiwi_test']['http'][KiwiCaptcha_Settings::all()['verify_url']] = [
    'response' => ['code' => 200],
    'body' => json_encode(['success' => true, 'error-codes' => []]),
];
$_POST['kiwi__token'] = 'good';
$result = apply_filters('authenticate', $user, 'ada', 'pw');
check('good token passes login guard', $result instanceof WP_User);

resetState();
$result = apply_filters('authenticate', $user, 'ada', 'pw');
check('missing token blocks login with WP_Error', $result instanceof WP_Error && $result->get_error_code() === 'kiwi_captcha_failed');

resetState(['enabled_login' => false]);
$result = apply_filters('authenticate', $user, 'ada', 'pw');
check('disabled login guard passes through', $result instanceof WP_User);

resetState();
$result = apply_filters('authenticate', new WP_Error('incorrect_password', 'nope'), 'ada', 'bad');
check('credential errors short circuit', $result instanceof WP_Error && $result->get_error_code() === 'incorrect_password');

resetState();
$errors = apply_filters('registration_errors', new WP_Error(), 'ada', 'ada@example.com');
check('missing token blocks registration', $errors instanceof WP_Error && $errors->get_error_code() === 'kiwi_captcha_failed');

resetState(['enabled_comment' => true]);
$_POST['kiwi__token'] = 'good';
$GLOBALS['kiwi_test']['http'][KiwiCaptcha_Settings::all()['verify_url']] = ['response' => ['code' => 200], 'body' => json_encode(['success' => true])];
$errors = apply_filters('registration_errors', new WP_Error(), 'ada', 'ada@example.com');
check('good token registers clean', $errors->get_error_code() === '');

resetState(['enabled_comment' => true]);
$died = false;
try {
    do_action('pre_comment_on_post');
} catch (KiwiTestDie $e) {
    $died = true;
}
check('comment guard dies without a token', $died && $GLOBALS['kiwi_test']['die']['args']['response'] === 403 && $GLOBALS['kiwi_test']['die']['args']['back_link'] === true);

resetState(['enabled_comment' => false]);
$died = false;
try {
    do_action('pre_comment_on_post');
} catch (KiwiTestDie $e) {
    $died = true;
}
check('disabled comment guard skips', !$died);

resetState(['enabled_checkout' => true]);
do_action('woocommerce_checkout_process');
check('checkout guard adds a wc error notice', ($GLOBALS['kiwi_test']['notices'][0]['type'] ?? '') === 'error');

resetState(['enabled_checkout' => true]);
$GLOBALS['kiwi_test']['http'][KiwiCaptcha_Settings::all()['verify_url']] = ['response' => ['code' => 200], 'body' => json_encode(['success' => true])];
$_POST['kiwi__token'] = 'good';
do_action('woocommerce_checkout_process');
check('checkout guard passes on success', $GLOBALS['kiwi_test']['notices'] === []);

resetState(['enabled_checkout' => false]);
do_action('woocommerce_checkout_process');
check('checkout guard inert when disabled', $GLOBALS['kiwi_test']['notices'] === []);

// Markup, shortcode and scopes.
$markup = KiwiCaptcha_Form::markup('comment', 'https://kiwi.test/api.js?compat=recaptcha');
check('markup carries scope and token field', strpos($markup, 'data-kiwi-scope="comment"') !== false && strpos($markup, 'name="kiwi__token"') !== false);
check('markup carries the shim script', strpos($markup, 'src="https://kiwi.test/api.js?compat=recaptcha"') !== false);
check('markup without shim url prints container only', strpos(KiwiCaptcha_Form::markup('login', ''), '<script') === false);

do_action('init');
check('shortcode registered', isset($GLOBALS['kiwi_test']['shortcodes']['kiwi_captcha']));
resetState(['shim_url' => 'https://kiwi.test/kiwi-captcha/api.js?compat=recaptcha']);
$html = call_user_func($GLOBALS['kiwi_test']['shortcodes']['kiwi_captcha'], ['scope' => 'guestbook']);
check('shortcode honors the scope attribute', strpos($html, 'data-kiwi-scope="guestbook"') !== false);
$html = call_user_func($GLOBALS['kiwi_test']['shortcodes']['kiwi_captcha'], []);
check('shortcode defaults to the comment scope', strpos($html, 'data-kiwi-scope="comment"') !== false);

resetState(['scope_checkout' => 'checkout:order']);
check('action suffix scopes survive', KiwiCaptcha_Form::scopeFor('checkout') === 'checkout:order');
check('bad scope falls back to login', KiwiCaptcha_Form::sanitizeScope('bad scope!') === 'login');

// Settings sanitization.
$dirty = [
    'verify_url' => ' https://kiwi.test/verify ',
    'mode' => 'yaml',
    'enabled_login' => '1',
    'scope_login' => 'drop table; --',
    'enabled_checkout' => true,
    'scope_checkout' => 'checkout:pay',
];
$clean = KiwiCaptcha_Settings::sanitize($dirty);
check('sanitize trims the verify url', $clean['verify_url'] === 'https://kiwi.test/verify');
check('sanitize rejects unknown modes', $clean['mode'] === 'json');
check('sanitize keeps boolean toggles', $clean['enabled_login'] === true && $clean['enabled_checkout'] === true);
check('sanitize rejects hostile scopes', $clean['scope_login'] === 'login' && $clean['scope_checkout'] === 'checkout:pay');

// The settings page fields exist once the admin hooks run.
do_action('admin_init');
check('settings registered through the API', $GLOBALS['kiwi_test']['settings_registered'] === 1);
check('every form has a settings field', isset($GLOBALS['kiwi_test']['fields']['enabled_login'], $GLOBALS['kiwi_test']['fields']['enabled_checkout']));

fwrite($failures === 0 ? STDOUT : STDERR, sprintf("%d checks, %d failures\n", $checks, $failures));
exit($failures === 0 ? 0 : 1);
