<?php

declare(strict_types=1);

/**
 * The framework-free test runner for the drupal module: loads
 * src/KiwiVerifyLogic.php and src/KiwiMarkup.php directly (neither
 * references a Drupal class) and exercises the surfaces the module
 * hooks delegate to. Run: php tests/test-kiwicaptcha-pure.php
 */

require dirname(__DIR__).'/src/KiwiVerifyLogic.php';
require dirname(__DIR__).'/src/KiwiMarkup.php';

use Drupal\kiwicaptcha\KiwiMarkup;
use Drupal\kiwicaptcha\KiwiVerifyLogic;

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

// Token extraction.
check('header token', KiwiVerifyLogic::extractToken(['HTTP_X_KIWI_TOKEN' => 'h1'], [], []) === 'h1');
check('native form token', KiwiVerifyLogic::extractToken([], ['kiwi__token' => 'n1'], []) === 'n1');
check('incumbent form token', KiwiVerifyLogic::extractToken([], ['h-captcha-response' => 'hc'], []) === 'hc');
check('cookie token', KiwiVerifyLogic::extractToken([], [], ['kiwi_token' => 'c1']) === 'c1');
check('no token is null', KiwiVerifyLogic::extractToken([], [], []) === null);

// Scope resolution over the settings shape.
$settings = [
    'enabled_login' => true,
    'enabled_signup' => false,
    'enabled_comment' => true,
    'enabled_contact' => false,
    'scope_login' => 'portal-login',
    'scope_comment' => 'comment',
];
check('login form resolves the configured scope', KiwiVerifyLogic::scopeForForm('user_login_form', $settings) === 'portal-login');
check('block login resolves the same scope', KiwiVerifyLogic::scopeForForm('user_login_block', $settings) === 'portal-login');
check('disabled signup resolves null', KiwiVerifyLogic::scopeForForm('user_register_form', $settings) === null);
check('comments resolve', KiwiVerifyLogic::scopeForForm('comment_form', $settings) === 'comment');
check('contact disabled resolves null', KiwiVerifyLogic::scopeForForm('contact_message_feedback', $settings) === null);
check('unknown form resolves null', KiwiVerifyLogic::scopeForForm('search_form', $settings) === null);
check('contact prefix match', KiwiVerifyLogic::scopeForForm('contact_message_personal', ['enabled_contact' => true, 'scope_contact' => 'contact:site']) === 'contact:site');

// The wire request in both modes.
$server = ['REMOTE_ADDR' => '192.0.2.9'];
$json = KiwiVerifyLogic::buildRequest(['verify_url' => 'http://127.0.0.1:7371/verify', 'bearer' => 'b'], 't1', 'login', $server);
$body = json_decode($json['body'], true);
check('json mode url', $json['url'] === 'http://127.0.0.1:7371/verify');
check('json mode body', ($body['token'] ?? '') === 't1' && ($body['scope'] ?? '') === 'login' && ($body['remoteip'] ?? '') === '192.0.2.9');
check('json mode bearer header', ($json['headers']['Authorization'] ?? '') === 'Bearer b');

$compat = KiwiVerifyLogic::buildRequest(['verify_url' => 'https://k.test/sv', 'mode' => 'compat', 'bearer' => 'sec', 'trust_proxy' => true], 't2', 'signup', ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '198.51.100.4, 10.0.0.2']);
check('compat mode encodes response and secret', strpos($compat['body'], 'response=t2') !== false && strpos($compat['body'], 'secret=sec') !== false && strpos($compat['body'], 'remoteip=198.51.100.4') !== false);
check('compat mode omits the bearer header', !isset($compat['headers']['Authorization']));

// The decision table over a fake transport.
$ok = ['status' => 200, 'body' => json_encode(['success' => true])];
$settings = ['verify_url' => 'http://127.0.0.1:7371/verify'];
check('success verifies', KiwiVerifyLogic::decide($settings, 't', 'login', [], fn () => $ok) === ['ok' => true, 'code' => 'verified']);
$fail = ['status' => 200, 'body' => json_encode(['success' => false, 'error-codes' => ['timeout-or-duplicate']])];
check('failed challenge denies', KiwiVerifyLogic::decide($settings, 't', 'login', [], fn () => $fail)['code'] === 'challenge_failed');
check('transport throw is a fault', KiwiVerifyLogic::decide($settings, 't', 'login', [], function (): array {
    throw new RuntimeException('down');
})['code'] === 'verify_unavailable');
check('5xx is a fault', KiwiVerifyLogic::decide($settings, 't', 'login', [], fn () => ['status' => 502, 'body' => ''])['code'] === 'verify_unavailable');
check('401 is a fault', KiwiVerifyLogic::decide($settings, 't', 'login', [], fn () => ['status' => 401, 'body' => '{}'])['code'] === 'verify_unavailable');
check('garbage body is a fault', KiwiVerifyLogic::decide($settings, 't', 'login', [], fn () => ['status' => 200, 'body' => '<html>'])['code'] === 'verify_unreadable');

// Markup.
$element = KiwiMarkup::renderElement('comment');
check('element carries scope', $element['#attributes']['data-kiwi-scope'] === 'comment' && $element['#kiwi_scope'] === 'comment');
check('element carries the token field', strpos((string) $element['#value'], 'name="kiwi__token"') !== false);
check('bad scope falls back to login', KiwiMarkup::sanitizeScope('no such') === 'login');
check('action suffix scopes survive', KiwiMarkup::sanitizeScope('checkout:pay') === 'checkout:pay');

fwrite($failures === 0 ? STDOUT : STDERR, sprintf("%d checks, %d failures\n", $checks, $failures));
exit($failures === 0 ? 0 : 1);
