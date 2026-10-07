<?php

declare(strict_types=1);

/**
 * The plugin test runner: boots the Joomla shim layer, loads the
 * captcha plugin, and exercises the plugin contract (onInit, onDisplay,
 * onCheckAnswer) plus the framework-free client. Run:
 * php tests/test-kiwicaptcha-plugin.php
 */

require __DIR__.'/joomla-shim.php';

use Joomla\CMS\Factory;
use Joomla\CMS\TestApplication;
use Joomla\CMS\TestDocument;
use Joomla\CMS\TestParams;
use Joomla\Plugin\Captcha\Kiwicaptcha\KiwiClient;

require dirname(__DIR__).'/pkg_kiwicaptcha/plg_captcha_kiwicaptcha/src/KiwiClient.php';
require dirname(__DIR__).'/pkg_kiwicaptcha/plg_captcha_kiwicaptcha/kiwicaptcha.php';

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
check('header token', KiwiClient::extractToken(['HTTP_X_KIWI_TOKEN' => 'h'], [], []) === 'h');
check('native form token', KiwiClient::extractToken([], ['kiwi__token' => 'n'], []) === 'n');
check('explicit answer code', KiwiClient::extractToken([], [], [], 'code-token') === 'code-token');
check('form beats code', KiwiClient::extractToken([], ['kiwi__token' => 'n'], [], 'code-token') === 'n');
check('cookie token', KiwiClient::extractToken([], [], ['kiwi_token' => 'c']) === 'c');
check('json token fields are namespaced, never bare token', KiwiClient::JSON_TOKEN_FIELDS === ['kiwi_token', 'captcha_response'] && !in_array('token', KiwiClient::JSON_TOKEN_FIELDS, true));
check('no token is null', KiwiClient::extractToken([], [], []) === null);
check('bad scope falls back to login', KiwiClient::sanitizeScope('bad scope') === 'login');
check('action suffix scopes survive', KiwiClient::sanitizeScope('login:signup') === 'login:signup');

// The wire request in both modes.
$json = KiwiClient::buildRequest(['verify_url' => 'http://127.0.0.1:7371/verify', 'bearer' => 'b'], 't', 'login', ['REMOTE_ADDR' => '192.0.2.7']);
$body = json_decode($json['body'], true);
check('json mode url and body', $json['url'] === 'http://127.0.0.1:7371/verify' && ($body['token'] ?? '') === 't' && ($body['scope'] ?? '') === 'login');
check('json mode bearer header', ($json['headers']['Authorization'] ?? '') === 'Bearer b');
$compat = KiwiClient::buildRequest(['verify_url' => 'https://k.test/sv', 'mode' => 'compat', 'bearer' => 'sec', 'trusted_proxies' => '10.0.0.0/24'], 't2', 'signup', ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5, 10.0.0.2']);
check('compat mode encodes response and secret', strpos($compat['body'], 'response=t2') !== false && strpos($compat['body'], 'secret=sec') !== false && strpos($compat['body'], 'remoteip=203.0.113.5') !== false);
check('untrusted peer ignores xff', KiwiClient::clientIp(['REMOTE_ADDR' => '192.0.2.7', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4']) === '192.0.2.7');
check('trusted lb takes next left', KiwiClient::clientIp(['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5, 10.0.0.1'], '10.0.0.0/24') === '203.0.113.5');
check('client-supplied leftmost entry is ignored', KiwiClient::clientIp(['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 203.0.113.5, 10.0.0.1'], '10.0.0.0/24') === '203.0.113.5');
check('garbage hop fails closed', KiwiClient::clientIp(['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4, garbage!!, 10.0.0.1'], '10.0.0.0/24') === '10.0.0.1');

// The decision table over the test transport.
KiwiClient::$testTransport = fn (): array => ['status' => 200, 'body' => json_encode(['success' => true])];
check('success verifies', KiwiClient::verify(['verify_url' => 'x'], 't', 'login') === ['ok' => true, 'code' => 'verified']);
KiwiClient::$testTransport = fn (): array => ['status' => 200, 'body' => json_encode(['success' => false])];
check('failed challenge denies', KiwiClient::verify(['verify_url' => 'x'], 't', 'login')['code'] === 'challenge_failed');
KiwiClient::$testTransport = fn (): array => ['status' => 502, 'body' => ''];
check('5xx is a fault', KiwiClient::verify(['verify_url' => 'x'], 't', 'login')['code'] === 'verify_unavailable');
KiwiClient::$testTransport = fn (): array => ['status' => 302, 'body' => json_encode(['success' => true])];
check('302 with success body fails closed', KiwiClient::verify(['verify_url' => 'x'], 't', 'login')['code'] === 'challenge_failed');
KiwiClient::$testTransport = fn (): array => ['status' => 403, 'body' => json_encode(['success' => true])];
check('403 with success body fails closed', KiwiClient::verify(['verify_url' => 'x'], 't', 'login')['code'] === 'challenge_failed');
KiwiClient::$testTransport = fn (): array => ['status' => 199, 'body' => json_encode(['success' => true])];
check('199 with success body fails closed', KiwiClient::verify(['verify_url' => 'x'], 't', 'login')['code'] === 'challenge_failed');
KiwiClient::$testTransport = fn (): array => ['status' => 204, 'body' => json_encode(['success' => true])];
check('204 with success body passes', KiwiClient::verify(['verify_url' => 'x'], 't', 'login') === ['ok' => true, 'code' => 'verified']);
KiwiClient::$testTransport = null;
check('missing peer fails closed', KiwiClient::clientIp([]) === '');
check('garbage peer fails closed', KiwiClient::clientIp(['REMOTE_ADDR' => 'not-an-ip']) === '');

// The plugin contract.
$params = new TestParams([
    'verify_url' => 'http://127.0.0.1:7371/verify',
    'shim_url' => 'https://kiwi.test/kiwi-captcha/api.js?compat=recaptcha',
    'scope' => 'signup',
    'mode' => 'json',
    'bearer' => '',
    'trusted_proxies' => '10.0.0.0/8',
]);
$plugin = new PlgCaptchaKiwicaptcha(null, $params);

$doc = new TestDocument();
Factory::$document = $doc;
check('onInit succeeds', $plugin->onInit('kiwicaptcha_1') === true);
check('onInit emits the shim script', count($doc->scripts) === 1 && $doc->scripts[0]['url'] === 'https://kiwi.test/kiwi-captcha/api.js?compat=recaptcha');

$markup = $plugin->onDisplay('kiwi', 'kiwicaptcha_1', 'extra-class');
check('onDisplay carries the scope', strpos($markup, 'data-kiwi-scope="signup"') !== false);
check('onDisplay carries the token field', strpos($markup, 'name="kiwi__token"') !== false);
check('onDisplay carries the class', strpos($markup, 'kiwi-container extra-class') !== false);

$app = new TestApplication(
    ['REMOTE_ADDR' => '192.0.2.7', 'HTTP_X_FORWARDED_FOR' => '203.0.113.9'],
    ['kiwi__token' => 'good-token']
);$plugin->setTestApp($app);
KiwiClient::$testTransport = function (array $request) use (&$captured): array {
    $captured = $request;

    return ['status' => 200, 'body' => json_encode(['success' => true])];
};
check('onCheckAnswer verifies a good token', $plugin->onCheckAnswer(null) === true);
$body = json_decode($captured['body'] ?? '', true);
check('onCheckAnswer binds the untrusted peer ip', ($body['remoteip'] ?? '') === '192.0.2.7' && ($body['token'] ?? '') === 'good-token' && ($body['scope'] ?? '') === 'signup');

KiwiClient::$testTransport = fn (): array => ['status' => 200, 'body' => json_encode(['success' => false])];
check('onCheckAnswer rejects a failed challenge', $plugin->onCheckAnswer(null) === false);

$app2 = new TestApplication([], []);
$plugin->setTestApp($app2);
check('onCheckAnswer rejects a missing token', $plugin->onCheckAnswer(null) === false);

KiwiClient::$testTransport = null;
Factory::$document = null;

fwrite($failures === 0 ? STDOUT : STDERR, sprintf("%d checks, %d failures\n", $checks, $failures));
exit($failures === 0 ? 0 : 1);
