<?php

declare(strict_types=1);

/**
 * The plain-php test of the phpBB extension's pure surfaces: the
 * client request building and decision table, and the captcha
 * plugin's token extraction and scope handling. The framework-typed
 * classes (config, Guzzle client) are stubbed as anonymous classes.
 * Run: php tests/test-client.php
 */

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

// Load the extension classes without phpBB: declare the config type.
if (!class_exists('phpbb\\config\\config')) {
    // phpcs:ignore
    eval('namespace phpbb\config; class config implements \ArrayAccess {
        private array $data;
        public function __construct(array $data = []) { $this->data = $data; }
        public function offsetExists(mixed $o): bool { return isset($this->data[$o]); }
        public function offsetGet(mixed $o): mixed { return $this->data[$o] ?? null; }
        public function offsetSet(mixed $o, mixed $v): void { $this->data[$o] = $v; }
        public function offsetUnset(mixed $o): void { unset($this->data[$o]); }
    }');
}
if (!interface_exists('GuzzleHttp\\ClientInterface')) {
    // phpcs:ignore
    eval('namespace GuzzleHttp; interface ClientInterface { public function request(string $m, string $u, array $o = []); }
    class Exception extends \Exception {}
    interface GuzzleException {}');
}

require dirname(__DIR__).'/captcha/client.php';
require dirname(__DIR__).'/captcha/kiwi.php';

use kiwi\captcha\captcha\client;
use kiwi\captcha\captcha\kiwi;

// Request building, both modes.
$json = client::build_request(
    ['verify_url' => 'http://127.0.0.1:7371/verify', 'bearer' => 'b'],
    't',
    'signup',
    ['REMOTE_ADDR' => '192.0.2.5']
);
$body = json_decode($json['body'], true);
check('json request shape', ($body['token'] ?? '') === 't' && ($body['scope'] ?? '') === 'signup' && ($body['remoteip'] ?? '') === '192.0.2.5');
check('json bearer header', ($json['headers']['Authorization'] ?? '') === 'Bearer b');
$compat = client::build_request(
    ['verify_url' => 'https://k.test/sv', 'mode' => 'compat', 'bearer' => 's', 'trusted_proxies' => '10.0.0.0/8'],
    't2',
    'login',
    ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.8, 10.0.0.2']
);
check('compat request encodes the incumbent shape', strpos($compat['body'], 'response=t2') !== false && strpos($compat['body'], 'secret=s') !== false && strpos($compat['body'], 'remoteip=203.0.113.8') !== false);
check('untrusted peer ignores xff', client::client_ip(['REMOTE_ADDR' => '192.0.2.5', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4']) === '192.0.2.5');
check('trusted lb takes next left', client::client_ip(['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.8, 10.0.0.1'], '10.0.0.0/8') === '203.0.113.8');
check('client-supplied leftmost entry is ignored', client::client_ip(['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 203.0.113.8, 10.0.0.1'], '10.0.0.0/8') === '203.0.113.8');
check('garbage hop fails closed', client::client_ip(['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4, garbage!!, 10.0.0.1'], '10.0.0.0/8') === '10.0.0.1');

// The decision table.
check('success verifies', client::decide(200, '{"success":true}') === ['ok' => true, 'code' => 'verified']);
check('failure denies', client::decide(200, '{"success":false}') === ['ok' => false, 'code' => 'challenge_failed']);
check('5xx is a fault', client::decide(503, '')['code'] === 'verify_unavailable');
check('302 with success body fails closed', client::decide(302, '{"success":true}')['code'] === 'challenge_failed');
check('403 with success body fails closed', client::decide(403, '{"success":true}')['code'] === 'challenge_failed');
check('429 with success body fails closed', client::decide(429, '{"success":true}')['code'] === 'challenge_failed');
check('199 with success body fails closed', client::decide(199, '{"success":true}')['code'] === 'challenge_failed');
check('204 with success body passes', client::decide(204, '{"success":true}') === ['ok' => true, 'code' => 'verified']);
check('missing peer fails closed', client::client_ip([]) === '');
check('garbage peer fails closed', client::client_ip(['REMOTE_ADDR' => 'not-an-ip']) === '');
check('garbage body is unreadable', client::decide(200, '<html>')['code'] === 'verify_unreadable');

// Token resolution: the collect/distinct/conflict authority rule.
check('header token', kiwi::resolve_token(['HTTP_X_KIWI_TOKEN' => 'h'], [], []) === ['token' => 'h', 'code' => null]);
check('incumbent field token', kiwi::resolve_token([], ['g-recaptcha-response' => 'g'], []) === ['token' => 'g', 'code' => null]);
check('cookie token', kiwi::resolve_token([], [], ['kiwi_token' => 'c']) === ['token' => 'c', 'code' => null]);
check('missing token', kiwi::resolve_token([], [], []) === ['token' => null, 'code' => null]);
check('blank values are no token', kiwi::resolve_token(['HTTP_X_KIWI_TOKEN' => '  '], ['kiwi__token' => ''], []) === ['token' => null, 'code' => null]);

// The ambiguity matrix: zero distinct values pass nothing, one
// distinct value verifies however many sources carry it, two or more
// distinct values refuse with the typed token_source_conflict code
// before any verification.
check('header a field b conflicts', kiwi::resolve_token(['HTTP_X_KIWI_TOKEN' => 'a'], ['kiwi__token' => 'b'], []) === ['token' => null, 'code' => 'token_source_conflict']);
check('header a cookie b conflicts', kiwi::resolve_token(['HTTP_X_KIWI_TOKEN' => 'a'], [], ['kiwi_token' => 'b']) === ['token' => null, 'code' => 'token_source_conflict']);
check('field a cookie b conflicts', kiwi::resolve_token([], ['kiwi__token' => 'a'], ['kiwi_token' => 'b']) === ['token' => null, 'code' => 'token_source_conflict']);
check('two distinct repeated header lines conflict', kiwi::resolve_token(['HTTP_X_KIWI_TOKEN' => 'a, b'], [], []) === ['token' => null, 'code' => 'token_source_conflict']);
check('two distinct form array values conflict', kiwi::resolve_token([], ['kiwi__token' => ['a', 'b']], []) === ['token' => null, 'code' => 'token_source_conflict']);
check('same token in every source verifies', kiwi::resolve_token(['HTTP_X_KIWI_TOKEN' => 'a'], ['kiwi__token' => 'a'], ['kiwi_token' => 'a']) === ['token' => 'a', 'code' => null]);
check('same value twice in the merged header verifies', kiwi::resolve_token(['HTTP_X_KIWI_TOKEN' => 'a, a'], [], []) === ['token' => 'a', 'code' => null]);
check('same value as a repeated form array verifies', kiwi::resolve_token([], ['kiwi__token' => ['a', 'a']], []) === ['token' => 'a', 'code' => null]);
check('bad scope falls back', kiwi::sanitize_scope('nope nope') === 'signup');

// The plugin against a stub config and a stub Guzzle client.
$config = new \phpbb\config\config([
    'kiwi_verify_url' => 'http://127.0.0.1:7371/verify',
    'kiwi_scope' => 'signup:board',
    'kiwi_shim_url' => 'https://kiwi.test/api.js',
]);
$plugin = new kiwi($config, new client(new class implements \GuzzleHttp\ClientInterface {
    public function request(string $method, string $url, array $options = [])
    {
        return new class {
            public function getStatusCode(): int
            {
                return 200;
            }
            public function getBody(): string
            {
                return '{"success":true}';
            }
        };
    }
}));
$plugin->init();
$_SERVER = ['REMOTE_ADDR' => '192.0.2.5'];
$_POST = ['kiwi__token' => 'good'];
check('confirm verifies with a good token', $plugin->confirm() === true);
$template = $plugin->get_template();
check('template names the captcha template', $template['filename'] === 'captcha_kiwi.html');
check('template carries the scope and shim url', $template['vars']['KIWI_SCOPE'] === 'signup:board' && $template['vars']['KIWI_SHIM_URL'] === 'https://kiwi.test/api.js');
check('template markup carries the token field', strpos((string) $template['vars']['KIWI_MARKUP'], 'name="kiwi__token"') !== false);
check('plugin reports config support', $plugin->has_config() === true);
check('plugin name is kiwi', $plugin->get_name() === 'kiwi');

$_POST = [];
$_SERVER = [];
$plugin->reset();
check('confirm denies a missing token', $plugin->confirm() === false);
check('attempts counted', $plugin->get_attempt_count() === 1);
check('a missing token carries no typed code', $plugin->get_last_code() === null);

// A token_source_conflict refuses the confirmation with the typed
// code before anything is verified: the stub client would answer
// success for any token, so only the authority rule can deny here.
$plugin->reset();
$_SERVER = ['REMOTE_ADDR' => '192.0.2.5', 'HTTP_X_KIWI_TOKEN' => 'good'];
$_POST = ['kiwi__token' => 'evil'];
check('confirm refuses a token_source_conflict', $plugin->confirm() === false);
check('the typed conflict code is exposed', $plugin->get_last_code() === 'token_source_conflict');
check('a conflict counts as a failed attempt', $plugin->get_attempt_count() === 1);

$_POST = [];
$_SERVER = [];
$plugin->reset();
$_SERVER = ['REMOTE_ADDR' => '192.0.2.5', 'HTTP_X_KIWI_TOKEN' => 'good'];
check('confirm passes the single token through', $plugin->confirm() === true);
check('a pass carries no typed code', $plugin->get_last_code() === null);

// The ACP surface: the module files exist and the module writes every
// config key the captcha plugin reads.
$extDir = dirname(__DIR__);
foreach ([
    'acp/main_info.php',
    'acp/main_module.php',
    'adm/style/acp_kiwi_settings.html',
    'language/en/info_acp_kiwi.php',
] as $relative) {
    check("ACP file {$relative} exists", is_file($extDir.'/'.$relative));
}

if (!defined('IN_PHPBB')) {
    define('IN_PHPBB', true);
}
$lang = [];
require $extDir.'/language/en/info_acp_kiwi.php';
require $extDir.'/acp/main_info.php';
$info = (new \kiwi\captcha\acp\main_info())->module();
check('ACP module points at main_module', str_ends_with((string) ($info['filename'] ?? ''), 'main_module'));
check('ACP settings mode has the extension auth', isset($info['modes']['settings']['auth']) && str_contains((string) $info['modes']['settings']['auth'], 'ext_kiwi/captcha'));
check('ACP mode title is a declared language key', array_key_exists((string) ($info['modes']['settings']['title'] ?? ''), $lang));

$moduleSource = (string) file_get_contents($extDir.'/acp/main_module.php');
$captchaSource = (string) file_get_contents($extDir.'/captcha/kiwi.php');
preg_match_all("/config\['(kiwi_[a-z_]+)'\]/", $captchaSource, $matches);
$configKeys = array_values(array_unique($matches[1]));
sort($configKeys);
check(
    'captcha reads the documented config keys',
    $configKeys === ['kiwi_bearer', 'kiwi_mode', 'kiwi_scope', 'kiwi_shim_url', 'kiwi_trusted_proxies', 'kiwi_verify_url']
);
foreach ($configKeys as $key) {
    check("ACP writes {$key}", str_contains($moduleSource, "'{$key}'"));
}

$template = (string) file_get_contents($extDir.'/adm/style/acp_kiwi_settings.html');
$languageSource = (string) file_get_contents($extDir.'/language/en/info_acp_kiwi.php');
preg_match_all('/\{L_([A-Z0-9_]+)\}/', $template, $languageMatches);
$coreKeys = ['COLON', 'RESET', 'SUBMIT'];
foreach (array_unique($languageMatches[1]) as $key) {
    if (in_array($key, $coreKeys, true)) {
        continue;
    }
    check("ACP language key {$key}", str_contains($languageSource, "'{$key}'"));
}
check('ACP template is wired to the module', str_contains($moduleSource, "'acp_kiwi_settings'"));

fwrite($failures === 0 ? STDOUT : STDERR, sprintf("%d checks, %d failures\n", $checks, $failures));
exit($failures === 0 ? 0 : 1);
