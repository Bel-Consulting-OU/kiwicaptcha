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
check('garbage body is unreadable', client::decide(200, '<html>')['code'] === 'verify_unreadable');

// Token extraction.
check('header token', kiwi::extract_token(['HTTP_X_KIWI_TOKEN' => 'h'], [], []) === 'h');
check('incumbent field token', kiwi::extract_token([], ['g-recaptcha-response' => 'g'], []) === 'g');
check('cookie token', kiwi::extract_token([], [], ['kiwi_token' => 'c']) === 'c');
check('missing token is null', kiwi::extract_token([], [], []) === null);
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

fwrite($failures === 0 ? STDOUT : STDERR, sprintf("%d checks, %d failures\n", $checks, $failures));
exit($failures === 0 ? 0 : 1);
