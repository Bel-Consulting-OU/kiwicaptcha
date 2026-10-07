<?php

declare(strict_types=1);

/**
 * Unit tests of kiwi-verify.php's pure logic. The include defines
 * KIWI_VERIFY_LIBRARY first, so only the functions load; the HTTP
 * surface runs in the live matrix (live.sh).
 */

define('KIWI_VERIFY_LIBRARY', 1);
require __DIR__.'/../kiwi-verify.php';

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

// Token extraction: header, form fields, JSON body, cookie, order.
$server = ['HTTP_X_KIWI_TOKEN' => ' header-token '];
check('header token wins and trims', kiwi_verify_extract_token($server, [], [], null) === 'header-token');

$server = ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'];
$post = ['g-recaptcha-response' => 'incumbent-token'];
check('incumbent form field token', kiwi_verify_extract_token($server, $post, [], null) === 'incumbent-token');

$post = ['kiwi__token' => 'native-token', 'g-recaptcha-response' => 'incumbent-token'];
check('native field outranks incumbent aliases', kiwi_verify_extract_token([], $post, [], null) === 'native-token');

$server = ['CONTENT_TYPE' => 'application/json'];
check('json body namespaced token', kiwi_verify_extract_token($server, [], [], '{"kiwi_token":"json-token","scope":"login"}') === 'json-token');
check('json body captcha_response token', kiwi_verify_extract_token($server, [], [], '{"captcha_response":"cr-token"}') === 'cr-token');
check('json body bare token field is ignored', kiwi_verify_extract_token($server, [], [], '{"token":"app-secret"}') === null);
check('cookie token', kiwi_verify_extract_token([], [], ['kiwi_token' => 'cookie-token'], null) === 'cookie-token');
check('missing token is null', kiwi_verify_extract_token([], [], [], null) === null);
check('whitespace token is null', kiwi_verify_extract_token([], ['kiwi__token' => '   '], [], null) === null);

// Client ip: the trust boundary. A forged forwarding header never
// moves the binding without a trusted peer.
$server = ['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7, 10.0.0.2'];
check('untrusted proxy uses the peer', kiwi_verify_client_ip($server, []) === '10.0.0.9');
check('trusted lb takes next left', kiwi_verify_client_ip(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7, 10.0.0.9'], ['10.0.0.0/24']) === '203.0.113.7');
check('client-supplied leftmost entry is ignored', kiwi_verify_client_ip(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 203.0.113.7, 10.0.0.9'], ['10.0.0.0/24']) === '203.0.113.7');
check('forged leftmost never wins on an untrusted peer', kiwi_verify_client_ip(['REMOTE_ADDR' => '203.0.113.7', 'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 203.0.113.7'], ['10.0.0.0/24']) === '203.0.113.7');
check('garbage hop fails closed', kiwi_verify_client_ip(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7, garbage!!, 10.0.0.9'], ['10.0.0.0/24']) === '10.0.0.9');
check('real ip when trusted and no xff', kiwi_verify_client_ip(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_REAL_IP' => '198.51.100.4'], ['10.0.0.0/24']) === '198.51.100.4');
check('ipv6 chain through the trusted hop', kiwi_verify_client_ip(['REMOTE_ADDR' => '2001:db8::9', 'HTTP_X_FORWARDED_FOR' => '2001:db8:1::50, 2001:db8::9'], ['2001:db8::/64']) === '2001:db8:1::50');
check('missing peer fails closed (never invents loopback)', kiwi_verify_client_ip([], []) === '');
check('cidr csv parses and drops blanks', kiwi_verify_parse_cidrs(' 10.0.0.0/24 , , 2001:db8::/32 ') === ['10.0.0.0/24', '2001:db8::/32']);

// The gate decision table.
$cfg = kiwi_verify_config();
$deny = kiwi_verify_deny($cfg);
check('default deny is 403 with the marker', $deny[0] === 403 && ($deny[1]['X-Kiwi-Deny'] ?? '') === '1');
$redirectCfg = ['deny_redirect' => true, 'redirect' => 'https://example.com/need-captcha'];
$redirect = kiwi_verify_deny($redirectCfg);
check('redirect deny is a 302 with Location', $redirect[0] === 302 && $redirect[1]['Location'] === 'https://example.com/need-captcha');

check('missing token denies', kiwi_verify_decide(null, ['http' => 0, 'success' => false, 'error_codes' => []], $cfg)[0] === 403);
check('success passes with 204', kiwi_verify_decide('t', ['http' => 200, 'success' => true, 'error_codes' => []], $cfg)[0] === 204);
check('failed verification denies with 403', kiwi_verify_decide('t', ['http' => 200, 'success' => false, 'error_codes' => ['timeout-or-duplicate']], $cfg)[0] === 403);
check('transport failure fails closed with 503', kiwi_verify_decide('t', ['http' => 0, 'success' => false, 'error_codes' => []], $cfg)[0] === 503);
check('upstream 5xx fails closed with 503', kiwi_verify_decide('t', ['http' => 500, 'success' => false, 'error_codes' => []], $cfg)[0] === 503);
check('upstream 401 is a gate fault, not a user fault', kiwi_verify_decide('t', ['http' => 401, 'success' => false, 'error_codes' => []], $cfg)[0] === 503);

// Configuration: $_SERVER overrides and defaults.
$_SERVER['KIWI_SCOPE'] = 'signup';
$_SERVER['KIWI_VERIFY_MODE'] = 'compat';
$cfg = kiwi_verify_config();
check('scope from $_SERVER', $cfg['scope'] === 'signup');
check('compat mode recognized', $cfg['mode'] === 'compat');
unset($_SERVER['KIWI_SCOPE'], $_SERVER['KIWI_VERIFY_MODE']);
$cfg = kiwi_verify_config();
check('default scope is login', $cfg['scope'] === 'login');
check('default mode is json', $cfg['mode'] === 'json');
check('default url is the sidecar', $cfg['verify_url'] === 'http://127.0.0.1:7371/verify');

fwrite($failures === 0 ? STDOUT : STDERR, sprintf("%d checks, %d failures\n", $checks, $failures));
exit($failures === 0 ? 0 : 1);
