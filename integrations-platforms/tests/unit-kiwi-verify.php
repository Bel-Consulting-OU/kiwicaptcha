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

// ============================================================
// Aggressive adversarial coverage. Each block maps to one attack
// family of the red-team brief: header injection, content-type
// confusion, body bombs, client-ip edges, token-source smuggling,
// upstream SSRF/status confusion, and configuration injection.
// ============================================================

// --- env var injection via headers: a request header must never
// reach the config knobs (headers land under HTTP_* keys).
$_SERVER['HTTP_KIWI_VERIFY_URL'] = 'http://evil.example/verify';
$_SERVER['HTTP_KIWI_SCOPE'] = 'hijacked';
$_SERVER['HTTP_KIWI_BEARER'] = 'stolen';
$cfg = kiwi_verify_config();
check('HTTP_ header names never reach KIWI_VERIFY_URL', $cfg['verify_url'] === 'http://127.0.0.1:7371/verify');
check('HTTP_ header names never reach KIWI_SCOPE', $cfg['scope'] === 'login');
check('HTTP_ header names never reach KIWI_BEARER', $cfg['bearer'] === '');
unset($_SERVER['HTTP_KIWI_VERIFY_URL'], $_SERVER['HTTP_KIWI_SCOPE'], $_SERVER['HTTP_KIWI_BEARER']);

// --- configuration injection / SSRF: the verify URL must be one
// absolute http(s) URL; every scheme a local-file or stream oracle
// could use is refused at the config boundary.
$_SERVER['KIWI_VERIFY_URL'] = 'file:///etc/passwd';
$cfg = kiwi_verify_config();
check('file:// verify url is refused', $cfg['config_error'] !== null);
$_SERVER['KIWI_VERIFY_URL'] = 'php://filter/convert.base64-encode/resource=/etc/passwd';
$cfg = kiwi_verify_config();
check('php:// verify url is refused', $cfg['config_error'] !== null);
$_SERVER['KIWI_VERIFY_URL'] = 'gopher://127.0.0.1:6379/_INFO';
$cfg = kiwi_verify_config();
check('gopher:// verify url is refused', $cfg['config_error'] !== null);
$_SERVER['KIWI_VERIFY_URL'] = 'dict://127.0.0.1:11211/stats';
$cfg = kiwi_verify_config();
check('dict:// verify url is refused', $cfg['config_error'] !== null);
$_SERVER['KIWI_VERIFY_URL'] = "http://127.0.0.1:7371/verify\r\nX-Injected: 1";
$cfg = kiwi_verify_config();
check('CRLF in verify url is refused', $cfg['config_error'] !== null);
$_SERVER['KIWI_VERIFY_URL'] = 'http://127.0.0.1:7371/verify';
$_SERVER['KIWI_BEARER'] = "s3cret\r\nX-Injected: 1";
$cfg = kiwi_verify_config();
check('CRLF in bearer is refused (upstream header injection)', $cfg['config_error'] !== null);
$_SERVER['KIWI_BEARER'] = "s3cret";
$_SERVER['KIWI_REDIRECT'] = "/need-captcha\r\nSet-Cookie: evil=1";
$cfg = kiwi_verify_config();
check('CRLF in redirect is refused (response splitting)', $cfg['config_error'] !== null);
$_SERVER['KIWI_REDIRECT'] = '/need-captcha';
$_SERVER['KIWI_SCOPE'] = "login\r\nX: 1";
$cfg = kiwi_verify_config();
check('CRLF in scope is refused', $cfg['config_error'] !== null);
$_SERVER['KIWI_SCOPE'] = 'logın'; // unicode dotless i
$cfg = kiwi_verify_config();
check('unicode scope is refused', $cfg['config_error'] !== null);
$_SERVER['KIWI_SCOPE'] = 'login/../admin';
$cfg = kiwi_verify_config();
check('scope with path metacharacters is refused', $cfg['config_error'] !== null);
$_SERVER['KIWI_SCOPE'] = 'a';
check('1-char scope is allowed', kiwi_verify_config()['config_error'] === null);
$_SERVER['KIWI_SCOPE'] = str_repeat('a', 128);
check('128-char scope is allowed', kiwi_verify_config()['config_error'] === null);
$_SERVER['KIWI_SCOPE'] = str_repeat('a', 129);
$cfg = kiwi_verify_config();
check('129-char scope is refused', $cfg['config_error'] !== null);
unset($_SERVER['KIWI_SCOPE']);
$_SERVER['KIWI_TIMEOUT'] = '0';
check('zero timeout refused', kiwi_verify_config()['config_error'] !== null);
$_SERVER['KIWI_TIMEOUT'] = '-1';
check('negative timeout refused', kiwi_verify_config()['config_error'] !== null);
$_SERVER['KIWI_TIMEOUT'] = '9999';
check('huge timeout refused', kiwi_verify_config()['config_error'] !== null);
$_SERVER['KIWI_TIMEOUT'] = '5';
$_SERVER['KIWI_REDIRECT'] = '';
check('clean config passes the audit', kiwi_verify_config()['config_error'] === null);
unset($_SERVER['KIWI_TIMEOUT']);

// --- deny/redirect response splitting: a redirect target with a
// control character never lands in a Location header.
$splitCfg = ['deny_redirect' => true, 'redirect' => "/ok\r\nSet-Cookie: evil=1"];
$deny = kiwi_verify_deny($splitCfg);
check('CRLF redirect target falls back to 403', $deny[0] === 403 && !isset($deny[1]['Location']));
$okCfg = ['deny_redirect' => true, 'redirect' => '/need-captcha'];
check('clean redirect target still 302s', kiwi_verify_deny($okCfg)[0] === 302);

// --- CRLF / control characters in the token header never become a
// header-injection vector: the token rides the JSON-encoded upstream
// body only, and the extracted candidate is passed through to decide
// unchanged (still subject to upstream verification).
$crlfToken = kiwi_verify_extract_token(['HTTP_X_KIWI_TOKEN' => "a\r\nX-Injected: 1"], [], [], null);
check('CRLF token is extracted as data (json-encoded upstream only)', $crlfToken === "a\r\nX-Injected: 1");
check(
    'CRLF token still gets the gate decision (denied by upstream verdict)',
    kiwi_verify_decide($crlfToken, ['http' => 200, 'success' => false, 'error_codes' => []], kiwi_verify_config())[0] === 403
);

// --- content-type confusion: only the exact application/json media
// type opens the JSON token source.
$server = ['CONTENT_TYPE' => 'application/jsonp'];
check('application/jsonp body does not open the JSON source', kiwi_verify_extract_token($server, [], [], '{"kiwi_token":"x"}') === null);
$server = ['CONTENT_TYPE' => 'application/json-seq'];
check('application/json-seq body does not open the JSON source', kiwi_verify_extract_token($server, [], [], '{"kiwi_token":"x"}') === null);
$server = ['CONTENT_TYPE' => 'text/application/json'];
check('text/application/json body does not open the JSON source', kiwi_verify_extract_token($server, [], [], '{"kiwi_token":"x"}') === null);
$server = ['CONTENT_TYPE' => 'Application/JSON; charset=UTF-8'];
check('case/params-insensitive exact json media type opens the source', kiwi_verify_extract_token($server, [], [], '{"kiwi_token":"x"}') === 'x');
$server = ['CONTENT_TYPE' => 'application/json'];
check('text body without json content type is ignored', kiwi_verify_extract_token($server, [], [], null) === null);

// --- token-source smuggling: only documented carriers. Query
// strings, alternate headers, alternate cookies and bare/alias JSON
// keys outside the closed list are not token sources.
check('query-string token is not a source', kiwi_verify_extract_token(['REQUEST_URI' => '/x?kiwi_token=q', 'QUERY_STRING' => 'kiwi_token=q'], [], [], null) === null);
check('path token is not a source', kiwi_verify_extract_token(['REQUEST_URI' => '/kiwi_token/path'], [], [], null) === null);
check('alternate header names are not sources', kiwi_verify_extract_token(['HTTP_X_TOKEN' => 'x', 'HTTP_AUTHORIZATION' => 'Bearer x', 'HTTP_TOKEN' => 'x'], [], [], null) === null);
check('alternate cookie names are not sources', kiwi_verify_extract_token([], [], ['token' => 'x', 'kiwi' => 'x'], null) === null);
check('array form values are not token candidates', kiwi_verify_extract_token([], ['kiwi__token' => ['nested']], [], null) === null);
check('json array values are not token candidates', kiwi_verify_extract_token(['CONTENT_TYPE' => 'application/json'], [], [], '{"kiwi_token":["x"]}') === null);
check('json bare token key stays ignored (app secret protection)', kiwi_verify_extract_token(['CONTENT_TYPE' => 'application/json'], [], [], '{"token":"app-secret"}') === null);
check('json legacy field names are NOT sources outside the namespaced list', kiwi_verify_extract_token(['CONTENT_TYPE' => 'application/json'], [], [], '{"g-recaptcha-response":"x","h-captcha-response":"y"}') === null);
check('form field names smuggled inside JSON are not form sources', kiwi_verify_extract_token(['CONTENT_TYPE' => 'application/json'], ['kiwi__token' => ''], [], '{"g-recaptcha-response":"x"}') === null);

// Field order is fixed: header > form > json > cookie.
$server = ['CONTENT_TYPE' => 'application/json', 'HTTP_X_KIWI_TOKEN' => 'from-header'];
check(
    'header outranks form and json and cookie',
    kiwi_verify_extract_token(
        $server,
        ['kiwi__token' => 'from-form'],
        ['kiwi_token' => 'from-cookie'],
        '{"kiwi_token":"from-json"}',
    ) === 'from-header'
);
$server = ['CONTENT_TYPE' => 'application/json'];
check(
    'form outranks json and cookie',
    kiwi_verify_extract_token($server, ['kiwi__token' => 'from-form'], ['kiwi_token' => 'from-cookie'], '{"kiwi_token":"from-json"}') === 'from-form'
);
check(
    'json outranks cookie',
    kiwi_verify_extract_token($server, [], ['kiwi_token' => 'from-cookie'], '{"kiwi_token":"from-json"}') === 'from-json'
);

// Duplicate JSON keys: the decoder keeps the LAST occurrence, and the
// gate extracts deterministically from that (a document with a
// duplicate namespaced key can never produce an ambiguous pick).
check(
    'duplicate namespaced keys resolve deterministically (last wins)',
    kiwi_verify_extract_token(['CONTENT_TYPE' => 'application/json'], [], [], '{"kiwi_token":"first","kiwi_token":"second"}') === 'second'
);

// UTF-16 BOM JSON: never decodes, so it never contributes a token.
$utf16 = "\xFF\xFE{\x00\"\x00k\x00i\x00w\x00i\x00_\x00t\x00o\x00k\x00e\x00n\x00\"\x00:\x00\"\x00x\x00\"\x00}\x00";
check('UTF-16 BOM JSON contributes no token', kiwi_verify_extract_token(['CONTENT_TYPE' => 'application/json'], [], [], $utf16) === null);
// UTF-8 BOM is equally refused by the decoder.
check('UTF-8 BOM JSON contributes no token', kiwi_verify_extract_token(['CONTENT_TYPE' => 'application/json'], [], [], "\xEF\xBB\xBF{\"kiwi_token\":\"x\"}") === null);
// A gzip magic body is opaque bytes here (PHP does not inflate
// php://input): never a decoded token, and the bounded read caps the
// materialized bytes (KIWI_MAX_BODY_BYTES) so a bomb cannot balloon.
$gzipBomb = "\x1f\x8b\x08\x00".str_repeat("\x00", 1024);
check('gzip bomb body contributes no token', kiwi_verify_extract_token(['CONTENT_TYPE' => 'application/json'], [], [], $gzipBomb) === null);

// Oversized token candidates are never forwarded upstream.
$oversized = str_repeat('a', KIWI_MAX_TOKEN_BYTES + 1);
check(
    'oversized header token is skipped and the cookie source wins',
    kiwi_verify_extract_token(['HTTP_X_KIWI_TOKEN' => $oversized], [], ['kiwi_token' => 'cookie-token'], null) === 'cookie-token'
);
check('oversized-only token set extracts null', kiwi_verify_extract_token(['HTTP_X_KIWI_TOKEN' => $oversized], [], [], null) === null);

// --- client ip edge grammar.
check('ipv4 with port', kiwi_verify_canonical_ip('203.0.113.7:8080') === '203.0.113.7');
check('bracketed ipv6 with port', kiwi_verify_canonical_ip('[2001:db8::1]:443') === '2001:db8::1');
check('bare ipv6', kiwi_verify_canonical_ip('2001:db8::1') === '2001:db8::1');
check('ipv4-mapped ipv6 normalizes', kiwi_verify_canonical_ip('::ffff:192.0.2.10') === '192.0.2.10');
check('zone id is refused', kiwi_verify_canonical_ip('fe80::1%eth0') === null);
check('obfuscated star is refused', kiwi_verify_canonical_ip('*') === null);
check('unknown token is refused', kiwi_verify_canonical_ip('unknown') === null);
check('underscore-prefixed token is refused', kiwi_verify_canonical_ip('_hidden') === null);
check('port 0 refused', kiwi_verify_canonical_ip('203.0.113.7:0') === null);
check('port 65536 refused', kiwi_verify_canonical_ip('203.0.113.7:65536') === null);
check('negative port refused', kiwi_verify_canonical_ip('203.0.113.7:-1') === null);
check('embedded control characters refuse', kiwi_verify_canonical_ip("203.0.113.\r\n7") === null);
check('surrounding whitespace is trimmed first', kiwi_verify_canonical_ip("  203.0.113.7  ") === '203.0.113.7');
check('unicode digit ip refused', kiwi_verify_canonical_ip('２０３.０.１１３.７') === null);
check('ipv6 with zone in brackets refused', kiwi_verify_canonical_ip('[fe80::1%eth0]:80') === null);

// XFF chain edges through a trusted peer.
$trusted = ['10.0.0.0/8'];
check('empty hops fall back to the peer', kiwi_verify_client_ip(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_FORWARDED_FOR' => ',, 10.0.0.9'], $trusted) === '10.0.0.9');
check('star hop fails closed to the peer', kiwi_verify_client_ip(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_FORWARDED_FOR' => '*, 10.0.0.9'], $trusted) === '10.0.0.9');
check('mapped-ipv6 hop resolves to its ipv4 form', kiwi_verify_client_ip(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_FORWARDED_FOR' => '::ffff:198.51.100.4, 10.0.0.9'], $trusted) === '198.51.100.4');
check('ipv6 hop with brackets and port', kiwi_verify_client_ip(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_FORWARDED_FOR' => '[2001:db8::50]:443, 10.0.0.9'], $trusted) === '2001:db8::50');
check('zone hop terminates the chain', kiwi_verify_client_ip(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_FORWARDED_FOR' => 'fe80::1%eth0, 10.0.0.9'], $trusted) === '10.0.0.9');
$chain = [];
for ($i = 0; $i < 29; $i++) {
    $chain[] = '6.6.6.6';
}
$chain[] = '10.0.0.9';
check(
    '30-hop chain takes the first hop outside the trusted set',
    kiwi_verify_client_ip(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_FORWARDED_FOR' => implode(', ', $chain)], $trusted) === '6.6.6.6'
);
check(
    'XFF wins over a conflicting X-Real-IP when both exist',
    kiwi_verify_client_ip(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_FORWARDED_FOR' => '198.51.100.4, 10.0.0.9', 'HTTP_X_REAL_IP' => '203.0.113.9'], $trusted) === '198.51.100.4'
);
check(
    'X-Real-IP with a port resolves its address',
    kiwi_verify_client_ip(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_REAL_IP' => '198.51.100.4:1234'], $trusted) === '198.51.100.4'
);
check(
    'X-Real-IP obfuscated token falls back to the peer',
    kiwi_verify_client_ip(['REMOTE_ADDR' => '10.0.0.9', 'HTTP_X_REAL_IP' => 'unknown'], $trusted) === '10.0.0.9'
);

// Trusted-proxy CIDR boundary conditions.
check('/32 matches only its own address', kiwi_verify_in_trusted('10.0.0.9', ['10.0.0.9/32']) && !kiwi_verify_in_trusted('10.0.0.10', ['10.0.0.9/32']));
check('/0 matches the whole family', kiwi_verify_in_trusted('203.0.113.7', ['10.0.0.0/0']));
check('/0 v4 does not match v6', !kiwi_verify_in_trusted('2001:db8::1', ['10.0.0.0/0']));
check('broadcast address matches its network', kiwi_verify_in_trusted('255.255.255.255', ['255.255.255.255/32']));
check('host bits set in a CIDR still mask-match', kiwi_verify_in_trusted('10.2.3.4', ['10.0.0.1/8']));
check('bare address entry matches exactly', kiwi_verify_in_trusted('10.0.0.9', ['10.0.0.9']));
check('bare address entry matches nothing else', !kiwi_verify_in_trusted('10.0.0.10', ['10.0.0.9']));
check('family mismatch never matches', !kiwi_verify_in_trusted('2001:db8::1', ['10.0.0.0/8']));
check('garbage cidr entry is ignored (never widens)', !kiwi_verify_in_trusted('203.0.113.7', ['garbage!!', '999.999.999.999/8', '10.0.0.0/99']));
check('invalid ip never matches a cidr', !kiwi_verify_in_trusted('not-an-ip', ['0.0.0.0/0']));

// A garbage socket peer fails closed (never forwarded as an identity).
check('garbage peer fails closed', kiwi_verify_client_ip(['REMOTE_ADDR' => 'not-an-ip'], []) === '');
check('unicode peer fails closed', kiwi_verify_client_ip(['REMOTE_ADDR' => '２０３.０.１１３.７'], []) === '');
check('CRLF peer fails closed', kiwi_verify_client_ip(['REMOTE_ADDR' => "10.0.0.9\r\nX: 1"], []) === '');
check('peer with port canonicalizes', kiwi_verify_client_ip(['REMOTE_ADDR' => '10.0.0.9:8080'], []) === '10.0.0.9');
check('mapped peer canonicalizes to ipv4', kiwi_verify_client_ip(['REMOTE_ADDR' => '::ffff:10.0.0.9'], []) === '10.0.0.9');

// --- upstream status/body mismatches: only a 2xx answer that says
// success opens the gate. A redirect or any other non-2xx carrying a
// success-shaped body is a status/body mismatch and fails closed.
$cfg = kiwi_verify_config();
check('204 with success body passes (2xx window includes 204)', kiwi_verify_decide('t', ['http' => 204, 'success' => true, 'error_codes' => []], $cfg)[0] === 204);
check('302 with success body fails closed', kiwi_verify_decide('t', ['http' => 302, 'success' => true, 'error_codes' => []], $cfg)[0] === 403);
check('301 with success body fails closed', kiwi_verify_decide('t', ['http' => 301, 'success' => true, 'error_codes' => []], $cfg)[0] === 403);
check('403 with success body fails closed', kiwi_verify_decide('t', ['http' => 403, 'success' => true, 'error_codes' => []], $cfg)[0] === 403);
check('200 with success body passes', kiwi_verify_decide('t', ['http' => 200, 'success' => true, 'error_codes' => []], $cfg)[0] === 204);
check('299 with success body passes', kiwi_verify_decide('t', ['http' => 299, 'success' => true, 'error_codes' => []], $cfg)[0] === 204);
check('199 with success body fails closed', kiwi_verify_decide('t', ['http' => 199, 'success' => true, 'error_codes' => []], $cfg)[0] === 403);
check('200 without success body denies', kiwi_verify_decide('t', ['http' => 200, 'success' => false, 'error_codes' => []], $cfg)[0] === 403);
check('429 from upstream denies (client is at fault)', kiwi_verify_decide('t', ['http' => 429, 'success' => false, 'error_codes' => []], $cfg)[0] === 403);
check('403 upstream never passes on a forged success bit', kiwi_verify_decide('t', ['http' => 403, 'success' => true, 'error_codes' => []], $cfg)[0] === 403);

fwrite($failures === 0 ? STDOUT : STDERR, sprintf("%d checks, %d failures\n", $checks, $failures));
exit($failures === 0 ? 0 : 1);
