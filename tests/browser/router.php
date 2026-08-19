<?php

declare(strict_types=1);

/**
 * Browser-test fixture server (php -S 127.0.0.1:8085 router.php).
 *
 * Serves the widget page and real challenge/verify endpoints backed by the
 * PURE PHP core (no Symfony needed): SHA-256 and Argon2id issuance + local
 * verification, so Playwright can exercise the actual browser solver.
 */

$repo = dirname(__DIR__, 2); // tests/browser -> repo root

require $repo.'/packages/kiwicaptcha-php/vendor/autoload.php';
// The Siteverify e2e route uses the REAL Symfony bundle
// controller + SiteVerify stores — load the bundle's autoloader when its
// vendor is installed (CI installs it for exactly this fixture fidelity).
$symfonyAutoload = $repo.'/packages/kiwicaptcha/integrations/symfony/vendor/autoload.php';
if (is_file($symfonyAutoload)) {
    require $symfonyAutoload;
}

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;

$secret = '0123456789abcdef0123456789abcdef';
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// php -S re-includes this router per request, so in-process state is lost —
// the record is persisted to a temp file PER NONCE (single-use: consumed
// on verify; a shared file would race when tests issue challenges).
function recordFile(string $nonce): string
{
    return sys_get_temp_dir().'/kiwicaptacha-record-'.preg_replace('/[^A-Za-z0-9_-]/', '', $nonce).'.json';
}
function metadataFile(string $nonce): string
{
    return sys_get_temp_dir().'/kiwicaptacha-meta-'.preg_replace('/[^A-Za-z0-9_-]/', '', $nonce).'.json';
}
// Risk-v2 fixture capture: challenge requests (and form submissions) are
// recorded to a temp file per capture name so Playwright can assert the
// driver's evidence fields (client_context / decoy_field / honeypot /
// chain_ticket) against the REAL requests the browser sends.
function captureFile(string $name): string
{
    return sys_get_temp_dir().'/kiwicaptacha-capture-'.preg_replace('/[^A-Za-z0-9_-]/', '', $name).'.json';
}
function writeCapture(string $name, string $rawBody): void
{
    if (preg_match('/^[A-Za-z0-9_-]{1,64}$/D', $name) !== 1) {
        return;
    }
    $tmp = tempnam(sys_get_temp_dir(), 'kiwc');
    file_put_contents($tmp, json_encode(['body' => $rawBody, 'at' => time()]));
    rename($tmp, captureFile($name));
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && preg_match('~^/capture/([A-Za-z0-9_-]{1,64})$~', $path, $m) === 1) {
    header('Content-Type: application/json');
    $f = captureFile($m[1]);
    echo json_encode(is_file($f) ? json_decode((string) file_get_contents($f), true) : null);

    return true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $path === '/form-submit') {
    // The form-submission honeypot fixture endpoint: records the raw POST
    // body exactly as the browser sent it (the decoy field rides the
    // form's application/x-www-form-urlencoded payload).
    writeCapture('form', http_build_query($_POST));
    header('Content-Type: application/json');
    echo json_encode(['ok' => true]);

    return true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($path === '/challenge' || $path === '/kiwi-captcha/challenge')) {
    $rawBody = (string) file_get_contents('php://input');
    // Risk-v2 fixture capture: ?capture=<name> records the raw challenge
    // request body for the Playwright assertions.
    if (isset($_GET['capture']) && is_string($_GET['capture'])) {
        writeCapture($_GET['capture'], $rawBody);
    }
    $body = json_decode($rawBody, true);
    $algorithm = ($body['algorithm'] ?? 'sha256') === 'argon2id' ? PoWAlgorithm::Argon2id : PoWAlgorithm::Sha256;
    $ttlOverride = isset($_GET['ttl']) ? max(1, (int) $_GET['ttl']) : null;
    $config = new Config(
        secretKey: $secret,
        algorithm: $algorithm,
        ttlSecs: $ttlOverride ?? 120,
        mKib: $algorithm === PoWAlgorithm::Argon2id ? 64 : 0,
        t: $algorithm === PoWAlgorithm::Argon2id ? 3 : 1,
        p: 1,
        targetBits: 8,
        argon2TargetBits: 4,
        minDurationMs: 0,
    );
    $issueStorage = new ArrayStorage();
    $issuer = new Issuer($config, $issueStorage, now: static fn (): int => time());
    // The bundle maps incumbent sitekeys -> policy scopes server-side
    // (sitekey_allowlist); the fixture mirrors that mapping so compat
    // challenges are issued under the intended scope.
    $sitekeyAllowlist = [
        '6Lc_turnstile_meta' => 'login',
        '0x4AAAAAAABC' => 'login',
        '6Lc_turnstile' => 'login',
        '6Lc_dynamic_explicit' => 'login',
        '6Lc_dynamic_implicit' => 'login',
        '6Lc_explicit_checkout_login' => 'login',
        '6Lc_explicit_login' => 'login',
        '6Lc_ready_explicit' => 'login',
    ];
    $scope = $sitekeyAllowlist[(string) ($body['scope'] ?? '')] ?? (string) ($body['scope'] ?? 'login');
    // The fixture mirrors the bundle's SERVER-OWNED
    // (sitekey, action) -> scope policy — the v3 browser e2e proves the
    // pair travels separately and resolves server-side.
    $sitekeyPolicy = [
        '6Lc_v3_sitekey_a' => ['default_scope' => 'login', 'actions' => ['checkout' => 'commerce_high_value']],
    ];
    $sitekey = isset($body['sitekey']) && is_string($body['sitekey']) ? $body['sitekey'] : null;
    if ($sitekey !== null && isset($sitekeyPolicy[$sitekey])) {
        $actionKey = isset($body['action']) && is_string($body['action']) ? $body['action'] : '';
        if ($actionKey !== '' && isset($sitekeyPolicy[$sitekey]['actions'][$actionKey])) {
            $scope = $sitekeyPolicy[$sitekey]['actions'][$actionKey];
        } elseif ($actionKey === '') {
            $scope = $sitekeyPolicy[$sitekey]['default_scope'];
        } else {
            http_response_code(422);
            echo '{"error":{"code":"UNKNOWN_ACTION"}}';

            return true;
        }
    }
    $challenge = $issuer->issue($scope, (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'));
    $record = $issueStorage->find($challenge->nonce);
    if ($record === null) {
        http_response_code(500);
        echo '{"error":"record missing"}';

        return true;
    }
    $tmp = tempnam(sys_get_temp_dir(), 'kiw'); 
    file_put_contents($tmp, json_encode($record->toArray()));
    rename($tmp, recordFile($challenge->nonce));
    // Provider-compatible metadata bound at issuance —
    // action/cData from the widget's challenge request are stored against
    // the nonce (server-owned; validated provider shapes).
    $action = isset($body['action']) && is_string($body['action']) ? $body['action'] : null;
    $cdata = isset($body['cdata']) && is_string($body['cdata']) ? $body['cdata'] : null;
    if ($action !== null || $cdata !== null) {
        if ($action !== null && !preg_match('/^[a-z0-9_-]{1,32}$/i', $action)) {
            http_response_code(422);
            echo '{"error":{"code":"INVALID_METADATA"}}';

            return true;
        }
        if ($cdata !== null && !preg_match('/^[a-z0-9_-]{1,255}$/i', $cdata)) {
            http_response_code(422);
            echo '{"error":{"code":"INVALID_METADATA"}}';

            return true;
        }
        $metaTmp = tempnam(sys_get_temp_dir(), 'kiwm');
        file_put_contents($metaTmp, json_encode(['action' => $action, 'cdata' => $cdata]));
        rename($metaTmp, metadataFile($challenge->nonce));
    }
    header('Content-Type: application/json');
    header('Cache-Control: no-store, private, max-age=0');
    $out = $challenge->toArray();
    // Risk-v2 fixture: ?decoy=1 makes the fixture emit the server-issued
    // decoy (honeypot) field name, mirroring the bundle's risk-enabled
    // issuance response.
    if (($_GET['decoy'] ?? '') === '1') {
        $out['decoy_field'] = 'decoy_'.substr(hash('sha256', $challenge->nonce), 0, 8);
    }
    echo json_encode($out);

    return true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($path === '/siteverify' || $path === '/kiwi-captcha/siteverify')) {
    // e2e: the REAL SiteVerifyController against the record
    // + metadata persisted at issuance (the fixture's file-based storage
    // stands in for the shared store).
    $body = json_decode((string) file_get_contents('php://input'), true);
    header('Content-Type: application/json');
    header('Cache-Control: no-store, private, max-age=0');
    $nonce = (string) (explode('.', (string) base64_decode((string) ($body['response'] ?? ''), true))[0] ?? '');
    if ($nonce === '' || !is_file(recordFile($nonce))) {
        echo json_encode(['success' => false, 'error-codes' => ['timeout-or-duplicate']]);

        return true;
    }
    $storage = new ArrayStorage();
    $storage->store(\KiwiCaptcha\ChallengeRecord::fromArray(json_decode((string) file_get_contents(recordFile($nonce)), true)));
    $metadataStore = new \BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyMetadataStore();
    if (is_file(metadataFile($nonce))) {
        $m = json_decode((string) file_get_contents(metadataFile($nonce)), true);
        $metadataStore->store($nonce, new \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata($m['action'] ?? null, $m['cdata'] ?? null, null), 300);
        @unlink(metadataFile($nonce));
    }
    $controller = new \BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController(
        new Verifier($storage),
        $secret,
        ['compat-secret-42' => 'login'],
        $storage,
        null,
        $metadataStore,
    );
    // A successful verification consumes the record (single-use); the
    // retained consumed-state machinery is per-request here (the fixture's
    // file stands in for the shared store), so the file is removed after
    // the first redemption.
    @unlink(recordFile($nonce));
    $response = $controller->siteverify(\Symfony\Component\HttpFoundation\Request::create('/kiwi-captcha/siteverify', 'POST', [
        'secret' => (string) ($body['secret'] ?? ''),
        'response' => (string) ($body['response'] ?? ''),
        'remoteip' => (string) ($body['remoteip'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'),
        'action' => $body['action'] ?? null,
    ]));
    $decoded = SolutionToken::decode((string) ($body['response'] ?? ''));
    error_log('SV-DEBUG nonce='.$nonce.' decode='.(($decoded instanceof SolutionToken) ? 'ok' : 'FAIL').' recordFile='.(is_file(recordFile($nonce)) ? 'yes' : 'no').' remoteip='.(string) ($body['remoteip'] ?? 'none'));
    echo $response->getContent();

    return true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $path === '/verify') {
    $body = json_decode((string) file_get_contents('php://input'), true);
    header('Content-Type: application/json');
    $nonce = (string) (explode('.', (string) base64_decode((string) ($body['token'] ?? ''), true))[0] ?? '');
    if ($nonce === '' || !is_file(recordFile($nonce))) {
        echo json_encode(['ok' => false, 'code' => 'record_not_found']);

        return true;
    }
    $storage = new ArrayStorage();
    $storage->store(\KiwiCaptcha\ChallengeRecord::fromArray(json_decode((string) file_get_contents(recordFile($nonce)), true)));
    @unlink(recordFile($nonce));
    $verifier = new Verifier($storage);
    $scope = (string) ($body['scope'] ?? 'login');
    $outcome = $verifier->verify((string) ($body['token'] ?? ''), $secret, $scope, (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'));
    echo json_encode(['ok' => $outcome->isOk(), 'code' => $outcome->code()]);

    return true;
}

if ($path === '/kiwi-worker.js' || $path === '/kiwicaptcha-wasm.js' || $path === '/kiwi-worker-stale.js') {
    $name = $path === '/kiwi-worker.js' ? 'kiwi-worker.js' : ($path === '/kiwicaptcha-wasm.js' ? 'kiwicaptcha-wasm.js' : 'kiwi-worker.js');
    $file = $repo.'/packages/kiwicaptcha-wasm/assets/'.$name;
    if (!is_file($file)) {
        http_response_code(404);
        echo 'not found';

        return true;
    }
    header('Content-Type: application/javascript');
    header('Cache-Control: no-store');
    $body = file_get_contents($file);
    // /kiwi-worker-stale.js serves the real worker with the solver build id
    // rewritten: the driver must refuse it with the controlled
    // kiwi:solver-mismatch state instead of accepting a stale worker.
    if ($path === '/kiwi-worker-stale.js') {
        $body = str_replace('2026-08-r1', '2026-08-r0', (string) $body);
    }
    echo $body;

    return true;
}

// Incumbent-compatibility loader + migration fixtures.
$assets = $repo.'/packages/kiwicaptcha-wasm/assets';

// The compat endpoints go through the REAL bundle
// controller — the hard-coded concat hid a production route
// failure (a missing Request import broke the actual routes).
$symfonyAutoload = $repo.'/packages/kiwicaptcha/integrations/symfony/vendor/autoload.php';
if (($path === '/kiwi-captcha/api.js' || $path === '/kiwi-captcha/widget.css') && is_file($symfonyAutoload)) {
    require $symfonyAutoload;
    $api = new \BelConsulting\KiwiCaptchaBundle\Controller\ApiJsController($assets);
    $srequest = \Symfony\Component\HttpFoundation\Request::create(
        $_SERVER['REQUEST_URI'],
        $_SERVER['REQUEST_METHOD'] ?? 'GET',
        [],
        [],
        [],
        $_SERVER,
    );
    $sresponse = $path === '/kiwi-captcha/api.js' ? $api->apiJs($srequest) : $api->widgetCss($srequest);
    foreach ($sresponse->headers->all() as $name => $values) {
        header($name.': '.implode(', ', $values));
    }
    http_response_code($sresponse->getStatusCode());
    echo $sresponse->getContent();

    return true;
}
if (preg_match('~^/migration/(recaptcha-v2|recaptcha-v2-ttl|recaptcha-v2-argon|recaptcha-v2-explicit|recaptcha-invisible|recaptcha-v3|hcaptcha|turnstile|turnstile-meta)\.html$~', $path, $m) === 1) {
    header('Content-Type: text/html');
    header('Cache-Control: no-store');
    $html = file_get_contents(__DIR__.'/migration/'.$m[1].'.html');
    // Page-level loader parameters (hl, render, onload) are
    // propagated into the fixture's api.js URL — the incumbent pattern
    // puts them on the SCRIPT URL, and the fixture HTML cannot know the
    // test's query string.
    $pageParams = $_GET;
    if (isset($pageParams['hl']) || isset($pageParams['render']) || isset($pageParams['onload'])) {
        $extra = [];
        foreach (['hl', 'render', 'onload'] as $p) {
            if (isset($pageParams[$p]) && is_string($pageParams[$p])) {
                $extra[] = $p.'='.rawurlencode($pageParams[$p]);
            }
        }
        if ($extra !== []) {
            $html = preg_replace('~(<script src=")([^"]*api\.js)([^"]*)(")~', '$1$2$3&'.implode('&', $extra).'$4', $html, 1);
        }
    }
    echo $html;

    return true;
}

if ($path === '/' || $path === '/index.html') {
    $assets = $repo.'/packages/kiwicaptcha-wasm/assets';
    $css = file_get_contents($assets.'/widget.css');
    $wasm = file_get_contents($assets.'/kiwicaptcha-wasm.js');
    $driver = file_get_contents($assets.'/widget-driver.js');
    $csp = ($_GET['csp'] ?? '') === 'strict'
        ? '<meta http-equiv="Content-Security-Policy" content="script-src \'unsafe-inline\'; style-src \'unsafe-inline\'">'
        : '';
    $algorithm = ($_GET['algorithm'] ?? '') === 'argon2id' ? 'argon2id' : 'sha256';
    $workerAttr = '';
    if (($_GET['worker'] ?? '') === '1') $workerAttr = ' data-kiwi-worker-src="/kiwi-worker.js"';
    if (($_GET['worker-stale'] ?? '') === '1') $workerAttr = ' data-kiwi-worker-src="/kiwi-worker-stale.js"';
    $binding = ($_GET['binding'] ?? '') !== '' ? ' data-kiwi-request-binding="'.htmlspecialchars((string) $_GET['binding'], ENT_QUOTES).'"' : '';
    $lang = ($_GET['lang'] ?? '') !== '' ? ' data-kiwi-lang="'.htmlspecialchars((string) $_GET['lang'], ENT_QUOTES).'"' : '';
    // Risk-v2 fixture knobs: ?decoy=1 emits the decoy field in the
    // challenge response, ?ttl=<s> shortens the challenge lifetime (the
    // expiry-driven re-solve test), ?capture=<name> records the challenge
    // request bodies, and ?chain=<ticket> seeds the container with
    // data-kiwi-chain-ticket.
    $endpointQuery = [];
    if (($_GET['decoy'] ?? '') === '1') $endpointQuery[] = 'decoy=1';
    if (($_GET['ttl'] ?? '') !== '') $endpointQuery[] = 'ttl='.rawurlencode((string) $_GET['ttl']);
    if (($_GET['capture'] ?? '') !== '') $endpointQuery[] = 'capture='.rawurlencode((string) $_GET['capture']);
    $endpoint = '/challenge'.($endpointQuery !== [] ? '?'.implode('&', $endpointQuery) : '');
    $chainAttr = ($_GET['chain'] ?? '') !== '' ? ' data-kiwi-chain-ticket="'.htmlspecialchars((string) $_GET['chain'], ENT_QUOTES).'"' : '';
    header('Content-Type: text/html');
    echo "<!DOCTYPE html><html lang=\"en\"><head><title>KiwiCaptcha widget test page</title><style>{$css}</style>{$csp}</head><body>
<div class=\"kiwi-container\" id=\"kiwicaptcha-root\" data-kiwi-endpoint=\"{$endpoint}\" data-kiwi-scope=\"login\" data-kiwi-algorithm=\"{$algorithm}\"{$workerAttr}{$binding}{$lang}{$chainAttr}>
  <input type=\"hidden\" name=\"kiwi__token\" data-kiwi-token value=\"\" />
  <div class=\"kiwi-widget\" data-kiwi-widget data-state=\"idle\">
    <div class=\"kiwi-icon-wrapper\"><svg></svg><div class=\"kiwi-glow\"></div></div>
    <div class=\"kiwi-main\">
      <div class=\"kiwi-top\"><span class=\"kiwi-label\" data-kiwi-label>Security Check</span><span class=\"kiwi-badge\" data-kiwi-badge>Idle</span></div>
      <div class=\"kiwi-track\" aria-hidden=\"true\"><div class=\"kiwi-bar\" data-kiwi-bar></div></div>
      <div class=\"kiwi-bottom\"><p class=\"kiwi-info\" data-kiwi-info>Protected</p><span class=\"kiwi-timer\" data-kiwi-timer></span></div>
    </div>
  </div>
</div>
<script>{$wasm}</script><script>{$driver}</script></body></html>";

    return true;
}

http_response_code(404);
echo 'not found';

return true;
