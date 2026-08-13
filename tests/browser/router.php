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

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $path === '/challenge') {
    $body = json_decode((string) file_get_contents('php://input'), true);
    $algorithm = ($body['algorithm'] ?? 'sha256') === 'argon2id' ? PoWAlgorithm::Argon2id : PoWAlgorithm::Sha256;
    $config = new Config(
        secretKey: $secret,
        algorithm: $algorithm,
        mKib: $algorithm === PoWAlgorithm::Argon2id ? 64 : 0,
        t: $algorithm === PoWAlgorithm::Argon2id ? 3 : 1,
        p: 1,
        targetBits: 8,
        argon2TargetBits: 4,
        ttlSecs: 120,
        minDurationMs: 0,
    );
    $issueStorage = new ArrayStorage();
    $issuer = new Issuer($config, $issueStorage, now: static fn (): int => time());
    $challenge = $issuer->issue((string) ($body['scope'] ?? 'login'), (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'));
    $record = $issueStorage->find($challenge->nonce);
    if ($record === null) {
        http_response_code(500);
        echo '{"error":"record missing"}';

        return true;
    }
    $tmp = tempnam(sys_get_temp_dir(), 'kiw'); 
    file_put_contents($tmp, json_encode($record->toArray()));
    rename($tmp, recordFile($challenge->nonce));
    header('Content-Type: application/json');
    header('Cache-Control: no-store, private, max-age=0');
    echo json_encode($challenge->toArray());

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
    $outcome = $verifier->verify((string) ($body['token'] ?? ''), $secret, 'login', (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'));
    echo json_encode(['ok' => $outcome->isOk(), 'code' => $outcome->code()]);

    return true;
}

if ($path === '/kiwi-worker.js' || $path === '/kiwicaptcha-wasm.js') {
    $name = $path === '/kiwi-worker.js' ? 'kiwi-worker.js' : 'kiwicaptcha-wasm.js';
    $file = $repo.'/packages/kiwicaptcha-wasm/assets/'.$name;
    if (!is_file($file)) {
        http_response_code(404);
        echo 'not found';

        return true;
    }
    header('Content-Type: application/javascript');
    header('Cache-Control: no-store');
    echo file_get_contents($file);

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
    $workerAttr = ($_GET['worker'] ?? '') === '1' ? ' data-kiwi-worker-src="/kiwi-worker.js"' : '';
    header('Content-Type: text/html');
    echo "<!DOCTYPE html><html><head><style>{$css}</style>{$csp}</head><body>
<div class=\"kiwi-container\" id=\"kiwicaptcha-root\" data-kiwi-endpoint=\"/challenge\" data-kiwi-scope=\"login\" data-kiwi-algorithm=\"{$algorithm}\"{$workerAttr}>
  <input type=\"hidden\" name=\"kiwi__token\" data-kiwi-token value=\"\" />
  <div class=\"kiwi-widget\" data-kiwi-widget data-state=\"idle\" role=\"status\" aria-live=\"polite\">
    <div class=\"kiwi-icon-wrapper\"><svg></svg><div class=\"kiwi-glow\"></div></div>
    <div class=\"kiwi-main\">
      <div class=\"kiwi-top\"><span class=\"kiwi-label\" data-kiwi-label>Security Check</span><span class=\"kiwi-badge\" data-kiwi-badge>Idle</span></div>
      <div class=\"kiwi-track\"><div class=\"kiwi-bar\" data-kiwi-bar></div></div>
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
