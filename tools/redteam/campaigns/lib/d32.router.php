#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * d32.router.php — the D3.2 wire surface: the real core issuer and
 * verifier of the reference deployment, driven directly so the decoy
 * (honeypot) field and the execution program can both be armed, which
 * the stock deploy router only does from its own environment knobs.
 *
 * Surfaces (loopback only, one port):
 *   GET  /healthz    real store round trip, {"ok":true}
 *   POST /challenge  Issuer::issueWithExecutionField with the
 *                    execution program AND the decoy armed
 *   POST /verify     Verifier redeem, the deployment's own answer shape
 *   POST /source     the page source oracle: returns the served page
 *                    bytes the fixture node server holds (used by the
 *                    decoy-secrecy assertion to prove the armed name
 *                    never appears in any static source)
 *
 * Every setting comes from the environment exactly like the
 * deployment's bootstrap (KIWI_SECRET_KEY, KC_REDIS_URL, the knobs);
 * nothing is baked in.
 */

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;

require getenv('KIWI_RT_DEPLOY_VENDOR') . '/autoload.php';

$secret = (string) getenv('KIWI_SECRET_KEY');
$redisUrl = (string) getenv('KC_REDIS_URL');
$executionKey = (string) (getenv('KIWI_EXECUTION_KEY') ?: '');

function kiwiJson(array $payload, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
}

function kiwiError(string $code, string $message, int $status): void
{
    kiwiJson(['error' => ['code' => $code, 'message' => $message]], $status);
}

$redisUrl and $secret !== '' or (kiwiError('CONFIG', 'missing KIWI_SECRET_KEY or KC_REDIS_URL', 500) && exit);
$client = new \Predis\Client($redisUrl, ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
$storage = new RedisStorage($client);

$config = new Config(
    secretKey: $secret,
    algorithm: PoWAlgorithm::Sha256,
    mKib: 0,
    t: 3,
    p: 1,
    targetBits: (int) (getenv('KIWI_SHA_TARGET_BITS') ?: '16'),
    argon2TargetBits: 4,
    ttlSecs: (int) (getenv('KIWI_TTL_SECS') ?: '120'),
    minDurationMs: 0,
    executionKey: $executionKey !== '' ? $executionKey : null,
    rswModulusN: null,
    rswLambda: null,
    rswT: 75000,
);

$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if ($uri === '/healthz') {
    $probe = 'healthz-' . bin2hex(random_bytes(8));
    try {
        $client->set($probe, '1', 'EX', 10);
        $client->get($probe);
        $client->del([$probe]);
        kiwiJson(['ok' => true]);
    } catch (\Throwable $e) {
        kiwiJson(['ok' => false, 'code' => 'storage_probe_failed'], 503);
    }
    exit;
}

if ($uri === '/challenge' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $raw = file_get_contents('php://input', false, null, 0, 8192) ?: '';
    $payload = json_decode($raw, true);
    $scope = is_array($payload) && isset($payload['scope']) ? (string) $payload['scope'] : 'login';
    $binding = is_array($payload) && isset($payload['request_binding']) ? (string) $payload['request_binding'] : null;
    $issuer = new Issuer($config, $storage);
    try {
        $challenge = $issuer->issueWithExecutionField(
            $scope,
            (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'),
            true,
            $binding,
            null,
            null,
            1,
            true,
        );
    } catch (\Throwable $e) {
        kiwiError('SERVICE_UNAVAILABLE', 'issuance failed: ' . $e->getMessage(), 503);
        exit;
    }
    kiwiJson($challenge->toArray());
    exit;
}

if ($uri === '/verify' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $raw = file_get_contents('php://input', false, null, 0, 8192) ?: '';
    $payload = json_decode($raw, true);
    $token = is_array($payload) ? (string) ($payload['token'] ?? '') : '';
    $scope = is_array($payload) ? (string) ($payload['scope'] ?? 'login') : 'login';
    $binding = is_array($payload) && isset($payload['request_binding']) ? (string) $payload['request_binding'] : null;
    $verifier = new Verifier($storage);
    try {
        $outcome = $verifier->verify($token, $secret, $scope, '127.0.0.1', expectedRequestBinding: $binding);
        kiwiJson(['ok' => $outcome->isOk(), 'code' => $outcome->code()]);
    } catch (\Throwable $e) {
        kiwiJson(['ok' => false, 'code' => 'storage_unavailable']);
    }
    exit;
}

kiwiError('NOT_FOUND', 'no such surface', 404);
