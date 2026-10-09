#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * d34.router.php — the D3.4 wire instance: the real core issuer and
 * verifier of the reference deployment behind a trusted edge. The one
 * difference from the stock deploy router is the client address: this
 * instance reads the first value of the X-Forwarded-For header, the
 * production shape of a deployment behind a reverse proxy, which is
 * exactly the surface a residential proxy pool attacks (every pooled
 * source arrives as a different forwarded address from the same
 * socket).
 *
 *   GET  /healthz    real store round trip
 *   POST /challenge  real Issuer, per-forwarded-source issuance limiter
 *   POST /verify     real Verifier, the deployment's answer shape
 *
 * The limiter is the deployment's own fixed-window pseudonym limiter
 * (HMAC key rotation, the union of the current and previous epoch), on
 * the same Redis as the storage. KIWI_ISSUANCE_PER_MINUTE_PER_IP
 * configures the budget exactly like the stock deployment.
 */

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;

require getenv('KIWI_RT_DEPLOY_VENDOR') . '/autoload.php';

$secret = (string) getenv('KIWI_SECRET_KEY');
$redisUrl = (string) getenv('KC_REDIS_URL');
$perMinute = (int) (getenv('KIWI_ISSUANCE_PER_MINUTE_PER_IP') ?: '30');

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

/** The trusted-edge client address: the first XFF value, else the peer. */
function kiwiEdgeClientIp(): string
{
    $forwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
    if (is_string($forwarded) && $forwarded !== '') {
        $first = trim(explode(',', $forwarded)[0]);
        if ($first !== '' && filter_var($first, FILTER_VALIDATE_IP) !== false) {
            return $first;
        }
    }

    return (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');
}

/** The deployment's limiter pseudonym (the raw address never appears). */
function kiwiLimitPseudo(string $masterSecret, string $ip, int $epoch): string
{
    $rateKey = hash_hmac('sha256', 'kiwi-deploy-rate-limit-v1', $masterSecret, true);

    return hash_hmac('sha256', 'kiwi:rl:issuance:v1|' . $epoch . '|' . $ip, $rateKey);
}

/**
 * The fixed-window limiter of the stock deployment: INCR under the
 * pseudonym, EXPIRE armed on the new counter, the union of the current
 * and the previous epoch budget.
 */
function kiwiIssuanceAllowed(\Predis\Client $client, string $ip, int $perMinute, string $masterSecret): string
{
    if ($perMinute < 1) {
        return 'allowed';
    }
    try {
        $epoch = (int) floor(time() / 60);
        $current = '{kiwi:rl}:issuance:v1:' . kiwiLimitPseudo($masterSecret, $ip, $epoch);
        $previous = '{kiwi:rl}:issuance:v1:' . kiwiLimitPseudo($masterSecret, $ip, $epoch - 1);
        $count = (int) $client->incr($current);
        if ($count === 1) {
            $client->expire($current, 60);
        }
        $prevRaw = $client->get($previous);
        $total = $count + (is_string($prevRaw) ? (int) $prevRaw : 0);

        return $total <= $perMinute ? 'allowed' : 'limited';
    } catch (\Throwable) {
        return 'indeterminate';
    }
}

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
    executionKey: null,
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
    } catch (\Throwable) {
        kiwiJson(['ok' => false, 'code' => 'storage_probe_failed'], 503);
    }
    exit;
}

if ($uri === '/challenge' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $raw = file_get_contents('php://input', false, null, 0, 8192) ?: '';
    $payload = json_decode($raw, true);
    $scope = is_array($payload) && isset($payload['scope']) ? (string) $payload['scope'] : 'login';
    $ip = kiwiEdgeClientIp();
    $verdict = kiwiIssuanceAllowed($client, $ip, $perMinute, $secret);
    if ($verdict === 'limited') {
        kiwiJson(['error' => ['code' => 'RATE_LIMITED', 'message' => 'Too many challenge requests from this address.']], 429);
        exit;
    }
    if ($verdict === 'indeterminate') {
        kiwiJson(['error' => ['code' => 'RATE_LIMIT_UNAVAILABLE', 'message' => 'The issuance rate limiter is unavailable.']], 503);
        exit;
    }
    $issuer = new Issuer($config, $storage);
    try {
        $challenge = $issuer->issue($scope, $ip);
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
        $outcome = $verifier->verify($token, $secret, $scope, kiwiEdgeClientIp(), expectedRequestBinding: $binding);
        kiwiJson(['ok' => $outcome->isOk(), 'code' => $outcome->code()]);
    } catch (\Throwable) {
        kiwiJson(['ok' => false, 'code' => 'storage_unavailable']);
    }
    exit;
}

kiwiError('NOT_FOUND', 'no such surface', 404);
