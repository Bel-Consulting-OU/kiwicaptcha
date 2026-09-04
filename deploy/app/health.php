<?php

declare(strict_types=1);

/**
 * The /healthz handler logic of the reference deployment.
 *
 * The probe is a REAL round trip through the core challenge-record
 * store, never a process-local check: the storage interface exposes no
 * ping, so the probe stores a synthetic pending record with a fresh
 * random nonce, reads it back, and atomically deletes it while pending
 * (the delete-if-pending transition). A record left behind by a failed
 * probe expires on its own short TTL. Success means the same storage
 * API the Symfony bundle uses for challenge records accepted a write,
 * a read and a delete.
 */

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\RedisStorage;

/**
 * Run one storage round trip and report the outcome.
 *
 * @return array{ok: bool, detail: string} the probe verdict and a
 *                                         one-line human detail
 */
function kiwiHealthProbe(RedisStorage $storage): array
{
    $now = time();
    $record = new ChallengeRecord(
        nonce: base64_encode(random_bytes(32)),
        scope: 'healthz',
        bindingTag: '',
        issuedAt: $now - 1,
        expiresAt: $now + 60,
        algorithm: PoWAlgorithm::Sha256,
        mKib: 0,
        t: 1,
        p: 1,
        targetBits: 8,
        salt: base64_encode(random_bytes(16)),
        prefix: 'healthz',
        challenge: 'healthz',
        minDurationMs: 0,
        issuedAtNs: (int) (microtime(true) * 1_000_000),
        protocolVersion: 2,
    );
    try {
        $storage->store($record);
    } catch (\Throwable $e) {
        return [false, 'store failed: '.$e->getMessage()];
    }
    try {
        $found = $storage->find($record->nonce);
    } catch (\Throwable $e) {
        return [false, 'read-back failed: '.$e->getMessage()];
    }
    if ($found === null || $found->nonce !== $record->nonce) {
        return [false, 'read-back returned no record'];
    }
    try {
        $cleanup = $storage->deleteIfPending($record->nonce);
    } catch (\Throwable $e) {
        return [false, 'delete-if-pending failed: '.$e->getMessage()];
    }
    if ($cleanup->state !== 'deleted-pending') {
        return [false, 'delete-if-pending returned state '.$cleanup->state];
    }

    return [true, 'store round trip (write, read, delete-if-pending) succeeded'];
}

/**
 * The /healthz request handler: answers 200 only when the configured
 * store completed the round trip, 503 otherwise.
 */
function kiwiHealthz(): void
{
    header('Content-Type: application/json');
    header('Cache-Control: no-store, private, max-age=0');
    try {
        $deployment = kiwiDeployment();
        $storage = kiwiStorage($deployment['redisUrl']);
        [$ok, $detail] = kiwiHealthProbe($storage);
    } catch (\Throwable $e) {
        $ok = false;
        $detail = $e->getMessage();
    }
    if (!$ok) {
        http_response_code(503);
        echo json_encode([
            'ok' => false,
            'code' => 'storage_probe_failed',
            'message' => $detail,
        ], JSON_UNESCAPED_SLASHES);

        return;
    }
    echo json_encode(['ok' => true], JSON_UNESCAPED_SLASHES);
}
