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
 *
 * The unauthenticated response never carries backend detail: on any
 * probe failure the one-line detail goes to the server log and the
 * answer is the fixed 503 document {"ok":false,"code":
 * "storage_probe_failed"} — no hostname, port, credentials, DSN or
 * driver text ever reaches the body.
 */

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\RedisStorage;

/**
 * Run one storage round trip and report the outcome.
 *
 * @return array{ok: bool, detail: string} the probe verdict and a
 *                                         one-line server-side detail
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
 * store completed the round trip, 503 otherwise. The detail of a
 * failed probe (or of a configuration/storage failure while probing)
 * is logged server-side and never serialized into the unauthenticated
 * response.
 */
function kiwiHealthz(): void
{
    $ok = false;
    $detail = '';
    try {
        $deployment = kiwiDeployment();
        $storage = kiwiStorage($deployment['redisUrl']);
        [$ok, $detail] = kiwiHealthProbe($storage);
    } catch (\Throwable $e) {
        $detail = $e->getMessage();
    }
    if (!$ok) {
        error_log('kiwicaptcha healthz probe failed: '.$detail);
        kiwiJson(['ok' => false, 'code' => 'storage_probe_failed'], 503);

        return;
    }
    kiwiJson(['ok' => true]);
}
