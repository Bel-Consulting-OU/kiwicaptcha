<?php

declare(strict_types=1);

/**
 * The storage-matrix router of the red-team target: the reference
 * deployment's wire contract over SqliteStorage and FilesystemStorage,
 * with no Redis anywhere in the path.
 *
 *   php -S 127.0.0.1:<port> -t deploy/app tools/redteam/target/router-storage.php
 *
 * change.md Part 9.2 requires the storage adapter matrix: the same core
 * issuer and verifier the reference deployment runs, with the store
 * swapped for the single-node adapters a small site deploys. The
 * campaign matrix (target.sh matrix <campaign.sh> sqlite files) drives
 * a campaign against each profile, so a behaviour that depends on the
 * store rather than on the protocol shows up as a differential between
 * profiles instead of passing on Redis alone.
 *
 * The surface is the reference router's, and deliberately so:
 *
 *   GET  /healthz -> the same store round trip (write, read,
 *                    delete-if-pending) through the profile's adapter,
 *                    answered 200 {"ok":true} or, on any probe
 *                    failure, 503 {"ok":false,"code":
 *                    "storage_probe_failed"} with the detail going to
 *                    the server log only.
 *   POST /challenge -> the canonical challenge document from the real
 *                    core issuer over the profile's adapter. The
 *                    server-owned algorithm profile, the request
 *                    fields, the scope and request-binding shapes and
 *                    the rejection codes are the reference surface's.
 *   POST /verify -> the reference answer document from the real core
 *                    verifier over the profile's adapter, including the
 *                    one-shot semantics: a hard cheap-phase verdict
 *                    retires the pending record, so a replayed token
 *                    answers already_consumed and a mislabeled binding
 *                    cannot be retried.
 *
 * What differs is only what has to:
 *
 *  - The store comes from KIWI_STORAGE: `sqlite` opens
 *    SqliteStorage on KIWI_STORAGE_PATH, `files` opens
 *    FilesystemStorage on KIWI_STORAGE_DIR. The local-disk
 *    acknowledgement is passed deliberately: these profiles ARE the
 *    documented single-node local-disk deployment, not a replicated
 *    one.
 *  - The issuance rate limiter cannot run here. Its counter lives in
 *    Redis by design (an atomic INCR with the window armed in the same
 *    script), and these profiles have no Redis. A profile that leaves
 *    the budget disabled (0, what target.sh sets) issues normally; a
 *    profile that configures a budget anyway is answered the retryable
 *    503 RATE_LIMIT_UNAVAILABLE rather than being silently allowed, so
 *    an explicit abuse limit can never become unlimited issuance just
 *    because the limiter's store is absent. This mirrors the reference
 *    deployment's own fail-closed limiter policy, where an unreachable
 *    limiter is INDETERMINATE and never a pass.
 *  - The framing rules are not restated here. They are required from
 *    deploy/app/framing.php, the one implementation the reference
 *    router also uses, so both deployments accept and refuse exactly
 *    the same bytes and the D3.12 parser legs mean the same thing on
 *    every profile.
 */

require __DIR__.'/../../../deploy/app/vendor/autoload.php';
require __DIR__.'/../../../deploy/app/bootstrap.php';
require __DIR__.'/../../../deploy/app/health.php';
require __DIR__.'/../../../deploy/app/framing.php';

/**
 * The issuance decision of a profile whose limiter store is
 * absent. These are not the reference deployment's three-valued
 * limiter states: with no counter store there is nothing to
 * evaluate, so a profile either has its budget disabled (the
 * shipped configuration, and issuance proceeds) or it is asking
 * for a limit this deployment cannot enforce (and issuance is
 * refused rather than silently unlimited).
 */
const KIWI_MATRIX_ISSUANCE_ALLOWED = 'allowed';
const KIWI_MATRIX_ISSUANCE_UNAVAILABLE = 'unavailable';

use KiwiCaptcha\AtomicDeleteIfPendingInterface;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Storage\FilesystemStorage;
use KiwiCaptcha\Storage\SqliteStorage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;

/**
 * The store of this profile, selected by KIWI_STORAGE. The adapter is
 * rebuilt per request exactly as the reference deployment rebuilds its
 * Redis client: php -S re-includes this router for every request, and
 * both adapters are cheap to open (SQLite reuses the file handle
 * through the connection, the filesystem adapter takes a directory).
 *
 * @throws RuntimeException on a missing or unknown profile
 */
function kiwiMatrixStorage(): StorageInterface&AtomicDeleteIfPendingInterface
{
    $profile = optionalEnv('KIWI_STORAGE');
    if ($profile === null) {
        throw new RuntimeException('required environment variable KIWI_STORAGE is not set (sqlite or files)');
    }

    return match ($profile) {
        'sqlite' => new SqliteStorage(requiredEnv('KIWI_STORAGE_PATH')),
        // The local-disk acknowledgement is the profile's own definition:
        // the documented small-site deployment keeps its records on one
        // node's disk, with no replication to fall back on.
        'files' => new FilesystemStorage(requiredEnv('KIWI_STORAGE_DIR'), localDiskAcknowledged: true),
        default => throw new RuntimeException(sprintf(
            'environment variable KIWI_STORAGE must be one of sqlite, files (got "%s")',
            $profile,
        )),
    };
}

/**
 * The issuance decision of a profile with no limiter store. A disabled
 * budget (0) allows issuance, which is how target.sh boots these
 * profiles; a configured budget is INDETERMINATE, because the limiter
 * cannot be evaluated without its store and an unenforceable limit is
 * never a pass.
 *
 * @return string one of KIWI_MATRIX_ISSUANCE_ALLOWED / KIWI_MATRIX_ISSUANCE_UNAVAILABLE
 */
function kiwiMatrixIssuanceAllowed(int $perMinute): string
{
    if ($perMinute < 1) {
        return KIWI_MATRIX_ISSUANCE_ALLOWED;
    }
    error_log(sprintf(
        'kiwicaptcha storage matrix: KIWI_ISSUANCE_PER_MINUTE_PER_IP is %d but this profile has no limiter store; refusing issuance',
        $perMinute,
    ));

    return KIWI_MATRIX_ISSUANCE_UNAVAILABLE;
}

/**
 * GET /healthz: the reference probe over this profile's store. The
 * shape, the log-only detail and the fixed 503 document are health.php's
 * own.
 */
function kiwiMatrixHealthz(): void
{
    $ok = false;
    $detail = '';
    try {
        kiwiDeployment();
        [$ok, $detail] = kiwiHealthProbe(kiwiMatrixStorage());
    } catch (\Throwable $e) {
        $detail = $e->getMessage();
    }
    if (!$ok) {
        error_log('kiwicaptcha storage matrix healthz probe failed: '.$detail);
        kiwiJson(['ok' => false, 'code' => 'storage_probe_failed'], 503);

        return;
    }
    kiwiJson(['ok' => true]);
}

/**
 * POST /challenge: the reference issuance path over this profile's
 * store, down to the same validation order and the same codes.
 */
function kiwiMatrixChallenge(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        header('Allow: POST');
        kiwiError('METHOD_NOT_ALLOWED', 'The challenge endpoint accepts POST requests only.', 405);

        return;
    }
    $payload = kiwiReadBody(['scope', 'algorithm', 'request_binding']);
    if ($payload === null) {
        return;
    }
    foreach (['scope', 'algorithm', 'request_binding'] as $field) {
        if (array_key_exists($field, $payload) && $payload[$field] !== null && !is_string($payload[$field])) {
            kiwiError('INVALID_JSON', 'The challenge request fields must be strings.', 422);

            return;
        }
    }
    $scope = isset($payload['scope']) && $payload['scope'] !== '' ? (string) $payload['scope'] : 'default';
    $requestBinding = isset($payload['request_binding']) && $payload['request_binding'] !== ''
        ? (string) $payload['request_binding']
        : null;
    if (preg_match(KIWI_IDENTIFIER_PATTERN, $scope) !== 1) {
        kiwiError('INVALID_SCOPE', 'The scope must be 1-128 characters of [A-Za-z0-9._:-].', 422);

        return;
    }
    if ($requestBinding !== null && preg_match(KIWI_IDENTIFIER_PATTERN, $requestBinding) !== 1) {
        kiwiError('INVALID_REQUEST_BINDING', 'The request_binding must be 1-128 characters of [A-Za-z0-9._:-].', 422);

        return;
    }

    $deployment = kiwiDeployment();
    if (isset($payload['algorithm']) && $payload['algorithm'] !== ''
        && !in_array($payload['algorithm'], KIWI_ALGORITHM_PROFILES, true)) {
        kiwiError('INVALID_ALGORITHM', 'The algorithm must be one of sha256, argon2id, rsw.', 422);

        return;
    }

    $limit = kiwiMatrixIssuanceAllowed((int) $deployment['issuancePerMinute']);
    if ($limit === KIWI_MATRIX_ISSUANCE_UNAVAILABLE) {
        kiwiError('RATE_LIMIT_UNAVAILABLE', 'The issuance rate limiter is unavailable. Try again shortly.', 503);

        return;
    }

    // Opening the store belongs inside the try: these adapters open
    // eagerly (the sqlite adapter takes its database file, the filesystem
    // adapter takes and validates its directory), so a store that cannot
    // be opened throws here rather than at the first write. A store
    // failure is an availability failure, exactly as it is on the
    // reference deployment, and it must not answer an unauthenticated
    // caller with the adapter's own detail: the local path and the driver
    // text stay in the server log, and the answer is the fixed retryable
    // document this contract uses for an unavailable store.
    try {
        $storage = kiwiMatrixStorage();
        $issuer = new Issuer($deployment['config'], $storage);
        $challenge = $deployment['config']->executionKey !== null
            ? $issuer->issueWithExecutionField($scope, kiwiClientIp(), true, $requestBinding)
            : $issuer->issue($scope, kiwiClientIp(), $requestBinding);
    } catch (\Throwable $e) {
        error_log(sprintf('kiwicaptcha storage matrix: challenge issuance failed: %s', $e->getMessage()));
        kiwiError('SERVICE_UNAVAILABLE', 'Challenge issuance is temporarily unavailable. Try again later.', 503);

        return;
    }
    kiwiJson($challenge->toArray());
}

/**
 * POST /verify: the reference redemption path over this profile's
 * store. The expected binding is an independent input handed to the
 * core verifier, exactly as in the reference surface, so a mismatching
 * binding is the core's own one-shot cheap-phase verdict.
 */
function kiwiMatrixVerify(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        header('Allow: POST');
        kiwiError('METHOD_NOT_ALLOWED', 'The verify endpoint accepts POST requests only.', 405);

        return;
    }
    $payload = kiwiReadBody(['token', 'scope', 'request_binding', 'remoteip']);
    if ($payload === null) {
        return;
    }
    $token = isset($payload['token']) && is_string($payload['token']) ? $payload['token'] : '';
    $scope = isset($payload['scope']) && is_string($payload['scope']) && $payload['scope'] !== ''
        ? $payload['scope']
        : 'default';

    $expectedRequestBinding = null;
    if (array_key_exists('request_binding', $payload) && $payload['request_binding'] !== null) {
        if (!is_string($payload['request_binding'])) {
            kiwiError('INVALID_JSON', 'The verify request fields must be strings.', 422);

            return;
        }
        if ($payload['request_binding'] !== ''
            && preg_match(KIWI_IDENTIFIER_PATTERN, $payload['request_binding']) !== 1) {
            kiwiError('INVALID_REQUEST_BINDING', 'The request_binding must be 1-128 characters of [A-Za-z0-9._:-].', 422);

            return;
        }
        $expectedRequestBinding = $payload['request_binding'] !== ''
            ? $payload['request_binding']
            : null;
    }

    $deployment = kiwiDeployment();
    try {
        $storage = kiwiMatrixStorage();
        $verifier = new Verifier(
            $storage,
            rswModulusN: $deployment['rswModulusN'],
            rswLambda: $deployment['rswLambda'],
        );
        $outcome = $verifier->verify(
            $token,
            $deployment['secret'],
            $scope,
            kiwiClientIp(),
            expectedRequestBinding: $expectedRequestBinding,
        );
    } catch (\Throwable $e) {
        error_log(sprintf('kiwicaptcha storage matrix: verification failed: %s', $e->getMessage()));
        kiwiJson(['ok' => false, 'code' => 'storage_unavailable']);

        return;
    }
    kiwiJson(['ok' => $outcome->isOk(), 'code' => $outcome->code()]);
}

$path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
try {
    if ($_SERVER['REQUEST_METHOD'] === 'GET' && $path === '/healthz') {
        kiwiMatrixHealthz();

        return true;
    }
    if ($path === '/challenge') {
        kiwiMatrixChallenge();

        return true;
    }
    if ($path === '/verify') {
        kiwiMatrixVerify();

        return true;
    }

    kiwiError('NOT_FOUND', 'not found', 404);
} catch (\RuntimeException $e) {
    error_log(sprintf('kiwicaptcha storage matrix: configuration error: %s', $e->getMessage()));
    kiwiError('CONFIGURATION_ERROR', $e->getMessage(), 500);
} catch (\LogicException $e) {
    error_log(sprintf('kiwicaptcha storage matrix: configuration error: %s', $e->getMessage()));
    kiwiError('CONFIGURATION_ERROR', $e->getMessage(), 500);
} catch (\Throwable $e) {
    error_log(sprintf('kiwicaptcha storage matrix: internal error: %s', $e->getMessage()));
    kiwiError('INTERNAL_ERROR', 'The request could not be completed.', 500);
}

return true;
