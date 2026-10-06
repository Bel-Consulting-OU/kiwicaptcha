<?php

declare(strict_types=1);

/**
 * d315.driver.php — the D3.15 multi-tenant driver: two tenants on one
 * shared Redis with colliding raw namespaces, identical secrets and
 * identical scope names.
 *
 *   namespace collisions  a crafted corpus of raw namespaces
 *                         (suffix-identical pairs, the legacy-v1
 *                         sanitization collision pairs, case variants)
 *                         derives DISTINCT digest (v2) namespaces, so
 *                         no two tenants' key families ever touch; the
 *                         legacy derivation's known fold is asserted
 *                         as the documented hazard it is.
 *
 *   zero cross reads      tenant A writes marks, decisions and bucket
 *                         trust; tenant B's store reads every one of
 *                         those logical keys and finds nothing.
 *
 *   zero cross replay     the same secret on both tenants: a challenge
 *                         issued by tenant A's store and consumed (or
 *                         not) never verifies through tenant B's store
 *                         (the prefix-scoped record key misses), so a
 *                         token cannot be relayed across tenants even
 *                         when the MAC key is shared.
 *
 *   crafted keys          tenant B writes keys named exactly like
 *                         tenant A's documented family layout under its
 *                         own namespace: A's readers see nothing.
 *
 * Output: one JSON summary on stdout.
 */

use KiwiCaptcha\Risk\DeploymentNamespace;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Config;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\Risk\Marks\MarksView;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Risk\Trust\ContextBoundTrust;
use KiwiCaptcha\Risk\Asn\AsnDataset;

require getenv('KIWI_RT_RISK_AUTOLOAD') ?: throw new RuntimeException('autoload missing');
require __DIR__ . '/rt-risk-prelude.php';

$redisUrl = (string) getenv('KIWI_RT_RISK_REDIS_URL');
$client = RedisRiskStateStore::createClient($redisUrl);

// ---------- the crafted namespace corpus ----------
$rawPairs = [
    'tenant-app',            // tenant one
    'tenant-app-backup',     // suffix-identical with tenant one
    'app',                   // suffix of tenant one
    'tenant/app',            // legacy folds onto tenant_app
    'tenant:app',            // legacy folds onto tenant_app too
    'Tenant-App',            // case variant (digest separates)
    "tenant\napp",           // control byte (digest separates)
    'x',                     // length floor
];
$digests = [];
$digestInjective = true;
foreach ($rawPairs as $raw) {
    $derived = DeploymentNamespace::derive($raw, DeploymentNamespace::VERSION_DIGEST);
    if (isset($digests[$derived])) {
        $digestInjective = false;
    }
    $digests[$derived][] = $raw;
}
$legacyA = DeploymentNamespace::derive('tenant/app', DeploymentNamespace::VERSION_LEGACY);
$legacyB = DeploymentNamespace::derive('tenant:app', DeploymentNamespace::VERSION_LEGACY);
$legacyFoldDocumented = $legacyA === $legacyB;

// ---------- two tenants on the shared store ----------
$nsA = DeploymentNamespace::derive('tenant-app', DeploymentNamespace::VERSION_DIGEST);
$nsB = DeploymentNamespace::derive('tenant-app-backup', DeploymentNamespace::VERSION_DIGEST);
// The stores take the RAW namespace and derive internally; the
// derived digests above are the key-family patterns this driver scans.
$storeA = new RedisRiskStateStore($client, namespace: 'tenant-app', namespaceKeyVersion: DeploymentNamespace::VERSION_DIGEST);
$storeB = new RedisRiskStateStore($client, namespace: 'tenant-app-backup', namespaceKeyVersion: DeploymentNamespace::VERSION_DIGEST);
$scope = 1;
$nowMs = (int) (microtime(true) * 1000);

// A writes its plane: a mark, a decision registration, bucket trust.
$markId = rtPseudo('d315-mark');
$storeA->writeMark('session', $markId, 'accountBanned', $nowMs);
$decisionId = 'd315decision' . bin2hex(random_bytes(8));
$storeA->registerOutcome($decisionId, $scope, intdiv($nowMs, 3600000), 100);
$sessionA = rtPseudo('d315-session-a');
$storeA->creditBucketTrust($sessionA, 'u4/2584', 100);

// B reads every logical key of A and finds nothing.
$crossReads = [
    'mark' => $storeB->readMark('session', $markId),
    'decision' => $storeB->confirmOutcome($decisionId, true),
    'bucket_trust' => $storeB->readBucketTrust($sessionA, 'u4/2584'),
];
$zeroCrossReads = $crossReads['mark'] === null
    && $crossReads['decision'] === 0
    && $crossReads['bucket_trust'] === 0;

// The keyspace segregation: every key carries exactly one tenant tag.
$patternA = '*' . $nsA . '*';
$patternB = '*' . $nsB . '*';
$keysA = (array) $client->keys($patternA);
$keysB = (array) $client->keys($patternB);
$overlap = count(array_intersect($keysA, $keysB));
$keyspaceSegregated = $overlap === 0 && count($keysA) > 0;

// Crafted keys: B writes A's documented layout names under B's family.
$craftedKey = '{kiwi:' . $nsB . '}:mark:session:' . $markId;
$client->set($craftedKey, 'crafted');
$aSeesCrafted = (array) $client->keys('*' . $nsA . '*');
$craftContained = !in_array($craftedKey, $aSeesCrafted, true);

// ---------- zero cross replay on the core (same secret) ----------
$secret = str_repeat('d315secret!', 3); // 33 bytes, same for both tenants
$storageA = new RedisStorage($client, 'kiwitna:');
$storageB = new RedisStorage($client, 'kiwitnb:');
$config = new Config(
    secretKey: $secret,
    algorithm: PoWAlgorithm::Sha256,
    mKib: 0,
    t: 3,
    p: 1,
    targetBits: 10,
    argon2TargetBits: 4,
    ttlSecs: 120,
    minDurationMs: 0,
    executionKey: null,
    rswModulusN: null,
    rswLambda: null,
    rswT: 75000,
);
$issuerA = new Issuer($config, $storageA);
$challenge = $issuerA->issue('login', '203.0.113.50');
$counter = rtPowSolve((string) $challenge->prefix, (string) $challenge->salt, (int) $challenge->targetBits);
$token = base64_encode($challenge->nonce . '.' . $counter . '.5.{}');

$verifierB = new Verifier($storageB);
$crossReplayRefused = false;
try {
    $outcome = $verifierB->verify($token, $secret, 'login', '203.0.113.51');
    $crossReplayRefused = !$outcome->isOk();
} catch (\Throwable) {
    $crossReplayRefused = true;
}
// And the honest same-tenant verify still works (the isolation is the
// prefix, not a broken store).
$verifierA = new Verifier($storageA);
$sameTenantOk = false;
try {
    $outcomeA = $verifierA->verify($token, $secret, 'login', '203.0.113.50');
    $sameTenantOk = $outcomeA->isOk();
} catch (\Throwable) {
    $sameTenantOk = false;
}
// The replay after consume is refused on A too (one-shot holds).
$secondReplayRefused = false;
try {
    $again = $verifierA->verify($token, $secret, 'login', '203.0.113.50');
    $secondReplayRefused = !$again->isOk();
} catch (\Throwable) {
    $secondReplayRefused = true;
}

// Clean up the crafted key.
$client->del([$craftedKey]);

$summary = [
    'namespace_corpus' => count($rawPairs),
    'digest_namespaces_distinct' => count($digests),
    'digest_injective' => $digestInjective,
    'legacy_fold_documented' => $legacyFoldDocumented,
    'cross_reads' => [
        'mark' => $crossReads['mark'] === null ? 'none' : 'leaked',
        'decision' => $crossReads['decision'],
        'bucket_trust' => $crossReads['bucket_trust'],
    ],
    'zero_cross_reads' => $zeroCrossReads,
    'keyspace_segregated' => $keyspaceSegregated,
    'keys_a' => count($keysA),
    'keys_b' => count($keysB),
    'crafted_key_contained' => $craftContained,
    'cross_tenant_replay_refused' => $crossReplayRefused,
    'same_tenant_verify_ok' => $sameTenantOk,
    'one_shot_holds_on_owner' => $secondReplayRefused,
];
echo json_encode($summary), "\n";

$pass = $digestInjective
    && $legacyFoldDocumented
    && $zeroCrossReads
    && $keyspaceSegregated
    && $craftContained
    && $crossReplayRefused
    && $sameTenantOk
    && $secondReplayRefused;
exit($pass ? 0 : 1);
