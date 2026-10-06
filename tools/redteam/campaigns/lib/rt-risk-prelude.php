<?php

declare(strict_types=1);

/**
 * rt-risk-prelude.php — the shared bootstrap of the php campaign
 * drivers.
 *
 * Stitches the autoload surfaces every driver needs, in conflict-safe
 * order, and exposes small shared helpers. A driver that needs the
 * Symfony bundle classes (step-up handlers, verified agents) gets them
 * from the repo tree; their runtime dependencies (http-foundation,
 * webauthn-lib) come from this directory's bundle-vendor install whose
 * composer.json records the exact versions. Nothing here reaches the
 * network: every path is inside the repository or the vendor install
 * beside it.
 *
 * Environment contract (set by the campaign wrapper):
 *   KIWI_RT_PRELUDE_SKIP_BUNDLE=1   skip the bundle and vendor wiring
 */

const RT_BUNDLE_SRC = __DIR__ . '/../../../../packages/kiwicaptcha/integrations/symfony/src';
const RT_BUNDLE_TESTS = __DIR__ . '/../../../../packages/kiwicaptcha/integrations/symfony/tests';
const RT_BUNDLE_VENDOR = __DIR__ . '/bundle-vendor/vendor';
const RT_RISK_VENDOR = __DIR__ . '/../../../../packages/kiwicaptcha-risk-php/vendor/autoload.php';

// The risk plane's own autoload: the prelude's runner class implements
// one of its interfaces, so this lands before anything else registers.
if (is_file(RT_RISK_VENDOR)) {
    require_once RT_RISK_VENDOR;
}

/**
 * Register a minimal PSR-4 loader for one prefix. The composer
 * autoloaders already registered keep priority: a prefix they own is
 * never reached here, because spl_autoload_register appends.
 */
function rtPsr4(string $prefix, string $baseDir): void
{
    spl_autoload_register(static function (string $class) use ($prefix, $baseDir): void {
        if (!str_starts_with($class, $prefix)) {
            return;
        }
        $relative = substr($class, strlen($prefix));
        $path = $baseDir . '/' . str_replace('\\', '/', $relative) . '.php';
        if (is_file($path)) {
            require $path;
        }
    });
}

$bundleWanted = getenv('KIWI_RT_PRELUDE_SKIP_BUNDLE') !== '1';
if ($bundleWanted) {
    foreach ([RT_BUNDLE_VENDOR . '/autoload.php'] as $autoload) {
        if (is_file($autoload)) {
            require_once $autoload;
        }
    }
    rtPsr4('BelConsulting\\KiwiCaptchaBundle\\', RT_BUNDLE_SRC);
    rtPsr4('BelConsulting\\KiwiCaptchaBundle\\Tests\\Fixtures\\', RT_BUNDLE_TESTS . '/Fixtures/');
}

/**
 * The redis client every driver shares: the same fail-fast shape the
 * deployment builds, from the risk-php vendor install.
 */
function rtRedis(string $url): \Predis\Client
{
    $client = KiwiCaptcha\Risk\Storage\RedisRiskStateStore::createClient($url);
    $client->ping();

    return $client;
}

/**
 * The production script runner shape the evidence stores take: the
 * canonical Lua runs on the real Redis through the real client, so a
 * decoy escalation write or read is the deployment's own atomic
 * transition, never a fixture.
 */
final class RtScriptRunner implements \KiwiCaptcha\Risk\Evidence\RedisScriptRunnerInterface
{
    public function __construct(private readonly \Predis\Client $client)
    {
    }

    public function evalScript(string $script, array $keys, array $args): int|string|null
    {
        $sha = sha1($script);
        $callArgs = array_merge($keys, $args);

        try {
            return $this->client->evalsha($sha, count($keys), ...$callArgs);
        } catch (\Predis\Response\ServerException $e) {
            if (!str_contains($e->getMessage(), 'NOSCRIPT')) {
                throw $e;
            }

            return $this->client->eval($script, count($keys), ...$callArgs);
        }
    }
}

/**
 * A hex pseudonym of fixed byte length, derived deterministically from
 * a label and a run seed, so a rerun of one campaign rebuilds the same
 * identity set while two campaigns never collide.
 */
function rtPseudo(string $label, int $bytes = 16): string
{
    $seed = getenv('KIWI_RT_SEED') ?: '0x6b776d74';

    return substr(hash('sha256', 'kiwi-rt|' . $seed . '|' . $label), 0, $bytes * 2);
}

/**
 * One honest pass through a deployment's own wire flow: issue, pay the
 * proof of work, carry the token. Returns the verify body document.
 */
function rtWireAttempt(string $base, string $scope, ?string $binding = null, ?int &$hashes = null): array
{
    $payload = ['scope' => $scope];
    if ($binding !== null) {
        $payload['request_binding'] = $binding;
    }
    $raw = rtHttpPost($base . '/challenge', $payload);
    $doc = json_decode($raw, true);
    if (!is_array($doc) || !isset($doc['nonce'], $doc['prefix'], $doc['salt'], $doc['targetBits'])) {
        return ['ok' => false, 'code' => 'challenge_unavailable', 'http' => 0];
    }
    $counter = rtPowSolve((string) $doc['prefix'], (string) $doc['salt'], (int) $doc['targetBits'], $hashes);
    $token = base64_encode($doc['nonce'] . '.' . $counter . '.5.{}');

    $verifyPayload = ['token' => $token, 'scope' => $scope];
    if ($binding !== null) {
        $verifyPayload['request_binding'] = $binding;
    }
    $body = rtHttpPost($base . '/verify', $verifyPayload);
    $decoded = json_decode($body, true);

    return is_array($decoded) ? $decoded : ['ok' => false, 'code' => 'wire_garbage', 'http' => 0];
}

function rtHttpPost(string $url, array $payload): string
{
    $context = stream_context_create(['http' => [
        'method' => 'POST',
        'header' => "content-type: application/json\r\n",
        'content' => json_encode($payload, JSON_UNESCAPED_SLASHES),
        'timeout' => 30,
        'ignore_errors' => true,
    ]]);
    $body = (string) file_get_contents($url, false, $context);

    return $body === '' ? '{}' : $body;
}

/**
 * The shared preimage contract: sha256(prefix || decimal(counter) ||
 * salt), the first counter whose digest carries the target leading
 * zero bits. Counts every hash into $hashes when the caller passes the
 * counter by reference.
 */
function rtPowSolve(string $prefix, string $salt, int $targetBits, ?int &$hashes = null): int
{
    $saltRaw = base64_decode($salt, true);
    if ($saltRaw === false) {
        throw new RuntimeException('salt did not decode');
    }
    $fullBytes = intdiv($targetBits, 8);
    $remBits = $targetBits % 8;
    for ($counter = 0; ; $counter++) {
        $digest = hash('sha256', $prefix . (string) $counter . $saltRaw, true);
        if ($hashes !== null) {
            $hashes++;
        }
        $pass = true;
        for ($i = 0; $i < $fullBytes; $i++) {
            if (ord($digest[$i]) !== 0) {
                $pass = false;
                break;
            }
        }
        if ($pass && $remBits > 0 && (ord($digest[$fullBytes]) >> (8 - $remBits)) !== 0) {
            $pass = false;
        }
        if ($pass) {
            return $counter;
        }
    }
}
