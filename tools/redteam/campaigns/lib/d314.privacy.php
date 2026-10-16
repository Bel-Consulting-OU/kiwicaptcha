<?php

declare(strict_types=1);

/**
 * d314.privacy.php: the D3.14 privacy campaign's instrument. The
 * campaign (tools/redteam/campaigns/d3.14-privacy.sh) is the only
 * importer of this file, and no other campaign or driver reads it.
 *
 * Two modes, one per hole this instrument closes.
 *
 *   identity <redis-url>
 *     Boots the real product kernel through rt.kernel.php. That kernel
 *     is FrameworkBundle, SecurityBundle and KiwiCaptchaBundle with the
 *     shipped abuse_first profile and the form_login firewall over
 *     redis. The canary account table is registered in place of the
 *     leaked-list provider, as the application's own user source. That
 *     table is application wiring, because every deployment supplies
 *     its own user database, and rt.kernel.php's own docblock describes
 *     its provider as the way any app plugs its user database into the
 *     security firewall. No product service changes.
 *     The canary user name and email address then walk the kernel's
 *     real login surface. Both take the failure lane with a wrong
 *     password, the user name takes the honest lane with the true
 *     password, and a withheld session is resolved through the
 *     product's own step-up controller with the code the application's
 *     delivery channel carried. Everything that persists under the
 *     canary identifiers persists under the product's own derived
 *     handles. This program reports the flow's outcomes and the store's
 *     key count; the caller's scan, never this program, hunts the raw
 *     values.
 *
 *   dump <redis-url> <out-file>
 *     Serializes the whole keyspace, one line per key:
 *
 *         "<key>"<TAB><type><TAB><value-json>
 *
 *     The key is JSON-encoded, so any key byte survives the line shape.
 *     The type is the literal reply of the TYPE command. The value is
 *     the complete contents of that type, JSON-encoded with slashes
 *     unescaped and invalid UTF-8 substituted. The per-type reads:
 *       - string: GET, as a JSON string;
 *       - hash: HGETALL, or HSCAN paging when the hash is large, as a
 *         JSON object of field to value;
 *       - list: LRANGE 0 -1, as a JSON array;
 *       - set: SMEMBERS, sorted, or SSCAN for a large set, as a JSON
 *         array;
 *       - sorted set: ZRANGE 0 -1 WITHSCORES, as a JSON object of
 *         member to score;
 *       - stream: XRANGE - + COUNT 1000, as a JSON object of id to
 *         fields. A stream longer than that bound is recorded as
 *         truncated and counted uncovered, never silently cut.
 *     A module type or a type this list does not know, a key that
 *     vanishes between SCAN and TYPE, and a truncated stream are all
 *     reported in the summary's uncovered list, and the program exits
 *     2. A partial sweep must never read as complete. Exit 0 means
 *     every key in the keyspace was serialized in full.
 *
 * Exit codes: 0 for a complete sweep or a driven flow; 2 with uncovered
 * keys, each named in the JSON summary with its reason; 3 on a boot or
 * flow failure in identity mode.
 */

namespace KiwiRt;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

require_once __DIR__ . '/rt.kernel.php';
require_once __DIR__ . '/rt.wire.php';

/**
 * The canary account table: the application's own user source for this
 * run. It answers exactly the two canary identifiers the campaign
 * generated and refuses everyone else with the canonical
 * UserNotFoundException. No constructor state: the identifiers come
 * from the environment at call time, so the compiled container is
 * canary-independent and may be cached across runs.
 */
final class D314CanaryUserProvider implements UserProviderInterface
{
    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        $user = getenv('KIWI_RT_CANARY_USER') ?: '';
        $email = getenv('KIWI_RT_CANARY_EMAIL') ?: '';
        $password = getenv('KIWI_RT_CANARY_PASSWORD') ?: '';
        if ($user === '' || $email === '' || $password === '') {
            throw new \RuntimeException('the canary identity environment (KIWI_RT_CANARY_USER/EMAIL/PASSWORD) is not set');
        }
        if ($identifier === $user || $identifier === $email) {
            return new InMemoryUser($identifier, $password, ['ROLE_USER']);
        }
        throw new UserNotFoundException(sprintf('no canary account "%s"', $identifier));
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        return $this->loadUserByIdentifier($user->getUserIdentifier());
    }

    public function supportsClass(string $class): bool
    {
        return $class === InMemoryUser::class || is_subclass_of($class, InMemoryUser::class);
    }
}

/**
 * The canary kernel: the campaign kernel with the canary account table
 * registered in place of the leaked-list provider at the same service
 * id, so the firewall, the risk scope row (target_field username) and
 * every product service stay exactly rt.kernel.php's wiring. The cache
 * directory is the kernel's own (the wiring version rides it, like the
 * reference kernel's), so no compiled container is shared with another
 * build.
 */
final class D314CanaryKernel extends RtCampaignKernel
{
    public const WIRING_VERSION = 'v1-canary-account-table';

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        parent::registerContainerConfiguration($loader);
        $loader->load(function (ContainerBuilder $container): void {
            // The application's own user source under the id the security
            // configuration names. Nothing else is touched.
            $container->register(RtLeakedListUserProvider::class, D314CanaryUserProvider::class)->setPublic(true);
        });
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/kiwi-rt-d314-' . md5(
            'd314-canary-kernel|' . self::WIRING_VERSION . '|' . (self::$riskNamespace ?? ''),
        ) . '/' . $this->environment;
    }
}

/**
 * The identity flow. Boots the kernel against $redisUrl, drives the
 * canary identifiers through the real login surface, and returns the
 * evidence document the campaign asserts from.
 */
function d314Identity(string $redisUrl): array
{
    $user = (string) getenv('KIWI_RT_CANARY_USER');
    $email = (string) getenv('KIWI_RT_CANARY_EMAIL');
    $password = (string) getenv('KIWI_RT_CANARY_PASSWORD');
    foreach (['user name' => $user, 'email' => $email, 'password' => $password] as $what => $value) {
        if ($value === '') {
            fwrite(STDERR, sprintf("FATAL: the canary %s is not set\n", $what));
            exit(3);
        }
    }

    // The kernel wiring reads the redis URL from the environment (the
    // deployment contract rt.kernel.php documents); the argument is the
    // single source of truth this process publishes.
    putenv('KIWI_RT_RISK_REDIS_URL=' . $redisUrl);
    D314CanaryKernel::$riskNamespace = 'd314-privacy';
    $kernel = new D314CanaryKernel();
    $kernel->boot();
    $wire = new RtWire($kernel);

    $canonicalEmail = \KiwiCaptcha\Risk\TargetIdentifierNormalizer::normalize($email);
    $evidence = [
        'driver' => get_class($kernel),
        'namespace' => D314CanaryKernel::$riskNamespace,
        'outcomes' => [],
        'step_up' => 'not_attempted',
        'canonical_email' => $canonicalEmail,
    ];

    // The failure lane, both identifiers: a real authentication failure
    // with the canary claimed identifier as its target.
    $failUser = new RtActor('127.0.0.1');
    $evidence['outcomes']['user_wrong_password'] = $wire->login($failUser, $user, $password . '-wrong');
    $failEmail = new RtActor('127.0.0.1');
    $evidence['outcomes']['email_wrong_password'] = $wire->login($failEmail, $email, $password . '-wrong');

    // The honest lane: the true password. The product may grant the
    // session or withhold it for the step-up plane; both are the
    // product's own answers and both have consumed the identity.
    $honest = new RtActor('127.0.0.1');
    $evidence['outcomes']['user_honest'] = $wire->login($honest, $user, $password);
    if ($evidence['outcomes']['user_honest'] === 'withheld') {
        // The step-up plane through the product's own controller with
        // the code the application's delivery channel captured. A
        // failure here is reported, not hidden; the identity traffic
        // above was already driven either way.
        $completed = $wire->completeStepUp($honest, 'email_otp', $wire->capturedCode());
        $evidence['step_up'] = $completed ? 'succeeded' : 'failed';
        $evidence['granted_after_step_up'] = $wire->hasSession($honest);
    }

    // The consumption evidence: the product's own identity factory
    // derives the target handles from the identifiers (the engine's
    // derivation, read through the booted container), and the store
    // must carry those derived handles. The raw values must not appear
    // in any key; the caller's scan covers the values.
    $container = $kernel->getContainer();
    $factory = $container->get('kiwi_captcha.risk.identity_factory');
    \assert($factory instanceof \KiwiCaptcha\Risk\RiskIdentityFactory);
    $client = new \Predis\Client($redisUrl);
    $handles = [];
    foreach (['user' => $user, 'email' => $email] as $label => $identifier) {
        $digest = $factory->targetId(\KiwiCaptcha\Risk\TargetIdentifierNormalizer::normalize($identifier));
        $present = false;
        $cursor = '0';
        do {
            $reply = $client->executeCommand(new \Predis\Command\RawCommand('SCAN', [$cursor, 'MATCH', '*risk:tgt:*' . $digest . '*', 'COUNT', '1000']));
            $cursor = (string) $reply[0];
            if ((array) $reply[1] !== []) {
                $present = true;
                break;
            }
        } while ($cursor !== '0');
        $handles[$label] = ['digest_present' => $present];
    }
    $evidence['target_handles'] = $handles;
    $rawInKeys = 0;
    foreach ([$user, $email, $canonicalEmail] as $needle) {
        $cursor = '0';
        do {
            $reply = $client->executeCommand(new \Predis\Command\RawCommand('SCAN', [$cursor, 'MATCH', '*' . d314GlobEscape($needle) . '*', 'COUNT', '1000']));
            $cursor = (string) $reply[0];
            $rawInKeys += count((array) $reply[1]);
        } while ($cursor !== '0');
    }
    $evidence['raw_identifier_in_store_keys'] = $rawInKeys;
    $evidence['store_keys'] = (int) $client->executeCommand(new \Predis\Command\RawCommand('DBSIZE', []));

    return $evidence;
}

/** Escape one literal for a redis glob MATCH pattern. */
function d314GlobEscape(string $literal): string
{
    return str_replace(['\\', '*', '?', '[', ']'], ['\\\\', '\\*', '\\?', '\\[', '\\]'], $literal);
}

/** JSON for the dump lines: slashes readable, invalid UTF-8 substituted. */
function d314Json(mixed $value): string
{
    $json = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    if ($json === false) {
        throw new \RuntimeException('json_encode failed: ' . json_last_error_msg());
    }

    return $json;
}

/**
 * The complete keyspace sweep. Returns the summary document; writes one
 * line per covered key to $outFile. Every key the sweep cannot prove it
 * serialized in full lands in the uncovered list with its reason.
 */
function d314Dump(string $redisUrl, string $outFile): array
{
    $client = new \Predis\Client($redisUrl);
    $cmd = static fn (string $name, array $args = []) => $client->executeCommand(new \Predis\Command\RawCommand($name, $args));

    $keys = [];
    $cursor = '0';
    do {
        $reply = $cmd('SCAN', [$cursor, 'COUNT', '5000']);
        $cursor = (string) $reply[0];
        foreach ((array) $reply[1] as $key) {
            $keys[(string) $key] = true;
        }
    } while ($cursor !== '0');
    $keys = array_keys($keys);
    sort($keys, SORT_STRING);

    $handle = fopen($outFile, 'wb');
    if ($handle === false) {
        fwrite(STDERR, "FATAL: cannot write the dump at $outFile\n");
        exit(3);
    }

    $summary = [
        'keys' => 0,
        'covered' => 0,
        'uncovered' => [],
        'truncated' => [],
        'types' => [],
        'bytes' => 0,
    ];
    foreach ($keys as $key) {
        $summary['keys']++;
        $type = strtolower((string) $cmd('TYPE', [$key]));
        if ($type === 'none' || $type === '') {
            // The key vanished between SCAN and TYPE (TTL, eviction, a
            // concurrent write): the sweep cannot prove it captured the
            // key, so it is uncovered evidence, never a silent skip.
            $summary['uncovered'][] = ['key' => $key, 'type' => $type === '' ? 'none' : $type, 'reason' => 'vanished_between_scan_and_type'];
            continue;
        }
        $summary['types'][$type] = ($summary['types'][$type] ?? 0) + 1;
        $payload = null;
        $truncated = false;
        switch ($type) {
            case 'string':
                $value = $cmd('GET', [$key]);
                if ($value !== null) {
                    $payload = d314Json((string) $value);
                }
                break;
            case 'hash':
                $fields = [];
                if ((int) $cmd('HLEN', [$key]) <= 4096) {
                    $flat = (array) $cmd('HGETALL', [$key]);
                    for ($i = 0; $i + 1 < count($flat); $i += 2) {
                        $fields[(string) $flat[$i]] = (string) $flat[$i + 1];
                    }
                } else {
                    // A large hash is paged, never HGETALL'd whole: HSCAN
                    // walks every field in bounded batches.
                    $cursor = '0';
                    do {
                        $reply = $cmd('HSCAN', [$key, $cursor, 'COUNT', '1000']);
                        $cursor = (string) $reply[0];
                        $flat = (array) $reply[1];
                        for ($i = 0; $i + 1 < count($flat); $i += 2) {
                            $fields[(string) $flat[$i]] = (string) $flat[$i + 1];
                        }
                    } while ($cursor !== '0');
                }
                $payload = d314Json((object) $fields);
                break;
            case 'list':
                $payload = d314Json(array_map('strval', (array) $cmd('LRANGE', [$key, '0', '-1'])));
                break;
            case 'set':
                $members = [];
                if ((int) $cmd('SCARD', [$key]) <= 4096) {
                    $members = array_map('strval', (array) $cmd('SMEMBERS', [$key]));
                } else {
                    $cursor = '0';
                    do {
                        $reply = $cmd('SSCAN', [$key, $cursor, 'COUNT', '1000']);
                        $cursor = (string) $reply[0];
                        $members = array_merge($members, array_map('strval', (array) $reply[1]));
                    } while ($cursor !== '0');
                }
                sort($members, SORT_STRING);
                $payload = d314Json($members);
                break;
            case 'zset':
                $flat = (array) $cmd('ZRANGE', [$key, '0', '-1', 'WITHSCORES']);
                $scored = [];
                for ($i = 0; $i + 1 < count($flat); $i += 2) {
                    $scored[(string) $flat[$i]] = (string) $flat[$i + 1];
                }
                $payload = d314Json((object) $scored);
                break;
            case 'stream':
                // The bounded read: COUNT 1000 entries. A longer stream is
                // recorded as truncated and counted uncovered, so the
                // bound can never pass as a complete dump.
                $length = (int) $cmd('XLEN', [$key]);
                $entries = [];
                foreach ((array) $cmd('XRANGE', [$key, '-', '+', 'COUNT', '1000']) as $entry) {
                    $entry = (array) $entry;
                    $fields = [];
                    $flat = array_map('strval', (array) ($entry[1] ?? []));
                    for ($i = 0; $i + 1 < count($flat); $i += 2) {
                        $fields[$flat[$i]] = $flat[$i + 1];
                    }
                    $entries[(string) ($entry[0] ?? '')] = (object) $fields;
                }
                if ($length > count($entries)) {
                    $truncated = true;
                    $summary['truncated'][] = ['key' => $key, 'length' => $length, 'serialized' => count($entries)];
                }
                $payload = d314Json((object) $entries);
                break;
            default:
                // A module type or a type Redis grows beyond this list:
                // the sweep cannot serialize it, so it must not claim it
                // did.
                $summary['uncovered'][] = ['key' => $key, 'type' => $type, 'reason' => 'unserializable_type'];
                continue 2;
        }
        if ($payload === null) {
            // The value vanished between TYPE and the read.
            $summary['uncovered'][] = ['key' => $key, 'type' => $type, 'reason' => 'vanished_between_type_and_read'];
            continue;
        }
        $line = d314Json($key) . "\t" . $type . "\t" . $payload . "\n";
        fwrite($handle, $line);
        $summary['bytes'] += strlen($line);
        $summary['covered']++;
        if ($truncated) {
            $summary['uncovered'][] = ['key' => $key, 'type' => $type, 'reason' => 'stream_truncated_at_bound'];
        }
    }
    fclose($handle);

    return $summary;
}

$mode = $argv[1] ?? '';
if ($mode === 'identity') {
    $url = $argv[2] ?? '';
    if ($url === '') {
        fwrite(STDERR, "FATAL: usage: d314.privacy.php identity <redis-url>\n");
        exit(3);
    }
    try {
        $evidence = d314Identity($url);
    } catch (\Throwable $e) {
        fwrite(STDERR, 'FATAL: the identity flow failed: ' . get_class($e) . ': ' . $e->getMessage() . "\n");
        fwrite(STDERR, $e->getFile() . ':' . $e->getLine() . "\n" . $e->getTraceAsString() . "\n");
        exit(3);
    }
    fwrite(STDOUT, d314Json($evidence) . "\n");
    exit(0);
}
if ($mode === 'dump') {
    $url = $argv[2] ?? '';
    $out = $argv[3] ?? '';
    if ($url === '' || $out === '') {
        fwrite(STDERR, "FATAL: usage: d314.privacy.php dump <redis-url> <out-file>\n");
        exit(3);
    }
    try {
        $summary = d314Dump($url, $out);
    } catch (\Throwable $e) {
        fwrite(STDERR, 'FATAL: the dump failed: ' . get_class($e) . ': ' . $e->getMessage() . "\n");
        exit(3);
    }
    fwrite(STDOUT, d314Json($summary) . "\n");
    exit($summary['uncovered'] === [] ? 0 : 2);
}
fwrite(STDERR, "FATAL: usage: d314.privacy.php identity|dump ...\n");
exit(3);
