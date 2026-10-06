<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Predis\ClientInterface;

/**
 * The Redis step-up store: the production state backend of the
 * step-up plane, keyed under the deployment's risk namespace family
 * ({kiwi:<ns>}:stepup:*) like every other risk-side key family.
 *
 * The single-use boundary is Redis-native: consume is GETDEL, so one
 * record answers exactly one completion across every PHP-FPM worker.
 * The attempt accounting and the begin-window counter are small Lua
 * scripts, atomic over their key like the bundle's other state
 * transitions. Every record is written and read through the strict
 * wire schema of {@see StepUpChallenge}; a record the script cannot
 * decode is removed and answered corrupt, fail-closed.
 */
final class RedisStepUpChallengeStore implements StepUpChallengeStore
{
    /**
     * The attempt-accounting script: bump the attempts field, keep the
     * record within its remaining TTL, remove it at the cap. Answers
     * the attempts now used (>= 1), 0 at the cap (removed), -1 when
     * absent, -2 when the stored value violates the schema (removed).
     */
    private const ATTEMPT_SCRIPT = <<<'LUA'
        -- Step-up attempt accounting: bump attempts, delete on exhaustion.
        local raw = redis.call('GET', KEYS[1])
        if not raw then return -1 end
        local ok, rec = pcall(cjson.decode, raw)
        if not ok or type(rec) ~= 'table' or type(rec['attempts']) ~= 'number'
            or type(rec['max_attempts']) ~= 'number' then
          redis.call('DEL', KEYS[1])
          return -2
        end
        rec['attempts'] = rec['attempts'] + 1
        if rec['attempts'] >= tonumber(ARGV[1]) then
          redis.call('DEL', KEYS[1])
          return 0
        end
        local ttl = redis.call('TTL', KEYS[1])
        if ttl > 0 then
          redis.call('SET', KEYS[1], cjson.encode(rec), 'EX', ttl)
        else
          redis.call('DEL', KEYS[1])
          return -1
        end
        return rec['attempts']
        LUA;

    /**
     * The begin-window script: fixed-window admission counter for one
     * principal pseudonym, the expiry armed exactly once and atomically
     * with the first admission (a counter whose expiry was lost to a
     * process death can never strand a principal at the cap forever).
     * Answers the window's new admission count.
     */
    private const BEGIN_SCRIPT = <<<'LUA'
        -- Step-up begin window: fixed-window admission counter.
        local n = redis.call('INCR', KEYS[1])
        if n == 1 then
          redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
        end
        return n
        LUA;

    /**
     * The replay-guard script: the last-used time-step of a principal
     * compared and advanced atomically. A step strictly newer than the
     * stored one wins and is stored (TTL refreshed); anything at or
     * below the stored step is a replay and answers 0.
     */
    private const STEP_SCRIPT = <<<'LUA'
        -- Step-up totp step: compare-and-advance the replay guard.
        local current = redis.call('GET', KEYS[1])
        if current and tonumber(current) >= tonumber(ARGV[1]) then
          return 0
        end
        redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[2]))
        return 1
        LUA;

    public function __construct(
        private readonly ClientInterface $redis,
        private readonly string $prefix,
    ) {
        if (!str_starts_with($prefix, '{') || !str_contains($prefix, '}:')) {
            throw new \InvalidArgumentException('The step-up store prefix must be a hash-tagged key family like {kiwi:<ns>}:stepup:');
        }
    }

    public function create(StepUpChallenge $challenge, int $ttlSecs): string
    {
        $key = $this->prefix.'challenge:'.$challenge->id;
        $json = (string) json_encode($challenge->toArray(), JSON_UNESCAPED_SLASHES);
        // NX: a minted id colliding with a live record refuses rather
        // than overwriting it; the caller mints a fresh id and retries.
        $stored = $this->redis->set($key, $json, 'EX', max(1, $ttlSecs), 'NX');
        if (!$this->isAffirmativeSetReply($stored)) {
            throw new \RuntimeException('The step-up challenge record could not be persisted (id collision or backend refusal)');
        }

        return $challenge->id;
    }

    /**
     * Whether a SET reply affirms the write. The reply shape is
     * client-specific: a real Predis client answers a
     * {@see \Predis\Response\Status} object whose string form is 'OK'.
     * phpredis answers a boolean and some proxies the bare string.
     * The comparison normalizes all three shapes and fails closed on
     * everything else; a nil answer is a refused NX, never a success.
     */
    private function isAffirmativeSetReply(mixed $reply): bool
    {
        if ($reply instanceof \Stringable) {
            return (string) $reply === 'OK';
        }
        if (\is_bool($reply)) {
            return $reply;
        }

        return \is_string($reply) && ($reply === 'OK' || $reply === '1');
    }

    public function read(string $challengeId): ?StepUpChallenge
    {
        return $this->decode($this->redis->get($this->challengeKey($challengeId)));
    }

    public function consume(string $challengeId): ?StepUpChallenge
    {
        // GETDEL: the atomic single-use boundary. Exactly one caller of
        // a concurrent pair receives the record.
        return $this->decode($this->redis->getdel($this->challengeKey($challengeId)));
    }

    public function recordFailure(string $challengeId, int $maxAttempts): int
    {
        $answer = $this->redis->eval(
            self::ATTEMPT_SCRIPT,
            1,
            $this->challengeKey($challengeId),
            (string) max(1, $maxAttempts),
        );
        if (\is_array($answer)) {
            throw new \RuntimeException('The step-up attempt accounting answered an unexpected shape');
        }

        return (int) $answer;
    }

    public function countBegin(string $principalPseudonym, int $windowSecs): int
    {
        $answer = $this->redis->eval(self::BEGIN_SCRIPT, 1, $this->prefix.'begins:'.$principalPseudonym, (string) max(1, $windowSecs));

        return (int) $answer;
    }

    public function saveTotpSecret(string $principalPseudonym, string $secretRaw): void
    {
        // Durable enrollment: no TTL.
        $this->redis->set($this->prefix.'totp:secret:'.$principalPseudonym, $secretRaw);
    }

    public function findTotpSecret(string $principalPseudonym): ?string
    {
        $value = $this->redis->get($this->prefix.'totp:secret:'.$principalPseudonym);

        return \is_string($value) && $value !== '' ? $value : null;
    }

    public function markTotpStep(string $principalPseudonym, int $step, int $ttlSecs): bool
    {
        $answer = $this->redis->eval(
            self::STEP_SCRIPT,
            1,
            $this->prefix.'totp:step:'.$principalPseudonym,
            (string) $step,
            (string) max(1, $ttlSecs),
        );

        return (int) $answer === 1;
    }

    private function challengeKey(string $challengeId): string
    {
        if (preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $challengeId) !== 1) {
            throw new \InvalidArgumentException('The step-up challenge id must be the base64url id shape');
        }

        return $this->prefix.'challenge:'.$challengeId;
    }

    private function decode(mixed $raw): ?StepUpChallenge
    {
        if (!\is_string($raw) || $raw === '') {
            return null;
        }

        return StepUpChallenge::fromJson($raw);
    }
    public function markStepUpSuccess(string $principalPseudonym, int $ttlSecs, int $now): void
    {
        // The marker's own TTL is the window: a completed step-up
        // gates enrollment for exactly that long.
        $this->redis->set($this->prefix.'stepup-done:'.$principalPseudonym, (string) $now, 'EX', max(1, $ttlSecs));
    }

    public function recentStepUpSuccess(string $principalPseudonym, int $withinSecs, int $now): bool
    {
        $value = $this->redis->get($this->prefix.'stepup-done:'.$principalPseudonym);

        return \is_string($value) && $value !== '' && ($now - (int) $value) <= $withinSecs;
    }
}
