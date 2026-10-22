<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Symfony\Component\Serializer\SerializerInterface;

/**
 * The durable credential registry of the WebAuthn step-up handler: the
 * credential store the ceremonies resolve credentials through. One
 * record per enrolled credential, keyed by the credential id's hash and
 * tagged with the principal pseudonym, so the assertion ceremony can
 * list a principal's allowed credentials and the counter check can hold
 * the per-credential sign counter.
 *
 * The registry rides the risk Redis under the step-up namespace, the
 * same protection boundary as every other security-side state of this
 * plane. Records carry the credential's public material and counters,
 * never a raw identifier: the user handle of a record is the principal
 * pseudonym the contexts carry anyway.
 *
 * The class exists (and is only wired) when the web-auth/webauthn-lib
 * package is installed: the {@see CredentialRecord} shape and the
 * library serializer live there.
 */
final class WebAuthnCredentialRegistry
{
    private const KEY_PREFIX = 'credential:';

    /** The per-principal index key fragment (the pseudonym's hash). */
    private const INDEX_PREFIX = 'principal:';

    /**
     * The one-time-backfill marker (`<prefix>` + this suffix). Present
     * means: every credential on this server has been walked into its
     * principal's index at least once — so a missing index set is a
     * genuinely credential-less principal, never an un-indexed legacy
     * record. The marker carries a bounded TTL: a rolling-upgrade
     * window where an old node still writes un-indexed records heals
     * with one cursor walk after the marker lapses, never a permanent
     * blind spot. PUBLIC so the tests can pin the steady-state path.
     */
    public const BACKFILL_MARKER = 'credential:index-initialized';

    /** The marker's lifetime: the rolling-upgrade heal window. */
    private const BACKFILL_MARKER_TTL_SECS = 604_800;

    private readonly SerializerInterface $serializer;

    public function __construct(
        private readonly \Predis\ClientInterface $redis,
        private readonly string $prefix,
        private readonly int $ttlSecs = 31_536_000,
        ?SerializerInterface $serializer = null,
    ) {
        $this->serializer = $serializer ?? (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create();
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
    {
        $json = $this->redis->get($this->key($publicKeyCredentialId));
        if (!\is_string($json) || $json === '') {
            return null;
        }
        try {
            $record = $this->serializer->deserialize($json, CredentialRecord::class, 'json');
        } catch (\Throwable) {
            // An unreadable record is no credential: the ceremony answers
            // unknown-credential instead of trusting broken bytes.
            return null;
        }

        return $record instanceof CredentialRecord ? $record : null;
    }

    /**
     * The enrolled credentials of a principal (the handler's allow-list
     * source and its creation/assertion branch decision). The stored
     * user handle is the raw principal pseudonym, the same value the
     * assertion ceremony compares the authenticator's user handle
     * against.
     *
     * The discovery is the principal's own index set (SMEMBERS) — one
     * bounded read of THIS principal's members — never a keyspace-wide
     * `KEYS` walk: the pre-index lookup scanned every credential key on
     * the server and deserialized every record on each ceremony, an
     * O(keyspace) blocking round trip that grew with the deployment.
     * The members arrive in one pipelined batch, so the steady state is
     * two round trips (index + batch) whatever the DEPLOYMENT's total
     * credential count, and the batch holds only this principal's
     * records.
     *
     * On the first lookup after a fresh install (or once the backfill
     * marker lapses after a rolling upgrade), the index is built once
     * from a cursor walk (`SCAN`, never `KEYS`), so pre-index records
     * stay visible without a migration step.
     *
     * @return list<CredentialRecord>
     */
    public function registeredCredentialsOf(string $principalPseudonym): array
    {
        if ($this->redis->get($this->prefix.self::BACKFILL_MARKER) === null) {
            $this->backfillIndexes();
        }
        $members = $this->redis->smembers($this->indexKey($principalPseudonym));
        if (!\is_array($members) || $members === []) {
            return [];
        }
        $keys = [];
        foreach ($members as $member) {
            if (\is_string($member) && $member !== '') {
                $keys[] = $member;
            }
        }
        if ($keys === []) {
            return [];
        }
        $values = $this->readBatch($keys);
        $found = [];
        foreach ($values as $json) {
            if (!\is_string($json) || $json === '') {
                continue;
            }
            try {
                $record = $this->serializer->deserialize($json, CredentialRecord::class, 'json');
            } catch (\Throwable) {
                continue;
            }
            if (!$record instanceof CredentialRecord || $record->userHandle !== $principalPseudonym) {
                continue;
            }
            $found[] = $record;
        }

        return $found;
    }

    /**
     * The one-time cursor walk that builds every principal's index
     * from the records already on the server (pre-index installs and
     * the rolling-upgrade heal window). `SCAN` with a bounded COUNT
     * walks the credential namespace without blocking Redis the way
     * `KEYS` does; each record lands in its own principal's set
     * (SADD is idempotent, so a concurrent save that indexed the same
     * record changes nothing). The marker then pins the steady state:
     * a missing index means a credential-less principal.
     */
    private function backfillIndexes(): void
    {
        $pattern = $this->prefix.self::KEY_PREFIX.'*';
        $membersByIndex = [];
        $cursor = '0';
        $collect = [];
        $flush = function () use (&$membersByIndex, &$collect): void {
            if ($collect === []) {
                return;
            }
            $chunk = $collect;
            $collect = [];
            $values = $this->readBatch($chunk);
            foreach ($chunk as $i => $key) {
                $json = $values[$i] ?? null;
                if (!\is_string($json) || $json === '') {
                    continue;
                }
                try {
                    $record = $this->serializer->deserialize($json, CredentialRecord::class, 'json');
                } catch (\Throwable) {
                    continue;
                }
                if (!$record instanceof CredentialRecord || $record->userHandle === '') {
                    continue;
                }
                $membersByIndex[$this->indexKey((string) $record->userHandle)][] = $key;
            }
        };
        do {
            $reply = $this->redis->scan($cursor, ['MATCH' => $pattern, 'COUNT' => 200]);
            if (!\is_array($reply)) {
                break;
            }
            $cursor = isset($reply[0]) ? (string) $reply[0] : (string) ($reply['cursor'] ?? '0');
            $keys = $reply[1] ?? ($reply['keys'] ?? []);
            if (\is_array($keys)) {
                foreach ($keys as $key) {
                    if (\is_string($key) && $key !== '') {
                        $collect[] = $key;
                    }
                }
            }
            if (\count($collect) >= 500) {
                $flush();
            }
        } while ($cursor !== '0' && $cursor !== '');
        $flush();
        foreach ($membersByIndex as $indexKey => $members) {
            foreach ($members as $member) {
                $this->redis->sadd($indexKey, $member);
            }
            $this->redis->expire($indexKey, $this->ttlSecs);
        }
        $this->redis->setex($this->prefix.self::BACKFILL_MARKER, self::BACKFILL_MARKER_TTL_SECS, '1');
    }

    /** The index set of one principal: members are the record keys. */
    private function indexKey(string $principalPseudonym): string
    {
        return $this->prefix.self::INDEX_PREFIX.hash('sha256', $principalPseudonym);
    }

    public function saveCredentialSource(CredentialRecord $record): void
    {
        $key = $this->key($record->publicKeyCredentialId);
        // Counter rollback guard: a write that would lower the stored
        // sign count is refused (fail-closed). A cloned or raced
        // authenticator can then never rewind the counter and re-use an
        // old assertion slot.
        $existingJson = $this->redis->get($key);
        if (\is_string($existingJson) && $existingJson !== '') {
            try {
                $existing = $this->serializer->deserialize($existingJson, CredentialRecord::class, 'json');
                if ($existing instanceof CredentialRecord && $record->counter < $existing->counter) {
                    return;
                }
            } catch (\Throwable) {
                // Unreadable prior record: fall through and overwrite
                // with the validated record (fail-closed on the
                // counter is impossible without a readable prior).
            }
        }
        $this->redis->setex(
            $key,
            $this->ttlSecs,
            (string) $this->serializer->serialize($record, 'json'),
        );
        // Keep the principal's index in step with the record: the
        // allow-list lookup reads this set instead of scanning the
        // keyspace, so every write (not just the backfill) maintains
        // it. SADD is idempotent; the index TTL refreshes with the
        // record's own lifetime and can only outlive a member, never
        // precede it.
        if ($record->userHandle !== '') {
            $indexKey = $this->indexKey((string) $record->userHandle);
            $this->redis->sadd($indexKey, $key);
            $this->redis->expire($indexKey, $this->ttlSecs);
        }
    }

    private function key(string $credentialId): string
    {
        return $this->prefix.self::KEY_PREFIX.hash('sha256', $credentialId);
    }

    /**
     * The values of the given keys as one pipelined batch. The batch
     * queues one GET per key in the key order and answers one response
     * per queued command in that same order, so the caller filters the
     * values it already holds.
     *
     * A response list that is not an array is no record set: the lookup
     * answers with no credential rather than reading the keys one at a
     * time, which keeps the batched call shape the only read path.
     *
     * @param list<string> $keys
     *
     * @return list<mixed>
     */
    private function readBatch(array $keys): array
    {
        $responses = $this->redis->pipeline(static function ($pipe) use ($keys): void {
            foreach ($keys as $key) {
                $pipe->get($key);
            }
        });

        return \is_array($responses) ? array_values($responses) : [];
    }
}
