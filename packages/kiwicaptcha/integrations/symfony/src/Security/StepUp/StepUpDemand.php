<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The server-held record that proves the engine raised the step-up
 * demand the email factor answers. The challenge controller mints it
 * when it answers the typed step-up 403 for a carrier scope, and the
 * validator mints it when a post-solve assessment lands on StepUp for
 * one. The factor refuses to send any code without it, so a grant can
 * only ever exist for a demand the engine actually raised.
 *
 * The record carries the whole demand binding: the carrier scope, the
 * continuity session hash of the refused browser, the chain id of the
 * transaction that was refused and the risk decision id that demanded
 * the step-up. begin() and complete() take every binding from this
 * record, never from the request. The record is single-send bounded:
 * one initial code delivery plus one resend after the resend delay,
 * then the demand is spent and stays only as the completion's
 * consumption proof.
 *
 * Only pseudonyms and opaque ids ride the wire form, exactly like the
 * challenge records of the same store.
 */
final class StepUpDemand
{
    private const SCHEMA_VERSION = 1;

    /** The maximum deliveries one demand funds: the initial code plus one resend. */
    public const MAX_SENDS = 2;

    private function __construct(
        public readonly string $id,
        public readonly string $scope,
        public readonly ?string $sessionHash,
        public readonly ?string $chainId,
        public readonly ?string $decisionId,
        public readonly int $createdAt,
        public readonly int $expiresAt,
        /** Deliveries used so far: 0, then 1 after the initial code, then 2 (spent). */
        public readonly int $sends = 0,
        /** The unix second of the last delivery, null before the first one. */
        public readonly ?int $lastSentAt = null,
    ) {
    }

    /**
     * Mint a fresh demand record. The id is the caller's unguessable
     * mint (the same id alphabet the challenge records use); the TTL
     * bounds the whole demand lifetime. The session hash arrives
     * precomputed (the presented continuity session's SHA-256 hex, the
     * same derivation the factor stores), never a raw session value.
     */
    public static function mint(
        string $id,
        string $scope,
        ?string $sessionHash,
        ?string $chainId,
        ?string $decisionId,
        int $now,
        int $ttlSecs,
    ): self {
        if ($ttlSecs < 1) {
            throw new \InvalidArgumentException('A step-up demand TTL must be positive');
        }

        return new self(
            self::id($id),
            self::scope($scope),
            self::sessionHash($sessionHash),
            $chainId === null || $chainId === '' ? null : self::chainId($chainId),
            $decisionId === null || $decisionId === '' ? null : self::decisionId($decisionId),
            $now,
            $now + $ttlSecs,
            0,
            null,
        );
    }

    /** The demand after one delivery: the send counter advanced by one. */
    public function withSend(int $at): self
    {
        return new self(
            $this->id,
            $this->scope,
            $this->sessionHash,
            $this->chainId,
            $this->decisionId,
            $this->createdAt,
            $this->expiresAt,
            min(self::MAX_SENDS, $this->sends + 1),
            $at,
        );
    }

    /** The demand restored to its exact pre-claim send state (a delivery refund). */
    public function withSends(int $sends, ?int $lastSentAt): self
    {
        return new self(
            $this->id,
            $this->scope,
            $this->sessionHash,
            $this->chainId,
            $this->decisionId,
            $this->createdAt,
            $this->expiresAt,
            $sends,
            $lastSentAt,
        );
    }

    /** Whether the demand still funds a delivery. */
    public function canSend(): bool
    {
        return $this->sends < self::MAX_SENDS;
    }

    /** Whether the next delivery is the bounded resend (one initial send already used). */
    public function nextSendIsResend(): bool
    {
        return $this->sends === 1;
    }

    public function expired(int $now): bool
    {
        return $now >= $this->expiresAt;
    }

    /**
     * The canonical wire form: the exact JSON the stores persist. Only
     * pseudonyms, hashes and opaque ids, never a raw identifier.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'v' => self::SCHEMA_VERSION,
            'id' => $this->id,
            'scope' => $this->scope,
            'session_hash' => $this->sessionHash,
            'chain_id' => $this->chainId,
            'decision_id' => $this->decisionId,
            'created_at' => $this->createdAt,
            'expires_at' => $this->expiresAt,
            'sends' => $this->sends,
            'last_sent_at' => $this->lastSentAt,
        ];
    }

    /**
     * The strict decode, all-or-nothing: a missing field, a wrong type
     * or a shape violation answers null (the caller treats the demand
     * as absent), never a defaulted record.
     *
     * @param array<string, mixed> $record
     */
    public static function fromArray(array $record): ?self
    {
        if (($record['v'] ?? null) !== self::SCHEMA_VERSION) {
            return null;
        }
        foreach (['id', 'scope', 'created_at', 'expires_at', 'sends'] as $field) {
            if (!isset($record[$field]) || !\is_scalar($record[$field])) {
                return null;
            }
        }
        if (!\is_string($record['id']) || preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $record['id']) !== 1) {
            return null;
        }
        if (!\is_string($record['scope']) || preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $record['scope']) !== 1) {
            return null;
        }
        foreach (['created_at', 'expires_at', 'sends'] as $field) {
            if (!\is_int($record[$field])) {
                return null;
            }
        }
        if ($record['sends'] < 0 || $record['sends'] > self::MAX_SENDS) {
            return null;
        }
        if ($record['expires_at'] <= $record['created_at']) {
            return null;
        }
        $sessionHash = $record['session_hash'] ?? null;
        if ($sessionHash !== null && (!\is_string($sessionHash) || preg_match('/^[0-9a-f]{64}$/D', $sessionHash) !== 1)) {
            return null;
        }
        $chainId = $record['chain_id'] ?? null;
        if ($chainId !== null && (!\is_string($chainId) || !ChainId::isValid($chainId))) {
            return null;
        }
        $decisionId = $record['decision_id'] ?? null;
        if ($decisionId !== null && (!\is_string($decisionId) || preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $decisionId) !== 1)) {
            return null;
        }
        $lastSentAt = $record['last_sent_at'] ?? null;
        if ($lastSentAt !== null && !\is_int($lastSentAt)) {
            return null;
        }

        return new self(
            $record['id'],
            $record['scope'],
            $sessionHash,
            $chainId,
            $decisionId,
            $record['created_at'],
            $record['expires_at'],
            $record['sends'],
            $lastSentAt,
        );
    }

    /** @return ?self null when the JSON is not a decodable demand record */
    public static function fromJson(string $json): ?self
    {
        $decoded = json_decode($json, true, 16);
        if (!\is_array($decoded)) {
            return null;
        }

        return self::fromArray($decoded);
    }

    private static function id(string $value): string
    {
        if (preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $value) !== 1) {
            throw new \InvalidArgumentException('The step-up demand id must be the base64url id shape');
        }

        return $value;
    }

    private static function scope(string $value): string
    {
        if (preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $value) !== 1) {
            throw new \InvalidArgumentException('The scope of a step-up demand must be 1-128 chars of [A-Za-z0-9._:-]');
        }

        return $value;
    }

    private static function sessionHash(?string $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (preg_match('/^[0-9a-f]{64}$/D', $value) !== 1) {
            throw new \InvalidArgumentException('The session hash of a step-up demand must be a 64-char lowercase hex digest');
        }

        return $value;
    }

    private static function chainId(string $value): string
    {
        if (!ChainId::isValid($value)) {
            throw new \InvalidArgumentException('The chain id of a step-up demand must be the canonical chain id shape');
        }

        return $value;
    }

    private static function decisionId(string $value): string
    {
        if (preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $value) !== 1) {
            throw new \InvalidArgumentException('The decision id of a step-up demand must be 1-128 chars of [A-Za-z0-9._:-]');
        }

        return $value;
    }
}
