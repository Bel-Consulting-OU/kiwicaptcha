<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\FactorRequirement;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\MalformedStepUpChallengeException;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpEffectsJournal;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationDigest;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadataCorruptException;
use PHPUnit\Framework\TestCase;

/**
 * Mutation fuzzing of the strict step-up wire decoders, of the wire enums
 * and of the operation-digest canonicalization.
 *
 * The decoders under test are {@see StepUpDemand::fromArray()},
 * {@see StepUpChallenge::fromArray()},
 * {@see StepUpEffectsJournal::fromArray()} and
 * {@see SiteVerifyMetadata::fromArray()}; the enums are
 * {@see StepUpDemandState::of()} and
 * {@see StepUpOperationBindingKind::of()}.
 *
 * The surface is deliberately new; no existing suite is re-run.
 *
 * Three properties are under test.
 *
 * (A) Valid records round-trip byte-identically. (B) No mutation of a
 * valid record ever throws an uncaught error, and none is silently
 * accepted into an incoherent record. The opaque string fields of a
 * challenge (the target pseudonym, the return path and the code hash)
 * refuse every wrong raw value outright: a field dropped to null would
 * shed its binding. (C) The length-prefixed canonicalization is
 * injective, so no two distinct field maps can forge the same digest.
 */
final class StepUpWireFuzzTest extends TestCase
{
    private const ROUND_TRIP_N = 200;

    private const MUTATION_BASES = 40;

    // ------------------------------------------------------------------
    // A. Round-trip property
    // ------------------------------------------------------------------

    public function testDemandRoundTripIsByteIdentical(): void
    {
        for ($i = 0; $i < self::ROUND_TRIP_N; ++$i) {
            $demand = $this->randomDemand();
            $wire = $demand->toArray();
            $first = json_encode($wire, JSON_THROW_ON_ERROR);

            $decoded = StepUpDemand::fromArray($wire);
            self::assertNotNull($decoded, 'a valid demand failed to decode: '.$first);
            self::assertSame(
                $first,
                json_encode($decoded->toArray(), JSON_THROW_ON_ERROR),
                'demand re-encoding is not byte-identical to the first encoding',
            );
        }
    }

    public function testChallengeRoundTripIsByteIdentical(): void
    {
        for ($i = 0; $i < self::ROUND_TRIP_N; ++$i) {
            $challenge = $this->randomChallenge();
            $wire = $challenge->toArray();
            $first = json_encode($wire, JSON_THROW_ON_ERROR);

            try {
                $decoded = StepUpChallenge::fromArray($wire);
            } catch (MalformedStepUpChallengeException $e) {
                self::fail('a valid challenge failed to decode: '.$first.' :: '.$e->getMessage());
            }

            self::assertSame(
                $first,
                json_encode($decoded->toArray(), JSON_THROW_ON_ERROR),
                'challenge re-encoding is not byte-identical to the first encoding',
            );
        }
    }

    // ------------------------------------------------------------------
    // B. Mutations never crash and never silently widen
    // ------------------------------------------------------------------

    public function testDemandMutationsNeverCrashOrWiden(): void
    {
        for ($b = 0; $b < self::MUTATION_BASES; ++$b) {
            $base = $this->randomDemand()->toArray();
            foreach ($this->mutations($base) as $label => $mutated) {
                $result = null;
                try {
                    $result = StepUpDemand::fromArray($mutated);
                } catch (\Throwable $e) {
                    self::fail(sprintf(
                        'StepUpDemand::fromArray threw %s for mutation [%s]: %s :: input=%s',
                        $e::class,
                        $label,
                        $e->getMessage(),
                        var_export($mutated, true),
                    ));
                }
                if ($result !== null) {
                    $this->assertDemandSchemaStable($result, $label, $mutated);
                }
            }
        }
    }

    public function testChallengeMutationsNeverCrashOrWiden(): void
    {
        for ($b = 0; $b < self::MUTATION_BASES; ++$b) {
            $base = $this->randomChallenge()->toArray();
            foreach ($this->mutations($base) as $label => $mutated) {
                try {
                    $result = StepUpChallenge::fromArray($mutated);
                } catch (MalformedStepUpChallengeException) {
                    continue; // the typed, expected refusal
                } catch (\Throwable $e) {
                    self::fail(sprintf(
                        'StepUpChallenge::fromArray threw %s (not MalformedStepUpChallengeException) for mutation [%s]: %s :: input=%s',
                        $e::class,
                        $label,
                        $e->getMessage(),
                        var_export($mutated, true),
                    ));
                }
                $this->assertChallengeSchemaStable($result, $label, $mutated);
            }
        }
    }

    // ------------------------------------------------------------------
    // B2. Effects journal: rides inside the demand record, decoded on
    //     every read, so a corrupt `fx` must never crash and never
    //     impersonate completed effects.
    // ------------------------------------------------------------------

    public function testEffectsJournalMutationsNeverCrash(): void
    {
        $journal = StepUpEffectsJournal::none()
            ->withEffect(StepUpEffectsJournal::SETTLED, 100)
            ->withEffect(StepUpEffectsJournal::OUTCOME_CREDITED, 101)
            ->withEffect(StepUpEffectsJournal::SESSION_RESTORED, 102)
            ->withEffect(StepUpEffectsJournal::TRUST_WRITTEN, 103);
        $base = $journal->toArray();

        for ($b = 0; $b < self::MUTATION_BASES; ++$b) {
            foreach ($this->mutationsForValueMap($base) as $label => $mutated) {
                try {
                    $result = StepUpEffectsJournal::fromArray($mutated);
                } catch (\Throwable $e) {
                    self::fail(sprintf(
                        'StepUpEffectsJournal::fromArray threw %s for mutation [%s]: %s :: input=%s',
                        $e::class,
                        $label,
                        $e->getMessage(),
                        var_export($mutated, true),
                    ));
                }
                if ($result !== null) {
                    $this->assertJournalSchemaStable($result, $label, $mutated);
                }
            }
        }
    }

    public function testEffectsJournalNonArrayInputsDecodeToNull(): void
    {
        // fromArray(mixed): a non-array, non-null value is never a journal.
        $scalars = [
            'string' => 'authorization_settled',
            'int' => 7,
            'bool' => true,
            'float' => 1.5,
            'object' => new \stdClass(),
        ];
        foreach ($scalars as $label => $value) {
            self::assertNull(
                StepUpEffectsJournal::fromArray($value),
                sprintf('a %s fx value must decode to null, not a journal', $label),
            );
        }
        self::assertNull(StepUpEffectsJournal::fromArray(null), 'an absent fx must decode to null');
        $empty = StepUpEffectsJournal::fromArray([]);
        self::assertNotNull($empty, 'an empty fx array decodes to the empty journal, never null');
        self::assertFalse($empty->complete(), 'an empty journal must not report every effect as landed');
    }

    private function assertJournalSchemaStable(StepUpEffectsJournal $journal, string $label, array $mutated): void
    {
        $wire = $journal->toArray();
        try {
            $again = StepUpEffectsJournal::fromArray($wire);
        } catch (\Throwable $e) {
            self::fail(sprintf(
                'an accepted journal is not schema-coherent: re-decode threw %s for mutation [%s] :: input=%s',
                $e::class,
                $label,
                var_export($mutated, true),
            ));
        }
        self::assertNotNull(
            $again,
            sprintf('an accepted journal re-decoded to null for mutation [%s] :: input=%s', $label, var_export($mutated, true)),
        );
        self::assertSame(
            json_encode($wire, JSON_THROW_ON_ERROR),
            json_encode($again->toArray(), JSON_THROW_ON_ERROR),
            sprintf('an accepted journal is not stable under re-encoding for mutation [%s]', $label),
        );
    }

    // ------------------------------------------------------------------
    // B3. SiteVerifyMetadata: a typed refusal (corrupt) or null, never
    //     an uncaught error and never a silently widened record.
    // ------------------------------------------------------------------

    public function testSiteVerifyMetadataMutationsNeverCrashOrWiden(): void
    {
        $bases = [
            'populated' => (new SiteVerifyMetadata('act', 'cd', 'site.key', null, 0, 'scope1'))->toArray(),
            'chained' => (new SiteVerifyMetadata(null, null, null, 'chain-abc', 2, null))->toArray(),
            'empty' => (new SiteVerifyMetadata(null, null, null, null, 0, null))->toArray(),
        ];

        for ($b = 0; $b < self::MUTATION_BASES; ++$b) {
            foreach ($bases as $baseLabel => $base) {
                foreach ($this->mutationsForValueMap($base) as $label => $mutated) {
                    try {
                        $result = SiteVerifyMetadata::fromArray($mutated);
                    } catch (SiteVerifyMetadataCorruptException) {
                        continue; // the typed, expected refusal
                    } catch (\Throwable $e) {
                        self::fail(sprintf(
                            'SiteVerifyMetadata::fromArray threw %s (not SiteVerifyMetadataCorruptException) for mutation [%s/%s]: %s :: input=%s',
                            $e::class,
                            $baseLabel,
                            $label,
                            $e->getMessage(),
                            var_export($mutated, true),
                        ));
                    }
                    if ($result !== null) {
                        $this->assertSiteVerifyMetadataSchemaStable($result, $baseLabel, $label, $mutated);
                    }
                }
            }
        }
    }

    private function assertSiteVerifyMetadataSchemaStable(SiteVerifyMetadata $meta, string $baseLabel, string $label, array $mutated): void
    {
        $wire = $meta->toArray();
        try {
            $again = SiteVerifyMetadata::fromArray($wire);
        } catch (\Throwable $e) {
            self::fail(sprintf(
                'an accepted metadata record is not schema-coherent: re-decode threw %s for mutation [%s/%s] :: input=%s',
                $e::class,
                $baseLabel,
                $label,
                var_export($mutated, true),
            ));
        }
        self::assertNotNull(
            $again,
            sprintf('an accepted metadata record re-decoded to null for mutation [%s/%s] :: input=%s', $baseLabel, $label, var_export($mutated, true)),
        );
        self::assertSame(
            json_encode($wire, JSON_THROW_ON_ERROR),
            json_encode($again->toArray(), JSON_THROW_ON_ERROR),
            sprintf('an accepted metadata record is not stable under re-encoding for mutation [%s/%s]', $baseLabel, $label),
        );
    }

    // ------------------------------------------------------------------
    // B4. The wire enums: every string that names no case answers null.
    // ------------------------------------------------------------------

    public function testDemandStateAndBindingKindRejectEveryUnknownString(): void
    {
        $unknown = [
            'empty' => '',
            'uppercase' => 'OPEN',
            'trailing space' => 'open ',
            'leading space' => ' open',
            'mixed case' => 'Open',
            '10k chars' => str_repeat('o', 10_000),
            'nul byte' => "open\0",
            'nul only' => "\0",
            'nul-prefixed' => "\0open",
            'int-ish' => '0',
            'json null' => 'null',
            'non-ascii' => 'opén',
        ];
        foreach ($unknown as $label => $value) {
            self::assertNull(
                StepUpDemandState::of($value),
                sprintf('StepUpDemandState::of() accepted the unknown string [%s]', $label),
            );
            self::assertNull(
                StepUpOperationBindingKind::of($value),
                sprintf('StepUpOperationBindingKind::of() accepted the unknown string [%s]', $label),
            );
        }

        foreach (StepUpDemandState::cases() as $case) {
            self::assertSame($case, StepUpDemandState::of($case->value), 'a valid demand state must decode to itself');
        }
        foreach (StepUpOperationBindingKind::cases() as $case) {
            self::assertSame($case, StepUpOperationBindingKind::of($case->value), 'a valid binding kind must decode to itself');
        }
    }

    /**
     * A generic mutation battery over any flat value map: deletes, wrong
     * types, truncations, NUL appends and integer probes (negative, zero,
     * PHP_INT_MAX, PHP_INT_MIN, float) for every integer-valued entry.
     *
     * @param array<string, mixed> $base
     *
     * @return array<string, array<string, mixed>>
     */
    private function mutationsForValueMap(array $base): array
    {
        $out = [];

        foreach (array_keys($base) as $key) {
            $m = $base;
            unset($m[$key]);
            $out['delete:'.$key] = $m;
        }

        $wrongTypes = ['str' => '0', 'int' => 0, 'null' => null, 'array' => [], 'bool' => true, 'float' => 1.5];
        foreach (array_keys($base) as $key) {
            foreach ($wrongTypes as $name => $value) {
                $m = $base;
                $m[$key] = $value;
                $out['type:'.$key.'='.$name] = $m;
            }
        }

        foreach ($base as $key => $value) {
            if (\is_string($value) && $value !== '') {
                $m = $base;
                $m[$key] = substr($value, 0, intdiv(\strlen($value), 2));
                $out['trunc:'.$key] = $m;
            }
        }

        foreach ($base as $key => $value) {
            if (\is_string($value)) {
                $m = $base;
                $m[$key] = $value."\0";
                $out['nul:'.$key] = $m;
            }
        }

        foreach ($base as $key => $value) {
            if (\is_int($value)) {
                foreach (['neg' => -1, 'zero' => 0, 'max' => PHP_INT_MAX, 'min' => PHP_INT_MIN, 'float' => 1.5] as $name => $probe) {
                    $m = $base;
                    $m[$key] = $probe;
                    $out['num:'.$key.'='.$name] = $m;
                }
            }
        }

        return $out;
    }

    /**
     * The raw values that are never a field's own type: an object, an
     * array, a boolean, a float, an integer, the empty string, a
     * stringly-typed number and explicit null. The generic mutation
     * battery replaces each field with each of these in turn, and the
     * strict-field battery reuses the same table so the two can never
     * drift apart.
     *
     * @return array<string, mixed>
     */
    private function wrongTypedValues(): array
    {
        return [
            'str' => '0',
            'empty' => '',
            'int' => 0,
            'null' => null,
            'array' => [],
            'bool' => true,
            'float' => 1.5,
            'object' => new \stdClass(),
        ];
    }

    // ------------------------------------------------------------------
    // B5. The opaque challenge fields: every wrong raw type answers the
    //     typed refusal, never a silently dropped binding.
    // ------------------------------------------------------------------

    /**
     * The three fields the record carries as opaque strings are the
     * target pseudonym, the return path and the stored code hash. They
     * decode strictly: absent and explicit null are one state, the
     * field rides absent. Every other raw value refuses the whole
     * record. A value dropped to null would shed the proof requirement
     * (code hash), the binding to the target its completion clears
     * (target pseudonym) or the completion redirect (return path).
     *
     * The wrong-typed probes are the mutation battery's own table, and
     * each field also gets strings that carry the right type but the
     * wrong shape, so a shape regression is caught alongside a type
     * regression.
     */
    public function testTheOpaqueChallengeFieldsRefuseEveryWrongRawValue(): void
    {
        $base = $this->challengeWireCarryingTheOpaqueFields();
        $shapeProbes = [
            'target' => [
                'short-hex' => str_repeat('a', 63),
                'long-hex' => str_repeat('a', 65),
                'principal-shape' => str_repeat('b', 32),
                'uppercase-hex' => str_repeat('A', 64),
                'raw-identifier' => 'user@example.com',
            ],
            'return_path' => [
                'foreign-origin' => 'https://evil.example/steal',
                'protocol-relative' => '//evil.example/steal',
                'dot-segment' => '/a/../b',
                'query' => '/a?x=1',
                'too-long' => '/'.str_repeat('a', 512),
            ],
            'code_hash' => [
                'short-hex' => str_repeat('a', 63),
                'long-hex' => str_repeat('a', 65),
                'uppercase-hex' => str_repeat('A', 64),
                'short-digits' => str_repeat('1', 16),
            ],
        ];

        foreach (['target', 'return_path', 'code_hash'] as $field) {
            foreach ($this->wrongTypedValues() as $name => $value) {
                if ($name === 'null') {
                    continue; // the legitimate absent state, asserted on its own below
                }
                $mutated = $base;
                $mutated[$field] = $value;
                $this->assertChallengeFieldRefused($mutated, $field, 'type:'.$field.'='.$name, $value);
            }
            foreach ($shapeProbes[$field] as $name => $value) {
                $mutated = $base;
                $mutated[$field] = $value;
                $this->assertChallengeFieldRefused($mutated, $field, 'shape:'.$field.'='.$name, $value);
            }
        }
    }

    /**
     * The two legitimate states of an opaque field are one. A key that
     * rides absent and a key that rides as explicit null both decode,
     * with the field absent from the decoded record. That is the
     * pre-field wire shape of the drain period. The canonical
     * re-encoding then carries the key with an explicit null, which
     * decodes again.
     */
    public function testTheOpaqueChallengeFieldsRideAbsentWhenUnsetOrNull(): void
    {
        $base = $this->totpChallengeWire();
        $accessors = [
            'target' => static fn (StepUpChallenge $challenge): ?string => $challenge->targetPseudonym,
            'return_path' => static fn (StepUpChallenge $challenge): ?string => $challenge->returnPath,
            'code_hash' => static fn (StepUpChallenge $challenge): ?string => $challenge->codeHash,
        ];

        foreach ($accessors as $field => $read) {
            $absent = $base;
            unset($absent[$field]);
            $explicitNull = $base;
            $explicitNull[$field] = null;

            foreach (['absent' => $absent, 'null' => $explicitNull] as $state => $wire) {
                try {
                    $decoded = StepUpChallenge::fromArray($wire);
                } catch (\Throwable $e) {
                    self::fail(sprintf(
                        'a %s `%s` must decode (the legitimate pre-field wire shape), got %s: %s',
                        $state,
                        $field,
                        $e::class,
                        $e->getMessage(),
                    ));
                }
                self::assertNull(
                    $read($decoded),
                    sprintf('a %s `%s` must decode as the field riding absent', $state, $field),
                );
                $reencoded = $decoded->toArray();
                self::assertArrayHasKey($field, $reencoded, sprintf('the canonical wire form must carry a %s key', $field));
                self::assertNull($reencoded[$field], sprintf('the canonical wire form must spell the absent %s as null', $field));
                self::assertNull(
                    $read(StepUpChallenge::fromArray($reencoded)),
                    sprintf('the canonical re-encoding of an absent %s must decode again', $field),
                );
            }
        }
    }

    /**
     * One mutation of the challenge wire that must answer the typed
     * refusal. A silently accepted value would drop the field's
     * binding, so the failure names the field and the offending value.
     *
     * @param array<string, mixed> $mutated
     */
    private function assertChallengeFieldRefused(array $mutated, string $field, string $label, mixed $value): void
    {
        $decoded = null;
        try {
            $decoded = StepUpChallenge::fromArray($mutated);
        } catch (MalformedStepUpChallengeException $e) {
            self::assertStringContainsString(
                $field,
                $e->getMessage(),
                sprintf('the refusal of mutation [%s] must name the field %s', $label, $field),
            );

            return;
        } catch (\Throwable $e) {
            self::fail(sprintf(
                'the mutation [%s] must answer MalformedStepUpChallengeException, got %s: %s :: input=%s',
                $label,
                $e::class,
                $e->getMessage(),
                var_export($mutated, true),
            ));
        }
        self::fail(sprintf(
            'the challenge field `%s` silently accepted the raw value %s (%s) for mutation [%s]: the decoded field reads %s :: input=%s',
            $field,
            var_export($value, true),
            get_debug_type($value),
            $label,
            var_export($decoded === null ? null : ($decoded->toArray()[$field] ?? null), true),
            var_export($mutated, true),
        ));
    }

    /**
     * A deterministic EmailOtp wire record that carries all three
     * opaque fields: a target pseudonym, an absolute same-site return
     * path and a code hash.
     *
     * @return array<string, mixed>
     */
    private function challengeWireCarryingTheOpaqueFields(): array
    {
        return StepUpChallenge::begin(
            'AABBCCDDEEFFGGHH0011',
            StepUpChallengeKind::EmailOtp,
            str_repeat('a', 32),
            str_repeat('b', 64),
            'login',
            '/dashboard',
            'post_solve_step_up_required',
            1700000000,
            300,
            5,
            str_repeat('c', 64),
            null,
            'session-opaque-0000000000000000001',
        )->toArray();
    }

    /**
     * A deterministic totp wire record: the kind that carries no code
     * hash at all, so all three opaque fields ride absent.
     *
     * @return array<string, mixed>
     */
    private function totpChallengeWire(): array
    {
        return StepUpChallenge::begin(
            'AABBCCDDEEFFGGHH0022',
            StepUpChallengeKind::Totp,
            str_repeat('a', 32),
            null,
            'login',
            null,
            'post_solve_step_up_required',
            1700000000,
            300,
            5,
            null,
            null,
            'session-opaque-0000000000000000002',
        )->toArray();
    }

    private function assertDemandSchemaStable(StepUpDemand $record, string $label, array $mutated): void
    {
        $wire = $record->toArray();
        try {
            $again = StepUpDemand::fromArray($wire);
        } catch (\Throwable $e) {
            self::fail(sprintf(
                'an accepted demand is not schema-coherent: re-decode threw %s for mutation [%s] :: input=%s',
                $e::class,
                $label,
                var_export($mutated, true),
            ));
        }
        self::assertNotNull(
            $again,
            sprintf('an accepted demand re-decoded to null for mutation [%s] :: input=%s', $label, var_export($mutated, true)),
        );
        self::assertSame(
            json_encode($wire, JSON_THROW_ON_ERROR),
            json_encode($again->toArray(), JSON_THROW_ON_ERROR),
            sprintf('an accepted demand is not stable under re-encoding for mutation [%s]', $label),
        );
    }

    private function assertChallengeSchemaStable(StepUpChallenge $record, string $label, array $mutated): void
    {
        $wire = $record->toArray();
        try {
            $again = StepUpChallenge::fromArray($wire);
        } catch (\Throwable $e) {
            self::fail(sprintf(
                'an accepted challenge is not schema-coherent: re-decode threw %s for mutation [%s] :: input=%s',
                $e::class,
                $label,
                var_export($mutated, true),
            ));
        }
        self::assertSame(
            json_encode($wire, JSON_THROW_ON_ERROR),
            json_encode($again->toArray(), JSON_THROW_ON_ERROR),
            sprintf('an accepted challenge is not stable under re-encoding for mutation [%s]', $label),
        );
    }

    /**
     * The full mutation battery over one valid record.
     *
     * @param array<string, mixed> $base
     *
     * @return array<string, array<string, mixed>>
     */
    private function mutations(array $base): array
    {
        $out = [];

        // Delete each key in turn.
        foreach (array_keys($base) as $key) {
            $m = $base;
            unset($m[$key]);
            $out['delete:'.$key] = $m;
        }

        // Replace each value with a wrong type.
        foreach (array_keys($base) as $key) {
            foreach ($this->wrongTypedValues() as $name => $value) {
                $m = $base;
                $m[$key] = $value;
                $out['type:'.$key.'='.$name] = $m;
            }
        }

        // Truncate each string value to half its length.
        foreach ($base as $key => $value) {
            if (\is_string($value) && $value !== '') {
                $m = $base;
                $m[$key] = substr($value, 0, intdiv(\strlen($value), 2));
                $out['trunc:'.$key] = $m;
            }
        }

        // Append a NUL byte to each string value.
        foreach ($base as $key => $value) {
            if (\is_string($value)) {
                $m = $base;
                $m[$key] = $value."\0";
                $out['nul:'.$key] = $m;
            }
        }

        // Numeric fields: negative, zero, PHP_INT_MAX, float.
        $numericFields = [
            'created_at', 'expires_at', 'sends', 'last_sent_at', 'state_at',
            'authorized_at', 'lease_until', 'active_challenge_expires_at',
            'generation', 'attempts', 'max_attempts', 'factor_rank', 'v',
        ];
        foreach ($numericFields as $field) {
            if (!array_key_exists($field, $base)) {
                continue;
            }
            foreach (['neg' => -1, 'zero' => 0, 'max' => PHP_INT_MAX, 'float' => 1.5] as $name => $value) {
                $m = $base;
                $m[$field] = $value;
                $out['num:'.$field.'='.$name] = $m;
            }
        }

        // Schema-version probes.
        foreach ([1, 2, 3, 4, 5, '4'] as $value) {
            $m = $base;
            $m['v'] = $value;
            $out['v:'.(\is_string($value) ? 'str-'.$value : (string) $value)] = $m;
        }

        // Class-specific shape probes.
        if (array_key_exists('family_digest', $base)) {
            $m = $base;
            $m['family_digest'] = '';
            $out['family_digest:empty'] = $m;
            $m = $base;
            $m['family_digest'] = 'zz'.str_repeat('0', 62);
            $out['family_digest:nonhex'] = $m;
        }
        if (array_key_exists('subject', $base)) {
            $m = $base;
            $m['subject'] = str_repeat('z', 32);
            $out['subject:nonhex'] = $m;
        }

        return $out;
    }

    // ------------------------------------------------------------------
    // C. Canonicalization injectivity by exhaustive small-domain search
    // ------------------------------------------------------------------

    public function testCanonicalOperationContentIsInjective(): void
    {
        $maps = $this->smallDomainMaps();
        self::assertGreaterThan(100, \count($maps), 'the small domain must be non-trivial');

        $seen = [];
        foreach ($maps as $map) {
            $bytes = StepUpOperationDigest::canonicalOperationContent($map);
            $signature = $this->mapSignature($map);
            $slot = 'k'.$bytes;
            if (isset($seen[$slot])) {
                self::assertSame(
                    $seen[$slot],
                    $signature,
                    sprintf(
                        'canonicalOperationContent collision: two distinct maps both encode to %s (0x%s)',
                        var_export($seen[$slot], true).' and '.var_export($signature, true),
                        bin2hex($bytes),
                    ),
                );
            } else {
                $seen[$slot] = $signature;
            }
        }
    }

    public function testFormFieldsIsInjective(): void
    {
        $maps = $this->smallDomainMaps();
        $scope = 'transfer:submit';

        $seen = [];
        foreach ($maps as $map) {
            $bytes = StepUpOperationDigest::formFields($scope, $map);
            $signature = $this->mapSignature($map);
            $slot = 'k'.$bytes;
            if (isset($seen[$slot])) {
                self::assertSame(
                    $seen[$slot],
                    $signature,
                    sprintf(
                        'formFields collision: two distinct maps both digest to %s (0x%s)',
                        var_export($seen[$slot], true).' and '.var_export($signature, true),
                        $bytes,
                    ),
                );
            } else {
                $seen[$slot] = $signature;
            }
        }
    }

    /**
     * Every field map of 1 and 2 fields over the fixed key/value alphabet.
     *
     * @return list<array<string, string>>
     */
    private function smallDomainMaps(): array
    {
        $keys = ['a', 'b', 'ab'];
        $values = ['', 'x', 'x0', '0x', 'a=b', "x\0y", "x\0b=2"];

        $maps = [];
        foreach ($keys as $k1) {
            foreach ($values as $v1) {
                $maps[] = [$k1 => $v1];
            }
        }
        foreach ($keys as $k1) {
            foreach ($keys as $k2) {
                if ($k1 === $k2) {
                    continue;
                }
                foreach ($values as $v1) {
                    foreach ($values as $v2) {
                        $maps[] = [$k1 => $v1, $k2 => $v2];
                    }
                }
            }
        }

        return $maps;
    }

    /** A canonical identity for a field map, order-insensitive. */
    private function mapSignature(array $map): string
    {
        ksort($map);

        return serialize($map);
    }

    // ------------------------------------------------------------------
    // D. Digest shape gate
    // ------------------------------------------------------------------

    public function testDigestShapeGate(): void
    {
        self::assertTrue(StepUpOperationDigest::isDigestShape(str_repeat('a', 64)), 'valid 64-lowercase-hex must be accepted');
        self::assertFalse(StepUpOperationDigest::isDigestShape(str_repeat('A', 64)), 'uppercase hex must be rejected');
        self::assertFalse(StepUpOperationDigest::isDigestShape(str_repeat('a', 63)), '63 chars must be rejected');
        self::assertFalse(StepUpOperationDigest::isDigestShape(str_repeat('a', 65)), '65 chars must be rejected');
        self::assertFalse(StepUpOperationDigest::isDigestShape(str_repeat('z', 64)), 'a non-hex 64-char string must be rejected');
    }

    // ------------------------------------------------------------------
    // Generators of valid records
    // ------------------------------------------------------------------

    private function randomDemand(): StepUpDemand
    {
        $kind = [
            StepUpOperationBindingKind::None,
            StepUpOperationBindingKind::FormFields,
            StepUpOperationBindingKind::RequestBinding,
            StepUpOperationBindingKind::Login,
        ][random_int(0, 3)];

        $now = random_int(1, 2_000_000_000);

        return StepUpDemand::mint(
            $this->randomId(),
            $this->randomScope(),
            random_int(0, 1) === 1 ? bin2hex(random_bytes(32)) : null,
            null,
            null,
            $now,
            random_int(1, 1_000_000),
            $kind,
            $kind === StepUpOperationBindingKind::None ? '' : bin2hex(random_bytes(32)),
            null,
            null,
            random_int(0, 1) === 1,
            null,
            null,
            $kind === StepUpOperationBindingKind::Login
                ? 'user-42'
                : (random_int(0, 1) === 1 ? $this->randomPseudonym() : null),
        );
    }

    private function randomChallenge(): StepUpChallenge
    {
        $kind = [
            StepUpChallengeKind::EmailOtp,
            StepUpChallengeKind::Totp,
            StepUpChallengeKind::WebAuthn,
            StepUpChallengeKind::EmailOwnership,
        ][random_int(0, 3)];

        $codeHash = null;
        $ceremony = null;
        switch ($kind) {
            case StepUpChallengeKind::EmailOtp:
                $codeHash = bin2hex(random_bytes(32));
                break;
            case StepUpChallengeKind::Totp:
                $codeHash = null;
                break;
            case StepUpChallengeKind::WebAuthn:
                $codeHash = bin2hex(random_bytes(32));
                $ceremony = random_int(0, 1) === 1 ? 'creation' : 'assertion';
                break;
            case StepUpChallengeKind::EmailOwnership:
                $codeHash = bin2hex(random_bytes(32));
                break;
        }

        $now = random_int(1, 2_000_000_000);
        $target = random_int(0, 1) === 1 ? bin2hex(random_bytes(32)) : null;
        $sessionId = random_int(0, 1) === 1 ? $this->randomId().$this->randomId() : null;

        return StepUpChallenge::begin(
            $this->randomId(),
            $kind,
            bin2hex(random_bytes(16)),
            $target,
            $this->randomScope(),
            random_int(0, 1) === 1 ? '/dashboard' : null,
            'post_solve_step_up_required',
            $now,
            random_int(1, 1_000_000),
            random_int(1, 10),
            $codeHash,
            $ceremony,
            $sessionId,
            random_int(0, 1) === 1,
            random_int(0, 1) === 1,
        );
    }

    private function randomFactor(): FactorRequirement
    {
        $family = [
            FactorRequirement::EMAIL_OTP,
            FactorRequirement::TOTP,
            FactorRequirement::WEBAUTHN,
        ][random_int(0, 2)];

        return new FactorRequirement($family, $family, FactorRequirement::LADDER[$family]);
    }

    private function randomId(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
    }

    private function randomScope(): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-';
        $length = random_int(1, 48);
        $out = '';
        for ($i = 0; $i < $length; ++$i) {
            $out .= $alphabet[random_int(0, \strlen($alphabet) - 1)];
        }

        return $out;
    }

    private function randomPseudonym(): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
        $length = random_int(1, 64);
        $out = '';
        for ($i = 0; $i < $length; ++$i) {
            $out .= $alphabet[random_int(0, \strlen($alphabet) - 1)];
        }

        return $out;
    }
}
