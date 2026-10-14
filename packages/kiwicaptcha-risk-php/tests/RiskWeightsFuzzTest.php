<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use PHPUnit\Framework\TestCase;

/**
 * Mutation fuzzing of the two risk wire decoders:
 * {@see RiskWeights::fromArray()}, {@see SignalVector::fromArray()} and
 * {@see SignalVector::fromJson()}.
 *
 * Same methodology as the step-up wire fuzz battery: every mutation of a
 * valid record must either be refused with the decoder's typed exception
 * ({@see \InvalidArgumentException}) or decode to a coherent, re-encode
 * stable record. An uncaught throwable is a crash; a wrong-typed field
 * that decodes to a coerced value instead of being refused is a silent
 * acceptance.
 */
final class RiskWeightsFuzzTest extends TestCase
{
    private const MUTATION_BASES = 40;

    // ------------------------------------------------------------------
    // A. Round-trip property
    // ------------------------------------------------------------------

    public function testRiskWeightsRoundTripIsStable(): void
    {
        for ($i = 0; $i < self::MUTATION_BASES; ++$i) {
            $wire = $this->randomWeights();
            $first = RiskWeights::fromArray($wire);
            self::assertSame(
                json_encode($first->toArray(), JSON_THROW_ON_ERROR),
                json_encode(RiskWeights::fromArray($first->toArray())->toArray(), JSON_THROW_ON_ERROR),
                'RiskWeights re-encoding is not stable',
            );
        }
    }

    // ------------------------------------------------------------------
    // B. Mutations never crash and never silently widen
    // ------------------------------------------------------------------

    public function testRiskWeightsMutationsNeverCrashOrWiden(): void
    {
        $base = RiskWeights::fromArray([])->toArray();

        for ($b = 0; $b < self::MUTATION_BASES; ++$b) {
            foreach ($this->mutations($base) as $label => $mutated) {
                try {
                    $result = RiskWeights::fromArray($mutated);
                } catch (\InvalidArgumentException) {
                    continue; // the typed, expected refusal
                } catch (\Throwable $e) {
                    self::fail(sprintf(
                        'RiskWeights::fromArray threw %s (not InvalidArgumentException) for mutation [%s]: %s :: input=%s',
                        $e::class,
                        $label,
                        $e->getMessage(),
                        var_export($mutated, true),
                    ));
                }
                $this->assertWeightsSchemaStable($result, $label, $mutated);
            }
        }
    }

    public function testSignalVectorMutationsNeverCrash(): void
    {
        $base = SignalVector::zero()->toArray();

        for ($b = 0; $b < self::MUTATION_BASES; ++$b) {
            foreach ($this->mutations($base) as $label => $mutated) {
                try {
                    $result = SignalVector::fromArray($mutated);
                } catch (\InvalidArgumentException) {
                    continue; // the typed, expected refusal
                } catch (\Throwable $e) {
                    self::fail(sprintf(
                        'SignalVector::fromArray threw %s (not InvalidArgumentException) for mutation [%s]: %s :: input=%s',
                        $e::class,
                        $label,
                        $e->getMessage(),
                        var_export($mutated, true),
                    ));
                }
                $this->assertSignalVectorSchemaStable($result, $label, $mutated);
            }
        }
    }

    // ------------------------------------------------------------------
    // C. Strictness: a present non-integer field must be refused, never
    //    coerced. RiskWeights already enforces this (the canonical policy
    //    hash must be identical in PHP and Rust, so floats and numeric
    //    strings are inadmissible); SignalVector must enforce it too.
    // ------------------------------------------------------------------

    public function testSignalVectorRejectsNonIntegerFieldValues(): void
    {
        $wrongValues = [
            'a numeric string "1"' => '1',
            'a non-numeric string "abc"' => 'abc',
            'an array [9]' => [9],
            'an empty array []' => [],
            'a bool true' => true,
            'a float 1.9' => 1.9,
        ];

        $violations = [];
        foreach (array_keys(SignalVector::zero()->toArray()) as $field) {
            foreach ($wrongValues as $valueLabel => $value) {
                $input = [$field => $value];
                try {
                    $decoded = SignalVector::fromArray($input);
                } catch (\InvalidArgumentException) {
                    continue; // strict refusal: the required behaviour
                }
                $violations[] = sprintf(
                    'SignalVector::fromArray(%s) silently accepted %s as %d (expected InvalidArgumentException)',
                    var_export($input, true),
                    $valueLabel,
                    $decoded->toArray()[$field],
                );
            }
        }

        self::assertSame(
            [],
            $violations,
            "SignalVector::fromArray coerces wrong-typed fields instead of refusing them:\n".implode("\n", $violations),
        );
    }

    public function testSignalVectorFromJsonRejectsNonIntegerPayloads(): void
    {
        $badJson = [
            'a JSON list [1,2,3]' => '[1,2,3]',
            'an empty JSON list []' => '[]',
            'a string field' => '{"source_fast":"abc"}',
            'an array field' => '{"source_fast":[9,9]}',
            'a bool field' => '{"source_fast":true}',
            'a float field' => '{"source_fast":1.9}',
        ];

        $violations = [];
        foreach ($badJson as $label => $json) {
            try {
                $decoded = SignalVector::fromJson($json);
            } catch (\InvalidArgumentException) {
                continue; // strict refusal: the required behaviour
            }
            $violations[] = sprintf(
                'SignalVector::fromJson(%s) silently accepted %s as %s (expected InvalidArgumentException)',
                var_export($json, true),
                $label,
                json_encode($decoded->toArray(), JSON_THROW_ON_ERROR),
            );
        }

        self::assertSame(
            [],
            $violations,
            "SignalVector::fromJson coerces wrong-typed / non-object JSON instead of refusing it:\n".implode("\n", $violations),
        );
    }

    private function assertWeightsSchemaStable(RiskWeights $weights, string $label, array $mutated): void
    {
        $wire = $weights->toArray();
        try {
            $again = RiskWeights::fromArray($wire);
        } catch (\Throwable $e) {
            self::fail(sprintf(
                'an accepted RiskWeights record is not schema-coherent: re-decode threw %s for mutation [%s] :: input=%s',
                $e::class,
                $label,
                var_export($mutated, true),
            ));
        }
        self::assertSame(
            json_encode($wire, JSON_THROW_ON_ERROR),
            json_encode($again->toArray(), JSON_THROW_ON_ERROR),
            sprintf('an accepted RiskWeights record is not stable under re-encoding for mutation [%s]', $label),
        );
    }

    private function assertSignalVectorSchemaStable(SignalVector $vector, string $label, array $mutated): void
    {
        $wire = $vector->toArray();
        try {
            $again = SignalVector::fromArray($wire);
        } catch (\Throwable $e) {
            self::fail(sprintf(
                'an accepted SignalVector is not schema-coherent: re-decode threw %s for mutation [%s] :: input=%s',
                $e::class,
                $label,
                var_export($mutated, true),
            ));
        }
        self::assertSame(
            json_encode($wire, JSON_THROW_ON_ERROR),
            json_encode($again->toArray(), JSON_THROW_ON_ERROR),
            sprintf('an accepted SignalVector is not stable under re-encoding for mutation [%s]', $label),
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

        foreach (array_keys($base) as $key) {
            $m = $base;
            unset($m[$key]);
            $out['delete:'.$key] = $m;
        }

        $wrongTypes = [
            'str' => '0',
            'numeric-str' => '1',
            'int' => 0,
            'null' => null,
            'array' => [],
            'nonempty-array' => [9],
            'bool' => true,
            'float' => 1.5,
        ];
        foreach (array_keys($base) as $key) {
            foreach ($wrongTypes as $name => $value) {
                $m = $base;
                $m[$key] = $value;
                $out['type:'.$key.'='.$name] = $m;
            }
        }

        foreach (array_keys($base) as $key) {
            foreach (['neg' => -1, 'zero' => 0, 'max' => PHP_INT_MAX, 'min' => PHP_INT_MIN, 'float' => 1.5, 'over1000' => 1001, 'over65535' => 65536] as $name => $probe) {
                $m = $base;
                $m[$key] = $probe;
                $out['num:'.$key.'='.$name] = $m;
            }
        }

        // Unknown and camelCase keys must be ignored, never crash.
        $m = $base;
        $m['unknown_key'] = 'x';
        $out['unknown:snake'] = $m;
        $m = $base;
        $m['sourceFast'] = 5;
        $out['unknown:camelCase'] = $m;

        return $out;
    }

    /** @return array<string, int> */
    private function randomWeights(): array
    {
        $out = [];
        foreach (RiskWeights::fromArray([])->toArray() as $field => $_) {
            $out[$field] = random_int(0, 1000);
        }

        return $out;
    }
}
