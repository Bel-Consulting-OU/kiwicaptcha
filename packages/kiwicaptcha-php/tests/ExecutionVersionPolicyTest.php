<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\ExecutionVersionPolicy;
use PHPUnit\Framework\TestCase;

/**
 * The exhaustive ExecutionVersionPolicy matrix: for every node cap
 * 1..3, every fleet floor state (absent or confirmed 1..3) and every
 * required tier 1..3, the policy derives the same effective tier and
 * the same satisfiability and downgrade-window answers as the
 * three-rung definition. The invalid required-above-cap combinations
 * are refused with an InvalidArgumentException exactly like the
 * config tree.
 */
final class ExecutionVersionPolicyTest extends TestCase
{
    public function testEffectiveTierMatrixMatchesTheThreeRungDefinition(): void
    {
        foreach ([1, 2, 3] as $cap) {
            foreach ([null, 1, 2, 3] as $floor) {
                $policy = new ExecutionVersionPolicy($cap, $floor);
                $expected = min($cap, $floor ?? 1, ExecutionChallengeGenerator::MAX_EXECUTION_VERSION);

                self::assertSame($expected, $policy->effectiveAvailableTier(), sprintf('cap %d floor %s', $cap, var_export($floor, true)));

                foreach ([1, 2, 3] as $required) {
                    $label = sprintf('cap %d floor %s required %d', $cap, var_export($floor, true), $required);
                    if ($required > $cap) {
                        // The compile-time invariant: a required tier
                        // above the node cap can never be satisfied, so
                        // the policy refuses the query, never answers.
                        $this->assertRequiredAboveCapIsRefused($policy, $required, $label);

                        continue;
                    }

                    self::assertSame(
                        $required <= $expected,
                        $policy->requirementSatisfiable($required),
                        $label.' satisfiability',
                    );
                    self::assertSame(
                        $required < $expected,
                        $policy->downgradeWindowExists($required),
                        $label.' downgrade window',
                    );
                }
            }
        }
    }

    public function testBinaryMaxDefaultsToTheGeneratorMaximum(): void
    {
        $max = ExecutionChallengeGenerator::MAX_EXECUTION_VERSION;
        $policy = new ExecutionVersionPolicy($max, $max);

        self::assertSame(ExecutionChallengeGenerator::MAX_EXECUTION_VERSION, $policy->effectiveAvailableTier(), 'the generator maximum is the ceiling of the effective tier');
    }

    public function testAnExplicitBinaryMaxBelowTheCapAndFloorBindsTheTier(): void
    {
        $policy = new ExecutionVersionPolicy(5, 5, 3);

        self::assertSame(3, $policy->effectiveAvailableTier(), 'the binary max binds when it is below the cap and the floor');
        self::assertTrue($policy->requirementSatisfiable(3));
        self::assertFalse($policy->requirementSatisfiable(4));
        self::assertTrue($policy->downgradeWindowExists(2), 'a required tier below the binary max is a downgrade window');
    }

    public function testConstructorRefusesANonPositiveNodeCap(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new ExecutionVersionPolicy(0);
    }

    public function testConstructorRefusesAnExplicitSubOneFleetFloor(): void
    {
        // An undeclared floor is null, never 0: a caller that passes a
        // raw parsed 0 (a confirmed policy without the execution-floor
        // key) must normalize it to null before constructing.
        $this->expectException(\InvalidArgumentException::class);
        new ExecutionVersionPolicy(2, 0);
    }

    public function testConstructorRefusesANonPositiveBinaryMax(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new ExecutionVersionPolicy(2, null, 0);
    }

    public function testClientCapabilityReadsTheExplicitZeroAsCapabilityNone(): void
    {
        // The explicit zero (`0`, exactly, after trim) reads as the
        // none capability: the client cannot execute the execution dimension at
        // all, so every issuance surface must never arm it — a different
        // statement from the v1 compatibility floor, which still allows
        // an armed version-1 issuance.
        self::assertSame(ExecutionVersionPolicy::CAPABILITY_NONE, ExecutionVersionPolicy::clientCapability('0'));
        self::assertSame(ExecutionVersionPolicy::CAPABILITY_NONE, ExecutionVersionPolicy::clientCapability(' 0'));
        self::assertSame(ExecutionVersionPolicy::CAPABILITY_NONE, ExecutionVersionPolicy::clientCapability("0\n"));
    }

    public function testClientCapabilityKeepsTheV1FloorAndAdvertisementSemantics(): void
    {
        $max = ExecutionChallengeGenerator::MAX_EXECUTION_VERSION;
        // Absence, emptiness and garbage degrade to the v1 floor — the
        // dimension may still arm at version 1 — and never refuse.
        foreach ([null, '', '   ', 'abc', '-1', '2.0', ' 2', '007', '00'] as $raw) {
            self::assertSame(
                1,
                ExecutionVersionPolicy::clientCapability($raw),
                'a malformed or absent advertisement ('.var_export($raw, true).') degrades to the v1 floor',
            );
        }
        // A canonical advertisement reads as itself, capped at the
        // binary's mintable maximum.
        foreach ([1 => 1, 2 => 2, 3 => 3, $max => $max, $max + 1 => $max, 999 => $max] as $raw => $expected) {
            self::assertSame($expected, ExecutionVersionPolicy::clientCapability((string) $raw), sprintf('advertisement %d', $raw));
        }
    }

    private function assertRequiredAboveCapIsRefused(ExecutionVersionPolicy $policy, int $required, string $label): void
    {
        foreach (['requirementSatisfiable', 'downgradeWindowExists'] as $method) {
            try {
                $policy->{$method}($required);
                self::fail($label.' must refuse '.$method);
            } catch (\InvalidArgumentException) {
                self::assertTrue(true, $label.' refuses '.$method);
            }
        }
    }
}
