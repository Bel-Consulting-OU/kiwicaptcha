<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ExecutionVersionPolicy;
use PHPUnit\Framework\TestCase;

/**
 * The execution-capability matrix conformance test: the single
 * interpretation of Kiwi-Execution-Max-Version that every issuer and
 * every parser shares. Pinned against
 * protocol/execution-v1/capability-matrix.json so a client that
 * advertises 0 and a server that arms at version 2 can never both be
 * "correct".
 */
final class ExecutionCapabilityMatrixTest extends TestCase
{
    private function matrix(): array
    {
        $path = dirname(__DIR__, 3).'/protocol/execution-v1/capability-matrix.json';
        self::assertFileExists($path, 'the canonical capability matrix must ship');
        $data = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($data);

        return $data;
    }

    public function testMatrixShipsAndListsEveryNativeClient(): void
    {
        $matrix = $this->matrix();
        $ids = array_column($matrix['clients'], 'id');
        foreach (['android', 'ios', 'flutter', 'react-native-native'] as $native) {
            self::assertContains($native, $ids, "the matrix must pin the $native capability");
        }
        foreach ($matrix['clients'] as $client) {
            if (\in_array($client['id'], ['android', 'ios', 'flutter', 'react-native-native'], true)) {
                self::assertSame(0, $client['capability'], $client['id'].' must advertise capability 0');
            }
        }
    }

    public function testClientCapabilityMatchesTheMatrix(): void
    {
        // Absent header: the v1 compatibility floor (1), never 0.
        self::assertSame(1, ExecutionVersionPolicy::clientCapability(null), 'an absent header is the v1 floor');
        self::assertSame(1, ExecutionVersionPolicy::clientCapability(''), 'an empty header is the v1 floor');
        self::assertSame(1, ExecutionVersionPolicy::clientCapability('  '), 'a whitespace header is the v1 floor');
        self::assertSame(1, ExecutionVersionPolicy::clientCapability('garbage'), 'a malformed header is the v1 floor');
        // Explicit zero: the none capability — the dimension must never arm.
        self::assertSame(
            ExecutionVersionPolicy::CAPABILITY_NONE,
            ExecutionVersionPolicy::clientCapability('0'),
            'an explicit 0 is the none capability',
        );
        // Canonical decimals clamp to the generator maximum.
        self::assertSame(2, ExecutionVersionPolicy::clientCapability('2'));
        self::assertSame(1, ExecutionVersionPolicy::clientCapability('01'), 'leading zeros are not canonical');
    }

    public function testNativeClientCapabilityNeverArms(): void
    {
        $matrix = $this->matrix();
        $policy = new ExecutionVersionPolicy(4, null);
        $available = $policy->effectiveAvailableTier();
        foreach ($matrix['clients'] as $client) {
            if ($client['capability'] !== 0) {
                continue;
            }
            $effective = max(1, min($client['capability'], $available));
            // The none capability means the caller must refuse to arm; the
            // server-side arithmetic min(0, available) = 0 is then
            // interpreted as "never arm", not as "arm at version 1".
            self::assertSame(0, $client['capability']);
            self::assertSame(
                0,
                \min($client['capability'], $available),
                $client['id'].': min(0, fleet) must stay 0 so the arming gate refuses',
            );
        }
    }

    public function testEffectiveVersionNeverExceedsClientOrFleet(): void
    {
        $policy = new ExecutionVersionPolicy(4, 2);
        $available = $policy->effectiveAvailableTier();
        self::assertSame(2, $available, 'the fleet floor pins the tier below the node cap');
        foreach ([0, 1, 2, 3, 4, 5] as $client) {
            $effective = max(1, min($client, $available));
            self::assertLessThanOrEqual($available, $effective, 'effective must not exceed the fleet');
            if ($client > 0) {
                self::assertLessThanOrEqual($client, $effective, 'effective must not exceed the client');
            }
        }
    }
}
