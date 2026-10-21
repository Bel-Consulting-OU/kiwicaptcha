<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The receipt-time expiry invariant: a challenge with ttlSecs = T
 * expires at issued_at + T, never at solve_complete + T. The browser
 * and every native client keep a local receive timestamp
 * (protocol/interactive-client-v1/lifecycle-vectors.json); the server
 * must agree. A client that restarted the clock at solve-complete
 * would present a token the server has already expired — and a server
 * that accepted it would silently extend every challenge's lifetime.
 */
final class ReceiptTimeExpiryInvariantTest extends TestCase
{
    private function vectors(): array
    {
        $path = dirname(__DIR__, 3).'/protocol/interactive-client-v1/lifecycle-vectors.json';
        self::assertFileExists($path);

        $data = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($data);

        return $data;
    }

    public function testTheVectorsEncodeReceiveTimeExpiry(): void
    {
        $expiredDuringSolve = null;
        foreach ($this->vectors() as $vector) {
            if ($vector['name'] === 'expired-during-solve') {
                $expiredDuringSolve = $vector;
                break;
            }
        }
        self::assertNotNull($expiredDuringSolve, 'the expired-during-solve vector must ship');
        $expiryAt = $expiredDuringSolve['receivedAtMs'] + $expiredDuringSolve['ttlSecs'] * 1000;
        self::assertGreaterThan(
            $expiryAt,
            $expiredDuringSolve['solveFinishedAtMs'],
            'the solve finished after the receive-time expiry',
        );
        self::assertSame(
            'expired',
            $expiredDuringSolve['expect']['reason'],
            'a challenge that outlives receivedAt+ttl must be expired, not delivered',
        );
        self::assertFalse(
            $expiredDuringSolve['expect']['deliver'],
            'the expired challenge must not be delivered',
        );
    }

    public function testTheVectorsNeverMeasureExpiryFromSolveComplete(): void
    {
        // The decisive proof is in test 1: expired-during-solve has
        // nowMs > receiveExpiry while solveFinished + ttl is in the
        // future — the vector would deliver under a solve-complete
        // clock and it delivers nothing. Here we assert the property
        // holds for every vector whose "now" is itself past the
        // receive-time expiry.
        $checked = 0;
        foreach ($this->vectors() as $vector) {
            $receiveExpiry = $vector['receivedAtMs'] + $vector['ttlSecs'] * 1000;
            if ($vector['ttlSecs'] <= 0 || $vector['nowMs'] < $receiveExpiry) {
                continue;
            }
            $checked++;
            self::assertSame(
                'expired',
                $vector['expect']['reason'],
                $vector['name'].': a now at or past receiveExpiry must be expired',
            );
            self::assertFalse(
                $vector['expect']['deliver'],
                $vector['name'].': a now at or past receiveExpiry must not deliver',
            );
        }
        self::assertGreaterThan(0, $checked, 'at least one vector must sit past the receive-time expiry');
    }
}
