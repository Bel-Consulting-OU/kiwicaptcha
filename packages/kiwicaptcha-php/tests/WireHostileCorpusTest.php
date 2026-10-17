<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\DecodeError;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Telemetry;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The shared hostile wire corpus against the reference decoder.
 *
 * The corpus in Fixtures/wire-hostile-corpus.json is expanded by
 * generate-wire-hostile-corpus.php and read byte-for-byte by every
 * hosted SDK suite. The expected verdict is produced by this decoder,
 * so a row here proves the reference behavior; the sibling suites
 * prove every other host agrees.
 */
final class WireHostileCorpusTest extends TestCase
{
    /** @return iterable<string, array{0: array<string, mixed>}> */
    public static function corpus(): iterable
    {
        $document = json_decode(
            (string) file_get_contents(__DIR__.'/Fixtures/wire-hostile-corpus.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
        foreach ($document['vectors'] as $row) {
            yield $row['id'] => [$row];
        }
    }

    /** @param array<string, mixed> $row */
    #[DataProvider('corpus')]
    public function testCorpusRow(array $row): void
    {
        $expected = $row['expect'];
        if ($expected['verdict'] === 'accept') {
            $token = SolutionToken::decode($row['raw']);
            self::assertSame($expected['counter'], $token->counter, $row['id']);
            self::assertSame($expected['duration_ms'], $token->durationMs, $row['id']);
            self::assertSame($expected['execution_digest'], $token->executionDigest, $row['id']);
            self::assertSame($expected['execution_trace'], $token->executionTrace, $row['id']);
            self::assertSame($expected['rsw_proof'], $token->rswProof, $row['id']);
            if (\array_key_exists('telemetry', $expected)) {
                $actual = json_decode(
                    (string) json_encode($token->telemetry, JSON_UNESCAPED_SLASHES),
                    true,
                );
                self::assertEquals($expected['telemetry'], $actual, $row['id'].': telemetry value');
            }
            if (\array_key_exists('telemetry_score', $expected)) {
                self::assertSame(
                    $expected['telemetry_score'],
                    Telemetry::score($token->telemetry, $token->durationMs),
                    $row['id'].': telemetry score',
                );
            }
            return;
        }

        try {
            SolutionToken::decode($row['raw']);
        } catch (DecodeError $error) {
            if ($expected['class'] !== 'any') {
                self::assertSame($expected['class'], self::classify($error->getMessage()), $row['id']);
            } else {
                self::assertTrue(true, $row['id'].': rejected');
            }
            return;
        }
        self::fail($row['id'].': the reference decoder accepted a hostile row');
    }

    private static function classify(string $code): string
    {
        return match ($code) {
            DecodeError::INVALID_BASE64 => 'base64',
            DecodeError::INVALID_UTF8 => 'utf8',
            DecodeError::INVALID_COUNTER,
            DecodeError::COUNTER_EXCEEDS_SOLVER_MAXIMUM => 'counter',
            DecodeError::INVALID_DURATION => 'duration',
            default => 'malformed',
        };
    }
}
