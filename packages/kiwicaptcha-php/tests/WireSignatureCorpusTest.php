<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The shared challenge-signature corpus against the reference
 * verifier. The fixture is expanded by
 * Fixtures/generate-wire-signature-corpus.php and read byte-for-byte
 * by every hosted SDK suite; a host whose signature extraction or
 * canonical signing drifts fails here.
 */
final class WireSignatureCorpusTest extends TestCase
{
    /** @return iterable<string, array{0: array<string, mixed>}> */
    public static function corpus(): iterable
    {
        $document = json_decode(
            (string) file_get_contents(__DIR__.'/Fixtures/wire-signature-corpus.json'),
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
        $record = ChallengeRecord::fromArray($row['record']);
        $verifier = new Verifier(storage: new ArrayStorage(), tenantId: $row['verify_tenant']);
        $method = new \ReflectionMethod(Verifier::class, 'verifyRecordSignature');
        $verified = $method->invoke($verifier, $record, $row['verify_secret']);
        self::assertSame($row['expect'] === 'accept', $verified, $row['id']);
    }
}
