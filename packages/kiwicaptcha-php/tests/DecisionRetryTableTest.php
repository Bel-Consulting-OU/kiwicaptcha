<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * The shared decision register: protocol/decision-v1/corpus.json. The
 * PHP core carries the retry classification; the framework HTTP gate
 * lives in the separate Symfony package and is out of this register's
 * HTTP rows.
 */
final class DecisionRetryTableTest extends TestCase
{
    private static function corpus(): array
    {
        $path = \dirname(__DIR__, 3) . '/protocol/decision-v1/corpus.json';
        $decoded = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        return $decoded;
    }

    public function testEveryWireCodeMapsToItsRegisteredRetryPolarity(): void
    {
        $corpus = self::corpus();
        foreach ($corpus['codes'] as $code => $disposition) {
            $error = VerifyError::from($code);
            self::assertSame(
                $disposition === 'retry',
                $error->isRetryable(),
                sprintf('%s maps to %s', $code, $disposition),
            );
        }
    }

    public function testTheRetryTableIsExactlyTheFourTransientCodes(): void
    {
        $retry = array_values(array_map(
            static fn (VerifyError $error): string => $error->value,
            array_filter(VerifyError::cases(), static fn (VerifyError $error): bool => $error->isRetryable()),
        ));
        $expected = self::corpus()['retry_codes'];
        sort($retry);
        sort($expected);
        self::assertSame($expected, $retry);
    }

    public function testThePhpRowCarriesNoHttpStatus(): void
    {
        $http = self::corpus()['http'];
        self::assertSame(200, $http['allow_status']);
        self::assertSame(503, $http['retry_status']);
        self::assertArrayNotHasKey('php', $http['deny_status']);
    }
}
