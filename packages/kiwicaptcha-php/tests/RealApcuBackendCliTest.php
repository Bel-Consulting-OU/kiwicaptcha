<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Storage\RealApcuBackend;
use PHPUnit\Framework\TestCase;

/**
 * The cli-refusal decision of the real APCu backend. A CLI process
 * (RoadRunner worker, queue consumer) owns a private APCu segment
 * invisible to the web tier. Construction therefore refuses the cli
 * SAPI while the apc.enable_cli opt-in is off. The ini flag is the
 * operator's explicit opt-in to a CLI segment.
 */
final class RealApcuBackendCliTest extends TestCase
{
    public function testTheCliSapiRefusesWhileTheEnableCliOptInIsOff(): void
    {
        self::assertTrue(RealApcuBackend::cliConstructionRefused('cli', false));
    }

    public function testTheEnableCliOptInAndTheWebSapisConstruct(): void
    {
        self::assertFalse(RealApcuBackend::cliConstructionRefused('cli', true));
        self::assertFalse(RealApcuBackend::cliConstructionRefused('fpm-fcgi', false));
        self::assertFalse(RealApcuBackend::cliConstructionRefused('apache2handler', false));
    }

    public function testTheEnableCliIniParsesAsABoolean(): void
    {
        self::assertTrue(RealApcuBackend::apcEnableCliIni('1'));
        self::assertTrue(RealApcuBackend::apcEnableCliIni('true'));
        self::assertTrue(RealApcuBackend::apcEnableCliIni(' on '));
        self::assertTrue(RealApcuBackend::apcEnableCliIni('Yes'));
        self::assertFalse(RealApcuBackend::apcEnableCliIni('0'));
        self::assertFalse(RealApcuBackend::apcEnableCliIni(''));
        self::assertFalse(RealApcuBackend::apcEnableCliIni('off'));
        // An unset ini entry (the extension is not loaded) reads off.
        self::assertFalse(RealApcuBackend::apcEnableCliIni(false));
    }
}
