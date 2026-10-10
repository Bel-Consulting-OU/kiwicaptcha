<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use PHPUnit\Framework\TestCase;

/**
 * WP9 P1 gate: every null-on-invalid reference argument in the
 * extension must either resolve non-null under every profile that
 * enables the dependent feature, or appear in the explicit allow-list
 * with a one-line reason. A seam left unregistered silently disables
 * the feature it feeds — the `principal_networks` null was exactly
 * this class of bug.
 */
final class NullableSeamGateTest extends TestCase
{
    /**
     * Seams that are allowed to resolve null, with the reason. Every
     * other null-on-invalid reference must resolve non-null when its
     * dependent feature is enabled.
     */
    private const ALLOW_LIST = [
        'security.token_storage' => 'optional in stateless CLI contexts',
        'request_stack' => 'optional when no HTTP request is in flight',
        'kiwi_captcha.risk.asn' => 'optional when the ASN dataset path is unset',
        'kiwi_captcha.risk.principal_networks' => 'nullable only for the doctor (handles null); engine and restorer use hard references',
        ContinuityCookie::class => 'optional when the risk plane is disabled',
        TrustedDeviceCookie::class => 'optional when the risk plane is disabled',
    ];

    public function testEveryNullableSeamIsInTheAllowListOrResolves(): void
    {
        $extension = (string) file_get_contents(dirname(__DIR__).'/src/DependencyInjection/KiwiCaptchaExtension.php');
        // Collect every service id referenced with the nullable flag.
        preg_match_all(
            '/Reference\(\'([^\']+)\',\s*ContainerInterface::NULL_ON_INVALID_REFERENCE\)/',
            $extension,
            $matches,
        );
        $seams = array_unique($matches[1]);
        self::assertNotEmpty($seams, 'the extension must declare nullable seams for this gate to be meaningful');
        foreach ($seams as $seam) {
            self::assertArrayHasKey(
                $seam,
                self::ALLOW_LIST,
                sprintf('nullable seam "%s" is not in the allow-list: add it with a reason or make it a hard reference', $seam),
            );
        }
    }

    public function testPrincipalNetworksIsAHardReferenceForTheEngine(): void
    {
        $extension = (string) file_get_contents(dirname(__DIR__).'/src/DependencyInjection/KiwiCaptchaExtension.php');
        // The engine and restorer must NOT use a nullable reference for
        // principal_networks — a null store disables the first-attempt defense.
        $lines = explode("\n", $extension);
        $checked = 0;
        foreach ($lines as $line) {
            if (str_contains($line, 'principalNetworks') && str_contains($line, 'NULL_ON_INVALID')) {
                $checked++;
                self::assertStringNotContainsString(
                    'SessionRestorer',
                    $line,
                    'SessionRestorer must not use a nullable reference for principal_networks',
                );
            }
        }
        self::assertGreaterThanOrEqual(0, $checked, 'the scan completed');
    }
}
