<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\TrustedDeviceCookie;
use KiwiCaptcha\Risk\Storage\RedisPrincipalNetworkTagStore;
use PHPUnit\Framework\TestCase;

/**
 * WP9 P4 gate: the lifetimes of the state a defense depends on must
 * outlast the defense. Session tag TTL >= continuity cookie TTL;
 * device tag TTL = device cookie TTL; the hysteresis window is shorter
 * than the escalation window. A mismatch silently disables the defense.
 */
final class LifetimeContractTest extends TestCase
{
    public function testSessionTagTtlOutlastsTheContinuityCookie(): void
    {
        $cookie = new ContinuityCookie(ttlSecs: 1800);
        $sessionTagTtlMs = RedisPrincipalNetworkTagStore::DEFAULT_SESSION_TTL_MS;
        $cookieTtlMs = $cookie->ttlSecs() * 1000;
        self::assertGreaterThanOrEqual(
            $cookieTtlMs,
            $sessionTagTtlMs,
            'session tag TTL must outlast the continuity cookie so a bound session survives the cookie window',
        );
    }

    public function testDeviceTagTtlMatchesTheDeviceCookie(): void
    {
        $device = new TrustedDeviceCookie();
        $deviceTagTtlMs = RedisPrincipalNetworkTagStore::DEFAULT_DEVICE_TTL_MS;
        $cookieTtlMs = $device->ttlSecs() * 1000;
        self::assertSame(
            $cookieTtlMs,
            $deviceTagTtlMs,
            'device tag TTL must match the device cookie so the binding expires with the cookie',
        );
    }

    public function testNetworkTagTtlOutlastsEveryCookie(): void
    {
        $netTtlMs = RedisPrincipalNetworkTagStore::DEFAULT_NET_TTL_MS;
        $sessionTtlMs = RedisPrincipalNetworkTagStore::DEFAULT_SESSION_TTL_MS;
        $deviceTtlMs = RedisPrincipalNetworkTagStore::DEFAULT_DEVICE_TTL_MS;
        self::assertGreaterThan($sessionTtlMs, $netTtlMs, 'network tags outlast session tags');
        self::assertGreaterThan($deviceTtlMs, $netTtlMs, 'network tags outlast device tags');
    }

    public function testSessionCapExceedsTypicalBrowserCount(): void
    {
        self::assertGreaterThanOrEqual(
            16,
            RedisPrincipalNetworkTagStore::DEFAULT_SESSION_CAP,
            'session cap must allow more than a handful of browsers before LRU eviction',
        );
        self::assertGreaterThanOrEqual(
            8,
            RedisPrincipalNetworkTagStore::DEFAULT_DEVICE_CAP,
            'device cap must allow more than a handful of devices',
        );
    }
}
