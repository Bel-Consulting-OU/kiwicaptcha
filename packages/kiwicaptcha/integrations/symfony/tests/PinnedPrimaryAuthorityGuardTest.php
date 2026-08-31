<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\Authority\AuthorityGuardedPredisClient;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedAuthorityRefusalException;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedPrimaryAuthorityGuard;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;

/**
 * The pinned-primary authority guard (docs/ha-authority.md): pins the
 * serving authority identity on first use and refuses every
 * subsequent use when the authority changed. The pin is write-once
 * (`SET NX`) in the same Redis namespace. A pin that disappears after
 * it was established is a refusal, never a silent re-pin; an
 * unverifiable authority is a refusal. The verification result is
 * cached for the reverify window, so the `INFO` probe costs one round
 * trip per window per process.
 *
 * These fake-based tests run without a server and exercise the exact
 * refusal semantics; the real promotion simulation (a restarted
 * primary with a new run_id, and a pointed-at replica) lives in
 * PinnedPrimaryAuthorityPromotionTest, gated on the shared real-Redis
 * environment.
 */
final class PinnedPrimaryAuthorityGuardTest extends TestCase
{
    private const NS = 'pinned-test';
    private const RUN_ID_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const RUN_ID_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    private function fake(): FakePredisClient
    {
        $fake = new FakePredisClient();
        $fake->infoReplication = ['role' => 'master', 'run_id' => self::RUN_ID_A];
        $fake->infoServer = ['run_id' => self::RUN_ID_A];

        return $fake;
    }

    private function pinKey(): string
    {
        return '{kiwi:'.self::NS.'}:authority:pin';
    }

    private function infoCalls(FakePredisClient $fake): int
    {
        return \count(array_filter($fake->calls, static fn (array $call): bool => $call[0] === 'INFO'));
    }

    public function testFirstUsePinsTheAuthorityAndSubsequentVerifiesPass(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);

        $guard->assertServeEligible($fake);
        self::assertSame(
            'master|'.self::RUN_ID_A,
            $fake->strings[$this->pinKey()] ?? null,
            'the first use writes the pin once (SET NX) in the same Redis namespace',
        );
        $state = $guard->state();
        self::assertTrue($state['armed'], 'after the first verification the guard is armed');
        self::assertSame('master|'.self::RUN_ID_A, $state['pinned'], 'the state reports the pinned identity');

        $guard->assertServeEligible($fake);
        $guard->assertServeEligible($fake);
        self::assertSame(
            'master|'.self::RUN_ID_A,
            $fake->strings[$this->pinKey()] ?? null,
            'the pin is write-once: a stable authority never rewrites it',
        );
    }

    public function testTheVerificationIsCachedWithinTheWindow(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 5);

        $guard->assertServeEligible($fake);
        $infoAfterFirst = $this->infoCalls($fake);
        self::assertGreaterThan(0, $infoAfterFirst, 'the first check reads the serving identity');

        $guard->assertServeEligible($fake);
        $guard->assertServeEligible($fake);
        self::assertSame(
            $infoAfterFirst,
            $this->infoCalls($fake),
            'within the reverify window the check serves from the cache without an INFO round trip',
        );
    }

    public function testAChangedRunIdIsRefusedWithTheExactMessage(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);
        $guard->assertServeEligible($fake);

        // The stale-promotion detection: the serving authority changed.
        // A restarted primary (new run_id) or a promoted stale replica
        // presents exactly this identity change.
        $fake->infoReplication['run_id'] = self::RUN_ID_B;
        $fake->infoServer['run_id'] = self::RUN_ID_B;

        try {
            $guard->assertServeEligible($fake);
            self::fail('the guard must refuse when the serving run_id changed');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('the serving authority changed', $e->getMessage(), 'the refusal names the identity change');
            self::assertStringContainsString('pinned master|'.self::RUN_ID_A, $e->getMessage(), 'the refusal names the PINNED identity');
            self::assertStringContainsString('observed master|'.self::RUN_ID_B, $e->getMessage(), 'the refusal names the OBSERVED identity');
            self::assertStringContainsString($this->pinKey(), $e->getMessage(), 'the refusal names the pin key for the re-pin');
            self::assertStringContainsString('Re-pin explicitly after a deliberate authority change', $e->getMessage(), 'the refusal names the remediation');
            self::assertSame('master|'.self::RUN_ID_A, $e->pinnedIdentity());
            self::assertSame('master|'.self::RUN_ID_B, $e->observedIdentity());
        }
    }

    public function testAChangedRoleIsRefused(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);
        $guard->assertServeEligible($fake);

        // Pointed at a replica: the serving role is no longer the
        // pinned role, so the guard refuses.
        $fake->infoReplication['role'] = 'slave';

        $this->expectException(PinnedAuthorityRefusalException::class);
        $this->expectExceptionMessage('pinned master|'.self::RUN_ID_A);
        $this->expectExceptionMessage('observed slave|'.self::RUN_ID_A);

        $guard->assertServeEligible($fake);
    }

    public function testAPinThatDisappearsAfterEstablishmentIsRefusedNeverRePinned(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);
        $guard->assertServeEligible($fake);
        self::assertNotNull($fake->strings[$this->pinKey()] ?? null);

        // A failover to a node that never received the pin presents
        // exactly this state: the key is gone. The guard must refuse,
        // never silently re-pin to the new authority.
        unset($fake->strings[$this->pinKey()]);

        try {
            $guard->assertServeEligible($fake);
            self::fail('a pin that disappears after establishment must be a refusal, never a silent re-pin');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('the pinned identity is missing', $e->getMessage());
            self::assertStringContainsString('was pinned to master|'.self::RUN_ID_A, $e->getMessage());
            self::assertStringContainsString('Re-pin explicitly after a deliberate authority change', $e->getMessage());
        }
        self::assertArrayNotHasKey($this->pinKey(), $fake->strings, 'the guard must not have re-pinned');
    }

    public function testFirstUseWithAnUnverifiableIdentityIsRefused(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);

        // The `INFO` read cannot succeed (Redis down): an unverifiable
        // authority is stale, never passed — the guard refuses instead
        // of pinning.
        $fake->failCommand = 'INFO';

        $this->expectException(PinnedAuthorityRefusalException::class);
        $this->expectExceptionMessage('the serving authority cannot be verified');

        $guard->assertServeEligible($fake);
    }

    public function testAConcurrentFirstUseComparesAgainstTheWinningPin(): void
    {
        $fake = $this->fake();
        // The pin already exists (a concurrent process pinned first) and
        // the observed identity matches it: the guard serves.
        $fake->strings[$this->pinKey()] = 'master|'.self::RUN_ID_A;
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);
        $guard->assertServeEligible($fake);

        // The observed identity differs from the existing pin: refused.
        $fake->infoReplication['run_id'] = self::RUN_ID_B;
        $fake->infoServer['run_id'] = self::RUN_ID_B;
        $this->expectException(PinnedAuthorityRefusalException::class);
        $this->expectExceptionMessage('pinned master|'.self::RUN_ID_A);
        $this->expectExceptionMessage('observed master|'.self::RUN_ID_B);

        $guard->assertServeEligible($fake);
    }

    public function testTheGuardedClientWrapperDelegatesAndRefuses(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);
        $wrapped = new AuthorityGuardedPredisClient($guard, $fake);

        // The command goes through the guard to the inner client.
        $wrapped->set('probe', '1');
        self::assertSame('1', $fake->strings['probe'], 'the guarded wrapper delegates commands to the inner client');

        // The authority changed: the next command refuses with the
        // pinned-vs-observed refusal, so a durability-critical
        // transition can never execute on the changed authority.
        $fake->infoReplication['run_id'] = self::RUN_ID_B;
        $fake->infoServer['run_id'] = self::RUN_ID_B;
        $this->expectException(PinnedAuthorityRefusalException::class);
        $this->expectExceptionMessage('the serving authority changed');

        $wrapped->set('probe', '2');
    }
}
