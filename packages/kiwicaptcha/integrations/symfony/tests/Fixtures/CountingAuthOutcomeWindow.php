<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

/**
 * The in-memory call-counting fake of the auth-outcome window: it
 * records every write (operation and window key) in call order so the
 * tests can assert the exact cardinality of one login's window traffic.
 * Ratio reads answer like an empty memory window (null), which keeps
 * the fail-closed default gate closed.
 */
final class CountingAuthOutcomeWindow implements \BelConsulting\KiwiCaptchaBundle\Risk\AuthOutcomeWindowInterface
{
    /** @var list<array{op: string, key: string}> */
    public array $calls = [];

    public function recordFailure(string $sessionPseudonym): void
    {
        $this->calls[] = ['op' => 'failure', 'key' => $sessionPseudonym];
    }

    public function recordSuccess(string $sessionPseudonym): void
    {
        $this->calls[] = ['op' => 'success', 'key' => $sessionPseudonym];
    }

    public function failureRatio(string $sessionPseudonym): ?float
    {
        return null;
    }

    /**
     * The failure writes, in call order.
     *
     * @return list<string>
     */
    public function failureKeys(): array
    {
        return array_values(array_map(
            static fn (array $call): string => $call['key'],
            array_values(array_filter($this->calls, static fn (array $call): bool => $call['op'] === 'failure')),
        ));
    }

    /**
     * The success writes, in call order.
     *
     * @return list<string>
     */
    public function successKeys(): array
    {
        return array_values(array_map(
            static fn (array $call): string => $call['key'],
            array_values(array_filter($this->calls, static fn (array $call): bool => $call['op'] === 'success')),
        ));
    }
}
