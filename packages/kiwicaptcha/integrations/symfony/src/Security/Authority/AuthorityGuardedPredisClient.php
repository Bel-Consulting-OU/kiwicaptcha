<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Authority;

use Predis\Command\CommandInterface;

/**
 * The pinned-primary wiring seam: a Predis\Client that delegates every
 * command to an inner client after consulting the authority guard.
 *
 * The bundle decorates the storage/limiter/risk client service with
 * this wrapper under `ha_authority: pinned_primary`. Every command
 * the bundle components issue (including the verified-WAIT
 * `executeRaw` calls) is preceded by
 * {@see AuthorityTransitionGuard::assertServeEligible()}, so a
 * durability transition can never execute on a changed authority.
 * The guard is consulted with the inner raw client (never this
 * wrapper), so its own `INFO` reads and pin-key operations cannot
 * recurse into the check.
 *
 * The guard caches its verification for a short window, so the wrapper
 * costs one `INFO` probe per window per process, not one round trip
 * per command. Within the window the check returns without any I/O.
 * Pipeline/transaction/pub-sub contexts (unused by the bundle today)
 * are verified at context entry; commands inside the context run
 * within the same verification window.
 *
 * The wrapper is a Predis\Client subclass (never a proxy) so every
 * existing `\Predis\Client` type hint keeps accepting the decorated
 * service. A phpredis `\Redis` client cannot be intercepted this way,
 * which is why the extension refuses phpredis under
 * `pinned_primary` (fail closed, never silently unguarded).
 */
final class AuthorityGuardedPredisClient extends \Predis\Client
{
    public function __construct(
        private readonly AuthorityTransitionGuard $guard,
        private readonly \Predis\Client $inner,
    ) {
        parent::__construct();
    }

    public function executeCommand(CommandInterface $command): mixed
    {
        $this->guard->assertServeEligible($this->inner);

        return $this->inner->executeCommand($command);
    }

    public function __call($commandID, $arguments): mixed
    {
        $this->guard->assertServeEligible($this->inner);

        return $this->inner->__call($commandID, $arguments);
    }

    public function executeRaw(array $arguments, &$error = null): mixed
    {
        $this->guard->assertServeEligible($this->inner);

        return $this->inner->executeRaw($arguments, $error);
    }

    public function pipeline(...$arguments): mixed
    {
        $this->guard->assertServeEligible($this->inner);

        return $this->inner->pipeline(...$arguments);
    }

    public function transaction(...$arguments): mixed
    {
        $this->guard->assertServeEligible($this->inner);

        return $this->inner->transaction(...$arguments);
    }

    public function pubSubLoop(...$arguments): mixed
    {
        $this->guard->assertServeEligible($this->inner);

        return $this->inner->pubSubLoop(...$arguments);
    }

    public function monitor(): mixed
    {
        $this->guard->assertServeEligible($this->inner);

        return $this->inner->monitor();
    }

    public function connect(): void
    {
        $this->inner->connect();
    }

    public function disconnect(): void
    {
        $this->inner->disconnect();
    }

    public function quit(): mixed
    {
        return $this->inner->quit();
    }

    public function isConnected(): bool
    {
        return $this->inner->isConnected();
    }

    public function getConnection(): mixed
    {
        return $this->inner->getConnection();
    }

    public function getClientBy($selector, $value): mixed
    {
        return $this->inner->getClientBy($selector, $value);
    }

    public function getCommandFactory(): mixed
    {
        return $this->inner->getCommandFactory();
    }

    public function getOptions(): mixed
    {
        return $this->inner->getOptions();
    }

    public function createCommand($commandID, $arguments = []): mixed
    {
        return $this->inner->createCommand($commandID, $arguments);
    }

    public function pack($value): mixed
    {
        return $this->inner->pack($value);
    }

    public function unpack($value): mixed
    {
        return $this->inner->unpack($value);
    }

    public function getIterator(): \Traversable
    {
        return $this->inner->getIterator();
    }

    public function __get(string $name): mixed
    {
        return $this->inner->{$name};
    }

    public function __set(string $name, $value): void
    {
        $this->inner->{$name} = $value;
    }

    public function __isset(string $name): bool
    {
        return isset($this->inner->{$name});
    }
}
