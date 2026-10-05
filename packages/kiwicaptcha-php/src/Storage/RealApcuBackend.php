<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

/**
 * The production {@see ApcuBackendInterface} over the real APCu
 * extension: `apcu_fetch()`, `apcu_store()`, `apcu_add()` and
 * `apcu_delete()` with their TTL arguments.
 *
 * Construction fails closed with one actionable error when the
 * extension is missing or disabled for the process. This replaces a
 * fatal error on an undefined function later: the web server usually loads
 * APCu while a cli process does not, so the message names the
 * `apc.enable_cli` remedy for that case.
 *
 * The atomicity promises are APCu's own: the segment is one shared
 * memory region guarded by its internal lock, `apcu_add()` is the
 * atomic create-if-absent the storage's transition lock builds on, and
 * a TTL-expired entry reads as absent on fetch.
 */
final class RealApcuBackend implements ApcuBackendInterface
{
    /**
     * @throws ApcuStorageException when the APCu extension is not
     *                              loaded or is disabled for this
     *                              process
     */
    public function __construct()
    {
        if (!\function_exists('apcu_store')) {
            throw new ApcuStorageException(
                'the APCu extension is not installed; install or enable ext-apcu to use ApcuStorage'
            );
        }
        if (\function_exists('apcu_enabled') && !apcu_enabled()) {
            throw new ApcuStorageException(
                'APCu is disabled for this process; enable the extension (for cli runs also set apc.enable_cli=1) to use ApcuStorage'
            );
        }
    }

    public function fetch(string $key): ApcuFetchOutcome
    {
        $success = false;
        $value = apcu_fetch($key, $success);
        if ($success !== true) {
            return ApcuFetchOutcome::notFound();
        }

        return ApcuFetchOutcome::found($value);
    }

    public function store(string $key, mixed $value, int $ttlSecs): bool
    {
        return apcu_store($key, $value, $ttlSecs);
    }

    public function add(string $key, mixed $value, int $ttlSecs): bool
    {
        return apcu_add($key, $value, $ttlSecs);
    }

    public function delete(string $key): bool
    {
        return apcu_delete($key);
    }
}
