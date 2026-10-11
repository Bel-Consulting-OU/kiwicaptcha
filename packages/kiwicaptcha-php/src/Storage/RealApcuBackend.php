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
 * Construction also refuses the cli SAPI while `apc.enable_cli` is
 * off. A CLI process (RoadRunner worker, queue consumer, command) owns
 * a private APCu segment invisible to the PHP-FPM workers that serve
 * traffic; records stored from CLI can never be verified by the web
 * tier and vice versa. The ini flag is the operator's explicit opt-in
 * to a CLI segment, so with `apc.enable_cli=1` the backend constructs
 * and the deployment owns the segment hazard (the doctor warns). CLI
 * hosts without the opt-in select the Redis or SQLite store instead.
 *
 * The atomicity promises are APCu's own: within one SAPI's segment the
 * region is shared memory guarded by APCu's internal lock,
 * `apcu_add()` is the atomic create-if-absent the storage's transition
 * lock builds on, and a TTL-expired entry reads as absent on fetch.
 */
final class RealApcuBackend implements ApcuBackendInterface
{
    /**
     * @param \Closure|null $sapiEnvironment the simulated SAPI
     *                                       environment for the cli
     *                                       detection, an array of the
     *                                       SAPI name and the raw
     *                                       apc.enable_cli ini value;
     *                                       defaults to reading the
     *                                       real process. The seam the
     *                                       constructor of
     *                                       {@see ApcuStorage} forwards
     *                                       its own probed values
     *                                       through, so both layers
     *                                       decide on one environment.
     *
     * @throws ApcuStorageException when the APCu extension is not
     *                              loaded or is disabled for this
     *                              process, or the process runs under
     *                              the cli SAPI with apc.enable_cli off
     */
    public function __construct(?\Closure $sapiEnvironment = null)
    {
        [$sapi, $enableCliRaw] = $sapiEnvironment !== null
            ? $sapiEnvironment()
            : [\PHP_SAPI, \ini_get('apc.enable_cli')];
        if (self::cliConstructionRefused($sapi, self::apcEnableCliIni($enableCliRaw))) {
            throw new ApcuStorageException(
                'ApcuStorage refuses the cli SAPI while apc.enable_cli is off: a CLI process '
                . '(RoadRunner worker, queue consumer, command) owns a private APCu segment '
                . 'invisible to the web tier that serves traffic. Set apc.enable_cli=1 in '
                . 'php.ini to opt this CLI host into its own segment, or select the '
                . 'Redis/SQLite store for CLI hosts.'
            );
        }
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

    /**
     * The cli-refusal decision, pure: the cli SAPI refuses while the
     * apc.enable_cli opt-in is off, every other SAPI constructs, and a
     * CLI host that sets the ini constructs and owns the private
     * segment its operator opted into.
     */
    public static function cliConstructionRefused(string $sapi, bool $apcEnableCliIni): bool
    {
        return $sapi === 'cli' && !$apcEnableCliIni;
    }

    /**
     * The apc.enable_cli ini read, parsed as a boolean the way PHP
     * stores ini values: on is 1, true, on or yes (case-insensitive);
     * everything else, including an unset entry (the extension is not
     * loaded, so ini_get() answers false), is off.
     *
     * @param string|false $raw the ini_get('apc.enable_cli') answer
     */
    public static function apcEnableCliIni(string|false $raw): bool
    {
        if ($raw === false) {
            return false;
        }

        return \in_array(strtolower(trim($raw)), ['1', 'true', 'on', 'yes'], true);
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
