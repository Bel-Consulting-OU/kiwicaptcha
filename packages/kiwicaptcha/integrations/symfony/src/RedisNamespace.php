<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle;

/**
 * The one derivation of a Redis-safe deployment namespace from its raw
 * configured bytes.
 *
 * A namespace is an identity discriminator, never a display string.
 * Replacement-sanitizing it first (`preg_replace` to `_`) folds
 * distinct raw values onto one sanitized value — `tenant/a` and
 * `tenant:a` both become `tenant_a` — and two project directories
 * that differ only in a separator-versus-underscore byte merge. Two
 * deployments sharing one Redis backend would then share every key
 * family built on the namespace. The derivation is therefore a digest
 * of the complete original bytes: injective for every practical
 * input, hex only (safe inside hash tags and every key grammar), and
 * stable across processes. Never derive from a sanitized value.
 *
 * Key shapes built on the derived value differ from the prior
 * sanitized shapes; the state they name is TTL-bound, so the cutover
 * is a deployment-time rollover after the maximum retained
 * security-state lifetime, not a dual-write migration.
 */
final class RedisNamespace
{
    /**
     * @param string $raw the raw configured namespace (a project
     *                    directory, a tenant label, any non-empty
     *                    string)
     *
     * @throws \InvalidArgumentException when the raw namespace is empty
     */
    public static function derive(string $raw): string
    {
        if ($raw === '') {
            throw new \InvalidArgumentException('the deployment namespace cannot be empty: derive() needs the raw configured discriminator');
        }

        return 'n_'.substr(hash('sha256', $raw), 0, 32);
    }

    /**
     * The derived namespace of a possibly-empty raw value under a
     * named fallback: an operator who explicitly leaves the namespace
     * unset shares the fallback's deployment scope by choice, never by
     * folding.
     */
    public static function deriveOr(string $raw, string $fallback): string
    {
        return self::derive($raw !== '' ? $raw : $fallback);
    }
}
