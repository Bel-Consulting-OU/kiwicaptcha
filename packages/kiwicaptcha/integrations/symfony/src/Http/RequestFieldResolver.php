<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Http;

use Symfony\Component\HttpFoundation\Request;

/**
 * Resolves a submitted form field whatever its nesting depth.
 *
 * Symfony forms nest their data under the form name
 * (`signup[kiwi_request_binding]` arrives as `['signup' =>
 * ['kiwi_request_binding' => ...]]`), so a flat
 * `$request->request->get($field)` misses every nested submission. The
 * lookup walks the request payload one bounded level of nesting at a
 * time, so both flat and nested bindings resolve.
 *
 * Ambiguity fails closed: two distinct values under the same field name
 * (two forms each carrying one) answer null, never a guess. Non-scalar
 * values are never usable field values and answer null.
 */
final class RequestFieldResolver
{
    /** The maximum nesting depth the lookup walks (form + embedded form). */
    private const MAX_DEPTH = 3;

    /**
     * The scalar string value submitted under $field, whatever its
     * nesting depth. Null when absent, non-scalar, or ambiguous.
     */
    public static function string(Request $request, string $field): ?string
    {
        $values = self::resolveMany($request, [$field]);

        return $values[$field] ?? null;
    }

    /**
     * The submitted values of the configured target fields, keyed by
     * field name — the nested-aware shape of a flat request read.
     *
     * @param list<string> $fields
     *
     * @return array<string, string>
     */
    public static function targetFields(Request $request, array $fields): array
    {
        $resolved = [];
        foreach (self::resolveMany($request, $fields) as $name => $value) {
            if ($value !== '') {
                $resolved[$name] = $value;
            }
        }

        return $resolved;
    }

    /**
     * Resolve every requested field in at most one walk of each
     * payload bag. The walk collects string values for all wanted
     * names at once, so the cost is linear in the payload plus the
     * requested field count rather than one full walk per field.
     *
     * @param list<string> $fields
     *
     * @return array<string, string>
     */
    private static function resolveMany(Request $request, array $fields): array
    {
        $wanted = [];
        foreach ($fields as $field) {
            $wanted[$field] = true;
        }
        $found = [];
        self::collect($request->request->all(), $wanted, $found, self::MAX_DEPTH);
        $missing = [];
        foreach ($fields as $field) {
            if (!isset($found[$field])) {
                $missing[$field] = true;
            }
        }
        if ($missing !== []) {
            // The payload bag merges JSON bodies too; fall back to it
            // for clients that posted nested JSON.
            try {
                self::collect($request->getPayload()->all(), $missing, $found, self::MAX_DEPTH);
            } catch (\Throwable) {
                // No payload bag: the form body is the only source.
            }
        }
        $resolved = [];
        foreach ($fields as $field) {
            if (!isset($found[$field])) {
                continue;
            }
            $values = $found[$field];
            if (\count($values) === 1) {
                $resolved[$field] = $values[0];
                continue;
            }
            $distinct = array_values(array_unique($values));
            if (\count($distinct) !== 1) {
                // Two different values under one name: deterministic
                // null, never a guess.
                continue;
            }
            $resolved[$field] = $distinct[0];
        }

        return $resolved;
    }

    /**
     * @param array<mixed>             $data
     * @param array<string, true>      $wanted
     * @param array<string, list<string>> $found
     */
    private static function collect(array $data, array $wanted, array &$found, int $depth): void
    {
        foreach ($data as $key => $value) {
            if (\is_string($key) && isset($wanted[$key])) {
                if (\is_string($value)) {
                    $found[$key][] = $value;
                    continue;
                }
                if ($depth > 0 && \is_array($value)) {
                    // For this field the match already decided the
                    // lookup, so its name stays blocked below; every
                    // other wanted field still descends.
                    $nested = $wanted;
                    unset($nested[$key]);
                    self::collect($value, $nested, $found, $depth - 1);
                }
                continue;
            }
            if ($depth > 0 && \is_array($value)) {
                self::collect($value, $wanted, $found, $depth - 1);
            }
        }
    }
}
