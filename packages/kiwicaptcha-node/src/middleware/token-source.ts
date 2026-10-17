/**
 * The shared token authority rule of the server SDKs, pinned by
 * protocol/decision-v1/corpus.json.
 *
 * Every non-empty value is collected from all three sources (the
 * x-kiwi-token header, the configured form or body field, the
 * same-named query parameter), repeated values included. One distinct
 * value verifies, however many sources carry it. Two or more distinct
 * values refuse the request before any token is verified, so a trusted
 * gateway's header can never be shadowed by an attacker-controlled
 * body field.
 */

export interface TokenSourceValues {
  header: readonly string[];
  form: readonly string[];
  query: readonly string[];
}

export type TokenResolution =
  | { token: string; code: null }
  | { token: null; code: 'malformed_token' | 'token_source_conflict' };

/** Resolve the collected source values under the authority rule. */
export function resolveTokenValues(values: TokenSourceValues): TokenResolution {
  const distinct = new Set<string>();
  for (const value of [...values.header, ...values.form, ...values.query]) {
    if (typeof value !== 'string' || value === '') {
      continue;
    }
    distinct.add(value);
    if (distinct.size > 1) {
      return { token: null, code: 'token_source_conflict' };
    }
  }
  const only = distinct.values().next();
  if (only.done === true) {
    return { token: null, code: 'malformed_token' };
  }
  return { token: only.value, code: null };
}

/** Every non-empty string of a body or query value, repeated values
 * included. */
export function stringValues(value: unknown): string[] {
  if (typeof value === 'string') {
    return value === '' ? [] : [value];
  }
  if (Array.isArray(value)) {
    const values: string[] = [];
    for (const item of value) {
      if (typeof item === 'string' && item !== '') {
        values.push(item);
      }
    }
    return values;
  }
  return [];
}

/**
 * Every header line for x-kiwi-token. Node folds duplicate header
 * lines into one comma-joined value for most headers, so rawHeaders is
 * preferred; a single line may itself carry a comma-joined list. The
 * token alphabet has no comma, so the split loses nothing.
 */
export function headerTokenValues(
  rawHeaders: readonly string[] | undefined,
  merged: unknown,
): string[] {
  const values: string[] = [];
  if (rawHeaders !== undefined) {
    for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
      const name = rawHeaders[index];
      if (typeof name !== 'string' || name.toLowerCase() !== 'x-kiwi-token') {
        continue;
      }
      for (const part of (rawHeaders[index + 1] ?? '').split(',')) {
        const value = part.trim();
        if (value !== '') {
          values.push(value);
        }
      }
    }
    return values;
  }
  for (const value of stringValues(merged)) {
    for (const part of value.split(',')) {
      const trimmed = part.trim();
      if (trimmed !== '') {
        values.push(trimmed);
      }
    }
  }
  return values;
}
