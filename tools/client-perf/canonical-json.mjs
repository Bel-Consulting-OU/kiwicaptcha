#!/usr/bin/env node
/**
 * The canonical JSON + hashing primitives of the client-performance
 * authority. They live in their own module so both the measurement
 * context (measurement-context.mjs) and the measurement-source snapshot
 * (measurement-sources.mjs) can share one implementation without an
 * import cycle.
 */
import { createHash } from 'node:crypto';

/**
 * Canonical JSON of an arbitrary value: object keys sorted recursively,
 * arrays kept in order, no whitespace. The hash domain is therefore
 * stable across JSON member ordering and machines. An `undefined`
 * member is not representable and throws: a hashed field set with a
 * missing member must never hash as if the member were absent.
 */
export function canonicalJson(value) {
  if (value === undefined) {
    throw new Error('canonical-json: undefined is not a representable canonical JSON value (a field is missing); bind the field or refuse the value');
  }
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v)).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

/** SHA-256, lowercase hex. */
export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}
