#!/usr/bin/env node
/**
 * The shared strict ISO-8601 instant parser for the qualification
 * validators (accessibility and autofill). It exists so freshness
 * checks can never be fooled by a malformed timestamp and so the two
 * validators cannot drift apart:
 *
 *   - the calendar components must be real (no 2026-02-30, no hour 24);
 *   - the seconds/minute/hour components are range-checked;
 *   - a numeric offset is range-checked (+23:59 is the maximum; +24:00,
 *     +99:99 and +01:60 are rejected);
 *   - the value must parse to a finite epoch. The epoch is returned so
 *     callers never call Date.parse() a second time: a NaN epoch compared
 *     with `<`/`>` is silently false in both directions, which used to
 *     make a malformed timestamp pass BOTH the future and the age check.
 *
 * Usage:
 *   import { parseStrictIsoInstant } from './strict-iso-instant.mjs';
 *   const epoch = parseStrictIsoInstant(row.tested_at);
 *   if (epoch === null) reasons.push('not a strict ISO-8601 instant');
 *   else { future/age checks on epoch }
 */

const STRICT_ISO_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(Z|([+-])(\d{2}):(\d{2}))$/;

/**
 * Parse a strict ISO-8601 instant to its epoch milliseconds, or null
 * when the value is not a real, unambiguous instant.
 */
export function parseStrictIsoInstant(value) {
  if (typeof value !== 'string') return null;
  const match = value.match(STRICT_ISO_PATTERN);
  if (!match) return null;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6] ?? 0);

  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;

  if (match[7] !== 'Z') {
    const offsetHour = Number(match[9]);
    const offsetMinute = Number(match[10]);
    if (offsetHour > 23 || offsetMinute > 59) return null;
  }

  const calendarProbe = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (
    calendarProbe.getUTCFullYear() !== year ||
    calendarProbe.getUTCMonth() !== month - 1 ||
    calendarProbe.getUTCDate() !== day ||
    calendarProbe.getUTCHours() !== hour ||
    calendarProbe.getUTCMinutes() !== minute ||
    calendarProbe.getUTCSeconds() !== second
  ) {
    return null;
  }

  const epoch = Date.parse(value);
  return Number.isFinite(epoch) ? epoch : null;
}
