import { createHmac, timingSafeEqual } from 'node:crypto';
import { derivedKeys } from './keys.js';

/**
 * Authentication of the server-written state that the challenge
 * signature does not cover: the record metadata (issued_at_ns and the
 * hostname) and the committed consumed result. The MAC input binds the
 * full challenge string, so a MAC can never be transplanted to another
 * record. Every variable-length field is length-prefixed and every
 * optional field carries a presence tag, mirroring the Rust
 * record_meta_mac and consumed_result_mac byte layout.
 */

export const RECORD_META_DOMAIN = 'kiwi/record-meta/v1';
export const CONSUMED_RESULT_DOMAIN = 'kiwi/consumed-result/v1';

const HEX_64 = /^[0-9a-f]{64}$/;

/** The wire shape of every server-state MAC: 64 lowercase hex. */
export const SERVER_STATE_MAC_PATTERN = HEX_64;

/** The server-state key for a kid secret and the deployment tenant. */
export function serverStateKey(secret: string | Buffer, tenantId: string | null = null): Buffer {
  return derivedKeys(secret, tenantId).serverStateKey;
}

function lp(value: string): string {
  return `${value.length}:${value}`;
}

function opt(value: string | null): string {
  return value === null ? '0' : `1:${lp(value)}`;
}

/** The exact record-metadata MAC input bytes (pinned by the shared vectors). */
export function recordMetaInput(
  challenge: string,
  issuedAtNs: number,
  hostname: string | null,
): string {
  return `${RECORD_META_DOMAIN}\n${lp(challenge)}\n${issuedAtNs}\n${opt(hostname)}`;
}

/** The exact consumed-result MAC input bytes (pinned by the shared vectors). */
export function consumedResultInput(
  challenge: string,
  valid: boolean,
  binding: string | null,
  operationIdentity: string | null,
): string {
  return (
    `${CONSUMED_RESULT_DOMAIN}\n${lp(challenge)}\n` +
    `${valid ? '1' : '0'}\n${opt(binding)}\n${opt(operationIdentity)}`
  );
}

/** The record-metadata MAC over the challenge, issuance clock and hostname. */
export function recordMetaMac(
  key: Buffer,
  challenge: string,
  issuedAtNs: number,
  hostname: string | null,
): string {
  return createHmac('sha256', key).update(recordMetaInput(challenge, issuedAtNs, hostname)).digest('hex');
}

/** The consumed-result MAC over the challenge, verdict, binding and identity. */
export function consumedResultMac(
  key: Buffer,
  challenge: string,
  valid: boolean,
  binding: string | null,
  operationIdentity: string | null,
): string {
  return createHmac('sha256', key)
    .update(consumedResultInput(challenge, valid, binding, operationIdentity))
    .digest('hex');
}

/** Constant-time hex string comparison. */
export function timingSafeEqualsHex(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) {
    return false;
  }
  return timingSafeEqual(ba, bb);
}
