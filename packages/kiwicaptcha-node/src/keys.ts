import { createHash, hkdfSync } from 'node:crypto';

/**
 * Purpose-key separation, byte-identical to the PHP DerivedKeys and the
 * Rust keys module. Every cryptographic purpose derives its own 32-byte
 * key from the single master secret:
 *
 *   PRK           = HKDF-Extract(SHA-256, salt = deploy salt, ikm = master)
 *   K_challenge   = HKDF-Expand(PRK, "kiwi/v2/challenge-sign", 32)
 *   K_ip_bind     = HKDF-Expand(PRK, "kiwi/v2/ip-bind", 32)
 *   K_result      = HKDF-Expand(PRK, "kiwi/v2/result-token", 32)
 *   K_server      = HKDF-Expand(PRK, "kiwi/v2/server-state", 32)
 *
 * A tenant id derives the purpose keys under the per-tenant root
 * "kiwi/v2/tenant/" + tenant id, so tenants of one shared master
 * secret cannot forge each other's material.
 */

/** The public deployment salt of the extraction step (domain separation). */
export const HKDF_DEPLOY_SALT = 'kiwicaptcha/deploy-salt/v1';

export const INFO_CHALLENGE_SIGN = 'kiwi/v2/challenge-sign';
export const INFO_IP_BIND = 'kiwi/v2/ip-bind';
export const INFO_RESULT_TOKEN = 'kiwi/v2/result-token';
export const INFO_SERVER_STATE = 'kiwi/v2/server-state';
export const INFO_TENANT_ROOT_PREFIX = 'kiwi/v2/tenant/';

/** The minimum master secret length, mirroring the shared limits register. */
export const MIN_SECRET_BYTES = 32;

export interface DerivedKeys {
  /** The challenge-signing key: HMAC over the canonical payload. */
  readonly challengeKey: Buffer;
  /** The IP-binding key: HMAC over nonce plus canonical IP bytes. */
  readonly ipBindKey: Buffer;
  /** The result-token key. */
  readonly resultKey: Buffer;
  /** The server-state key: MAC over record metadata and committed results. */
  readonly serverStateKey: Buffer;
}

function hkdf32(ikm: Buffer, info: string, salt: string): Buffer {
  return Buffer.from(hkdfSync('sha256', ikm, salt, info, 32));
}

function derive(master: Buffer, tenantId: string | null): DerivedKeys {
  let salt = HKDF_DEPLOY_SALT;
  let ikm = master;
  if (tenantId !== null) {
    ikm = hkdf32(master, INFO_TENANT_ROOT_PREFIX + tenantId, salt);
    salt = '';
  }
  return {
    challengeKey: hkdf32(ikm, INFO_CHALLENGE_SIGN, salt),
    ipBindKey: hkdf32(ikm, INFO_IP_BIND, salt),
    resultKey: hkdf32(ikm, INFO_RESULT_TOKEN, salt),
    serverStateKey: hkdf32(ikm, INFO_SERVER_STATE, salt),
  };
}

const cache = new Map<string, DerivedKeys>();
const CACHE_LIMIT = 64;

/**
 * Derive the purpose keys from the master secret, memoized per secret
 * and tenant for the process lifetime. Throws when the secret is
 * shorter than 32 bytes: a short secret must never derive usable keys.
 */
export function derivedKeys(secret: string | Buffer, tenantId: string | null = null): DerivedKeys {
  const master = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'utf8');
  if (master.length < MIN_SECRET_BYTES) {
    throw new RangeError(
      `the master secret must be at least ${MIN_SECRET_BYTES} bytes (got ${master.length})`,
    );
  }
  const presenceTag = tenantId === null ? Buffer.of(0) : Buffer.of(1);
  const tenantBytes = tenantId === null ? Buffer.alloc(0) : Buffer.from(tenantId, 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(tenantBytes.length, 0);
  const masterLen = Buffer.alloc(4);
  masterLen.writeUInt32BE(master.length, 0);
  const cacheKey = createHash('sha256')
    .update(Buffer.concat([presenceTag, len, tenantBytes, masterLen, master]))
    .digest('hex');
  const hit = cache.get(cacheKey);
  if (hit) {
    return hit;
  }
  const derived = derive(master, tenantId);
  if (cache.size >= CACHE_LIMIT) {
    cache.clear();
  }
  cache.set(cacheKey, derived);
  return derived;
}
