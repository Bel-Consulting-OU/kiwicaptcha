import { createHash } from 'node:crypto';
import { MIN_SECRET_BYTES } from './keys.js';
import type { StoreAdapter } from './store.js';
import type { RswVerifierConfig } from './verify.js';
import { Rsw } from './rsw.js';

/**
 * The doctor: the deployment self-check of the shared server-SDK
 * contract. It validates the four-setting quickstart surface (the
 * profile is an adoption choice, so the doctor checks the other
 * three): secret strength, store reachability and atomicity, and the
 * optional rsw trapdoor pair. Findings come back typed and ordered so
 * a wrapper can print or assert them.
 */

export interface DoctorCheck {
  readonly name: string;
  readonly ok: boolean;
  readonly detail: string;
}

export interface DoctorInput {
  /** The master secret of the deployment. */
  secret: string | Buffer;
  /** The store adapter to probe. */
  store: StoreAdapter;
  /** The optional rsw trapdoor configuration to validate. */
  rsw?: RswVerifierConfig | null;
  /** The optional expected region (identifier shape check). */
  region?: string | null;
  /** The optional expected issuer (identifier shape check). */
  issuer?: string | null;
}

export interface DoctorReport {
  readonly ok: boolean;
  readonly checks: readonly DoctorCheck[];
}

const IDENTIFIER_ALPHABET = /^[A-Za-z0-9._:-]+$/;

/**
 * Run every deployment check. The store probe writes a nonce-shaped
 * probe record, consumes it, and requires the exactly-once semantics:
 * the second consume must answer consumedBefore with no fresh win.
 */
export async function runDoctor(input: DoctorInput): Promise<DoctorReport> {
  const checks: DoctorCheck[] = [];

  const secretLength = Buffer.isBuffer(input.secret) ? input.secret.length : Buffer.byteLength(input.secret, 'utf8');
  checks.push({
    name: 'secret',
    ok: secretLength >= MIN_SECRET_BYTES,
    detail:
      secretLength >= MIN_SECRET_BYTES
        ? `${secretLength} bytes, meets the ${MIN_SECRET_BYTES}-byte floor`
        : `${secretLength} bytes, below the ${MIN_SECRET_BYTES}-byte floor`,
  });

  const regionOk = input.region === null || input.region === undefined || IDENTIFIER_ALPHABET.test(input.region);
  checks.push({
    name: 'region',
    ok: regionOk,
    detail: regionOk ? 'identifier shape valid or unset' : 'region must match [A-Za-z0-9._:-]',
  });

  const issuerOk = input.issuer === null || input.issuer === undefined || IDENTIFIER_ALPHABET.test(input.issuer);
  checks.push({
    name: 'issuer',
    ok: issuerOk,
    detail: issuerOk ? 'identifier shape valid or unset' : 'issuer must match [A-Za-z0-9._:-]',
  });

  checks.push(await probeStore(input.store));

  if (input.rsw !== null && input.rsw !== undefined) {
    checks.push(probeRsw(input.rsw));
  }

  return { ok: checks.every((check) => check.ok), checks };
}

async function probeStore(store: StoreAdapter): Promise<DoctorCheck> {
  const probe = createHash('sha256').update(String(Date.now())).digest();
  const nonce = probe.toString('base64');
  const now = Math.floor(Date.now() / 1000);
  const record = {
    nonce,
    scope: 'doctor',
    bindingTag: '',
    issuedAt: now,
    expiresAt: now + 120,
    algorithm: 'sha256' as const,
    mKib: 0,
    t: 1,
    p: 1,
    targetBits: 1,
    salt: probe.subarray(0, 16).toString('base64'),
    prefix: `${nonce}.`,
    challenge: `${nonce}.sig`,
    minDurationMs: 0,
    issuedAtNs: 0,
    protocolVersion: 2,
    region: null,
    policyVersion: 1,
    requestBinding: null,
    issuer: null,
    kid: 1,
    hostname: null,
    decoyField: null,
    executionProgram: null,
    executionVersion: null,
    executionCommitment: null,
    rswModulusSha256: null,
    serverMac: null,
  };
  try {
    await store.store(record);
    const found = await store.find(nonce);
    if (found === null) {
      return { name: 'store', ok: false, detail: 'the probe record did not read back' };
    }
    const first = await store.consume(nonce);
    if (first === null || !first.consumedNow) {
      return { name: 'store', ok: false, detail: 'the first probe consume did not win' };
    }
    const second = await store.consume(nonce);
    if (second === null || !second.consumedBefore) {
      return {
        name: 'store',
        ok: false,
        detail: 'the second probe consume won again: the store is not single-use',
      };
    }
    return { name: 'store', ok: true, detail: 'reachable and single-use under the probe' };
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return { name: 'store', ok: false, detail: `store probe failed: ${detail}` };
  }
}

function probeRsw(config: RswVerifierConfig): DoctorCheck {
  try {
    const trapdoor = new Rsw(config.modulusN, config.lambda);
    return { name: 'rsw', ok: true, detail: `trapdoor valid for modulus ${trapdoor.n.toString(16).slice(0, 16)}...` };
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return { name: 'rsw', ok: false, detail };
  }
}
