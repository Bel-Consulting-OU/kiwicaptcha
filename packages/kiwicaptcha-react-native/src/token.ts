/**
 * Token assembly: the same grammar the widget driver and the Rust
 * solver produce, base64(nonce.counter.durationMs.telemetry) with the
 * rsw proof riding as the final 512-hex segment.
 *
 * base64 here is a dependency-free canonical encoder (padded, standard
 * alphabet), so no platform polyfill is required.
 */

const TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function base64Encode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = i + 1 < bytes.length ? (bytes[i + 1] ?? 0) : 0;
    const b2 = i + 2 < bytes.length ? (bytes[i + 2] ?? 0) : 0;
    out += TABLE.charAt((b0 >> 2) & 0x3f);
    out += TABLE.charAt(((b0 << 4) | (b1 >> 4)) & 0x3f);
    out += i + 1 < bytes.length ? TABLE.charAt(((b1 << 2) | (b2 >> 6)) & 0x3f) : "=";
    out += i + 2 < bytes.length ? TABLE.charAt(b2 & 0x3f) : "=";
  }
  return out;
}

function utf8Bytes(value: string): Uint8Array {
  // TextEncoder exists in Hermes (react-native 0.73+) and Jest; the
  // manual path covers anything older.
  if (typeof TextEncoder !== "undefined") {
    return new TextEncoder().encode(value) as Uint8Array;
  }
  const out = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c > 0x7f) throw new Error("non-ASCII telemetry is not supported on this runtime");
    out[i] = c;
  }
  return out;
}

export interface TokenInput {
  nonce: string;
  counter: number;
  durationMs: number;
  /** Folded verbatim; the off-widget default is the empty object. */
  telemetry?: Record<string, unknown>;
  /** The rsw final value, 512 lowercase hex. */
  rswProof?: string;
}

/** Pack the wire token the verify endpoint accepts. */
export function encodeToken(input: TokenInput): string {
  const duration = Math.max(0, Math.min(input.durationMs, 3600000));
  const telemetry = JSON.stringify(input.telemetry ?? {});
  let plain = `${input.nonce}.${input.counter}.${duration}.${telemetry}`;
  if (input.rswProof !== undefined) {
    if (!/^[0-9a-f]{512}$/.test(input.rswProof)) {
      throw new Error("the rsw proof must be 512 lowercase hex characters");
    }
    plain += `.${input.rswProof}`;
  }
  return base64Encode(utf8Bytes(plain));
}
