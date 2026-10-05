/**
 * A compact, dependency-free SHA-256 for the low-difficulty fallback.
 * Correctness is pinned against CryptoKit/openssl test vectors in the
 * Jest suite; it is only ever used below the low-difficulty ceiling,
 * where the expected work is a few hundred hashes.
 */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const W = new Uint32Array(64);

/** SHA-256 over the concatenation of the given byte arrays. */
export function sha256(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const padded = new Uint8Array((Math.floor((total + 8) / 64) + 1) * 64);
  let offset = 0;
  for (const c of chunks) {
    padded.set(c, offset);
    offset += c.length;
  }
  padded[total] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(total / 0x20000000), false);
  view.setUint32(padded.length - 4, (total << 3) >>> 0, false);

  for (let block = 0; block < padded.length; block += 64) {
    for (let i = 0; i < 16; i++) {
      W[i] = view.getUint32(block + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const x = W[i - 15] as number;
      const y = W[i - 2] as number;
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      W[i] = (((W[i - 16] as number) + s0 + (W[i - 7] as number) + s1) | 0) >>> 0;
    }
    let a = h[0] as number;
    let b = h[1] as number;
    let c = h[2] as number;
    let d = h[3] as number;
    let e = h[4] as number;
    let f = h[5] as number;
    let g = h[6] as number;
    let hh = h[7] as number;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + (K[i] as number) + (W[i] as number)) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    h[0] = ((h[0] as number) + a) | 0;
    h[1] = ((h[1] as number) + b) | 0;
    h[2] = ((h[2] as number) + c) | 0;
    h[3] = ((h[3] as number) + d) | 0;
    h[4] = ((h[4] as number) + e) | 0;
    h[5] = ((h[5] as number) + f) | 0;
    h[6] = ((h[6] as number) + g) | 0;
    h[7] = ((h[7] as number) + hh) | 0;
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const v = h[i] as number;
    out[i * 4] = (v >>> 24) & 0xff;
    out[i * 4 + 1] = (v >>> 16) & 0xff;
    out[i * 4 + 2] = (v >>> 8) & 0xff;
    out[i * 4 + 3] = v & 0xff;
  }
  return out;
}

export function hex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/** Leading zero bits, big-endian bit order (the shared difficulty notion). */
export function leadingZeroBits(digest: Uint8Array): number {
  let n = 0;
  for (const b of digest) {
    if (b === 0) {
      n += 8;
      continue;
    }
    let m = b;
    while ((m & 0x80) === 0) {
      n++;
      m <<= 1;
    }
    break;
  }
  return n;
}
