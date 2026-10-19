package com.kiwicaptcha;

/**
 * BLAKE2b, the RFC 7693 hash, one-shot form. The JDK carries no
 * blake2b, so the pure proof-phase derivation stack (argon2id) is
 * built on this implementation. Supports the variable digest length
 * of 1 to 64 bytes and an optional key, the two parameters the
 * protocol derivation surfaces use.
 */
public final class Blake2b {
    private Blake2b() {}

    private static final int BLOCK_BYTES = 128;
    private static final int ROUNDS = 12;

    private static final long[] IV = {
        0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL,
        0xa54ff53a5f1d36f1L, 0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
        0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L,
    };

    private static final byte[][] SIGMA = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    };

    /**
     * One-shot blake2b over the message with the digest length and an
     * optional key. Mirrors the hashlib.blake2b surfaces the php and
     * Python cores use on this path.
     */
    public static byte[] digest(int digestLength, byte[] key, byte[] message) {
        if (digestLength < 1 || digestLength > 64) {
            throw new IllegalArgumentException("blake2b digest length must be 1..64");
        }
        if (key == null) {
            key = new byte[0];
        }
        if (key.length > 64) {
            throw new IllegalArgumentException("blake2b key must be at most 64 bytes");
        }
        long[] h = IV.clone();
        h[0] ^= 0x01010000L ^ ((long) key.length << 8) ^ digestLength;

        long[] m = new long[16];
        long[] v = new long[16];
        int offset = 0;
        long seen = 0;
        if (key.length > 0) {
            byte[] keyed = new byte[BLOCK_BYTES];
            System.arraycopy(key, 0, keyed, 0, key.length);
            if (message.length == 0) {
                // The key block is the only block: it compresses once,
                // as the final block, per the reference implementation.
                compress(h, m, v, keyed, 0, BLOCK_BYTES, true);
            } else {
                compress(h, m, v, keyed, 0, BLOCK_BYTES, false);
            }
            seen = BLOCK_BYTES;
        }
        if (message.length > 0) {
            int remaining = message.length;
            while (remaining > BLOCK_BYTES) {
                compress(h, m, v, message, offset, seen + BLOCK_BYTES, false);
                seen += BLOCK_BYTES;
                offset += BLOCK_BYTES;
                remaining -= BLOCK_BYTES;
            }
            byte[] last = new byte[BLOCK_BYTES];
            System.arraycopy(message, offset, last, 0, remaining);
            compress(h, m, v, last, 0, seen + remaining, true);
        } else if (key.length == 0) {
            // The keyless empty message still compresses one zero
            // block as final, with a zero counter.
            compress(h, m, v, new byte[BLOCK_BYTES], 0, 0, true);
        }

        byte[] out = new byte[digestLength];
        for (int i = 0; i < digestLength; i++) {
            out[i] = (byte) (h[i / 8] >>> (8 * (i % 8)));
        }
        return out;
    }

    private static void compress(long[] h, long[] m, long[] v, byte[] block, int blockOffset,
                                 long blockLength, boolean isLast) {
        for (int i = 0; i < 16; i++) {
            m[i] = littleEndianWord(block, blockOffset + i * 8);
        }
        System.arraycopy(h, 0, v, 0, 8);
        System.arraycopy(IV, 0, v, 8, 8);
        v[12] ^= blockLength;
        if (isLast) {
            v[14] ^= 0xffffffffffffffffL;
        }

        for (int round = 0; round < ROUNDS; round++) {
            byte[] s = SIGMA[round];
            g(v, m, s[0], s[1], 0, 4, 8, 12);
            g(v, m, s[2], s[3], 1, 5, 9, 13);
            g(v, m, s[4], s[5], 2, 6, 10, 14);
            g(v, m, s[6], s[7], 3, 7, 11, 15);
            g(v, m, s[8], s[9], 0, 5, 10, 15);
            g(v, m, s[10], s[11], 1, 6, 11, 12);
            g(v, m, s[12], s[13], 2, 7, 8, 13);
            g(v, m, s[14], s[15], 3, 4, 9, 14);
        }

        for (int i = 0; i < 8; i++) {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    private static void g(long[] v, long[] m, int ma, int mb, int a, int b, int c, int d) {
        v[a] = v[a] + v[b] + m[ma];
        v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + m[mb];
        v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 63);
    }

    private static long littleEndianWord(byte[] bytes, int offset) {
        long result = 0;
        for (int i = 7; i >= 0; i--) {
            result = (result << 8) | (bytes[offset + i] & 0xffL);
        }
        return result;
    }
}
