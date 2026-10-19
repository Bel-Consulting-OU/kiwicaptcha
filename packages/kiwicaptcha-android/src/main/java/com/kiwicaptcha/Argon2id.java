package com.kiwicaptcha;

/**
 * Pure JDK Argon2id, version 1.3, per RFC 9106 and the reference
 * implementation. The JVM ships no argon2 binding, so the proof-phase
 * recompute for argon2id records is implemented here over the pure
 * Blake2b. Every exported profile the protocol allows is computed:
 * one to four lanes and one to sixteen passes, with the memory
 * parameter in KiB exactly like the PHP verifier's libsodium call
 * (sodium_crypto_pwhash with memlimit = m_kib * 1024, a 32-byte tag).
 * The protocol profile split pins lanes to one and t to at least
 * three; the general implementation keeps the full parameter space so
 * the RFC vectors pin it.
 */
public final class Argon2id {
    private Argon2id() {}

    private static final int TYPE_ARGON2ID = 2;
    private static final int VERSION_13 = 0x13;
    private static final int SYNC_POINTS = 4;
    private static final int ADDRESSES_IN_BLOCK = 128;
    private static final int BLOCK_QWORDS = 128;
    private static final long MASK32 = 0xffffffffL;

    /** Raised when the requested parameters leave the implementable space. */
    public static final class Argon2Exception extends RuntimeException {
        public Argon2Exception(String message) {
            super(message);
        }
    }

    /**
     * Derives an Argon2id tag, byte-identical to the reference build.
     * lanes is the parallelism p, tCost the passes, mCost the memory
     * in KiB.
     */
    public static byte[] derive(byte[] password, byte[] salt, int tCost, int mCost,
                                int lanes, int outLen, byte[] secret, byte[] ad) {
        if (tCost < 1) {
            throw new Argon2Exception("argon2 passes must be at least 1");
        }
        if (lanes < 1 || lanes > 0xffffff) {
            throw new Argon2Exception("argon2 lanes out of range");
        }
        if (mCost < 8 * lanes) {
            throw new Argon2Exception("argon2 memory must cover eight blocks per lane");
        }
        int mPrime = (4 * lanes) * (mCost / (4 * lanes));
        int laneLength = mPrime / lanes;
        int segLen = laneLength / SYNC_POINTS;
        long[][] memory = new long[mPrime][];

        byte[] h0 = h0(lanes, outLen, mCost, tCost, password, salt, secret, ad);
        for (int lane = 0; lane < lanes; lane++) {
            int base = lane * laneLength;
            for (int firstWord = 0; firstWord <= 1; firstWord++) {
                byte[] seed = concat(h0, le32(firstWord), le32(lane));
                memory[base + firstWord] = loadBlock(hPrime(1024, seed));
            }
        }
        for (int pickPass = 0; pickPass < tCost; pickPass++) {
            for (int pickSlice = 0; pickSlice < SYNC_POINTS; pickSlice++) {
                for (int lane = 0; lane < lanes; lane++) {
                    fillSegment(memory, lanes, laneLength, segLen, pickPass, pickSlice, lane, tCost, mPrime);
                }
            }
        }
        long[] finalBlock = memory[laneLength - 1].clone();
        for (int lane = 1; lane < lanes; lane++) {
            long[] last = memory[lane * laneLength + laneLength - 1];
            for (int i = 0; i < BLOCK_QWORDS; i++) {
                finalBlock[i] ^= last[i];
            }
        }
        return hPrime(outLen, storeBlock(finalBlock));
    }

    private static void fillSegment(long[][] memory, int lanes, int laneLength, int segLen,
                                    int pickPass, int pickSlice, int lane, int tCost, int mPrime) {
        boolean independent = pickPass == 0 && pickSlice < SYNC_POINTS / 2;
        long[] inputBlock = new long[BLOCK_QWORDS];
        if (independent) {
            inputBlock[0] = pickPass;
            inputBlock[1] = lane;
            inputBlock[2] = pickSlice;
            inputBlock[3] = mPrime;
            inputBlock[4] = tCost;
            inputBlock[5] = TYPE_ARGON2ID;
        }
        long[] address = null;
        int[] counterCell = {0};
        int start = 0;
        if (pickPass == 0 && pickSlice == 0) {
            start = 2;
            if (independent) {
                address = nextAddresses(inputBlock, counterCell);
            }
        }
        int curr = lane * laneLength + pickSlice * segLen + start;
        int prev = curr % laneLength == 0 ? curr + laneLength - 1 : curr - 1;
        for (int i = start; i < segLen; i++, curr++, prev++) {
            if (curr % laneLength == 1) {
                prev = curr - 1;
            }
            long pseudoRand;
            if (independent) {
                if (i % ADDRESSES_IN_BLOCK == 0) {
                    address = nextAddresses(inputBlock, counterCell);
                }
                pseudoRand = address[i % ADDRESSES_IN_BLOCK];
            } else {
                pseudoRand = memory[prev][0];
            }
            int refLane = (int) ((pseudoRand >>> 32) % lanes);
            if (pickPass == 0 && pickSlice == 0) {
                refLane = lane;
            }
            boolean sameLane = refLane == lane;
            int refIndex = indexAlpha(pickPass, pickSlice, i, segLen, laneLength,
                    pseudoRand & MASK32, sameLane);
            long[] refBlock = memory[refLane * laneLength + refIndex];
            long[] prevBlock = memory[prev];
            if (pickPass == 0) {
                memory[curr] = fillBlock(prevBlock, refBlock, null);
            } else {
                memory[curr] = fillBlock(prevBlock, refBlock, memory[curr]);
            }
        }
    }

    private static long[] nextAddresses(long[] inputBlock, int[] counterCell) {
        counterCell[0]++;
        inputBlock[6] = counterCell[0];
        long[] address = fillBlock(new long[BLOCK_QWORDS], inputBlock, null);
        return fillBlock(new long[BLOCK_QWORDS], address, null);
    }

    private static int indexAlpha(int pickPass, int pickSlice, int index, int segLen,
                                  int laneLength, long pseudoRand, boolean sameLane) {
        int ras;
        if (pickPass == 0) {
            if (pickSlice == 0) {
                ras = index - 1;
            } else if (sameLane) {
                ras = pickSlice * segLen + index - 1;
            } else {
                ras = pickSlice * segLen + (index == 0 ? -1 : 0);
            }
        } else if (sameLane) {
            ras = laneLength - segLen + index - 1;
        } else {
            ras = laneLength - segLen + (index == 0 ? -1 : 0);
        }
        ras &= (int) MASK32;
        // Both products stay below 2^64 over 32-bit operands, so the
        // unsigned shift of the wrapping long product is the exact
        // Python >> 32.
        long rel = (pseudoRand * pseudoRand) >>> 32;
        rel = (Integer.toUnsignedLong(ras) - 1 - ((Integer.toUnsignedLong(ras) * rel) >>> 32)) & MASK32;
        int start = 0;
        if (pickPass != 0 && pickSlice != SYNC_POINTS - 1) {
            start = (pickSlice + 1) * segLen;
        }
        return (int) ((start + rel) % laneLength);
    }

    private static long[] fillBlock(long[] prevBlock, long[] refBlock, long[] oldNext) {
        long[] r = new long[BLOCK_QWORDS];
        long[] tmp = new long[BLOCK_QWORDS];
        for (int i = 0; i < BLOCK_QWORDS; i++) {
            r[i] = prevBlock[i] ^ refBlock[i];
            tmp[i] = r[i];
        }
        if (oldNext != null) {
            for (int i = 0; i < BLOCK_QWORDS; i++) {
                tmp[i] ^= oldNext[i];
            }
        }
        long[] z = compressInto(r);
        for (int i = 0; i < BLOCK_QWORDS; i++) {
            tmp[i] ^= z[i];
        }
        return tmp;
    }

    /** Applies G's two P passes over R and returns the result Z. */
    private static long[] compressInto(long[] r) {
        long[] t = r.clone();
        for (int i = 0; i < 8; i++) {
            int base = 16 * i;
            long[] column = new long[16];
            System.arraycopy(t, base, column, 0, 16);
            pPerm(column);
            System.arraycopy(column, 0, t, base, 16);
        }
        for (int i = 0; i < 8; i++) {
            int base = 2 * i;
            long[] column = {
                t[base], t[base + 1],
                t[base + 16], t[base + 17],
                t[base + 32], t[base + 33],
                t[base + 48], t[base + 49],
                t[base + 64], t[base + 65],
                t[base + 80], t[base + 81],
                t[base + 96], t[base + 97],
                t[base + 112], t[base + 113],
            };
            pPerm(column);
            for (int k = 0; k < 8; k++) {
                t[base + 16 * k] = column[2 * k];
                t[base + 16 * k + 1] = column[2 * k + 1];
            }
        }
        return t;
    }

    private static long rotr(long value, int bits) {
        return Long.rotateRight(value, bits);
    }

    private static long low32(long value) {
        return value & 0xffffffffL;
    }

    /** One G of the argon2 compression, in place over the four words. */
    private static void gb(long[] v, int a, int b, int c, int d) {
        v[a] = v[a] + v[b] + 2L * low32(v[a]) * low32(v[b]);
        v[d] = rotr(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d] + 2L * low32(v[c]) * low32(v[d]);
        v[b] = rotr(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + 2L * low32(v[a]) * low32(v[b]);
        v[d] = rotr(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d] + 2L * low32(v[c]) * low32(v[d]);
        v[b] = rotr(v[b] ^ v[c], 63);
    }

    /**
     * The permutation P over sixteen 64-bit words: one column round
     * and one diagonal round, the exact pairs the reference applies.
     */
    private static void pPerm(long[] v) {
        gb(v, 0, 4, 8, 12);
        gb(v, 1, 5, 9, 13);
        gb(v, 2, 6, 10, 14);
        gb(v, 3, 7, 11, 15);
        gb(v, 0, 5, 10, 15);
        gb(v, 1, 6, 11, 12);
        gb(v, 2, 7, 8, 13);
        gb(v, 3, 4, 9, 14);
    }

    private static byte[] h0(int lanes, int outLen, int mCost, int tCost,
                             byte[] password, byte[] salt, byte[] secret, byte[] ad) {
        byte[][] parts = {
            le32(lanes), le32(outLen), le32(mCost), le32(tCost), le32(VERSION_13), le32(TYPE_ARGON2ID),
            le32(password.length), password,
            le32(salt.length), salt,
            le32(secret.length), secret,
            le32(ad.length), ad,
        };
        return Blake2b.digest(64, new byte[0], concat(parts));
    }

    /** The variable-length hash H'(T, A), mirroring blake2b_long. */
    static byte[] hPrime(int tLen, byte[] data) {
        if (tLen <= 64) {
            return Blake2b.digest(tLen, new byte[0], concat(le32(tLen), data));
        }
        byte[] v = Blake2b.digest(64, new byte[0], concat(le32(tLen), data));
        byte[] out = new byte[32];
        System.arraycopy(v, 0, out, 0, 32);
        int toProduce = tLen - 32;
        while (toProduce > 64) {
            v = Blake2b.digest(64, new byte[0], v);
            byte[] grown = new byte[out.length + 32];
            System.arraycopy(out, 0, grown, 0, out.length);
            System.arraycopy(v, 0, grown, out.length, 32);
            out = grown;
            toProduce -= 32;
        }
        byte[] tail = Blake2b.digest(toProduce, new byte[0], v);
        byte[] full = new byte[out.length + tail.length];
        System.arraycopy(out, 0, full, 0, out.length);
        System.arraycopy(tail, 0, full, out.length, tail.length);
        return full;
    }

    private static long[] loadBlock(byte[] raw) {
        long[] block = new long[BLOCK_QWORDS];
        for (int i = 0; i < BLOCK_QWORDS; i++) {
            block[i] = littleEndianWord(raw, i * 8);
        }
        return block;
    }

    private static byte[] storeBlock(long[] block) {
        byte[] out = new byte[BLOCK_QWORDS * 8];
        for (int i = 0; i < BLOCK_QWORDS; i++) {
            long word = block[i];
            for (int j = 0; j < 8; j++) {
                out[i * 8 + j] = (byte) (word >>> (8 * j));
            }
        }
        return out;
    }

    private static byte[] le32(int value) {
        return new byte[]{
            (byte) value, (byte) (value >>> 8), (byte) (value >>> 16), (byte) (value >>> 24),
        };
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    private static long littleEndianWord(byte[] bytes, int offset) {
        long result = 0;
        for (int i = 7; i >= 0; i--) {
            result = (result << 8) | (bytes[offset + i] & 0xffL);
        }
        return result;
    }
}
