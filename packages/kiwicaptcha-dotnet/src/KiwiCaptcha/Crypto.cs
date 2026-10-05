using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace KiwiCaptcha;

/// <summary>
/// BLAKE2b, the RFC 7693 hash, one-shot form. The .NET base class
/// libraries carry no blake2b, so the pure proof-phase derivation
/// stack (argon2id) is built on this implementation. Supports the
/// variable digest length of 1 to 64 bytes and an optional key, the
/// two parameters the protocol derivation surfaces use.
/// </summary>
public static class Blake2b
{
    private const int BlockBytes = 128;
    private const int Rounds = 12;

    private static readonly long[] Iv =
    {
        unchecked((long)0x6a09e667f3bcc908UL), unchecked((long)0xbb67ae8584caa73bUL),
        unchecked((long)0x3c6ef372fe94f82bUL), unchecked((long)0xa54ff53a5f1d36f1UL),
        unchecked((long)0x510e527fade682d1UL), unchecked((long)0x9b05688c2b3e6c1fUL),
        unchecked((long)0x1f83d9abfb41bd6bUL), unchecked((long)0x5be0cd19137e2179UL),
    };

    private static readonly byte[][] Sigma =
    {
        new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        new byte[] {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        new byte[] {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        new byte[] {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        new byte[] {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        new byte[] {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        new byte[] {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        new byte[] {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        new byte[] {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        new byte[] {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
        new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        new byte[] {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    };

    /// <summary>
    /// One-shot blake2b over the message with the digest length and
    /// an optional key.
    /// </summary>
    public static byte[] Digest(int digestLength, byte[]? key, byte[] message)
    {
        if (digestLength is < 1 or > 64)
        {
            throw new ArgumentException("blake2b digest length must be 1..64");
        }
        key ??= Array.Empty<byte>();
        if (key.Length > 64)
        {
            throw new ArgumentException("blake2b key must be at most 64 bytes");
        }
        var h = (long[])Iv.Clone();
        h[0] ^= 0x01010000L ^ ((long)key.Length << 8) ^ digestLength;

        var m = new long[16];
        var v = new long[16];
        var offset = 0;
        long seen = 0;
        if (key.Length > 0)
        {
            var keyed = new byte[BlockBytes];
            Array.Copy(key, keyed, key.Length);
            if (message.Length == 0)
            {
                // The key block is the only block: it compresses
                // once, as the final block, per the reference.
                Compress(h, m, v, keyed, 0, BlockBytes, true);
            }
            else
            {
                Compress(h, m, v, keyed, 0, BlockBytes, false);
            }
            seen = BlockBytes;
        }
        if (message.Length > 0)
        {
            var remaining = message.Length;
            while (remaining > BlockBytes)
            {
                Compress(h, m, v, message, offset, seen + BlockBytes, false);
                seen += BlockBytes;
                offset += BlockBytes;
                remaining -= BlockBytes;
            }
            var last = new byte[BlockBytes];
            Array.Copy(message, offset, last, 0, remaining);
            Compress(h, m, v, last, 0, seen + remaining, true);
        }
        else if (key.Length == 0)
        {
            // The keyless empty message still compresses one zero
            // block as final, with a zero counter.
            Compress(h, m, v, new byte[BlockBytes], 0, 0, true);
        }

        var outBytes = new byte[digestLength];
        for (var i = 0; i < digestLength; i++)
        {
            outBytes[i] = (byte)(h[i / 8] >>> (8 * (i % 8)));
        }
        return outBytes;
    }

    private static void Compress(long[] h, long[] m, long[] v, byte[] block, int blockOffset,
        long blockLength, bool isLast)
    {
        for (var i = 0; i < 16; i++)
        {
            m[i] = LittleEndianWord(block, blockOffset + i * 8);
        }
        Array.Copy(h, v, 8);
        Array.Copy(Iv, 0, v, 8, 8);
        v[12] ^= blockLength;
        if (isLast)
        {
            v[14] ^= -1L;
        }

        for (var round = 0; round < Rounds; round++)
        {
            var s = Sigma[round];
            G(v, m, s[0], s[1], 0, 4, 8, 12);
            G(v, m, s[2], s[3], 1, 5, 9, 13);
            G(v, m, s[4], s[5], 2, 6, 10, 14);
            G(v, m, s[6], s[7], 3, 7, 11, 15);
            G(v, m, s[8], s[9], 0, 5, 10, 15);
            G(v, m, s[10], s[11], 1, 6, 11, 12);
            G(v, m, s[12], s[13], 2, 7, 8, 13);
            G(v, m, s[14], s[15], 3, 4, 9, 14);
        }

        for (var i = 0; i < 8; i++)
        {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    private static long Rotr64(long value, int bits) =>
        (long)System.Numerics.BitOperations.RotateRight((ulong)value, bits);

    private static void G(long[] v, long[] m, int ma, int mb, int a, int b, int c, int d)
    {
        v[a] = v[a] + v[b] + m[ma];
        v[d] = Rotr64(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = Rotr64(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + m[mb];
        v[d] = Rotr64(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Rotr64(v[b] ^ v[c], 63);
    }

    internal static long LittleEndianWord(byte[] bytes, int offset)
    {
        long result = 0;
        for (var i = 7; i >= 0; i--)
        {
            result = (result << 8) | (bytes[offset + i] & 0xffL);
        }
        return result;
    }
}

/// <summary>
/// Pure .NET Argon2id, version 1.3, per RFC 9106 and the reference
/// implementation. The base class libraries ship no argon2 binding,
/// so the proof-phase recompute for argon2id records is implemented
/// here over the pure Blake2b. Every exported profile the protocol
/// allows is computed: one to four lanes and one to sixteen passes,
/// with the memory parameter in KiB exactly like the PHP verifier's
/// libsodium call (sodium_crypto_pwhash with memlimit = m_kib * 1024,
/// a 32-byte tag). The protocol profile split pins lanes to one and t
/// to at least three; the general implementation keeps the full
/// parameter space so the reference vectors pin it.
/// </summary>
public static class Argon2Id
{
    private const int TypeArgon2Id = 2;
    private const int Version13 = 0x13;
    private const int SyncPoints = 4;
    private const int AddressesInBlock = 128;
    private const int BlockQwords = 128;
    private const ulong Mask32 = 0xffffffffL;
    private const int Mask32Int = unchecked((int)0xffffffffL);

    /// <summary>Raised when the requested parameters leave the implementable space.</summary>
    public sealed class Argon2Exception : Exception
    {
        public Argon2Exception(string message) : base(message)
        {
        }
    }

    /// <summary>
    /// Derives an Argon2id tag, byte-identical to the reference
    /// build. lanes is the parallelism p, tCost the passes, mCost the
    /// memory in KiB.
    /// </summary>
    public static byte[] Derive(byte[] password, byte[] salt, int tCost, int mCost, int lanes,
        int outLen, byte[] secret, byte[] ad)
    {
        if (tCost < 1)
        {
            throw new Argon2Exception("argon2 passes must be at least 1");
        }
        if (lanes is < 1 or > 0xffffff)
        {
            throw new Argon2Exception("argon2 lanes out of range");
        }
        if (mCost < 8 * lanes)
        {
            throw new Argon2Exception("argon2 memory must cover eight blocks per lane");
        }
        var mPrime = (4 * lanes) * (mCost / (4 * lanes));
        var laneLength = mPrime / lanes;
        var segLen = laneLength / SyncPoints;
        var memory = new long[mPrime][];

        var h0 = H0(lanes, outLen, mCost, tCost, password, salt, secret, ad);
        for (var lane = 0; lane < lanes; lane++)
        {
            var baseIndex = lane * laneLength;
            for (var firstWord = 0; firstWord <= 1; firstWord++)
            {
                var seed = Concat(h0, Le32(firstWord), Le32(lane));
                memory[baseIndex + firstWord] = LoadBlock(HPrime(1024, seed));
            }
        }
        for (var pickPass = 0; pickPass < tCost; pickPass++)
        {
            for (var pickSlice = 0; pickSlice < SyncPoints; pickSlice++)
            {
                for (var lane = 0; lane < lanes; lane++)
                {
                    FillSegment(memory, lanes, laneLength, segLen, pickPass, pickSlice, lane, tCost, mPrime);
                }
            }
        }
        var finalBlock = (long[])memory[laneLength - 1].Clone();
        for (var lane = 1; lane < lanes; lane++)
        {
            var last = memory[lane * laneLength + laneLength - 1];
            for (var i = 0; i < BlockQwords; i++)
            {
                finalBlock[i] ^= last[i];
            }
        }
        return HPrime(outLen, StoreBlock(finalBlock));
    }

    private static void FillSegment(long[][] memory, int lanes, int laneLength, int segLen,
        int pickPass, int pickSlice, int lane, int tCost, int mPrime)
    {
        var independent = pickPass == 0 && pickSlice < SyncPoints / 2;
        var inputBlock = new long[BlockQwords];
        if (independent)
        {
            inputBlock[0] = pickPass;
            inputBlock[1] = lane;
            inputBlock[2] = pickSlice;
            inputBlock[3] = mPrime;
            inputBlock[4] = tCost;
            inputBlock[5] = TypeArgon2Id;
        }
        long[]? address = null;
        var counterCell = 0;
        var start = 0;
        if (pickPass == 0 && pickSlice == 0)
        {
            start = 2;
            if (independent)
            {
                address = NextAddresses(inputBlock, ref counterCell);
            }
        }
        var curr = lane * laneLength + pickSlice * segLen + start;
        var prev = curr % laneLength == 0 ? curr + laneLength - 1 : curr - 1;
        for (var i = start; i < segLen; i++, curr++, prev++)
        {
            if (curr % laneLength == 1)
            {
                prev = curr - 1;
            }
            long pseudoRand;
            if (independent)
            {
                if (i % AddressesInBlock == 0)
                {
                    address = NextAddresses(inputBlock, ref counterCell);
                }
                pseudoRand = address[i % AddressesInBlock];
            }
            else
            {
                pseudoRand = memory[prev][0];
            }
            var refLane = (int)(((ulong)pseudoRand >> 32) % (ulong)lanes);
            if (pickPass == 0 && pickSlice == 0)
            {
                refLane = lane;
            }
            var sameLane = refLane == lane;
            var refIndex = IndexAlpha(pickPass, pickSlice, i, segLen, laneLength,
                pseudoRand & (long)Mask32, sameLane);
            var refBlock = memory[refLane * laneLength + refIndex];
            var prevBlock = memory[prev];
            memory[curr] = pickPass == 0
                ? FillBlock(prevBlock, refBlock, null)
                : FillBlock(prevBlock, refBlock, memory[curr]);
        }
    }

    private static long[] NextAddresses(long[] inputBlock, ref int counterCell)
    {
        counterCell++;
        inputBlock[6] = counterCell;
        var address = FillBlock(new long[BlockQwords], inputBlock, null);
        return FillBlock(new long[BlockQwords], address, null);
    }

    private static int IndexAlpha(int pickPass, int pickSlice, int index, int segLen,
        int laneLength, long pseudoRand, bool sameLane)
    {
        int ras;
        if (pickPass == 0)
        {
            if (pickSlice == 0)
            {
                ras = index - 1;
            }
            else if (sameLane)
            {
                ras = pickSlice * segLen + index - 1;
            }
            else
            {
                ras = pickSlice * segLen + (index == 0 ? -1 : 0);
            }
        }
        else if (sameLane)
        {
            ras = laneLength - segLen + index - 1;
        }
        else
        {
            ras = laneLength - segLen + (index == 0 ? -1 : 0);
        }
        ras &= Mask32Int;
        // Both products stay below 2^64 over 32-bit operands, so the
        // unsigned shift of the wrapping ulong product is the exact
        // reference >> 32.
        var rel = ((ulong)pseudoRand * (ulong)pseudoRand) >> 32;
        var rasUnsigned = (ulong)ras;
        rel = (rasUnsigned - 1 - (rasUnsigned * rel >> 32)) & Mask32;
        var start = 0;
        if (pickPass != 0 && pickSlice != SyncPoints - 1)
        {
            start = (pickSlice + 1) * segLen;
        }
        return (int)(((ulong)start + rel) % (ulong)laneLength);
    }

    private static long[] FillBlock(long[] prevBlock, long[] refBlock, long[]? oldNext)
    {
        var r = new long[BlockQwords];
        var tmp = new long[BlockQwords];
        for (var i = 0; i < BlockQwords; i++)
        {
            r[i] = prevBlock[i] ^ refBlock[i];
            tmp[i] = r[i];
        }
        if (oldNext != null)
        {
            for (var i = 0; i < BlockQwords; i++)
            {
                tmp[i] ^= oldNext[i];
            }
        }
        var z = CompressInto(r);
        for (var i = 0; i < BlockQwords; i++)
        {
            tmp[i] ^= z[i];
        }
        return tmp;
    }

    /// <summary>Applies G's two P passes over R and returns the result Z.</summary>
    private static long[] CompressInto(long[] r)
    {
        var t = (long[])r.Clone();
        for (var i = 0; i < 8; i++)
        {
            var baseIndex = 16 * i;
            var column = new long[16];
            Array.Copy(t, baseIndex, column, 0, 16);
            PPerm(column);
            Array.Copy(column, 0, t, baseIndex, 16);
        }
        for (var i = 0; i < 8; i++)
        {
            var baseIndex = 2 * i;
            var column = new long[16]
            {
                t[baseIndex], t[baseIndex + 1],
                t[baseIndex + 16], t[baseIndex + 17],
                t[baseIndex + 32], t[baseIndex + 33],
                t[baseIndex + 48], t[baseIndex + 49],
                t[baseIndex + 64], t[baseIndex + 65],
                t[baseIndex + 80], t[baseIndex + 81],
                t[baseIndex + 96], t[baseIndex + 97],
                t[baseIndex + 112], t[baseIndex + 113],
            };
            PPerm(column);
            for (var k = 0; k < 8; k++)
            {
                t[baseIndex + 16 * k] = column[2 * k];
                t[baseIndex + 16 * k + 1] = column[2 * k + 1];
            }
        }
        return t;
    }

    private static long Rotr(long value, int bits) =>
        (long)System.Numerics.BitOperations.RotateRight((ulong)value, bits);

    private static long Low32(long value) => value & 0xffffffffL;

    /// <summary>One G of the argon2 compression, in place over the four words.</summary>
    private static void Gb(long[] v, int a, int b, int c, int d)
    {
        v[a] = v[a] + v[b] + 2L * Low32(v[a]) * Low32(v[b]);
        v[d] = Rotr(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d] + 2L * Low32(v[c]) * Low32(v[d]);
        v[b] = Rotr(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + 2L * Low32(v[a]) * Low32(v[b]);
        v[d] = Rotr(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d] + 2L * Low32(v[c]) * Low32(v[d]);
        v[b] = Rotr(v[b] ^ v[c], 63);
    }

    /// <summary>
    /// The permutation P over sixteen 64-bit words: one column round
    /// and one diagonal round, the exact pairs the reference applies.
    /// </summary>
    private static void PPerm(long[] v)
    {
        Gb(v, 0, 4, 8, 12);
        Gb(v, 1, 5, 9, 13);
        Gb(v, 2, 6, 10, 14);
        Gb(v, 3, 7, 11, 15);
        Gb(v, 0, 5, 10, 15);
        Gb(v, 1, 6, 11, 12);
        Gb(v, 2, 7, 8, 13);
        Gb(v, 3, 4, 9, 14);
    }

    private static byte[] H0(int lanes, int outLen, int mCost, int tCost,
        byte[] password, byte[] salt, byte[] secret, byte[] ad)
    {
        using var h = new IncrementalBlake2b64();
        h.Update(Le32(lanes));
        h.Update(Le32(outLen));
        h.Update(Le32(mCost));
        h.Update(Le32(tCost));
        h.Update(Le32(Version13));
        h.Update(Le32(TypeArgon2Id));
        h.Update(Le32(password.Length));
        h.Update(password);
        h.Update(Le32(salt.Length));
        h.Update(salt);
        h.Update(Le32(secret.Length));
        h.Update(secret);
        h.Update(Le32(ad.Length));
        h.Update(ad);
        return h.Digest();
    }

    /// <summary>The variable-length hash H'(T, A), mirroring blake2b_long.</summary>
    internal static byte[] HPrime(int tLen, byte[] data)
    {
        if (tLen <= 64)
        {
            return Blake2b.Digest(tLen, Array.Empty<byte>(), Concat(Le32(tLen), data));
        }
        var v = Blake2b.Digest(64, Array.Empty<byte>(), Concat(Le32(tLen), data));
        var outBytes = new byte[32];
        Array.Copy(v, outBytes, 32);
        var toProduce = tLen - 32;
        while (toProduce > 64)
        {
            v = Blake2b.Digest(64, Array.Empty<byte>(), v);
            var grown = new byte[outBytes.Length + 32];
            Array.Copy(outBytes, grown, outBytes.Length);
            Array.Copy(v, 0, grown, outBytes.Length, 32);
            outBytes = grown;
            toProduce -= 32;
        }
        var tail = Blake2b.Digest(toProduce, Array.Empty<byte>(), v);
        var full = new byte[outBytes.Length + tail.Length];
        Array.Copy(outBytes, full, outBytes.Length);
        Array.Copy(tail, 0, full, outBytes.Length, tail.Length);
        return full;
    }

    private static long[] LoadBlock(byte[] raw)
    {
        var block = new long[BlockQwords];
        for (var i = 0; i < BlockQwords; i++)
        {
            block[i] = Blake2b.LittleEndianWord(raw, i * 8);
        }
        return block;
    }

    private static byte[] StoreBlock(long[] block)
    {
        var outBytes = new byte[BlockQwords * 8];
        for (var i = 0; i < BlockQwords; i++)
        {
            var word = block[i];
            for (var j = 0; j < 8; j++)
            {
                outBytes[i * 8 + j] = (byte)(word >>> (8 * j));
            }
        }
        return outBytes;
    }

    private static byte[] Le32(int value) => new[]
    {
        (byte)value, (byte)(value >>> 8), (byte)(value >>> 16), (byte)(value >>> 24),
    };

    private static byte[] Concat(params byte[][] parts)
    {
        var total = 0;
        foreach (var part in parts)
        {
            total += part.Length;
        }
        var outBytes = new byte[total];
        var offset = 0;
        foreach (var part in parts)
        {
            Array.Copy(part, 0, outBytes, offset, part.Length);
            offset += part.Length;
        }
        return outBytes;
    }

    /// <summary>A buffered blake2b-64 over appended parts, for the H0 construction.</summary>
    private sealed class IncrementalBlake2b64 : IDisposable
    {
        private readonly MemoryStream _buffer = new();

        internal void Update(byte[] part) => _buffer.Write(part, 0, part.Length);

        internal byte[] Digest() => Blake2b.Digest(64, Array.Empty<byte>(), _buffer.ToArray());

        public void Dispose() => _buffer.Dispose();
    }
}

/// <summary>
/// The rsw time-lock trapdoor and its shared arithmetic, a port of
/// the php Rsw onto System.Numerics.BigInteger. The client squares a
/// challenge derived base T times modulo the 2048 bit composite n,
/// and the server verifies instantly through the secret lambda: with
/// e = 2^T mod lambda, the group order relation gives base^(2^T) =
/// base^e mod n.
///
/// Validation proves the shape, rejects a modulus with a small prime
/// factor or a probable prime modulus, and runs the deterministic
/// trapdoor spot check over the fixed small prime base set. Invalid
/// pairs are never memoized, so a weak input revalidates and is
/// refused identically on every construction.
/// </summary>
public sealed class Rsw
{
    /// <summary>Rsw modulus and proof wire bounds.</summary>
    public const int RswModulusBytes = 256;
    public const int RswProofHexLen = 512;
    private const int RswSmallPrimeLimit = 1000;

    /// <summary>The fixed base set of the trapdoor consistency spot check.</summary>
    private static readonly long[] RswSelftestBases = {2, 3, 5, 7, 11, 13, 17, 19};

    /// <summary>Reports a rejected trapdoor pair.</summary>
    public sealed class RswValidationError : Exception
    {
        public RswValidationError(string reason) : base("kiwicaptcha: invalid rsw configuration: " + reason)
        {
        }
    }

    /// <summary>The canonical base64 modulus text.</summary>
    public string ModulusB64 { get; }

    /// <summary>The canonical base64 lambda text.</summary>
    public string LambdaB64 { get; }

    private readonly BigInteger _n;
    private readonly BigInteger _lambda;

    private static readonly object PairCacheLock = new();
    private static readonly Dictionary<string, Rsw> PairCache = new();

    private Rsw(string modulusB64, string lambdaB64, BigInteger n, BigInteger lambda)
    {
        ModulusB64 = modulusB64;
        LambdaB64 = lambdaB64;
        _n = n;
        _lambda = lambda;
    }

    private static List<BigInteger> SmallPrimes()
    {
        var limit = RswSmallPrimeLimit;
        var sieve = new bool[limit + 1];
        for (var i = 2; i <= limit; i++)
        {
            sieve[i] = true;
        }
        for (var value = 2; (long)value * value <= limit; value++)
        {
            if (!sieve[value])
            {
                continue;
            }
            for (var multiple = value * value; multiple <= limit; multiple += value)
            {
                sieve[multiple] = false;
            }
        }
        var outList = new List<BigInteger>();
        for (var value = 2; value <= limit; value++)
        {
            if (sieve[value])
            {
                outList.Add(new BigInteger(value));
            }
        }
        return outList;
    }

    /// <summary>Shape validates and decodes the modulus bytes.</summary>
    public static BigInteger DecodeRswModulus(string modulusB64)
    {
        var raw = Canonical.B64CanonicalDecode(modulusB64);
        if (raw == null)
        {
            throw new RswValidationError("rsw_modulus_n must be canonical standard base64");
        }
        if (raw.Length != RswModulusBytes)
        {
            throw new RswValidationError(
                "rsw_modulus_n must be the base64 of exactly 256 bytes (a 2048 bit composite)");
        }
        if ((raw[0] & 0x80) == 0)
        {
            throw new RswValidationError("rsw_modulus_n must have its top bit set");
        }
        if ((raw[RswModulusBytes - 1] & 1) == 0)
        {
            throw new RswValidationError("rsw_modulus_n must be odd (the product of two odd primes)");
        }
        return BigInt.FromUnsignedBigEndian(raw);
    }

    /// <summary>Shape validates and decodes the trapdoor bytes.</summary>
    public static BigInteger DecodeRswLambda(string lambdaB64)
    {
        var raw = Canonical.B64CanonicalDecode(lambdaB64);
        if (raw == null)
        {
            throw new RswValidationError("rsw_lambda must be canonical standard base64");
        }
        if (raw.Length == 0 || raw.Length > RswModulusBytes)
        {
            throw new RswValidationError("rsw_lambda must be the base64 of 1..256 bytes");
        }
        if ((raw[^1] & 1) == 1)
        {
            throw new RswValidationError(
                "rsw_lambda must be even (the lcm of the two even primality offsets)");
        }
        return BigInt.FromUnsignedBigEndian(raw);
    }

    private static void RejectSmallPrimeFactor(BigInteger n)
    {
        var first = true;
        foreach (var prime in SmallPrimes())
        {
            if (first)
            {
                // Two is even; the modulus is odd, so the trial is skipped.
                first = false;
                continue;
            }
            if (BigInteger.Remainder(n, prime).IsZero)
            {
                throw new RswValidationError("rsw_modulus_n must not be divisible by a small prime");
            }
        }
    }

    private static bool TrapdoorConsistent(BigInteger n, BigInteger lambda)
    {
        foreach (var baseValue in RswSelftestBases)
        {
            if (!BigInteger.ModPow(new BigInteger(baseValue), lambda, n).IsOne)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>Validates and memoizes one trapdoor pair.</summary>
    public static Rsw Of(string modulusB64, string lambdaB64)
    {
        var cacheKey = modulusB64 + "\0" + lambdaB64;
        lock (PairCacheLock)
        {
            if (PairCache.TryGetValue(cacheKey, out var cached))
            {
                return cached;
            }
            var n = DecodeRswModulus(modulusB64);
            var lambda = DecodeRswLambda(lambdaB64);
            RejectSmallPrimeFactor(n);
            if (MillerRabinIsProbablePrime(n, 24))
            {
                throw new RswValidationError(
                    "rsw_modulus_n must not itself be a probable prime (a genuine 2048 bit modulus is the product of two large primes)");
            }
            if (!TrapdoorConsistent(n, lambda))
            {
                throw new RswValidationError(
                    "rsw_lambda is not a matching trapdoor for rsw_modulus_n (the lambda shortcut diverges from sequential squaring)");
            }
            var rsw = new Rsw(modulusB64, lambdaB64, n, lambda);
            if (PairCache.Count >= 8)
            {
                PairCache.Clear();
            }
            PairCache[cacheKey] = rsw;
            return rsw;
        }
    }

    /// <summary>Derives the challenge base: the sha256 of the prefix plus nonce, reduced modulo n.</summary>
    public static BigInteger DeriveBase(string prefix, string nonce, BigInteger n) =>
        BigInteger.Remainder(
            BigInt.FromUnsignedBigEndian(Canonical.Sha256(Encoding.UTF8.GetBytes(prefix + nonce))), n);

    /// <summary>Renders the fixed 512 lowercase hex wire form of a residue.</summary>
    public static string ProofHex(BigInteger value)
    {
        var text = value.ToString("x");
        if (text.Length > RswProofHexLen)
        {
            return text[^RswProofHexLen..];
        }
        return new string('0', RswProofHexLen - text.Length) + text;
    }

    /// <summary>
    /// Computes the expected final value as the fixed 512 hex wire
    /// form. One modular exponentiation replaces the client's T
    /// sequential squarings.
    /// </summary>
    public string ExpectedProofHex(string prefix, string nonce, int t)
    {
        var baseValue = DeriveBase(prefix, nonce, _n);
        var exponent = BigInteger.ModPow(new BigInteger(2), new BigInteger(t), _lambda);
        var expected = BigInteger.ModPow(baseValue, exponent, _n);
        return ProofHex(expected);
    }

    /// <summary>The canonical identity of a modulus: the hex sha256 of the decoded bytes.</summary>
    public static string Fingerprint(string modulusB64)
    {
        var raw = Canonical.B64CanonicalDecode(modulusB64);
        if (raw == null || raw.Length != RswModulusBytes)
        {
            return "";
        }
        return Canonical.Hex(Canonical.Sha256(raw));
    }

    /// <summary>The pre-v5 legacy identity: the sha256 of the base64 text itself.</summary>
    public static string LegacyIdentity(string modulusB64) =>
        Canonical.Hex(Canonical.Sha256(Encoding.UTF8.GetBytes(modulusB64)));

    /// <summary>
    /// Whether the identity is an accepted form of the modulus: the
    /// canonical fingerprint always, the legacy base64-text alias
    /// only while the bounded migration mode is enabled.
    /// </summary>
    public static bool IdentityMatches(string identity, string modulusB64, bool allowLegacyAlias)
    {
        var canonical = Fingerprint(modulusB64);
        if (canonical.Length > 0 && Canonical.ConstantTimeEquals(canonical, identity))
        {
            return true;
        }
        return allowLegacyAlias && Canonical.ConstantTimeEquals(LegacyIdentity(modulusB64), identity);
    }

    /// <summary>
    /// A Miller-Rabin probable prime test over random bases, the
    /// equivalent of java.math.BigInteger.isProbablePrime for the
    /// composite-modulus rejection gate.
    /// </summary>
    internal static bool MillerRabinIsProbablePrime(BigInteger n, int rounds)
    {
        if (n.IsZero || n.IsOne)
        {
            return false;
        }
        foreach (var small in new[] {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37})
        {
            if (n == new BigInteger(small))
            {
                return true;
            }
            if (BigInteger.Remainder(n, new BigInteger(small)).IsZero)
            {
                return false;
            }
        }
        var d = n - BigInteger.One;
        var s = 0;
        while (d.IsEven)
        {
            d >>= 1;
            s++;
        }
        var bytes = n.ToByteArray();
        for (var round = 0; round < rounds; round++)
        {
            BigInteger a;
            do
            {
                var buffer = RandomNumberGenerator.GetBytes(bytes.Length);
                a = BigInt.FromUnsignedBigEndian(buffer);
            }
            while (a < BigInteger.One || a >= n - BigInteger.One);
            var x = BigInteger.ModPow(a, d, n);
            if (x.IsOne || x == n - BigInteger.One)
            {
                continue;
            }
            var witness = true;
            for (var i = 0; i < s - 1; i++)
            {
                x = BigInteger.ModPow(x, new BigInteger(2), n);
                if (x == n - BigInteger.One)
                {
                    witness = false;
                    break;
                }
            }
            if (witness)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>The decoded modulus, for tests and solver parity checks.</summary>
    public BigInteger Modulus() => _n;
}
