package com.kiwicaptcha;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The rsw time-lock trapdoor and its shared arithmetic, a port of the
 * php Rsw onto java.math.BigInteger. The client squares a challenge
 * derived base T times modulo the 2048 bit composite n, and the server
 * verifies instantly through the secret lambda: with e = 2^T mod
 * lambda, the group order relation gives base^(2^T) = base^e mod n.
 *
 * Validation proves the shape, rejects a modulus with a small prime
 * factor or a probable prime modulus, and runs the deterministic
 * trapdoor spot check over the fixed small prime base set. Invalid
 * pairs are never memoized, so a weak input revalidates and is refused
 * identically on every construction.
 */
public final class Rsw {
    /** Rsw modulus and proof wire bounds. */
    public static final int RSW_MODULUS_BYTES = 256;
    public static final int RSW_PROOF_HEX_LEN = 512;
    private static final int RSW_SMALL_PRIME_LIMIT = 1000;

    /** The fixed base set of the trapdoor consistency spot check. */
    private static final long[] RSW_SELFTEST_BASES = {2, 3, 5, 7, 11, 13, 17, 19};

    /** Reports a rejected trapdoor pair. */
    public static final class RswValidationError extends RuntimeException {
        public RswValidationError(String reason) {
            super("kiwicaptcha: invalid rsw configuration: " + reason);
        }
    }

    /** The canonical base64 modulus text. */
    public final String modulusB64;
    /** The canonical base64 lambda text. */
    public final String lambdaB64;
    private final BigInteger n;
    private final BigInteger lambda;

    private Rsw(String modulusB64, String lambdaB64, BigInteger n, BigInteger lambda) {
        this.modulusB64 = modulusB64;
        this.lambdaB64 = lambdaB64;
        this.n = n;
        this.lambda = lambda;
    }

    private static final Map<String, Rsw> PAIR_CACHE = new ConcurrentHashMap<>();

    private static List<BigInteger> smallPrimes() {
        int limit = RSW_SMALL_PRIME_LIMIT;
        boolean[] sieve = new boolean[limit + 1];
        for (int i = 2; i <= limit; i++) {
            sieve[i] = true;
        }
        for (int value = 2; (long) value * value <= limit; value++) {
            if (!sieve[value]) {
                continue;
            }
            for (int multiple = value * value; multiple <= limit; multiple += value) {
                sieve[multiple] = false;
            }
        }
        List<BigInteger> out = new ArrayList<>();
        for (int value = 2; value <= limit; value++) {
            if (sieve[value]) {
                out.add(BigInteger.valueOf(value));
            }
        }
        return out;
    }

    /** Shape validates and decodes the modulus bytes. */
    public static BigInteger decodeRswModulus(String modulusB64) {
        byte[] raw = Canonical.b64CanonicalDecode(modulusB64);
        if (raw == null) {
            throw new RswValidationError("rsw_modulus_n must be canonical standard base64");
        }
        if (raw.length != RSW_MODULUS_BYTES) {
            throw new RswValidationError(
                    "rsw_modulus_n must be the base64 of exactly 256 bytes (a 2048 bit composite)");
        }
        if ((raw[0] & 0x80) == 0) {
            throw new RswValidationError("rsw_modulus_n must have its top bit set");
        }
        if ((raw[RSW_MODULUS_BYTES - 1] & 1) == 0) {
            throw new RswValidationError("rsw_modulus_n must be odd (the product of two odd primes)");
        }
        return new BigInteger(1, raw);
    }

    /** Shape validates and decodes the trapdoor bytes. */
    public static BigInteger decodeRswLambda(String lambdaB64) {
        byte[] raw = Canonical.b64CanonicalDecode(lambdaB64);
        if (raw == null) {
            throw new RswValidationError("rsw_lambda must be canonical standard base64");
        }
        if (raw.length == 0 || raw.length > RSW_MODULUS_BYTES) {
            throw new RswValidationError("rsw_lambda must be the base64 of 1..256 bytes");
        }
        if ((raw[raw.length - 1] & 1) == 1) {
            throw new RswValidationError("rsw_lambda must be even (the lcm of the two even primality offsets)");
        }
        return new BigInteger(1, raw);
    }

    private static void rejectSmallPrimeFactor(BigInteger n) {
        for (BigInteger prime : smallPrimes()) {
            if (prime.longValue() == 2) {
                continue;
            }
            if (n.mod(prime).signum() == 0) {
                throw new RswValidationError("rsw_modulus_n must not be divisible by a small prime");
            }
        }
    }

    private static boolean trapdoorConsistent(BigInteger n, BigInteger lambda) {
        for (long base : RSW_SELFTEST_BASES) {
            if (!BigInteger.valueOf(base).modPow(lambda, n).equals(BigInteger.ONE)) {
                return false;
            }
        }
        return true;
    }

    /** Validates and memoizes one trapdoor pair. */
    public static Rsw of(String modulusB64, String lambdaB64) {
        String cacheKey = modulusB64 + "\u0000" + lambdaB64;
        Rsw cached = PAIR_CACHE.get(cacheKey);
        if (cached != null) {
            return cached;
        }
        BigInteger n = decodeRswModulus(modulusB64);
        BigInteger lambda = decodeRswLambda(lambdaB64);
        rejectSmallPrimeFactor(n);
        if (n.isProbablePrime(24)) {
            throw new RswValidationError(
                    "rsw_modulus_n must not itself be a probable prime (a genuine 2048 bit modulus is the product of two large primes)");
        }
        if (!trapdoorConsistent(n, lambda)) {
            throw new RswValidationError(
                    "rsw_lambda is not a matching trapdoor for rsw_modulus_n (the lambda shortcut diverges from sequential squaring)");
        }
        Rsw rsw = new Rsw(modulusB64, lambdaB64, n, lambda);
        if (PAIR_CACHE.size() >= 8) {
            PAIR_CACHE.clear();
        }
        PAIR_CACHE.put(cacheKey, rsw);
        return rsw;
    }

    /** Derives the challenge base: the sha256 of the prefix plus nonce, reduced modulo n. */
    public static BigInteger deriveBase(String prefix, String nonce, BigInteger n) {
        byte[] digest = Canonical.sha256((prefix + nonce).getBytes(StandardCharsets.UTF_8));
        return new BigInteger(1, digest).mod(n);
    }

    /** Renders the fixed 512 lowercase hex wire form of a residue. */
    public static String proofHex(BigInteger value) {
        String text = value.toString(16);
        if (text.length() > RSW_PROOF_HEX_LEN) {
            return text.substring(text.length() - RSW_PROOF_HEX_LEN);
        }
        return "0".repeat(RSW_PROOF_HEX_LEN - text.length()) + text;
    }

    /**
     * Computes the expected final value as the fixed 512 hex wire
     * form. One modular exponentiation replaces the client's T
     * sequential squarings.
     */
    public String expectedProofHex(String prefix, String nonce, int t) {
        BigInteger base = deriveBase(prefix, nonce, n);
        BigInteger exponent = BigInteger.TWO.modPow(BigInteger.valueOf(t), lambda);
        BigInteger expected = base.modPow(exponent, n);
        return proofHex(expected);
    }

    /** The canonical identity of a modulus: the hex sha256 of the decoded bytes. */
    public static String fingerprint(String modulusB64) {
        byte[] raw = Canonical.b64CanonicalDecode(modulusB64);
        if (raw == null || raw.length != RSW_MODULUS_BYTES) {
            return "";
        }
        return Canonical.hex(sha256Raw(raw));
    }

    /** The pre-v5 legacy identity: the sha256 of the base64 text itself. */
    public static String legacyIdentity(String modulusB64) {
        return Canonical.hex(sha256Raw(modulusB64.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Whether the identity is an accepted form of the modulus: the
     * canonical fingerprint always, the legacy base64-text alias only
     * while the bounded migration mode is enabled.
     */
    public static boolean identityMatches(String identity, String modulusB64, boolean allowLegacyAlias) {
        String canonical = fingerprint(modulusB64);
        if (!canonical.isEmpty() && Canonical.constantTimeEquals(canonical, identity)) {
            return true;
        }
        return allowLegacyAlias && Canonical.constantTimeEquals(legacyIdentity(modulusB64), identity);
    }

    private static byte[] sha256Raw(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (Exception e) {
            throw new IllegalStateException("sha256 unavailable", e);
        }
    }

    BigInteger modulus() {
        return n;
    }

    BigInteger lambda() {
        return lambda;
    }
}
