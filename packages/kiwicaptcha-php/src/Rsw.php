<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The RSW time-lock trapdoor and its shared arithmetic.
 *
 * The optional experimental rsw algorithm (Rivest-Shamir-Wagner style)
 * is a sequential time-lock: the client squares a challenge-derived
 * base T times modulo a 2048-bit composite n, and the server verifies
 * instantly because it holds the factorization. This class decodes and
 * validates the two operator-configured secrets — the public modulus n
 * and the secret lambda, the Carmichael value lcm(p-1, q-1) of the two
 * primes — and computes the expected final value through the trapdoor.
 *
 * The math: with base derived deterministically from the signed
 * challenge bytes, the client's T sequential squarings produce
 * base^(2^T) mod n. When e = 2^T mod lambda, Euler's theorem gives
 * base^(2^T) ≡ base^e (mod n) for every base, because lambda is a
 * multiple of both p-1 and q-1. The exponent e is never below 1: lambda
 * is even with odd cofactors for 1024-bit primes, so lambda never
 * divides a power of two. The verifier therefore computes base^e mod n
 * with one modular exponentiation, about 2048 squarings, while the
 * client without the factorization must perform the full T squarings.
 *
 * The server never reveals the factorization. The configuration holds
 * only n and lambda, never the primes: an operator who can generate the
 * primes keeps them offline, and a deployment that leaks its config
 * leaks the trapdoor but nothing else. n is public by design (the
 * client squares modulo n), so it also rides the challenge response;
 * lambda never leaves the server configuration.
 *
 * Validation first proves the shape: the modulus must be exactly 256
 * bytes with the top bit set and odd, and lambda must decode to 1..256
 * even bytes. Beyond the shape, three weak or inconsistent inputs are
 * refused: a modulus divisible by any prime at or below 1000, a
 * modulus reading as a probable prime, and a lambda failing the Euler
 * self-test for a few small bases. No product of two 1024-bit primes
 * has a small factor, and a genuine modulus is composite. The Euler
 * test requires base^lambda == 1 modulo n and is the exact condition
 * under which the trapdoor shortcut agrees with the client's
 * sequential squaring at every cost T. The full lcm relation cannot be established without the
 * factorization, exactly like an RSA public key cannot be verified
 * against its private exponent. The residual assurance for a deployed
 * pair is its provenance: generate n and lambda with the shipped
 * rsw-keygen tool and record the modulus fingerprint. Both values are
 * canonical standard base64 of their big-endian bytes.
 *
 * gmp is required for the arithmetic. The optional algorithm is refused
 * at configuration time when the extension is missing, so the default
 * sha256/argon2id deployment never needs it.
 */
final class Rsw
{
    /** The modulus is a 2048-bit composite: exactly 256 bytes. */
    public const MODULUS_BYTES = 256;

    /**
     * The fixed 512-hex wire form of a final value: the 256-byte
     * big-endian residue, zero-padded. Both the solver output and the
     * trapdoor expectation render into this exact shape, so the
     * constant-time comparison runs over equal-length strings.
     */
    public const PROOF_HEX_LENGTH = 512;

    /** The decoded modulus n (2048-bit composite). */
    private readonly \GMP $n;

    /** The decoded secret lambda = lcm(p-1, q-1). */
    private readonly \GMP $lambda;

    /**
     * Redacted dump shape: the four constructor fields print under their
     * property names, with the secret lambda material — the raw
     * `lambdaB64` input and the decoded `lambda` — replaced by
     * '<redacted>'. The modulus half (`modulusB64` and the decoded `n`)
     * is public material (the client squares modulo n) and prints as
     * itself.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'modulusB64' => $this->modulusB64,
            'lambdaB64' => '<redacted>',
            'n' => $this->n,
            'lambda' => '<redacted>',
        ];
    }

    /**
     * The trial-division ceiling of the weak-modulus rejection: any
     * prime factor at or below this bound marks the modulus as
     * severely weak, because a genuine modulus is the product
     * of two primes of roughly 1024 bits.
     */
    private const SMALL_PRIME_LIMIT = 1000;

    /**
     * The deterministic bases of the Euler self-test. Each stays below
     * the trial-division ceiling, so a conforming modulus shares no
     * factor with any base and the exponent reduction of the trapdoor
     * applies.
     */
    private const SELFTEST_BASES = [2, 3, 5];

    /**
     * @param string $modulusB64 canonical standard base64 of the
     *                           2048-bit composite n, exactly 256 bytes
     *                           with the top bit set and odd.
     * @param string $lambdaB64   canonical standard base64 of the
     *                           secret lambda, 1..256 even bytes.
     *
     * @throws \InvalidArgumentException on a malformed modulus or
     *                           lambda, on a modulus with a small prime
     *                           factor or a probable-prime modulus, and
     *                           on a lambda that fails the Euler
     *                           self-test against the modulus
     */
    public function __construct(
        private readonly string $modulusB64,
        private readonly string $lambdaB64,
    ) {
        if (!\extension_loaded('gmp')) {
            throw new \InvalidArgumentException(
                'the rsw algorithm requires the gmp extension for its modular arithmetic'
            );
        }
        $this->n = self::decodeModulus($modulusB64);
        $this->lambda = self::decodeLambda($lambdaB64);
        self::rejectSmallPrimeFactor($this->n);
        if (gmp_prob_prime($this->n) !== 0) {
            throw new \InvalidArgumentException(
                'rsw_modulus_n must not itself be a probable prime (a genuine 2048-bit modulus is the product of two large primes)'
            );
        }
        if (!self::trapdoorConsistent($this->n, $this->lambda)) {
            throw new \InvalidArgumentException(
                'rsw_lambda is not a matching trapdoor for rsw_modulus_n (the lambda shortcut diverges from sequential squaring)'
            );
        }
    }

    

    /** The decoded modulus n. */
    public function modulus(): \GMP
    {
        return $this->n;
    }

    /**
     * The expected final value of a challenge as the fixed 512-hex wire
     * form: base^(2^T mod lambda) mod n, with base the
     * challenge-derived residue. One modular exponentiation replaces the
     * client's T sequential squarings.
     */
    public function expectedProofHex(string $prefix, string $nonce, int $t): string
    {
        $base = self::deriveBase($prefix, $nonce, $this->n);
        $exponent = \gmp_powm(gmp_init(2), $t, $this->lambda);
        $expected = \gmp_powm($base, $exponent, $this->n);

        return self::proofHex($expected);
    }

    /**
     * The challenge-derived base: the SHA-256 of the signed prefix bytes
     * concatenated with the nonce bytes, interpreted as a 256-bit
     * big-endian integer and reduced modulo n. The reduction is a no-op
     * for a conforming modulus (n is at least 2^2047 and the digest at
     * most 2^256-1), and it keeps the residue canonical for any n.
     */
    public static function deriveBase(string $prefix, string $nonce, \GMP $n): \GMP
    {
        $digest = hash('sha256', $prefix.$nonce, true);

        return \gmp_mod(gmp_init(bin2hex($digest), 16), $n);
    }

    /**
     * The fixed 512-hex wire form of a residue: 256 bytes of big-endian,
     * zero-padded to the full length.
     */
    public static function proofHex(\GMP $value): string
    {
        return str_pad(gmp_strval($value, 16), self::PROOF_HEX_LENGTH, '0', \STR_PAD_LEFT);
    }

    /**
     * Validate and decode the modulus: canonical standard base64 of
     * exactly 256 bytes with the top bit set (a genuine 2048-bit
     * composite) and odd (it is the product of two odd primes).
     *
     * @throws \InvalidArgumentException on a malformed modulus
     */
    public static function decodeModulus(string $modulusB64): \GMP
    {
        $bytes = self::canonicalBase64Bytes($modulusB64, 'rsw_modulus_n');
        if (\strlen($bytes) !== self::MODULUS_BYTES) {
            throw new \InvalidArgumentException(sprintf(
                'rsw_modulus_n must be the base64 of exactly %d bytes (a 2048-bit composite), got %d',
                self::MODULUS_BYTES,
                \strlen($bytes),
            ));
        }
        if ((\ord($bytes[0]) & 0x80) === 0) {
            throw new \InvalidArgumentException(
                'rsw_modulus_n must have its top bit set (a genuine 2048-bit composite)'
            );
        }
        if ((\ord($bytes[self::MODULUS_BYTES - 1]) & 1) === 0) {
            throw new \InvalidArgumentException(
                'rsw_modulus_n must be odd (the product of two odd primes)'
            );
        }

        return gmp_init(bin2hex($bytes), 16);
    }

    /**
     * Validate and decode the secret lambda = lcm(p-1, q-1): canonical
     * standard base64 of 1..256 bytes, even. The lcm relation to the
     * modulus cannot be verified without the primes.
     *
     * @throws \InvalidArgumentException on a malformed lambda
     */
    public static function decodeLambda(string $lambdaB64): \GMP
    {
        $bytes = self::canonicalBase64Bytes($lambdaB64, 'rsw_lambda');
        if ($bytes === '' || \strlen($bytes) > self::MODULUS_BYTES) {
            throw new \InvalidArgumentException(sprintf(
                'rsw_lambda must be the base64 of 1..%d bytes, got %d',
                self::MODULUS_BYTES,
                \strlen($bytes),
            ));
        }
        if ((\ord($bytes[\strlen($bytes) - 1]) & 1) === 1) {
            throw new \InvalidArgumentException(
                'rsw_lambda must be even (lcm(p-1, q-1) of two odd primes)'
            );
        }

        return gmp_init(bin2hex($bytes), 16);
    }

    /**
     * Strict canonical base64 decode: the value must be exactly the
     * canonical padded standard-base64 encoding of its bytes, the same
     * determinism the token wire enforces.
     *
     * @throws \InvalidArgumentException on a malformed value
     */
    private static function canonicalBase64Bytes(string $value, string $name): string
    {
        if ($value === '') {
            throw new \InvalidArgumentException($name.' must be non-empty base64');
        }
        $bytes = base64_decode($value, true);
        if ($bytes === false || base64_encode($bytes) !== $value) {
            throw new \InvalidArgumentException($name.' must be canonical standard base64');
        }

        return $bytes;
    }

    /**
     * Refuse a modulus divisible by any prime at or below
     * self::SMALL_PRIME_LIMIT. The parity check already ran, so the
     * factor 2 is skipped: a genuine modulus has no small factor at
     * all.
     *
     * @throws \InvalidArgumentException on a modulus with a small
     *                           prime factor
     */
    private static function rejectSmallPrimeFactor(\GMP $n): void
    {
        foreach (self::smallPrimes() as $prime) {
            if ($prime === 2) {
                continue;
            }
            if (gmp_cmp(gmp_mod($n, gmp_init((string) $prime)), gmp_init(0)) === 0) {
                throw new \InvalidArgumentException(sprintf(
                    'rsw_modulus_n must not be divisible by a small prime (a genuine 2048-bit modulus has none; found %d)',
                    $prime
                ));
            }
        }
    }

    /**
     * Does lambda act as the trapdoor of n? The check is Euler's
     * theorem per small base: base^lambda must equal 1 modulo n. The
     * equality holds exactly when the base's order divides lambda,
     * which is precisely the condition that the lambda shortcut
     * base^(2^T mod lambda) matches the T sequential squarings of the
     * base at every cost T. Every genuine pair passes, because lambda
     * is the Carmichael value of the semiprime; a mismatched or
     * fabricated lambda fails almost surely, so it is refused at
     * configuration time.
     */
    private static function trapdoorConsistent(\GMP $n, \GMP $lambda): bool
    {
        foreach (self::SELFTEST_BASES as $base) {
            if (gmp_cmp(gmp_powm(gmp_init((string) $base), $lambda, $n), gmp_init(1)) !== 0) {
                return false;
            }
        }

        return true;
    }

    /**
     * The primes at or below self::SMALL_PRIME_LIMIT, sieve-generated
     * once.
     *
     * @return list<int>
     */
    private static function smallPrimes(): array
    {
        static $primes = null;
        if ($primes !== null) {
            return $primes;
        }
        $limit = self::SMALL_PRIME_LIMIT;
        $sieve = array_fill(0, $limit + 1, true);
        $sieve[0] = false;
        $sieve[1] = false;
        for ($p = 2; $p * $p <= $limit; ++$p) {
            if (!$sieve[$p]) {
                continue;
            }
            for ($m = $p * $p; $m <= $limit; $m += $p) {
                $sieve[$m] = false;
            }
        }
        $primes = [];
        foreach ($sieve as $candidate => $isPrime) {
            if ($isPrime) {
                $primes[] = $candidate;
            }
        }

        return $primes;
    }
}
