//! The rsw-keygen library: fresh trapdoor generation, the pre-emission
//! self-test against the shipped trapdoor math, and the --check rule
//! list that mirrors the configuration validators of both language
//! cores.
//!
//! The generator draws two independent random 1024-bit probable primes
//! (rejection sampling with trial division and enough Miller-Rabin
//! rounds for the size), requires distinct primes and an exactly
//! 2048-bit product, and derives lambda = lcm(p-1, q-1) from the two
//! primes. Before anything is emitted the fresh pair must pass the
//! shipped decode and the sequential-squaring self-test, so the tool
//! exercises exactly the trapdoor math that verifies real challenges.
//! The primes leave the process only under the explicit --diagnostic
//! flag.
//!
//! The check mode reuses the shipped validation primitives
//! (small_prime_factor, is_probable_prime and trapdoor_consistent), so
//! a pair that the tool accepts is exactly a pair the configuration
//! boundary of the Rust and PHP cores accepts.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kiwicaptcha::rsw::{
    derive_base, is_probable_prime, proof_hex, small_prime_factor, trapdoor_consistent,
    RswTrapdoor, MODULUS_BYTES,
};
use num_bigint::BigUint;
use num_integer::Integer;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// The size of each generated prime.
pub const PRIME_BITS: u64 = 1024;

/// The canonical n wire shape: exactly 256 bytes.
pub const N_HEX_CHARS: usize = MODULUS_BYTES * 2;

/// The sha256 fingerprint of the canonical n, as lowercase hex.
pub const FINGERPRINT_HEX_CHARS: usize = 32 * 2;

/// The Miller-Rabin rounds of the prime generation: the base-2 round
/// plus 39 uniform random bases, the FIPS 186-4 count for a 1024-bit
/// prime at the 2^-80 error bound.
pub const MR_ROUNDS: u32 = 40;

/// The trial-division ceiling of the candidate filter. Shared with the
/// shipped modulus validator, so the generator never emits a modulus
/// the validator would refuse on a small factor.
pub const SMALL_PRIME_LIMIT: u64 = 1000;

/// The deterministic (prefix, nonce) pairs whose challenge-derived
/// bases stand in for the small integer bases of an idealized self
/// test. The base of a real challenge is the sha256 of exactly this
/// shape, so the comparison covers the shipped derivation too.
pub const SELFTEST_PAIRS: [(&str, &str); 4] = [
    ("rsw-keygen-selftest", "base-1"),
    ("rsw-keygen-selftest", "base-2"),
    ("rsw-keygen-selftest", "base-3"),
    ("rsw-keygen-selftest", "base-4"),
];

/// The self-test sequential costs, covering a small value, a thousand
/// and the real issuance range of the protocol floor.
pub const SELFTEST_T_VALUES: [u64; 3] = [17, 1000, 10_007];

/// The single large cost that exercises the squaring loop deeply.
pub const SELFTEST_LARGE_T: u64 = 250_000;

/// A generated trapdoor pair, before emission.
#[derive(Debug, Clone)]
pub struct KeyPair {
    p: BigUint,
    q: BigUint,
    n: BigUint,
    lambda: BigUint,
}

impl KeyPair {
    /// The canonical 256-byte big-endian modulus.
    pub fn n_bytes(&self) -> Vec<u8> {
        let bytes = self.n.to_bytes_be();
        let mut padded = vec![0u8; MODULUS_BYTES - bytes.len()];
        padded.extend_from_slice(&bytes);
        padded
    }

    /// The modulus as exactly 512 lowercase hex chars. The top bit of
    /// a genuine modulus is set, so the minimal hex has no leading
    /// zeros and the padded form is the canonical one.
    pub fn n_hex(&self) -> String {
        hex::encode(self.n_bytes())
    }

    /// The modulus as canonical standard base64, the config wire form.
    pub fn n_base64(&self) -> String {
        B64.encode(self.n_bytes())
    }

    /// Lambda as minimal lowercase hex, without leading zeros.
    pub fn lambda_hex(&self) -> String {
        self.lambda.to_str_radix(16)
    }

    /// Lambda as canonical standard base64 of its minimal big-endian
    /// bytes, the config wire form.
    pub fn lambda_base64(&self) -> String {
        B64.encode(self.lambda.to_bytes_be())
    }

    /// The p prime as exactly 256 lowercase hex chars (1024 bits with
    /// the top bit set). Diagnostic output only.
    pub fn p_hex(&self) -> String {
        hex::encode(self.p.to_bytes_be())
    }

    /// The q prime as exactly 256 lowercase hex chars. Diagnostic
    /// output only.
    pub fn q_hex(&self) -> String {
        hex::encode(self.q.to_bytes_be())
    }

    /// The sha256 fingerprint of the canonical 256-byte modulus.
    pub fn fingerprint_hex(&self) -> String {
        modulus_fingerprint_hex(&self.n_bytes())
    }
}

/// The sha256 fingerprint of the canonical 256-byte modulus.
pub fn modulus_fingerprint_hex(n_bytes: &[u8]) -> String {
    let digest = Sha256::digest(n_bytes);
    hex::encode(digest)
}

/// Generate a fresh trapdoor pair: two independent random 1024-bit
/// probable primes with an exactly 2048-bit product, and
/// lambda = lcm(p-1, q-1).
pub fn generate_pair() -> Result<KeyPair, String> {
    let mut rng = rand::rngs::OsRng;
    loop {
        let p = generate_prime(&mut rng)?;
        let q = generate_prime(&mut rng)?;
        if p == q {
            continue;
        }
        let n = &p * &q;
        if n.bits() != 2048 {
            // Both primes exceed 2^1023, so the product reaches at
            // least 2^2046; only the upper half of the range needs the
            // retry to land the exact 2048-bit shape.
            continue;
        }
        let lambda = lcm(&(&p - BigUint::from(1u8)), &(&q - BigUint::from(1u8)));
        return Ok(KeyPair { p, q, n, lambda });
    }
}

/// The least common multiple of two positive integers.
fn lcm(a: &BigUint, b: &BigUint) -> BigUint {
    (a / a.gcd(b)) * b
}

/// A random 1024-bit probable prime: rejection sampling over odd
/// candidates with the top bit set, trial division by the small
/// primes, then the Miller-Rabin rounds.
fn generate_prime(rng: &mut rand::rngs::OsRng) -> Result<BigUint, String> {
    let small_primes = primes_below(SMALL_PRIME_LIMIT + 1);
    let byte_len = (PRIME_BITS / 8) as usize;
    let mut bytes = vec![0u8; byte_len];
    'candidate: loop {
        rng.try_fill_bytes(&mut bytes)
            .map_err(|e| format!("the OS random source failed: {e}"))?;
        bytes[0] |= 0x80;
        bytes[byte_len - 1] |= 1;
        let candidate = BigUint::from_bytes_be(&bytes);
        for p in small_primes.iter().skip(1) {
            if &candidate % BigUint::from(*p) == BigUint::from(0u8) {
                continue 'candidate;
            }
        }
        if !miller_rabin(&candidate, &BigUint::from(2u8)) {
            continue;
        }
        for _ in 1..MR_ROUNDS {
            let base = random_base(&candidate, rng)?;
            if !miller_rabin(&candidate, &base) {
                continue 'candidate;
            }
        }
        return Ok(candidate);
    }
}

/// A uniform random base in [2, n-2] for a Miller-Rabin round: random
/// 1024-bit draws accepted only inside the range, so the distribution
/// is exact.
fn random_base(n: &BigUint, rng: &mut rand::rngs::OsRng) -> Result<BigUint, String> {
    let byte_len = (PRIME_BITS / 8) as usize;
    let mut bytes = vec![0u8; byte_len];
    loop {
        rng.try_fill_bytes(&mut bytes)
            .map_err(|e| format!("the OS random source failed: {e}"))?;
        let base = BigUint::from_bytes_be(&bytes);
        if base >= BigUint::from(2u8) && base < n - BigUint::from(1u8) {
            return Ok(base);
        }
    }
}

/// A strong Miller-Rabin round to the base `a`: does the odd candidate
/// survive as a probable prime?
fn miller_rabin(n: &BigUint, a: &BigUint) -> bool {
    let n_minus_1 = n - BigUint::from(1u8);
    let s = n_minus_1.trailing_zeros().expect("n is odd and above 1") as usize;
    let d = &n_minus_1 >> s;
    let mut x = a.modpow(&d, n);
    if x == BigUint::from(1u8) || x == n_minus_1 {
        return true;
    }
    for _ in 0..s - 1 {
        x = (&x * &x) % n;
        if x == n_minus_1 {
            return true;
        }
    }
    false
}

/// The primes below `limit`, sieve-generated.
fn primes_below(limit: u64) -> Vec<u64> {
    let mut sieve = vec![true; limit.max(2) as usize];
    sieve[0] = false;
    sieve[1] = false;
    let mut p = 2usize;
    while p * p < sieve.len() {
        if sieve[p] {
            let mut m = p * p;
            while m < sieve.len() {
                sieve[m] = false;
                m += p;
            }
        }
        p += 1;
    }
    (0..sieve.len())
        .filter(|&i| sieve[i])
        .map(|i| i as u64)
        .collect()
}

/// The browser-equivalent final value of an rsw challenge over the
/// generated modulus: the base derived from the signed prefix and
/// nonce, squared T times. The loop is the client's sequential work;
/// everything around it (derivation, residue rendering) is the shipped
/// core math, so the self-test compares like with like.
fn sequential_hex(prefix: &str, nonce: &str, t: u64, n: &BigUint) -> String {
    let mut value = derive_base(prefix, nonce, n);
    for _ in 0..t {
        value = (&value * &value) % n;
    }
    proof_hex(&value)
}

/// Run the pre-emission self-test of a fresh pair: the shipped decode
/// must accept it, and the shipped trapdoor expectation must equal the
/// sequential squaring at every deterministic base and cost.
pub fn selftest(pair: &KeyPair) -> Result<(), String> {
    let trapdoor = RswTrapdoor::new(&pair.n_base64(), &pair.lambda_base64())
        .map_err(|e| format!("the fresh pair fails the shipped decode: {e}"))?;
    for &(prefix, nonce) in &SELFTEST_PAIRS {
        for &t in &SELFTEST_T_VALUES {
            check_equality(&trapdoor, &pair.n, prefix, nonce, t)?;
        }
    }
    let (prefix, nonce) = SELFTEST_PAIRS[0];
    check_equality(&trapdoor, &pair.n, prefix, nonce, SELFTEST_LARGE_T)
}

fn check_equality(
    trapdoor: &RswTrapdoor,
    n: &BigUint,
    prefix: &str,
    nonce: &str,
    t: u64,
) -> Result<(), String> {
    let sequential = sequential_hex(prefix, nonce, t, n);
    let expected = trapdoor.expected_proof_hex(prefix, nonce, t);
    if sequential != expected {
        return Err(format!(
            "self-test mismatch for the base of ({prefix}, {nonce}) at T={t}: the sequential solve and the shipped trapdoor disagree"
        ));
    }
    Ok(())
}

/// The --check rule list over an (n, lambda) pair given as lowercase
/// hex, mirroring the configuration validators of both cores: every
/// reason that applies is listed, in a stable order. An empty list
/// means the pair passes the shipped validation.
pub fn check_pair(n_hex: &str, lambda_hex: &str) -> Vec<String> {
    let mut reasons = Vec::new();

    let n_bytes = match hex::decode(n_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            reasons.push("n is not valid hex".to_string());
            return reasons;
        }
    };
    let n = BigUint::from_bytes_be(&n_bytes);
    if n_bytes.len() != MODULUS_BYTES {
        reasons.push(format!(
            "n is not exactly 256 bytes (a genuine 2048-bit modulus); got {}",
            n_bytes.len()
        ));
    }
    if n_bytes.len() == MODULUS_BYTES && n_bytes[0] & 0x80 == 0 {
        reasons.push("n is not exactly 2048 bits (the top bit is clear)".to_string());
    }
    if !n.bit(0) {
        reasons.push("n is even (a genuine modulus is the product of two odd primes)".to_string());
    }
    if let Some(factor) = small_prime_factor(&n) {
        reasons.push(format!(
            "n is divisible by the small prime {factor} (a genuine modulus has none at or below 1000)"
        ));
    }
    if is_probable_prime(&n) {
        reasons.push(
            "n is a probable prime (a genuine modulus is the product of two large primes)"
                .to_string(),
        );
    }

    // Lambda is accepted in its minimal form: an odd number of hex
    // digits is padded with a leading zero before the byte decode.
    let lambda_hex = if lambda_hex.len() % 2 == 1 {
        format!("0{lambda_hex}")
    } else {
        lambda_hex.to_string()
    };
    let lambda = match hex::decode(&lambda_hex) {
        Ok(bytes) if !bytes.is_empty() && bytes.len() <= MODULUS_BYTES => {
            BigUint::from_bytes_be(&bytes)
        }
        Ok(bytes) if bytes.is_empty() => {
            reasons.push("lambda is empty".to_string());
            return reasons;
        }
        Ok(bytes) => {
            reasons.push(format!(
                "lambda must fit 1..=256 bytes (a genuine lambda does); got {}",
                bytes.len()
            ));
            return reasons;
        }
        Err(_) => {
            reasons.push("lambda is not valid hex".to_string());
            return reasons;
        }
    };
    if lambda.bit(0) {
        reasons.push("lambda is odd (a genuine lambda is even)".to_string());
    }

    if !trapdoor_consistent(&n, &lambda) {
        reasons.push(
            "lambda is not a matching trapdoor for n (the lambda shortcut diverges from sequential squaring)"
                .to_string(),
        );
    }
    reasons
}

/// The fingerprint of a modulus given as hex: the sha256 of the
/// canonical 256-byte form, as 64 lowercase hex chars.
pub fn fingerprint_of_hex(n_hex: &str) -> Result<String, String> {
    let bytes = hex::decode(n_hex).map_err(|_| "n is not valid hex".to_string())?;
    if bytes.len() != MODULUS_BYTES {
        return Err(format!(
            "n is not exactly 256 bytes (a genuine 2048-bit modulus); got {}",
            bytes.len()
        ));
    }
    Ok(modulus_fingerprint_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared fixture pair of the kiwicaptcha suites, in hex.
    const FIXTURE_N_HEX: &str = "b0bd4c936619e019f39c18167b6601dee399f8a14dfd51139754f41fdcee5a43f9e3f9c037cb203e1aa8cc3ad109543174973920382487d11e9801b362392efb3aafd9f76bc9fcb98876ed4048641c956dfb97ffeb2c6b643bc750c8600d10262deeeb463108642f06a9c7dc6d0c95102831ccd7dddc513e0137aec5cf3029a7e352d43faef8b3141242a392f4af853aec90e8a1756de324cbb51b2814add664138a20e499f84d2f6490edd9d75e0d296e4bfa9aa99e42ddd49579a4b269e957f1d1a99a8bebf310a50bef522ac16731cfba9bd581a360ac092a491a4dcb64cdbce3b1cce7faf681f98d74de7345e723118e4c2cb110ff7e098a7b8cb4c269bb";

    const FIXTURE_LAMBDA_HEX: &str = "585ea649b30cf00cf9ce0c0b3db300ef71ccfc50a6fea889cbaa7a0fee772d21fcf1fce01be5901f0d54661d6884aa18ba4b9c901c1243e88f4c00d9b11c977d9d57ecfbb5e4fe5cc43b76a024320e4ab6fdcbfff59635b21de3a8643006881316f775a3188432178354e3ee36864a881418e66beeee289f009bd762e79814d31c130309747422f2580d14124cc0d37edbaee8562b8d76f5d1b422f1d0c78e4a220f3af0cd9cb53405ae1b260e664d72d8f6594830fb4eb8753906237c13b218f24282758969253806aaffaebb968d4bf48f425dec311f1d228df39fbc1985cb0ccb32759ff74b647352c17b37417e97414f81c7c395cf9a662583d325476c10";

    /// A real 2048-bit probable prime, shared with the core suites.
    const PROBABLE_PRIME_N_HEX: &str = "dd007bd3d23ae90f08be9d8fe51b600f8f9c8b7f1d1ee02e5dfcc62f82ad0a4df85065fdb8e1b5160355f7607d05c552d625f824261da8df5c1e0eb6b2a116c7ea747e7eeb502b8f619485a67c1c5a95631cc6e2833cf6c235adda6864a8bb5b819ffe9daaffa6d42eeda1ca3ab418540a6961fd2dc667f0b6751b1d25a9c8c66152fd742529cd3d1b8f2fac2b6f4707f138c77b1d96f748ac95cdea3c0c22f6501976d5fff8e7a91412c39268e7138ca2d92c8167be641d69febdeee75e0d37e76cdb3ed2f7828b3ae7c949b1555db7721ba9e55fd48f709d5891629212f846072b9a255a6dfeb0ec7065f6e2c6580b874a7725a7d0a029d9a641768fef46cf";

    const FIXTURE_FINGERPRINT: &str =
        "8aa0239a5d27b93ceff3317fcee8ef9ac59510685178e6f34d0f07decc075fc2";

    fn weak_n_with_factor(factor: u64) -> String {
        let factor_bits = 64 - factor.leading_zeros();
        let shift = 2048 - factor_bits;
        let value = BigUint::from(factor) * ((BigUint::from(1u8) << shift) + BigUint::from(1u8));
        let bytes = value.to_bytes_be();
        let mut padded = vec![0u8; MODULUS_BYTES - bytes.len()];
        padded.extend_from_slice(&bytes);
        hex::encode(padded)
    }

    #[test]
    fn fixture_pair_passes_check() {
        assert!(check_pair(FIXTURE_N_HEX, FIXTURE_LAMBDA_HEX).is_empty());
    }

    #[test]
    fn fixture_fingerprint_is_stable() {
        assert_eq!(
            modulus_fingerprint_hex(&hex::decode(FIXTURE_N_HEX).unwrap()),
            FIXTURE_FINGERPRINT
        );
        assert_eq!(
            fingerprint_of_hex(FIXTURE_N_HEX).unwrap(),
            FIXTURE_FINGERPRINT
        );
    }

    #[test]
    fn fingerprint_rejects_non_canonical_moduli() {
        assert!(fingerprint_of_hex(&FIXTURE_N_HEX[..510]).is_err());
        assert!(fingerprint_of_hex("zz").is_err());
    }

    #[test]
    fn even_n_is_rejected() {
        let mut bytes = hex::decode(FIXTURE_N_HEX).unwrap();
        bytes[255] &= !1;
        let reasons = check_pair(&hex::encode(bytes), FIXTURE_LAMBDA_HEX);
        assert!(reasons.iter().any(|r| r.contains("n is even")));
    }

    #[test]
    fn wrong_bit_length_is_rejected() {
        let short = &FIXTURE_N_HEX[..256];
        let reasons = check_pair(short, FIXTURE_LAMBDA_HEX);
        assert!(reasons.iter().any(|r| r.contains("not exactly 256 bytes")));

        let mut bytes = hex::decode(FIXTURE_N_HEX).unwrap();
        bytes[0] = 0x0f;
        let reasons = check_pair(&hex::encode(bytes), FIXTURE_LAMBDA_HEX);
        assert!(reasons.iter().any(|r| r.contains("top bit is clear")));
    }

    #[test]
    fn small_prime_factor_is_rejected() {
        let reasons = check_pair(&weak_n_with_factor(3), FIXTURE_LAMBDA_HEX);
        assert!(reasons.iter().any(|r| r.contains("small prime 3")));
    }

    #[test]
    fn probable_prime_modulus_is_rejected() {
        let reasons = check_pair(PROBABLE_PRIME_N_HEX, FIXTURE_LAMBDA_HEX);
        assert!(reasons.iter().any(|r| r.contains("probable prime")));
    }

    #[test]
    fn mismatched_lambda_is_rejected() {
        let lambda =
            BigUint::parse_bytes(FIXTURE_LAMBDA_HEX.as_bytes(), 16).unwrap() - BigUint::from(2u8);
        let shifted = lambda.to_str_radix(16);
        let reasons = check_pair(FIXTURE_N_HEX, &shifted);
        assert!(reasons
            .iter()
            .any(|r| r.contains("not a matching trapdoor")));
    }

    #[test]
    fn odd_and_oversized_lambda_are_rejected() {
        let lambda = BigUint::parse_bytes(FIXTURE_LAMBDA_HEX.as_bytes(), 16).unwrap();
        let odd = (lambda + BigUint::from(1u8)).to_str_radix(16);
        let reasons = check_pair(FIXTURE_N_HEX, &odd);
        assert!(reasons.iter().any(|r| r.contains("lambda is odd")));

        let oversized = format!("{}{}", "ab", FIXTURE_LAMBDA_HEX);
        let reasons = check_pair(FIXTURE_N_HEX, &oversized);
        assert!(reasons.iter().any(|r| r.contains("1..=256 bytes")));
    }

    #[test]
    fn generation_emits_an_exactly_2048_bit_modulus() {
        let pair = generate_pair().unwrap();
        assert_eq!(pair.n_hex().len(), N_HEX_CHARS);
        assert_eq!(pair.n.bits(), 2048);
        assert_eq!(pair.p.bits(), 1024);
        assert_eq!(pair.q.bits(), 1024);
        assert_ne!(pair.p, pair.q);
        assert_eq!(pair.fingerprint_hex().len(), FINGERPRINT_HEX_CHARS);
        assert!(!pair.lambda_hex().starts_with('0'), "lambda hex is minimal");
        let expected_lambda = lcm(
            &(&pair.p - BigUint::from(1u8)),
            &(&pair.q - BigUint::from(1u8)),
        );
        assert_eq!(pair.lambda, expected_lambda);
    }

    #[test]
    fn fresh_pair_passes_check_and_selftest() {
        let pair = generate_pair().unwrap();
        selftest(&pair).unwrap();
        assert!(check_pair(&pair.n_hex(), &pair.lambda_hex()).is_empty());
        assert_eq!(
            fingerprint_of_hex(&pair.n_hex()).unwrap(),
            pair.fingerprint_hex()
        );
    }
}
