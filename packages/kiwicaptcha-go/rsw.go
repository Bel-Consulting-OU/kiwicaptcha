package kiwicaptcha

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"
)

// The rsw time-lock trapdoor and its shared arithmetic, a port of the
// php Rsw onto math/big. The client squares a challenge derived base
// T times modulo the 2048 bit composite n, and the server verifies
// instantly through the secret lambda: with e = 2^T mod lambda, the
// group order relation gives base^(2^T) = base^e mod n.
//
// Validation proves the shape, rejects a modulus with a small prime
// factor or a probable prime modulus, and runs the deterministic
// trapdoor spot check over the fixed small prime base set. Invalid
// pairs are never memoized, so a weak input revalidates and is
// refused identically on every construction.

// Rsw modulus and proof wire bounds.
const (
	RswModulusBytes    = 256
	RswProofHexLen     = 512
	rswSmallPrimeLimit = 1000
)

// The fixed base set of the trapdoor consistency spot check: the
// primes below the trial division ceiling. A conforming modulus
// shares no factor with any base, so the exponent reduction applies.
var rswSelftestBases = []int64{2, 3, 5, 7, 11, 13, 17, 19}

var (
	rswSmallPrimesOnce sync.Once
	rswSmallPrimes     []*big.Int
	rswPairCacheMu     sync.Mutex
	rswPairCache       = map[string][2]*big.Int{}
	rswPairCacheOrder  []string
)

// RswValidationError reports a rejected trapdoor pair.
type RswValidationError struct{ Reason string }

func (e *RswValidationError) Error() string {
	return "kiwicaptcha: invalid rsw configuration: " + e.Reason
}

func rswErr(reason string) error {
	return &RswValidationError{Reason: reason}
}

func rswPrimesUpto(limit int) []*big.Int {
	sieve := make([]bool, limit+1)
	for i := 2; i <= limit; i++ {
		sieve[i] = true
	}
	for value := 2; value*value <= limit; value++ {
		if !sieve[value] {
			continue
		}
		for multiple := value * value; multiple <= limit; multiple += value {
			sieve[multiple] = false
		}
	}
	out := make([]*big.Int, 0, limit/8)
	for value := 2; value <= limit; value++ {
		if sieve[value] {
			out = append(out, big.NewInt(int64(value)))
		}
	}
	return out
}

// DecodeRswModulus shape validates and decodes the modulus: canonical
// standard base64 of exactly 256 bytes with the top bit set and odd.
func DecodeRswModulus(modulusB64 string) (*big.Int, error) {
	raw, ok := canonicalB64Decode(modulusB64)
	if !ok {
		return nil, rswErr("rsw_modulus_n must be canonical standard base64")
	}
	if len(raw) != RswModulusBytes {
		return nil, rswErr("rsw_modulus_n must be the base64 of exactly 256 bytes (a 2048 bit composite)")
	}
	if raw[0]&0x80 == 0 {
		return nil, rswErr("rsw_modulus_n must have its top bit set")
	}
	if raw[RswModulusBytes-1]&1 == 0 {
		return nil, rswErr("rsw_modulus_n must be odd (the product of two odd primes)")
	}
	return new(big.Int).SetBytes(raw), nil
}

// DecodeRswLambda shape validates and decodes the trapdoor: canonical
// standard base64 of 1 to 256 even bytes.
func DecodeRswLambda(lambdaB64 string) (*big.Int, error) {
	raw, ok := canonicalB64Decode(lambdaB64)
	if !ok {
		return nil, rswErr("rsw_lambda must be canonical standard base64")
	}
	if len(raw) == 0 || len(raw) > RswModulusBytes {
		return nil, rswErr("rsw_lambda must be the base64 of 1..256 bytes")
	}
	if raw[len(raw)-1]&1 == 1 {
		return nil, rswErr("rsw_lambda must be even (the lcm of the two even primality offsets)")
	}
	return new(big.Int).SetBytes(raw), nil
}

func rswRejectSmallPrimeFactor(n *big.Int) error {
	rswSmallPrimesOnce.Do(func() {
		rswSmallPrimes = rswPrimesUpto(rswSmallPrimeLimit)
	})
	remainder := new(big.Int)
	for _, prime := range rswSmallPrimes {
		if prime.Int64() == 2 {
			continue
		}
		remainder.Mod(n, prime)
		if remainder.Sign() == 0 {
			return rswErr("rsw_modulus_n must not be divisible by a small prime")
		}
	}
	return nil
}

func rswTrapdoorConsistent(n, lambda *big.Int) bool {
	result := new(big.Int)
	for _, base := range rswSelftestBases {
		result.Exp(big.NewInt(base), lambda, n)
		if result.Cmp(big.NewInt(1)) != 0 {
			return false
		}
	}
	return true
}

// Rsw is one validated trapdoor pair with the memoized validation
// verdict.
type Rsw struct {
	ModulusB64 string
	LambdaB64  string
	n          *big.Int
	lambda     *big.Int
}

// NewRsw validates and memoizes one trapdoor pair.
func NewRsw(modulusB64, lambdaB64 string) (*Rsw, error) {
	cacheKey := modulusB64 + "\x00" + lambdaB64
	rswPairCacheMu.Lock()
	if cached, ok := rswPairCache[cacheKey]; ok {
		rswPairCacheMu.Unlock()
		return &Rsw{ModulusB64: modulusB64, LambdaB64: lambdaB64, n: cached[0], lambda: cached[1]}, nil
	}
	rswPairCacheMu.Unlock()
	n, err := DecodeRswModulus(modulusB64)
	if err != nil {
		return nil, err
	}
	lambda, err := DecodeRswLambda(lambdaB64)
	if err != nil {
		return nil, err
	}
	if err := rswRejectSmallPrimeFactor(n); err != nil {
		return nil, err
	}
	if n.ProbablyPrime(24) {
		return nil, rswErr("rsw_modulus_n must not itself be a probable prime (a genuine 2048 bit modulus is the product of two large primes)")
	}
	if !rswTrapdoorConsistent(n, lambda) {
		return nil, rswErr("rsw_lambda is not a matching trapdoor for rsw_modulus_n (the lambda shortcut diverges from sequential squaring)")
	}
	rswPairCacheMu.Lock()
	if len(rswPairCache) >= 8 {
		oldest := rswPairCacheOrder[0]
		rswPairCacheOrder = rswPairCacheOrder[1:]
		delete(rswPairCache, oldest)
	}
	rswPairCache[cacheKey] = [2]*big.Int{n, lambda}
	rswPairCacheOrder = append(rswPairCacheOrder, cacheKey)
	rswPairCacheMu.Unlock()
	return &Rsw{ModulusB64: modulusB64, LambdaB64: lambdaB64, n: n, lambda: lambda}, nil
}

// RswDeriveBase derives the challenge base: the sha256 of the prefix
// plus nonce bytes, reduced modulo n. The reduction is a no-op for a
// conforming modulus and keeps the residue canonical for any n.
func RswDeriveBase(prefix, nonce string, n *big.Int) *big.Int {
	digest := sha256.Sum256([]byte(prefix + nonce))
	return new(big.Int).Mod(new(big.Int).SetBytes(digest[:]), n)
}

// RswProofHex renders the fixed 512 lowercase hex wire form of a
// residue: 256 bytes of big-endian, zero padded to the full length.
func RswProofHex(value *big.Int) string {
	text := value.Text(16)
	if len(text) > RswProofHexLen {
		return text[len(text)-RswProofHexLen:]
	}
	padded := make([]byte, RswProofHexLen-len(text))
	for i := range padded {
		padded[i] = '0'
	}
	return string(padded) + text
}

// ExpectedProofHex computes the expected final value as the fixed 512
// hex wire form. One modular exponentiation replaces the client's T
// sequential squarings.
func (r *Rsw) ExpectedProofHex(prefix, nonce string, t int) string {
	base := RswDeriveBase(prefix, nonce, r.n)
	exponent := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(t)), r.lambda)
	expected := new(big.Int).Exp(base, exponent, r.n)
	return RswProofHex(expected)
}

// RswFingerprint is the canonical identity of a modulus: the hex
// sha256 of the decoded bytes, or the empty string for a modulus
// outside the canonical byte shape. This is the keyring key the
// issuer signs into identity bearing records.
func RswFingerprint(modulusB64 string) string {
	raw, ok := canonicalB64Decode(modulusB64)
	if !ok || len(raw) != RswModulusBytes {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// RswLegacyIdentity is the pre-v5 legacy identity: the sha256 of the
// base64 text itself.
func RswLegacyIdentity(modulusB64 string) string {
	sum := sha256.Sum256([]byte(modulusB64))
	return hex.EncodeToString(sum[:])
}

// RswIdentityMatches reports whether the identity is an accepted form
// of the modulus: the canonical fingerprint always, the legacy
// base64-text alias only while the bounded migration mode is enabled.
func RswIdentityMatches(identity, modulusB64 string, allowLegacyAlias bool) bool {
	if canonical := RswFingerprint(modulusB64); canonical != "" && ConstantTimeEquals(canonical, identity) {
		return true
	}
	return allowLegacyAlias && ConstantTimeEquals(RswLegacyIdentity(modulusB64), identity)
}

// ErrRswNotConfigured marks a signed rsw record this verifier cannot
// represent: authentic but unsupported.
var ErrRswNotConfigured = errors.New("kiwicaptcha: the rsw trapdoor is not configured")
