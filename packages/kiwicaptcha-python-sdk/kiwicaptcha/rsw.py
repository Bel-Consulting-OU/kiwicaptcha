"""The rsw time-lock trapdoor and its shared arithmetic.

Port of packages/kiwicaptcha-php/src/Rsw.php. The client squares a
challenge derived base T times modulo the 2048-bit composite n, and
the server verifies instantly through the secret lambda: with
``e = 2^T mod lambda``, Euler gives ``base^(2^T) = base^e mod n``.
Python big integers make the arithmetic native; the validation
pipeline mirrors the PHP one exactly, including the rejection order.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import random
from typing import Dict, Optional, Tuple

MODULUS_BYTES = 256
PROOF_HEX_LENGTH = 512
SMALL_PRIME_LIMIT = 1000
SELFTEST_BASES = (2, 3, 5, 7, 11, 13, 17, 19)
VALIDATED_PAIR_CACHE_MAX = 8

_small_primes: Tuple[int, ...] = ()


def _primes_upto(limit: int) -> Tuple[int, ...]:
    sieve = bytearray([1]) * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    value = 2
    while value * value <= limit:
        if sieve[value]:
            sieve[value * value::value] = bytearray(len(sieve[value * value::value]))
        value += 1
    return tuple(i for i in range(2, limit + 1) if sieve[i])


def _miller_rabin_composite(n: int, rounds: int = 24) -> bool:
    """Deterministic rounds of Miller Rabin; True when n is composite.

    The gmp probe answers composite for any witness, so the guard only
    needs one direction: a fixed witness set with enough rounds rejects
    every practical prime with overwhelming probability, and a true
    composite is always caught.
    """
    if n < 2:
        return True
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n != p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    rng = random.Random(0x4B495749)
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return True
    return False


def _canonical_base64_bytes(value: str, name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be canonical standard base64")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise ValueError(f"{name} must be canonical standard base64") from None
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{name} must be canonical standard base64")
    return decoded


def decode_modulus(modulus_b64: str) -> int:
    """Decode and shape validate the modulus: 256 bytes, top bit set, odd."""
    raw = _canonical_base64_bytes(modulus_b64, "rsw_modulus_n")
    if len(raw) != MODULUS_BYTES:
        raise ValueError(
            f"rsw_modulus_n must be the base64 of exactly {MODULUS_BYTES} bytes,"
            f" got {len(raw)}"
        )
    if raw[0] & 0x80 == 0:
        raise ValueError("rsw_modulus_n must have its top bit set")
    if raw[MODULUS_BYTES - 1] & 1 == 0:
        raise ValueError("rsw_modulus_n must be odd, the product of two odd primes")
    return int.from_bytes(raw, "big")


def decode_lambda(lambda_b64: str) -> int:
    """Decode and shape validate the trapdoor: 1 to 256 even bytes."""
    raw = _canonical_base64_bytes(lambda_b64, "rsw_lambda")
    if len(raw) == 0 or len(raw) > MODULUS_BYTES:
        raise ValueError(
            f"rsw_lambda must be the base64 of 1..{MODULUS_BYTES} bytes, got {len(raw)}"
        )
    if raw[len(raw) - 1] & 1 == 1:
        raise ValueError("rsw_lambda must be even (the lcm of the two even primality offsets)")
    return int.from_bytes(raw, "big")


def _reject_small_prime_factor(n: int) -> None:
    global _small_primes
    if not _small_primes:
        _small_primes = _primes_upto(SMALL_PRIME_LIMIT)
    for p in _small_primes:
        if n % p == 0:
            raise ValueError(
                "rsw_modulus_n has a prime factor at or below"
                f" {SMALL_PRIME_LIMIT}; a genuine modulus is the product of two"
                " roughly 1024-bit primes"
            )


def _trapdoor_consistent(n: int, lam: int) -> bool:
    for base in SELFTEST_BASES:
        if pow(base, lam, n) != 1:
            return False
    return True


def derive_base(prefix: str, nonce: str, n: int) -> int:
    """The challenge derived base: sha256 of prefix plus nonce, mod n.

    The reduction is a no-op for a conforming modulus and keeps the
    residue canonical for any n.
    """
    digest = hashlib.sha256(
        prefix.encode("utf-8", "surrogatepass") + nonce.encode("utf-8", "surrogatepass")
    ).digest()
    return int.from_bytes(digest, "big") % n


def proof_hex(value: int) -> str:
    """The fixed 512 lowercase hex wire form, zero padded."""
    return format(value, "x").rjust(PROOF_HEX_LENGTH, "0")


class Rsw:
    """One validated trapdoor pair with the memoized validation verdict.

    Validation proves the shape, rejects a modulus with a small prime
    factor or a probable prime modulus, and runs the deterministic
    trapdoor spot check over the fixed small prime base set. Invalid
    pairs are never memoized, so a weak input re validates and is
    refused identically on every construction.
    """

    _cache: Dict[str, Tuple[int, int]] = {}

    __slots__ = ("modulus_b64", "lambda_b64", "n", "lam")

    def __init__(self, modulus_b64: str, lambda_b64: str) -> None:
        key = modulus_b64 + "\x00" + lambda_b64
        cached = Rsw._cache.get(key)
        if cached is not None:
            self.modulus_b64 = modulus_b64
            self.lambda_b64 = lambda_b64
            self.n, self.lam = cached
            return
        n = decode_modulus(modulus_b64)
        lam = decode_lambda(lambda_b64)
        _reject_small_prime_factor(n)
        if not _miller_rabin_composite(n):
            raise ValueError(
                "rsw_modulus_n must not itself be a probable prime"
                " (a genuine 2048-bit modulus is the product of two large primes)"
            )
        if not _trapdoor_consistent(n, lam):
            raise ValueError(
                "rsw_lambda is not a matching trapdoor for rsw_modulus_n"
                " (the lambda shortcut diverges from sequential squaring)"
            )
        if len(Rsw._cache) >= VALIDATED_PAIR_CACHE_MAX:
            Rsw._cache.pop(next(iter(Rsw._cache)))
        Rsw._cache[key] = (n, lam)
        self.modulus_b64 = modulus_b64
        self.lambda_b64 = lambda_b64
        self.n = n
        self.lam = lam

    def expected_proof_hex(self, prefix: str, nonce: str, t: int) -> str:
        """The expected final value as the fixed 512 hex wire form.

        One modular exponentiation replaces the client's T sequential
        squarings.
        """
        base = derive_base(prefix, nonce, self.n)
        exponent = pow(2, t, self.lam)
        return proof_hex(pow(base, exponent, self.n))


def fingerprint(modulus_b64: str) -> Optional[str]:
    """The canonical identity of a modulus: hex sha256 of the bytes.

    Returns None for a modulus outside the canonical byte shape, the
    keyring key the issuer signs into identity bearing records.
    """
    try:
        raw = _canonical_base64_bytes(modulus_b64, "rsw_modulus_n")
    except ValueError:
        return None
    return hashlib.sha256(raw).hexdigest()
