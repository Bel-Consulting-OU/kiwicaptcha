//! # kiwicaptcha-ffi — the native FFI core of the Flutter package
//!
//! This crate implements the C ABI declared in
//! `packages/kiwicaptcha-flutter/src/kiwicaptcha_solver.h` and consumed
//! by the Dart bindings in `packages/kiwicaptcha-flutter/lib/src/
//! ffi_bindings.dart`. The library file it produces is named
//! `libkiwicaptcha_solver.{so,dylib}` (`kiwicaptcha_solver.dll` on
//! Windows) — exactly the name `KiwiFfi` opens.
//!
//! ## The ABI (stable; mirrored by the Dart typedefs)
//!
//! ```c
//! int32_t kiwi_solve_sha256(
//!     const uint8_t* prefix, uint32_t prefix_len,
//!     const uint8_t* salt, uint32_t salt_len,
//!     uint32_t target_bits, uint64_t max_hashes,
//!     uint64_t* out_counter);
//!
//! int32_t kiwi_solve_rsw(
//!     const uint8_t* modulus, uint32_t modulus_len,
//!     const uint8_t* prefix, uint32_t prefix_len,
//!     const uint8_t* nonce, uint32_t nonce_len,
//!     uint64_t t, uint8_t* out_proof);          // out_proof: 256 bytes
//!
//! int32_t kiwi_solve_argon2id(
//!     const uint8_t* prefix, uint32_t prefix_len,
//!     const uint8_t* salt, uint32_t salt_len,
//!     uint32_t m_kib, uint32_t t, uint32_t p,
//!     uint32_t target_bits, uint64_t* out_counter);
//!
//! // The batched spelling the Dart solver drives so its cooperative
//! // cancellation probe fires at the Interactive-Client Lifecycle v1
//! // cadence (sha256: every 2048 candidates; argon2id: between
//! // derivations; rsw: every 256 squarings):
//! int32_t kiwi_solve_sha256_range(
//!     const uint8_t* prefix, uint32_t prefix_len,
//!     const uint8_t* salt, uint32_t salt_len,
//!     uint32_t target_bits, uint64_t start_counter,
//!     uint64_t max_hashes, uint64_t* out_counter);
//!
//! int32_t kiwi_solve_argon2id_range(
//!     const uint8_t* prefix, uint32_t prefix_len,
//!     const uint8_t* salt, uint32_t salt_len,
//!     uint32_t m_kib, uint32_t t, uint32_t p,
//!     uint32_t target_bits, uint64_t start_counter,
//!     uint64_t max_hashes, uint64_t* out_counter);
//!
//! int32_t kiwi_rsw_begin(
//!     const uint8_t* modulus, uint32_t modulus_len,
//!     const uint8_t* prefix, uint32_t prefix_len,
//!     const uint8_t* nonce, uint32_t nonce_len,
//!     uint8_t* out_value);                       // out_value: 256 bytes
//!
//! int32_t kiwi_rsw_square(
//!     const uint8_t* modulus, uint32_t modulus_len,
//!     uint8_t* value, uint32_t squarings);       // value: 256 bytes, in place
//! ```
//!
//! The three `kiwi_solve_*` entry points keep their original semantics
//! (one call, whole search); the range/batched exports above are
//! strictly additive, so existing consumers never see a change.
//!
//! Memory ownership: the caller owns everything. Inputs are
//! caller-owned read-only buffers; results are written into
//! caller-allocated out buffers (`out_counter`, `out_proof`). The
//! library performs no allocation the caller must release, so there is
//! no exported free function. Out buffers are written only on
//! `KIWI_OK`.
//!
//! Status codes (the `kiwi*` constants of the Dart bindings):
//!
//! * `0` `KIWI_OK`
//! * `1` `KIWI_ERR_MALFORMED` — the input is outside the contract
//! * `2` `KIWI_ERR_CAP` — difficulty (or a hash budget) above the caps
//! * `3` `KIWI_ERR_ARGON_UNAVAILABLE` — built `--no-default-features`
//! * `4` `KIWI_ERR_EXECUTION_UNSUPPORTED` — reserved: the Dart
//!   validation layer refuses execution-armed challenges before this
//!   ABI is ever reached, so the native side never produces it
//! * `5` `KIWI_ERR_EXHAUSTED` — the search window had no winner
//!
//! ## Algorithms (the shared preimage contracts)
//!
//! * **sha256** — the shared search `SHA-256(prefix || decimal(counter)
//!   || salt)` for `target_bits` leading zero bits, counter from zero,
//!   at most `max_hashes` tries. Caps are the core crate's constants
//!   (the Rust mirror of protocol/limits.json): target bits 1..=20,
//!   budget at most 20,000,000.
//! * **rsw** — the sequential time lock: `SHA-256(prefix || nonce)`
//!   reduced modulo the canonical 2048-bit odd composite, squared T
//!   times, rendered as the 256-byte big-endian wire form (the 512-hex
//!   proof). The base derivation and the proof rendering are the core
//!   crate's own public functions ([kiwicaptcha::derive_base],
//!   [kiwicaptcha::proof_hex]), so the loop starts and ends exactly
//!   where the trapdoor verifier expects. T stays inside the protocol
//!   bounds 10,000..=300,000.
//! * **argon2id** — Argon2id over `prefix || decimal(counter)` as the
//!   password with the issued salt and `m_kib`/`t`/`p`, the same
//!   derivation the verifier re-runs. The issued contract: target bits
//!   1..=10, `m_kib` 8..=65536 KiB (and at least `8 * p`), `t` 3..=6,
//!   `p` = 1.
//!
//! The integration test (`tests/abi.rs`) loads the built cdylib the
//! way Dart does and drives these three entry points over the shared
//! golden PHP vectors, verifying each solution with the workspace's
//! real verifier.

use std::panic::{catch_unwind, AssertUnwindSafe};

use kiwicaptcha::{derive_base, SOLVER_MAX_HASHES, SOLVER_MAX_TARGET_BITS};
#[cfg(feature = "argon")]
use kiwicaptcha::{SOLVER_MAX_ARGON2_M_KIB, SOLVER_MAX_ARGON2_TARGET_BITS};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

/// The rsw squaring-count bounds of the client contract (protocol/
/// limits.json rsw_t_min/rsw_t_max, mirrored by the core crate's
/// issuance constants).
const RSW_T_MIN: u64 = kiwicaptcha::challenge::MIN_RSW_T as u64;
const RSW_T_MAX: u64 = kiwicaptcha::challenge::MAX_RSW_T as u64;

/// The canonical 2048-bit odd composite is exactly 256 bytes.
const MODULUS_BYTES: usize = kiwicaptcha::rsw::MODULUS_BYTES;

/// The wire nonce is the standard base64 of 32 bytes: 44 ASCII
/// characters ending in '='.
const NONCE_LEN: usize = 44;

pub const KIWI_OK: i32 = 0;
pub const KIWI_ERR_MALFORMED: i32 = 1;
pub const KIWI_ERR_CAP: i32 = 2;
pub const KIWI_ERR_ARGON_UNAVAILABLE: i32 = 3;
pub const KIWI_ERR_EXECUTION_UNSUPPORTED: i32 = 4;
pub const KIWI_ERR_EXHAUSTED: i32 = 5;

/// Borrow the caller's input buffer as a slice, refusing a null
/// pointer for a non-empty length (and tolerating a null/empty pair,
/// which the per-function length validation rejects where the contract
/// demands content).
unsafe fn input_slice<'a>(ptr: *const u8, len: u32) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, len as usize))
}

/// The shared preimage counter spelling: plain decimal ASCII, the
/// wasm/solver/verifier notion.
fn write_decimal(mut n: u64, buf: &mut [u8; 20]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut temp = [0u8; 20];
    let mut j = 0;
    while n > 0 {
        temp[j] = b'0' + (n % 10) as u8;
        n /= 10;
        j += 1;
    }
    for i in 0..j {
        buf[i] = temp[j - 1 - i];
    }
    j
}

/// Leading zero bits of a digest, big-endian bit order — the shared
/// notion of the verifier and both solvers.
fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

fn solve_sha256(
    prefix: &[u8],
    salt: &[u8],
    target_bits: u32,
    max_hashes: u64,
    out_counter: &mut u64,
) -> i32 {
    if prefix.is_empty() || prefix.len() > 4096 {
        return KIWI_ERR_MALFORMED;
    }
    if salt.is_empty() || salt.len() > 512 {
        return KIWI_ERR_MALFORMED;
    }
    if target_bits == 0 || target_bits > SOLVER_MAX_TARGET_BITS {
        return KIWI_ERR_CAP;
    }
    let cap = match max_hashes {
        0 => SOLVER_MAX_HASHES,
        n if n > SOLVER_MAX_HASHES => return KIWI_ERR_CAP,
        n => n,
    };
    solve_sha256_range(prefix, salt, target_bits, 0, cap, out_counter)
}

/// The batched spelling the Dart-side cancellation loop drives: scan
/// `SHA-256(prefix || decimal(counter) || salt)` for `target_bits`
/// leading zero bits over the half-open counter window
/// `[start_counter, start_counter + max_hashes)`. The window must be
/// non-empty (`max_hashes >= 1`) and within the shared budget
/// (`max_hashes <= SOLVER_MAX_HASHES`); the Dart solver calls it in
/// 2048-counter batches so its cancellation probe fires at the
/// Interactive-Client Lifecycle v1 cadence. Answers
/// `KIWI_ERR_EXHAUSTED` when the window held no winner.
#[allow(clippy::too_many_arguments)]
fn solve_sha256_range(
    prefix: &[u8],
    salt: &[u8],
    target_bits: u32,
    start_counter: u64,
    max_hashes: u64,
    out_counter: &mut u64,
) -> i32 {
    if prefix.is_empty() || prefix.len() > 4096 {
        return KIWI_ERR_MALFORMED;
    }
    if salt.is_empty() || salt.len() > 512 {
        return KIWI_ERR_MALFORMED;
    }
    if target_bits == 0 || target_bits > SOLVER_MAX_TARGET_BITS {
        return KIWI_ERR_CAP;
    }
    if max_hashes == 0 || max_hashes > SOLVER_MAX_HASHES {
        return KIWI_ERR_CAP;
    }
    let end = match start_counter.checked_add(max_hashes) {
        Some(end) => end,
        None => return KIWI_ERR_MALFORMED,
    };
    let mut base = Sha256::new();
    base.update(prefix);
    let mut counter_buf = [0u8; 20];
    for counter in start_counter..end {
        let mut hasher = base.clone();
        let len = write_decimal(counter, &mut counter_buf);
        hasher.update(&counter_buf[..len]);
        hasher.update(salt);
        let digest = hasher.finalize();
        if leading_zero_bits(&digest) >= target_bits {
            *out_counter = counter;
            return KIWI_OK;
        }
    }
    KIWI_ERR_EXHAUSTED
}

/// The shared rsw input validation: canonical 2048-bit odd composite,
/// prefix inside 1..=4096 bytes, the wire nonce. Returns the modulus
/// as a big integer, or `None` for a refusal (`KIWI_ERR_MALFORMED`).
fn validate_rsw_inputs(modulus: &[u8], prefix: &str, nonce: &str) -> Option<BigUint> {
    if modulus.len() != MODULUS_BYTES
        || modulus[0] & 0x80 == 0
        || modulus[MODULUS_BYTES - 1] & 1 == 0
    {
        return None;
    }
    if prefix.is_empty() || prefix.len() > 4096 {
        return None;
    }
    if nonce.len() != NONCE_LEN
        || !nonce.as_bytes()[..NONCE_LEN - 1]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
        || !nonce.ends_with('=')
    {
        return None;
    }
    Some(BigUint::from_bytes_be(modulus))
}

/// Store a residue as the 256-byte big-endian wire form (the
/// byte-level mirror of the core's `proof_hex`: 512 lowercase hex,
/// zero-padded).
fn write_be_256(value: &BigUint, out: &mut [u8]) {
    let bytes = value.to_bytes_be();
    debug_assert!(bytes.len() <= MODULUS_BYTES);
    out.fill(0);
    let start = MODULUS_BYTES - bytes.len();
    out[start..].copy_from_slice(&bytes);
}

fn solve_rsw(modulus: &[u8], prefix: &str, nonce: &str, t: u64, out_proof: &mut [u8]) -> i32 {
    let n = match validate_rsw_inputs(modulus, prefix, nonce) {
        Some(n) => n,
        None => return KIWI_ERR_MALFORMED,
    };
    if !(RSW_T_MIN..=RSW_T_MAX).contains(&t) {
        return KIWI_ERR_MALFORMED;
    }
    // The base derivation and the wire rendering are the core crate's
    // own public functions, so the sequential loop starts and ends
    // exactly where the trapdoor verifier expects.
    let mut value = derive_base(prefix, nonce, &n);
    for _ in 0..t {
        value = (&value * &value) % &n;
    }
    write_be_256(&value, out_proof);
    KIWI_OK
}

/// The batched rsw spelling the Dart-side cancellation loop drives,
/// step one: validate the inputs and derive the squaring base
/// `SHA-256(prefix || nonce) mod n`, written big-endian to
/// `out_value` (256 bytes). The Dart side then advances the value with
/// [kiwi_rsw_square] in 256-squaring batches and renders the final
/// 256 bytes as the 512-hex proof itself.
fn rsw_begin(modulus: &[u8], prefix: &str, nonce: &str, out_value: &mut [u8]) -> i32 {
    let n = match validate_rsw_inputs(modulus, prefix, nonce) {
        Some(n) => n,
        None => return KIWI_ERR_MALFORMED,
    };
    let value = derive_base(prefix, nonce, &n);
    write_be_256(&value, out_value);
    KIWI_OK
}

/// Step two: square the 256-byte big-endian `value` modulo the
/// canonical composite exactly `squarings` times, updating the buffer
/// in place. A value at or above the modulus is refused
/// (`KIWI_ERR_MALFORMED`) — a state the begin/square chain can never
/// produce, so it only flags a misused buffer.
fn rsw_square(modulus: &[u8], value: &mut [u8], squarings: u32) -> i32 {
    if modulus.len() != MODULUS_BYTES
        || modulus[0] & 0x80 == 0
        || modulus[MODULUS_BYTES - 1] & 1 == 0
    {
        return KIWI_ERR_MALFORMED;
    }
    let n = BigUint::from_bytes_be(modulus);
    let mut v = BigUint::from_bytes_be(value);
    if v >= n {
        return KIWI_ERR_MALFORMED;
    }
    for _ in 0..squarings {
        v = (&v * &v) % &n;
    }
    write_be_256(&v, value);
    KIWI_OK
}

#[cfg(feature = "argon")]
fn solve_argon2id(
    prefix: &[u8],
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
    target_bits: u32,
    out_counter: &mut u64,
) -> i32 {
    solve_argon2id_range(
        prefix,
        salt,
        m_kib,
        t,
        p,
        target_bits,
        0,
        SOLVER_MAX_HASHES,
        out_counter,
    )
}

/// The batched spelling the Dart-side cancellation loop drives:
/// argon2id over `prefix || decimal(counter)` for counters in the
/// half-open window `[start_counter, start_counter + max_hashes)`,
/// first hit wins. The Dart solver calls it one derivation at a time
/// so its cancellation probe fires between candidate derivations (the
/// lifecycle contract's argon2id cadence).
#[cfg(feature = "argon")]
#[allow(clippy::too_many_arguments)]
fn solve_argon2id_range(
    prefix: &[u8],
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
    target_bits: u32,
    start_counter: u64,
    max_hashes: u64,
    out_counter: &mut u64,
) -> i32 {
    use argon2::{Algorithm, Argon2, Block, Params, Version};

    if prefix.is_empty() || prefix.len() > 4096 {
        return KIWI_ERR_MALFORMED;
    }
    if salt.is_empty() || salt.len() > 512 {
        return KIWI_ERR_MALFORMED;
    }
    if target_bits == 0 || target_bits > SOLVER_MAX_ARGON2_TARGET_BITS {
        return KIWI_ERR_CAP;
    }
    if !(8..=SOLVER_MAX_ARGON2_M_KIB).contains(&m_kib)
        || m_kib < 8 * p
        || !(3..=6).contains(&t)
        || p != 1
    {
        return KIWI_ERR_MALFORMED;
    }
    if max_hashes == 0 || max_hashes > SOLVER_MAX_HASHES {
        return KIWI_ERR_CAP;
    }
    let end = match start_counter.checked_add(max_hashes) {
        Some(end) => end,
        None => return KIWI_ERR_MALFORMED,
    };
    let params = match Params::new(m_kib, t, p, Some(32)) {
        Ok(params) => params,
        Err(_) => return KIWI_ERR_MALFORMED,
    };
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    // The memory buffer is allocated once and reused across counters,
    // exactly like the wasm chunk solver and the automation solver.
    let mut memory = vec![Block::default(); params.block_count()];
    let mut password = Vec::with_capacity(prefix.len() + 20);
    password.extend_from_slice(prefix);
    let digit_start = password.len();
    let mut counter_buf = [0u8; 20];
    let mut output = [0u8; 32];
    for counter in start_counter..end {
        password.truncate(digit_start);
        let len = write_decimal(counter, &mut counter_buf);
        password.extend_from_slice(&counter_buf[..len]);
        if hasher
            .hash_password_into_with_memory(&password, salt, &mut output, &mut memory)
            .is_err()
        {
            return KIWI_ERR_MALFORMED;
        }
        if leading_zero_bits(&output) >= target_bits {
            *out_counter = counter;
            return KIWI_OK;
        }
    }
    KIWI_ERR_EXHAUSTED
}

#[cfg(not(feature = "argon"))]
fn solve_argon2id(
    _prefix: &[u8],
    _salt: &[u8],
    _m_kib: u32,
    _t: u32,
    _p: u32,
    _target_bits: u32,
    _out_counter: &mut u64,
) -> i32 {
    KIWI_ERR_ARGON_UNAVAILABLE
}

#[cfg(not(feature = "argon"))]
#[allow(clippy::too_many_arguments)]
fn solve_argon2id_range(
    _prefix: &[u8],
    _salt: &[u8],
    _m_kib: u32,
    _t: u32,
    _p: u32,
    _target_bits: u32,
    _start_counter: u64,
    _max_hashes: u64,
    _out_counter: &mut u64,
) -> i32 {
    KIWI_ERR_ARGON_UNAVAILABLE
}

/// Every export is a thin panic guard over its implementation: a panic
/// never unwinds across the C boundary (it would abort the host);
/// unsound input maps to `KIWI_ERR_MALFORMED` instead.
fn guard(body: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(KIWI_ERR_MALFORMED)
}

/// Search `SHA-256(prefix || decimal(counter) || salt)` for
/// `target_bits` leading zero bits. Writes the winning counter to
/// `*out_counter` on success. A zero `max_hashes` selects the
/// documented 20,000,000 budget; a larger one is refused
/// (`KIWI_ERR_CAP`). Answers `KIWI_ERR_EXHAUSTED` when the window was
/// scanned without a hit.
///
/// # Safety
///
/// `prefix`/`salt` must point to `prefix_len`/`salt_len` readable
/// bytes; `out_counter` to one writable `uint64_t`. Nulls are refused
/// with `KIWI_ERR_MALFORMED`.
#[no_mangle]
pub unsafe extern "C" fn kiwi_solve_sha256(
    prefix: *const u8,
    prefix_len: u32,
    salt: *const u8,
    salt_len: u32,
    target_bits: u32,
    max_hashes: u64,
    out_counter: *mut u64,
) -> i32 {
    guard(|| {
        // SAFETY: the caller guarantees the buffer lengths above; the
        // slices live for this call only and outlive the body below.
        let prefix = input_slice(prefix, prefix_len);
        let salt = input_slice(salt, salt_len);
        let (prefix, salt) = match (prefix, salt) {
            (Some(p), Some(s)) => (p, s),
            _ => return KIWI_ERR_MALFORMED,
        };
        if out_counter.is_null() {
            return KIWI_ERR_MALFORMED;
        }
        // SAFETY: non-null caller-provided u64 slot.
        let out = &mut *out_counter;
        solve_sha256(prefix, salt, target_bits, max_hashes, out)
    })
}

/// T sequential modular squarings of `SHA-256(prefix || nonce)` mod n
/// over the canonical 2048-bit odd composite (exactly 256 bytes, top
/// bit set, odd), T inside 10,000..=300,000. Writes the final value
/// big-endian to `out_proof` (exactly 256 bytes).
///
/// # Safety
///
/// `modulus`/`prefix`/`nonce` must point to `modulus_len`/
/// `prefix_len`/`nonce_len` readable bytes; `out_proof` to 256
/// writable bytes. Nulls are refused with `KIWI_ERR_MALFORMED`.
#[no_mangle]
pub unsafe extern "C" fn kiwi_solve_rsw(
    modulus: *const u8,
    modulus_len: u32,
    prefix: *const u8,
    prefix_len: u32,
    nonce: *const u8,
    nonce_len: u32,
    t: u64,
    out_proof: *mut u8,
) -> i32 {
    guard(|| {
        let modulus = match input_slice(modulus, modulus_len) {
            Some(slice) => slice,
            None => return KIWI_ERR_MALFORMED,
        };
        let prefix = match input_slice(prefix, prefix_len) {
            Some(slice) => slice,
            None => return KIWI_ERR_MALFORMED,
        };
        let nonce = match input_slice(nonce, nonce_len) {
            Some(slice) => slice,
            None => return KIWI_ERR_MALFORMED,
        };
        // The base derivation reuses the core crate's `derive_base`,
        // which takes the wire strings; non-UTF-8 input is outside the
        // wire contract (both fields are ASCII/UTF-8 on the wire).
        let (prefix, nonce): (&str, &str) =
            match (std::str::from_utf8(prefix), std::str::from_utf8(nonce)) {
                (Ok(p), Ok(n)) => (p, n),
                _ => return KIWI_ERR_MALFORMED,
            };
        if out_proof.is_null() {
            return KIWI_ERR_MALFORMED;
        }
        // SAFETY: non-null caller-provided 256-byte buffer.
        let out = std::slice::from_raw_parts_mut(out_proof, MODULUS_BYTES);
        solve_rsw(modulus, prefix, nonce, t, out)
    })
}

/// Argon2id over `prefix || decimal(counter)` with the issued salt and
/// `m_kib`/`t`/`p` parameters, first counter meeting `target_bits`
/// wins. Built without the `argon` feature this answers
/// `KIWI_ERR_ARGON_UNAVAILABLE`.
///
/// # Safety
///
/// Same buffer rules as [`kiwi_solve_sha256`].
#[no_mangle]
pub unsafe extern "C" fn kiwi_solve_argon2id(
    prefix: *const u8,
    prefix_len: u32,
    salt: *const u8,
    salt_len: u32,
    m_kib: u32,
    t: u32,
    p: u32,
    target_bits: u32,
    out_counter: *mut u64,
) -> i32 {
    guard(|| {
        let prefix = input_slice(prefix, prefix_len);
        let salt = input_slice(salt, salt_len);
        let (prefix, salt) = match (prefix, salt) {
            (Some(p), Some(s)) => (p, s),
            _ => return KIWI_ERR_MALFORMED,
        };
        if out_counter.is_null() {
            return KIWI_ERR_MALFORMED;
        }
        // SAFETY: non-null caller-provided u64 slot.
        let out = &mut *out_counter;
        solve_argon2id(prefix, salt, m_kib, t, p, target_bits, out)
    })
}

/// Batched sha256 search over the half-open counter window
/// `[start_counter, start_counter + max_hashes)`: the entry point the
/// Dart solver drives in 2048-counter batches so its cancellation
/// probe fires at the Interactive-Client Lifecycle v1 cadence. Writes
/// the winning counter to `*out_counter` on success; answers
/// `KIWI_ERR_EXHAUSTED` when the window was scanned without a hit.
///
/// # Safety
///
/// Same buffer rules as [`kiwi_solve_sha256`].
#[no_mangle]
pub unsafe extern "C" fn kiwi_solve_sha256_range(
    prefix: *const u8,
    prefix_len: u32,
    salt: *const u8,
    salt_len: u32,
    target_bits: u32,
    start_counter: u64,
    max_hashes: u64,
    out_counter: *mut u64,
) -> i32 {
    guard(|| {
        // SAFETY: the caller guarantees the buffer lengths above; the
        // slices live for this call only and outlive the body below.
        let prefix = input_slice(prefix, prefix_len);
        let salt = input_slice(salt, salt_len);
        let (prefix, salt) = match (prefix, salt) {
            (Some(p), Some(s)) => (p, s),
            _ => return KIWI_ERR_MALFORMED,
        };
        if out_counter.is_null() {
            return KIWI_ERR_MALFORMED;
        }
        // SAFETY: non-null caller-provided u64 slot.
        let out = &mut *out_counter;
        solve_sha256_range(prefix, salt, target_bits, start_counter, max_hashes, out)
    })
}

/// Batched argon2id search over the half-open counter window
/// `[start_counter, start_counter + max_hashes)`: the entry point the
/// Dart solver drives one derivation at a time so its cancellation
/// probe fires between candidate derivations. Built without the
/// `argon` feature this answers `KIWI_ERR_ARGON_UNAVAILABLE`.
///
/// # Safety
///
/// Same buffer rules as [`kiwi_solve_sha256`].
#[no_mangle]
pub unsafe extern "C" fn kiwi_solve_argon2id_range(
    prefix: *const u8,
    prefix_len: u32,
    salt: *const u8,
    salt_len: u32,
    m_kib: u32,
    t: u32,
    p: u32,
    target_bits: u32,
    start_counter: u64,
    max_hashes: u64,
    out_counter: *mut u64,
) -> i32 {
    guard(|| {
        let prefix = input_slice(prefix, prefix_len);
        let salt = input_slice(salt, salt_len);
        let (prefix, salt) = match (prefix, salt) {
            (Some(p), Some(s)) => (p, s),
            _ => return KIWI_ERR_MALFORMED,
        };
        if out_counter.is_null() {
            return KIWI_ERR_MALFORMED;
        }
        // SAFETY: non-null caller-provided u64 slot.
        let out = &mut *out_counter;
        solve_argon2id_range(
            prefix,
            salt,
            m_kib,
            t,
            p,
            target_bits,
            start_counter,
            max_hashes,
            out,
        )
    })
}

/// Rsw step one (the batched spelling of [`kiwi_solve_rsw`]):
/// validate the inputs and derive the squaring base
/// `SHA-256(prefix || nonce) mod n`, written big-endian to
/// `out_value` (exactly 256 bytes).
///
/// # Safety
///
/// Same buffer rules as [`kiwi_solve_rsw`], with `out_value` taking
/// the 256-byte proof buffer's role.
#[no_mangle]
pub unsafe extern "C" fn kiwi_rsw_begin(
    modulus: *const u8,
    modulus_len: u32,
    prefix: *const u8,
    prefix_len: u32,
    nonce: *const u8,
    nonce_len: u32,
    out_value: *mut u8,
) -> i32 {
    guard(|| {
        let modulus = match input_slice(modulus, modulus_len) {
            Some(slice) => slice,
            None => return KIWI_ERR_MALFORMED,
        };
        let prefix = match input_slice(prefix, prefix_len) {
            Some(slice) => slice,
            None => return KIWI_ERR_MALFORMED,
        };
        let nonce = match input_slice(nonce, nonce_len) {
            Some(slice) => slice,
            None => return KIWI_ERR_MALFORMED,
        };
        let (prefix, nonce): (&str, &str) =
            match (std::str::from_utf8(prefix), std::str::from_utf8(nonce)) {
                (Ok(p), Ok(n)) => (p, n),
                _ => return KIWI_ERR_MALFORMED,
            };
        if out_value.is_null() {
            return KIWI_ERR_MALFORMED;
        }
        // SAFETY: non-null caller-provided 256-byte buffer.
        let out = std::slice::from_raw_parts_mut(out_value, MODULUS_BYTES);
        rsw_begin(modulus, prefix, nonce, out)
    })
}

/// Rsw step two: square the 256-byte big-endian `value` (updated in
/// place) modulo the canonical composite exactly `squarings` times.
/// The Dart solver drives it in 256-squaring batches so its
/// cancellation probe fires at the lifecycle contract's rsw cadence.
///
/// # Safety
///
/// `modulus` must point to `modulus_len` readable bytes and `value` to
/// 256 writable bytes (holding a residue below the modulus, as
/// [`kiwi_rsw_begin`] produced). Nulls are refused with
/// `KIWI_ERR_MALFORMED`.
#[no_mangle]
pub unsafe extern "C" fn kiwi_rsw_square(
    modulus: *const u8,
    modulus_len: u32,
    value: *mut u8,
    squarings: u32,
) -> i32 {
    guard(|| {
        let modulus = match input_slice(modulus, modulus_len) {
            Some(slice) => slice,
            None => return KIWI_ERR_MALFORMED,
        };
        if value.is_null() {
            return KIWI_ERR_MALFORMED;
        }
        // SAFETY: non-null caller-provided 256-byte buffer.
        let out = std::slice::from_raw_parts_mut(value, MODULUS_BYTES);
        rsw_square(modulus, out, squarings)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_spelling_matches_the_format_macro() {
        let mut buf = [0u8; 20];
        for value in [0u64, 1, 9, 10, 42, 19_999_999, 20_000_000, u32::MAX as u64] {
            let len = write_decimal(value, &mut buf);
            assert_eq!(
                std::str::from_utf8(&buf[..len]).unwrap(),
                format!("{value}"),
                "the counter spelling must be the plain decimal one"
            );
        }
    }

    #[test]
    fn sha256_range_windows_match_the_single_call() {
        let prefix = b"kiwi|login|";
        let salt: &[u8] = &[1, 2, 3, 4];
        let mut whole = 0u64;
        assert_eq!(solve_sha256(prefix, salt, 8, 1000, &mut whole), KIWI_OK);
        // The window ending just below the winner exhausts; the window
        // starting at the winner finds it in a one-counter batch.
        let mut out = 0u64;
        assert_eq!(
            solve_sha256_range(prefix, salt, 8, 0, whole, &mut out),
            KIWI_ERR_EXHAUSTED
        );
        assert_eq!(
            solve_sha256_range(prefix, salt, 8, whole, 1, &mut out),
            KIWI_OK
        );
        assert_eq!(
            out, whole,
            "the batched search finds the same first counter"
        );
        // A window past the winner still solves (the first hit inside
        // the window, never an earlier one).
        assert_eq!(
            solve_sha256_range(prefix, salt, 8, whole + 1, 2048, &mut out),
            KIWI_OK
        );
        assert!(
            out > whole,
            "the shifted window never revisits earlier counters"
        );
    }

    #[test]
    fn sha256_range_refuses_an_empty_or_oversized_window() {
        let mut out = 0u64;
        assert_eq!(
            solve_sha256_range(b"prefix", b"salt", 8, 0, 0, &mut out),
            KIWI_ERR_CAP
        );
        assert_eq!(
            solve_sha256_range(b"prefix", b"salt", 8, 0, SOLVER_MAX_HASHES + 1, &mut out),
            KIWI_ERR_CAP
        );
        // The window must stay inside u64 (start + max must not wrap).
        assert_eq!(
            solve_sha256_range(b"prefix", b"salt", 8, u64::MAX, 2, &mut out),
            KIWI_ERR_MALFORMED
        );
    }

    #[test]
    fn rsw_begin_and_square_reproduce_the_single_call_proof() {
        let modulus = [0xffu8; MODULUS_BYTES];
        let prefix = "prefix|";
        let nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let t = RSW_T_MIN; // 10,000 squarings: crosses the 256 batch many times
        let mut proof = [0u8; MODULUS_BYTES];
        assert_eq!(solve_rsw(&modulus, prefix, nonce, t, &mut proof), KIWI_OK);

        let mut value = [0u8; MODULUS_BYTES];
        assert_eq!(rsw_begin(&modulus, prefix, nonce, &mut value), KIWI_OK);
        assert_ne!(
            value, [0u8; MODULUS_BYTES],
            "the base derivation is nonzero"
        );

        // The Dart loop's shape: 256-squaring batches until t is spent.
        let mut remaining = t;
        while remaining > 0 {
            let step = remaining.min(256) as u32;
            assert_eq!(rsw_square(&modulus, &mut value, step), KIWI_OK);
            remaining -= step as u64;
        }
        assert_eq!(value, proof, "batched squarings land on the one-call proof");
        // A zero-squaring call is a no-op, and a value at or above the
        // modulus is refused.
        assert_eq!(rsw_square(&modulus, &mut value, 0), KIWI_OK);
        assert_eq!(value, proof);
        let mut above = [0xffu8; MODULUS_BYTES];
        assert_eq!(rsw_square(&modulus, &mut above, 1), KIWI_ERR_MALFORMED);
    }

    #[test]
    fn rsw_begin_refuses_out_of_contract_input_before_any_work() {
        let mut value = [0u8; MODULUS_BYTES];
        let prefix = "prefix|";
        let nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let short = [0u8; MODULUS_BYTES - 1];
        assert_eq!(
            rsw_begin(&short, prefix, nonce, &mut value),
            KIWI_ERR_MALFORMED
        );
        assert_eq!(
            rsw_begin(&[0xffu8; MODULUS_BYTES], prefix, "short", &mut value),
            KIWI_ERR_MALFORMED
        );
    }

    #[test]
    fn leading_zero_counting_matches_the_shared_notion() {
        assert_eq!(leading_zero_bits(&[0, 0, 1]), 23);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0]), 8);
        assert_eq!(leading_zero_bits(&[0x0f]), 4);
    }

    #[test]
    fn sha256_refuses_out_of_contract_input_before_any_work() {
        let mut out = 0u64;
        // Empty prefix, oversized salt, zero and over-cap difficulty.
        assert_eq!(
            solve_sha256(b"", b"salt", 8, 1000, &mut out),
            KIWI_ERR_MALFORMED
        );
        assert_eq!(
            solve_sha256(b"prefix", &[b'x'; 513], 8, 1000, &mut out),
            KIWI_ERR_MALFORMED
        );
        assert_eq!(
            solve_sha256(b"prefix", b"salt", 0, 1000, &mut out),
            KIWI_ERR_CAP
        );
        assert_eq!(
            solve_sha256(
                b"prefix",
                b"salt",
                SOLVER_MAX_TARGET_BITS + 1,
                1000,
                &mut out
            ),
            KIWI_ERR_CAP
        );
        // A budget above the documented cap is a cap refusal too.
        assert_eq!(
            solve_sha256(b"prefix", b"salt", 8, SOLVER_MAX_HASHES + 1, &mut out),
            KIWI_ERR_CAP
        );
        // A tiny budget deterministically exhausts.
        assert_eq!(
            solve_sha256(b"prefix", b"salt", 20, 3, &mut out),
            KIWI_ERR_EXHAUSTED
        );
    }

    #[test]
    fn rsw_refuses_out_of_contract_input_before_any_work() {
        let mut out = [0u8; MODULUS_BYTES];
        let prefix = "prefix|";
        let nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let short = [0u8; MODULUS_BYTES - 1];
        assert_eq!(
            solve_rsw(&short, prefix, nonce, 10_000, &mut out),
            KIWI_ERR_MALFORMED
        );
        let mut even = [0xffu8; MODULUS_BYTES];
        even[MODULUS_BYTES - 1] &= !1;
        assert_eq!(
            solve_rsw(&even, prefix, nonce, 10_000, &mut out),
            KIWI_ERR_MALFORMED
        );
        assert_eq!(
            solve_rsw(&[0x80u8; MODULUS_BYTES], prefix, nonce, 10_000, &mut out),
            KIWI_ERR_MALFORMED
        );
        // T below the protocol floor and above the ceiling.
        assert_eq!(
            solve_rsw(
                &[0xffu8; MODULUS_BYTES],
                prefix,
                nonce,
                RSW_T_MIN - 1,
                &mut out
            ),
            KIWI_ERR_MALFORMED
        );
        assert_eq!(
            solve_rsw(
                &[0xffu8; MODULUS_BYTES],
                prefix,
                nonce,
                RSW_T_MAX + 1,
                &mut out
            ),
            KIWI_ERR_MALFORMED
        );
        // A nonce that is not the standard base64 of 32 bytes.
        assert_eq!(
            solve_rsw(
                &[0xffu8; MODULUS_BYTES],
                prefix,
                "short",
                RSW_T_MIN,
                &mut out
            ),
            KIWI_ERR_MALFORMED
        );
    }

    #[cfg(not(feature = "argon"))]
    #[test]
    fn argon2id_answers_unavailable_when_the_feature_is_compiled_out() {
        let mut out = 0u64;
        assert_eq!(
            solve_argon2id(b"prefix", b"salt", 64, 3, 1, 4, &mut out),
            KIWI_ERR_ARGON_UNAVAILABLE
        );
    }

    #[cfg(feature = "argon")]
    #[test]
    fn argon2id_refuses_out_of_contract_parameters_before_any_work() {
        let mut out = 0u64;
        assert_eq!(
            solve_argon2id(b"prefix", b"salt", 4, 3, 1, 4, &mut out),
            KIWI_ERR_MALFORMED,
            "memory below the 8 KiB Argon2 minimum"
        );
        assert_eq!(
            solve_argon2id(
                b"prefix",
                b"salt",
                SOLVER_MAX_ARGON2_M_KIB + 1,
                3,
                1,
                4,
                &mut out
            ),
            KIWI_ERR_MALFORMED,
            "memory above the browser wasm ceiling"
        );
        assert_eq!(
            solve_argon2id(b"prefix", b"salt", 8, 2, 1, 4, &mut out),
            KIWI_ERR_MALFORMED,
            "time cost below the issued range"
        );
        assert_eq!(
            solve_argon2id(b"prefix", b"salt", 8, 7, 1, 4, &mut out),
            KIWI_ERR_MALFORMED,
            "time cost above the issued range"
        );
        assert_eq!(
            solve_argon2id(b"prefix", b"salt", 8, 3, 2, 4, &mut out),
            KIWI_ERR_MALFORMED,
            "parallelism is pinned to 1"
        );
        assert_eq!(
            solve_argon2id(
                b"prefix",
                b"salt",
                8,
                3,
                1,
                SOLVER_MAX_ARGON2_TARGET_BITS + 1,
                &mut out
            ),
            KIWI_ERR_CAP,
            "difficulty above the argon2id ceiling"
        );
    }

    #[cfg(feature = "argon")]
    #[test]
    fn argon2id_range_agrees_with_the_single_call() {
        // The Argon2 layer refuses salts shorter than 8 bytes, so the
        // happy-path window check needs a wire-legal salt.
        let salt = b"0123456789abcdef";
        let mut whole = 0u64;
        assert_eq!(
            solve_argon2id(b"prefix", salt, 8, 3, 1, 4, &mut whole),
            KIWI_OK
        );
        let mut out = 0u64;
        // The window ending below the winner exhausts; the
        // one-derivation window starting at the winner finds it — the
        // exact call shape the Dart-side cancellation loop issues.
        if whole > 0 {
            assert_eq!(
                solve_argon2id_range(b"prefix", salt, 8, 3, 1, 4, 0, whole, &mut out),
                KIWI_ERR_EXHAUSTED
            );
        }
        assert_eq!(
            solve_argon2id_range(b"prefix", salt, 8, 3, 1, 4, whole, 1, &mut out),
            KIWI_OK
        );
        assert_eq!(
            out, whole,
            "the batched search finds the same first counter"
        );
        // An empty window is a cap refusal.
        assert_eq!(
            solve_argon2id_range(b"prefix", salt, 8, 3, 1, 4, 0, 0, &mut out),
            KIWI_ERR_CAP
        );
    }
}
