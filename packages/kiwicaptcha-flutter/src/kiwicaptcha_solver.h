/*
 * kiwicaptcha_solver.h — the cbindgen-style C ABI contract of the Rust
 * wrapper crate around packages/kiwicaptcha-solver.
 *
 * BUILD (the artifact the Dart FFI loads):
 *   cargo build --release
 *   # Android: cargo-ndk for each ABI
 *   cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o app/src/main/jniLibs build --release
 *   # iOS: a static library, linked into the app binary
 *   cargo build --release --target aarch64-apple-ios
 *
 * The library name is libkiwicaptcha_solver.{so,a}; the Dart side opens
 * it via DynamicLibrary.open('libkiwicaptcha_solver.so') on Android and
 * DynamicLibrary.process() on iOS.
 *
 * CONTRACT
 * ========
 * All functions answer an int32 error code:
 *   0 KIWI_OK
 *   1 KIWI_ERR_MALFORMED            (the input is outside the contract)
 *   2 KIWI_ERR_CAP                  (difficulty above the shared caps)
 *   3 KIWI_ERR_ARGON_UNAVAILABLE    (built without an Argon2 feature)
 *   4 KIWI_ERR_EXECUTION_UNSUPPORTED
 *   5 KIWI_ERR_EXHAUSTED            (no counter met the target)
 *
 * The shared preimage contract: SHA-256 over
 *   prefix || decimal(counter) || salt
 * with the counter in ASCII decimal starting at zero. The caps are the
 * shared ones (protocol/limits.json): target_bits 1..=20 sha256,
 * at most 20,000,000 hashes; rsw T in 10000..=300000 over a canonical
 * 2048-bit odd composite; argon2id per the issued m_kib/t/p ranges
 * (1..=10 bits, 8..=65536 KiB, t 3..=6, p = 1).
 */

#ifndef KIWI_CAPTCHA_SOLVER_H
#define KIWI_CAPTCHA_SOLVER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Search prefix||dec(counter)||salt for target_bits leading zero bits.
 * Writes the winning counter to *out_counter on success. Answers
 * KIWI_ERR_EXHAUSTED when the window was scanned without a hit.
 */
int32_t kiwi_solve_sha256(
    const uint8_t* prefix, uint32_t prefix_len,
    const uint8_t* salt, uint32_t salt_len,
    uint32_t target_bits,
    uint64_t max_hashes,
    uint64_t* out_counter);

/*
 * T sequential modular squarings of SHA-256(prefix || nonce) mod n over
 * the canonical 2048-bit odd composite (256 bytes). Writes the final
 * value big-endian to out_proof (exactly 256 bytes).
 */
int32_t kiwi_solve_rsw(
    const uint8_t* modulus, uint32_t modulus_len,
    const uint8_t* prefix, uint32_t prefix_len,
    const uint8_t* nonce, uint32_t nonce_len,
    uint64_t t,
    uint8_t* out_proof);

/*
 * Argon2id over prefix||dec(counter) with the issued salt and
 * parameters. Only available when the crate is built with the
 * "argon" feature; otherwise answers KIWI_ERR_ARGON_UNAVAILABLE.
 */
int32_t kiwi_solve_argon2id(
    const uint8_t* prefix, uint32_t prefix_len,
    const uint8_t* salt, uint32_t salt_len,
    uint32_t m_kib, uint32_t t, uint32_t p,
    uint32_t target_bits,
    uint64_t* out_counter);

#ifdef __cplusplus
}
#endif

#endif /* KIWI_CAPTCHA_SOLVER_H */
