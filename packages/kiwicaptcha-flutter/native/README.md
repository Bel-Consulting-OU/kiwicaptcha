# The native solver core (`libkiwicaptcha_solver`)

This crate is the C ABI the Dart bindings
(`../lib/src/ffi_bindings.dart`) load at runtime. It implements
exactly the contract declared in `../src/kiwicaptcha_solver.h`:

```c
int32_t kiwi_solve_sha256(
    const uint8_t* prefix, uint32_t prefix_len,
    const uint8_t* salt, uint32_t salt_len,
    uint32_t target_bits, uint64_t max_hashes,
    uint64_t* out_counter);

int32_t kiwi_solve_rsw(
    const uint8_t* modulus, uint32_t modulus_len,
    const uint8_t* prefix, uint32_t prefix_len,
    const uint8_t* nonce, uint32_t nonce_len,
    uint64_t t, uint8_t* out_proof);           /* out_proof: 256 bytes */

int32_t kiwi_solve_argon2id(
    const uint8_t* prefix, uint32_t prefix_len,
    const uint8_t* salt, uint32_t salt_len,
    uint32_t m_kib, uint32_t t, uint32_t p,
    uint32_t target_bits, uint64_t* out_counter);
```

## ABI and ownership rules

* Status codes: `0` ok, `1` malformed input, `2` difficulty/budget
  above the caps, `3` built without Argon2 (`--no-default-features`),
  `4` reserved (execution-armed challenges are refused by the Dart
  validation layer before this ABI is reached), `5` search exhausted.
  The Dart `_check` maps these onto the `KiwiRefusal` vocabulary
  one-to-one.
* Memory: the caller owns everything. Inputs are read-only buffers;
  results are written into caller-allocated out buffers
  (`out_counter`, the 256-byte `out_proof`). The library performs no
  allocation the caller must release, so there is **no exported free
  function** — `KiwiFfi` `calloc`s its buffers and frees them itself.
* Out buffers are written only on `KIWI_OK`.
* Caps (protocol/limits.json, imported from the workspace core crate,
  never reimplemented): sha256 target bits 1..=20 and a budget of at
  most 20,000,000 hashes; rsw T in 10,000..=300,000 over a canonical
  2048-bit odd composite; argon2id target bits 1..=10, `m_kib`
  8..=65536 KiB (and at least `8 * p`), `t` 3..=6, `p` = 1.

## Algorithms (all real, all shared with the verifier)

* **sha256** — the shared search `SHA-256(prefix || decimal(counter) ||
  salt)`, counter from zero, first hit wins.
* **rsw** — `SHA-256(prefix || nonce)` reduced modulo n, squared T
  times sequentially, rendered as the 256-byte big-endian wire form
  (the 512-hex proof). The base derivation and the proof rendering are
  the core crate's own public functions (`kiwicaptcha::derive_base`,
  `kiwicaptcha::proof_hex`).
* **argon2id** — Argon2id over `prefix || decimal(counter)` with the
  issued salt and `m_kib`/`t`/`p`; the memory buffer is allocated once
  and reused across counters.

## Build per target

```sh
cd native            # this directory

# macOS / Linux host library (what `cargo test` exercises locally)
cargo build --release
#   -> target/release/libkiwicaptcha_solver.dylib | .so + .a

# Android (per ABI; needs the NDK and cargo-ndk)
cargo install cargo-ndk
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o ../android/src/main/jniLibs build --release
#   -> ../android/src/main/jniLibs/<abi>/libkiwicaptcha_solver.so

# iOS (static libraries, one per slice; needs the rust targets)
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
cargo build --release --target aarch64-apple-ios
#   -> target/aarch64-apple-ios/release/libkiwicaptcha_solver.a
```

Inside the repository the crate is a workspace member, so `cargo
build` from this directory writes into the workspace-root `target/`
directory; standalone checkouts build a local `target/` instead.

## Tests

`cargo test` here does two things:

1. Unit tests of the search/validation internals (including, under
   `--no-default-features`, the `KIWI_ERR_ARGON_UNAVAILABLE` path).
2. The ABI integration test (`tests/abi.rs`): it builds the cdylib,
   loads it the way Dart does (dlopen by file name, late-bound
   symbols), solves the shared golden PHP vectors
   (`packages/kiwicaptcha-jvm/testdata/golden/golden-php-vectors.json`
   — the same records the JVM suite pins) for sha256, argon2id and rsw
   through the EXPORTED C ABI, and hands every solution to the
   workspace's real verifier (`kiwicaptcha::verify_solution`). No
   vector is mocked; a drifted preimage or a broken ABI fails here.

These tests ran green on macOS arm64 with rustc 1.96; the Flutter/Dart
toolchain is a separate surface (`flutter test` at the package root,
see ../README.md for its status).
