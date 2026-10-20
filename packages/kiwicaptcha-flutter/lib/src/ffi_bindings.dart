/// dart:ffi binding to the native solver core (libkiwicaptcha_solver),
/// built from the FFI crate in `native/` of this package.
///
/// The C ABI contract lives in `src/kiwicaptcha_solver.h` and is
/// implemented by the crate at `native/`:
///
/// * every function answers an int32 status code (the `kiwi*` constants
///   below) and writes its result into a CALLER-ALLOCATED out buffer
///   (`uint64_t* out_counter`, or the 256-byte `uint8_t* out_proof` of
///   the rsw solve). The library allocates nothing the caller must
///   free; all input and output memory is owned by this side, so no
///   exported free function exists.
/// * pointers are `const uint8_t*` with a `uint32_t` length each; the
///   counter/t arguments are `uint32_t`/`uint64_t` exactly as the
///   typedefs below spell them.
/// * alongside the three whole-search entry points there is the
///   batched spelling the solver's cooperative cancellation loop
///   drives (`kiwi_solve_sha256_range`, `kiwi_solve_argon2id_range`,
///   `kiwi_rsw_begin` + `kiwi_rsw_square`) — windowed searches and
///   in-place squaring batches, so the Dart side can probe
///   `isCancelled` at the Interactive-Client Lifecycle v1 cadence.
///
/// Build the native library once per platform (see native/README.md):
///
/// ```sh
/// cd native
/// cargo build --release
/// # Android: cargo-ndk for each ABI
/// # iOS:    --target aarch64-apple-ios (staticlib, linked with -force_load)
/// ```
library kiwicaptcha.ffi;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'challenge.dart';

/// Error codes of the C ABI (mirror of src/kiwicaptcha_solver.h).
const int kiwiOk = 0;
const int kiwiErrMalformed = 1;
const int kiwiErrCap = 2;
const int kiwiErrArgonUnavailable = 3;
const int kiwiErrExecutionUnsupported = 4;
const int kiwiErrExhausted = 5;

typedef _SolveSha256Native = Int32 Function(Pointer<Uint8>, Uint32,
    Pointer<Uint8>, Uint32, Uint32, Uint64, Pointer<Uint64>);
typedef _SolveSha256Dart = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, int, int, Pointer<Uint64>);

typedef _SolveSha256RangeNative = Int32 Function(
    Pointer<Uint8>,
    Uint32,
    Pointer<Uint8>,
    Uint32,
    Uint32,
    Uint64,
    Uint64,
    Pointer<Uint64>);
typedef _SolveSha256RangeDart = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, int, int, int, Pointer<Uint64>);

typedef _SolveRswNative = Int32 Function(Pointer<Uint8>, Uint32,
    Pointer<Uint8>, Uint32, Pointer<Uint8>, Uint32, Uint64, Pointer<Uint8>);
typedef _SolveRswDart = int Function(Pointer<Uint8>, int, Pointer<Uint8>,
    int, Pointer<Uint8>, int, int, Pointer<Uint8>);

typedef _RswBeginNative = Int32 Function(Pointer<Uint8>, Uint32,
    Pointer<Uint8>, Uint32, Pointer<Uint8>, Uint32, Pointer<Uint8>);
typedef _RswBeginDart = int Function(Pointer<Uint8>, int, Pointer<Uint8>,
    int, Pointer<Uint8>, int, Pointer<Uint8>);

typedef _RswSquareNative = Int32 Function(
    Pointer<Uint8>, Uint32, Pointer<Uint8>, Uint32);
typedef _RswSquareDart = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int);

typedef _SolveArgonNative = Int32 Function(Pointer<Uint8>, Uint32,
    Pointer<Uint8>, Uint32, Uint32, Uint32, Uint32, Uint64, Pointer<Uint64>);
typedef _SolveArgonDart = int Function(Pointer<Uint8>, int, Pointer<Uint8>,
    int, int, int, int, int, Pointer<Uint64>);

typedef _SolveArgonRangeNative = Int32 Function(
    Pointer<Uint8>,
    Uint32,
    Pointer<Uint8>,
    Uint32,
    Uint32,
    Uint32,
    Uint32,
    Uint32,
    Uint64,
    Uint64,
    Pointer<Uint64>);
typedef _SolveArgonRangeDart = int Function(Pointer<Uint8>, int,
    Pointer<Uint8>, int, int, int, int, int, int, int, Pointer<Uint64>);

/// Test seam: swap the native functions for fakes. Null restores the
/// real library.
KiwiFfi? debugFfiOverride;

/// The typed bindings plus the solve dispatch over them.
class KiwiFfi {
  final _SolveSha256Dart solveSha256;
  final _SolveSha256RangeDart solveSha256Range;
  final _SolveRswDart solveRsw;
  final _RswBeginDart rswBeginFn;
  final _RswSquareDart rswSquareFn;
  final _SolveArgonDart solveArgon;
  final _SolveArgonRangeDart solveArgonRange;

  KiwiFfi._(DynamicLibrary lib)
      : solveSha256 = lib
            .lookupFunction<_SolveSha256Native, _SolveSha256Dart>('kiwi_solve_sha256'),
        solveSha256Range = lib.lookupFunction<_SolveSha256RangeNative, _SolveSha256RangeDart>(
            'kiwi_solve_sha256_range'),
        solveRsw = lib
            .lookupFunction<_SolveRswNative, _SolveRswDart>('kiwi_solve_rsw'),
        rswBeginFn = lib
            .lookupFunction<_RswBeginNative, _RswBeginDart>('kiwi_rsw_begin'),
        rswSquareFn = lib
            .lookupFunction<_RswSquareNative, _RswSquareDart>('kiwi_rsw_square'),
        solveArgon = lib
            .lookupFunction<_SolveArgonNative, _SolveArgonDart>('kiwi_solve_argon2id'),
        solveArgonRange = lib.lookupFunction<_SolveArgonRangeNative, _SolveArgonRangeDart>(
            'kiwi_solve_argon2id_range');

  factory KiwiFfi.instance() {
    final override = debugFfiOverride;
    if (override != null) return override;
    return KiwiFfi._(_open());
  }

  static DynamicLibrary _open() {
    // Static-linked into the app binary on iOS (the podspec links the
    // staticlib with -force_load, so the symbols stay live); a shared
    // object everywhere else: the .so on Android and Linux, the .dylib
    // on macOS, the DLL on Windows.
    if (Platform.isIOS) return DynamicLibrary.process();
    if (Platform.isMacOS) return DynamicLibrary.open('libkiwicaptcha_solver.dylib');
    if (Platform.isWindows) return DynamicLibrary.open('kiwicaptcha_solver.dll');
    return DynamicLibrary.open('libkiwicaptcha_solver.so');
  }

  /// Solve a validated sha256 challenge through the Rust core.
  /// Returns the winning counter; throws [KiwiSolveError] on any
  /// refusal (including exhaustion of the hash budget).
  int sha256Search({
    required String prefix,
    required Uint8List salt,
    required int targetBits,
    int maxHashes = KiwiLimits.maxHashes,
  }) {
    final prefixBytes = Uint8List.fromList(utf8.encode(prefix));
    final prefixPtr = _bytesPtr(prefixBytes);
    final saltPtr = _bytesPtr(salt);
    final outCounter = calloc<Uint64>();
    try {
      final code = solveSha256(
          prefixPtr, prefixBytes.length, saltPtr, salt.length, targetBits, maxHashes, outCounter);
      _check(code);
      return outCounter.value;
    } finally {
      calloc.free(prefixPtr);
      calloc.free(saltPtr);
      calloc.free(outCounter);
    }
  }

  /// The batched sha256 search the solver's cancellation loop drives:
  /// scan counters in `[startCounter, startCounter + maxHashes)` and
  /// return the first one meeting [targetBits]. Answers
  /// [KiwiRefusal.exhausted] when the window held no winner.
  int sha256SearchRange({
    required String prefix,
    required Uint8List salt,
    required int targetBits,
    required int startCounter,
    required int maxHashes,
  }) {
    final prefixBytes = Uint8List.fromList(utf8.encode(prefix));
    final prefixPtr = _bytesPtr(prefixBytes);
    final saltPtr = _bytesPtr(salt);
    final outCounter = calloc<Uint64>();
    try {
      final code = solveSha256Range(prefixPtr, prefixBytes.length, saltPtr, salt.length,
          targetBits, startCounter, maxHashes, outCounter);
      _check(code);
      return outCounter.value;
    } finally {
      calloc.free(prefixPtr);
      calloc.free(saltPtr);
      calloc.free(outCounter);
    }
  }

  /// The batched rsw solve, step one: derive the squaring base
  /// (256 bytes big-endian) for a validated challenge.
  Uint8List rswBegin({
    required Uint8List modulus,
    required String prefix,
    required String nonce,
  }) {
    final modulusPtr = _bytesPtr(modulus);
    final prefixBytes = Uint8List.fromList(utf8.encode(prefix));
    final prefixPtr = _bytesPtr(prefixBytes);
    final nonceBytes = Uint8List.fromList(utf8.encode(nonce));
    final noncePtr = _bytesPtr(nonceBytes);
    final outValue = calloc<Uint8>(256);
    try {
      final code = rswBeginFn(modulusPtr, modulus.length, prefixPtr, prefixBytes.length,
          noncePtr, nonceBytes.length, outValue);
      _check(code);
      return Uint8List.fromList(outValue.asTypedList(256));
    } finally {
      calloc.free(modulusPtr);
      calloc.free(prefixPtr);
      calloc.free(noncePtr);
      calloc.free(outValue);
    }
  }

  /// The batched rsw solve, step two: square [value] (256 bytes,
  /// updated in place) exactly [squarings] times modulo the modulus.
  void rswSquare({
    required Uint8List modulus,
    required Uint8List value,
    required int squarings,
  }) {
    final modulusPtr = _bytesPtr(modulus);
    final valuePtr = _bytesPtr(value);
    try {
      final code = rswSquareFn(modulusPtr, modulus.length, valuePtr, squarings);
      _check(code);
      value.setAll(0, valuePtr.asTypedList(256));
    } finally {
      calloc.free(modulusPtr);
      calloc.free(valuePtr);
    }
  }

  /// Solve a validated rsw challenge; returns the 512-hex proof.
  String rswSquarings({
    required Uint8List modulus,
    required String prefix,
    required String nonce,
    required int t,
  }) {
    final modulusPtr = _bytesPtr(modulus);
    final prefixBytes = Uint8List.fromList(utf8.encode(prefix));
    final prefixPtr = _bytesPtr(prefixBytes);
    final nonceBytes = Uint8List.fromList(utf8.encode(nonce));
    final noncePtr = _bytesPtr(nonceBytes);
    final outProof = calloc<Uint8>(256);
    try {
      final code = solveRsw(modulusPtr, modulus.length, prefixPtr, prefixBytes.length,
          noncePtr, nonceBytes.length, t, outProof);
      _check(code);
      return outProof.asTypedList(256).map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    } finally {
      calloc.free(modulusPtr);
      calloc.free(prefixPtr);
      calloc.free(noncePtr);
      calloc.free(outProof);
    }
  }

  /// Argon2id through the core; a core built without the `argon`
  /// feature answers `kiwiErrArgonUnavailable`, which this package
  /// surfaces verbatim. Returns the winning counter; throws
  /// [KiwiSolveError] on any refusal.
  int argon2id({
    required String prefix,
    required Uint8List salt,
    required int mKib,
    required int t,
    required int p,
    required int targetBits,
  }) {
    final prefixBytes = Uint8List.fromList(utf8.encode(prefix));
    final prefixPtr = _bytesPtr(prefixBytes);
    final saltPtr = _bytesPtr(salt);
    final outCounter = calloc<Uint64>();
    try {
      final code = solveArgon(prefixPtr, prefixBytes.length, saltPtr, salt.length, mKib, t,
          p, targetBits, outCounter);
      _check(code);
      return outCounter.value;
    } finally {
      calloc.free(prefixPtr);
      calloc.free(saltPtr);
      calloc.free(outCounter);
    }
  }

  /// The batched argon2id search the solver's cancellation loop drives
  /// (one derivation per call): scan counters in
  /// `[startCounter, startCounter + maxHashes)` and return the first
  /// one meeting [targetBits]. Answers [KiwiRefusal.exhausted] when
  /// the window held no winner.
  int argon2idRange({
    required String prefix,
    required Uint8List salt,
    required int mKib,
    required int t,
    required int p,
    required int targetBits,
    required int startCounter,
    required int maxHashes,
  }) {
    final prefixBytes = Uint8List.fromList(utf8.encode(prefix));
    final prefixPtr = _bytesPtr(prefixBytes);
    final saltPtr = _bytesPtr(salt);
    final outCounter = calloc<Uint64>();
    try {
      final code = solveArgonRange(prefixPtr, prefixBytes.length, saltPtr, salt.length, mKib,
          t, p, targetBits, startCounter, maxHashes, outCounter);
      _check(code);
      return outCounter.value;
    } finally {
      calloc.free(prefixPtr);
      calloc.free(saltPtr);
      calloc.free(outCounter);
    }
  }

  void _check(int code) {
    switch (code) {
      case kiwiOk:
        return;
      case kiwiErrMalformed:
        throw const KiwiSolveError.malformed('the core refused the challenge');
      case kiwiErrCap:
        throw const KiwiSolveError(
            KiwiRefusal.difficultyBeyondCap, 'the core refused the difficulty');
      case kiwiErrArgonUnavailable:
        throw const KiwiSolveError(
            KiwiRefusal.argonUnavailable, 'the core was built without an Argon2 implementation');
      case kiwiErrExecutionUnsupported:
        throw const KiwiSolveError(
            KiwiRefusal.executionUnsupported, 'the core refused an execution-armed challenge');
      case kiwiErrExhausted:
        throw const KiwiSolveError(KiwiRefusal.exhausted, 'the core exhausted the search');
      default:
        throw KiwiSolveError(KiwiRefusal.solverUnavailable, 'unknown core code $code');
    }
  }
}

Pointer<Uint8> _bytesPtr(Uint8List bytes) {
  final ptr = calloc<Uint8>(bytes.length);
  ptr.asTypedList(bytes.length).setAll(0, bytes);
  return ptr;
}
