/// dart:ffi binding to the Rust solver core (libkiwicaptcha_solver).
///
/// The required artifact and the full C header contract live in
/// `src/kiwicaptcha_solver.h` (cbindgen-style). Build the wrapper crate
/// once per platform and ship the library beside the app:
///
/// ```sh
/// cargo build --release
/// # iOS:     target/aarch64-apple-ios/release/libkiwicaptcha_solver.a
/// # Android: target/aarch64-linux-android/release/libkiwicaptcha_solver.so
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

typedef _SolveRswNative = Int32 Function(Pointer<Uint8>, Uint32,
    Pointer<Uint8>, Uint32, Pointer<Uint8>, Uint32, Uint64, Pointer<Uint8>);
typedef _SolveRswDart = int Function(Pointer<Uint8>, int, Pointer<Uint8>,
    int, Pointer<Uint8>, int, int, Pointer<Uint8>);

typedef _SolveArgonNative = Int32 Function(Pointer<Uint8>, Uint32,
    Pointer<Uint8>, Uint32, Uint32, Uint32, Uint32, Uint64, Pointer<Uint64>);
typedef _SolveArgonDart = int Function(Pointer<Uint8>, int, Pointer<Uint8>,
    int, int, int, int, int, Pointer<Uint64>);

/// Test seam: swap the native functions for fakes. Null restores the
/// real library.
KiwiFfi? debugFfiOverride;

/// The typed bindings plus the solve dispatch over them.
class KiwiFfi {
  final _SolveSha256Dart solveSha256;
  final _SolveRswDart solveRsw;
  final _SolveArgonDart solveArgon;

  KiwiFfi._(DynamicLibrary lib)
      : solveSha256 = lib
            .lookupFunction<_SolveSha256Native, _SolveSha256Dart>('kiwi_solve_sha256'),
        solveRsw = lib
            .lookupFunction<_SolveRswNative, _SolveRswDart>('kiwi_solve_rsw'),
        solveArgon = lib
            .lookupFunction<_SolveArgonNative, _SolveArgonDart>('kiwi_solve_argon2id');

  factory KiwiFfi.instance() {
    final override = debugFfiOverride;
    if (override != null) return override;
    return KiwiFfi._(_open());
  }

  static DynamicLibrary _open() {
    // Static-linked into the app binary on iOS; a shared object on
    // Android and desktop.
    return Platform.isIOS ? DynamicLibrary.process() : DynamicLibrary.open('libkiwicaptcha_solver.so');
  }

  /// Solve a validated sha256 challenge through the Rust core.
  /// Returns the winning counter, or null on exhaustion.
  int? sha256Search({
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
      return code == kiwiOk ? outCounter.value : null;
    } finally {
      calloc.free(prefixPtr);
      calloc.free(saltPtr);
      calloc.free(outCounter);
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

  /// Argon2id through the core; the Rust wrapper refuses when its
  /// feature is compiled out, which this package surfaces verbatim.
  int? argon2id({
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
