/// The shared wire contract, mirrored from protocol/limits.json and the
/// Rust solver crate (packages/kiwicaptcha-solver).
library kiwicaptcha.contracts;

import 'dart:typed_data';

/// The proof-of-work algorithms the protocol issues.
enum KiwiAlgorithm { sha256, argon2id, rsw }

/// Protocol caps, mirrored from protocol/limits.json.
class KiwiLimits {
  static const int maxHashes = 20000000;
  static const int shaMaxTargetBits = 20;
  static const int argonMaxTargetBits = 10;
  static const int argonMaxMibKib = 65536;
  static const int rswTMin = 10000;
  static const int rswTMax = 300000;
  static const int maxDurationMs = 3600000;
}

/// The challenge document the endpoint returns.
class KiwiChallenge {
  final String nonce;
  final String salt;
  final KiwiAlgorithm algorithm;
  final int mKib;
  final int t;
  final int p;
  final int targetBits;
  final String prefix;
  final int ttlSecs;
  final int minDurationMs;
  final String? executionProgram;
  final String? rswModulus;

  const KiwiChallenge({
    required this.nonce,
    required this.salt,
    required this.algorithm,
    required this.mKib,
    required this.t,
    required this.p,
    required this.targetBits,
    required this.prefix,
    this.ttlSecs = 0,
    this.minDurationMs = 0,
    this.executionProgram,
    this.rswModulus,
  });

  /// Parse the endpoint's JSON document. The wire keys are the
  /// endpoint's own (camelCase mKib/targetBits/ttlSecs beside the
  /// snake_case optionals).
  factory KiwiChallenge.fromJson(Map<String, dynamic> json) {
    final algorithmValue = json['algorithm'];
    final String algorithmName;
    if (algorithmValue == null) {
      algorithmName = 'sha256';
    } else if (algorithmValue is String) {
      algorithmName = algorithmValue;
    } else {
      throw const KiwiSolveError.malformed('the algorithm is not a string');
    }
    final KiwiAlgorithm algorithm = switch (algorithmName) {
      'sha256' => KiwiAlgorithm.sha256,
      'argon2id' => KiwiAlgorithm.argon2id,
      'rsw' => KiwiAlgorithm.rsw,
      _ => throw const KiwiSolveError.malformed(
          'the algorithm is not one of sha256, argon2id, rsw'),
    };
    String stringOf(String key) {
      final value = json[key];
      if (value is String) return value;
      throw KiwiSolveError.malformed('the key $key is missing or not a string');
    }

    String? optionalStringOf(String key) {
      final value = json[key];
      if (value == null) return null;
      if (value is String) return value;
      throw KiwiSolveError.malformed('the key $key is not a string');
    }

    int intOf(String key) {
      final value = json[key];
      if (value is int) return value;
      if (value is num && value.isFinite && value.toInt() == value) {
        return value.toInt();
      }
      throw KiwiSolveError.malformed('the key $key is missing or not an integer');
    }

    int optionalIntOf(String key) {
      final value = json[key];
      if (value == null) return 0;
      if (value is int) return value;
      if (value is num && value.isFinite && value.toInt() == value) {
        return value.toInt();
      }
      throw KiwiSolveError.malformed('the key $key is not an integer');
    }

    return KiwiChallenge(
      nonce: stringOf('nonce'),
      salt: stringOf('salt'),
      algorithm: algorithm,
      mKib: intOf('mKib'),
      t: intOf('t'),
      p: intOf('p'),
      targetBits: intOf('targetBits'),
      prefix: stringOf('prefix'),
      ttlSecs: optionalIntOf('ttlSecs'),
      minDurationMs: optionalIntOf('minDurationMs'),
      executionProgram: optionalStringOf('execution_program'),
      rswModulus: optionalStringOf('rsw_modulus'),
    );
  }
}

/// Why a solve refused to run.
enum KiwiRefusal {
  malformed,
  difficultyBeyondCap,
  unsupportedParams,
  argonUnavailable,
  executionUnsupported,
  solverUnavailable,
  exhausted,

  /// The cooperative-cancellation probe fired (a newer generation
  /// started, or the expiry deadline passed mid-solve). Never produced
  /// by the native core; surfaced by the solver and the widget as the
  /// Interactive-Client Lifecycle v1 cancelled outcome.
  cancelled,
}

class KiwiSolveError implements Exception {
  final KiwiRefusal refusal;
  final String message;
  const KiwiSolveError(this.refusal, this.message);

  const KiwiSolveError.malformed(String detail)
      : this(KiwiRefusal.malformed, detail);

  /// The typed cancelled outcome: the widget distinguishes "stopped
  /// because the expiry race was lost or a newer generation started"
  /// from "the solve failed".
  const KiwiSolveError.cancelled()
      : this(KiwiRefusal.cancelled, 'the solve was cancelled');

  @override
  String toString() => 'KiwiSolveError(${refusal.name}): $message';
}

/// A completed solve.
class KiwiSolution {
  final int counter;
  final int durationMs;
  final String hashHex;
  final String? rswProof;
  const KiwiSolution({
    required this.counter,
    required this.durationMs,
    required this.hashHex,
    this.rswProof,
  });
}

const String _base64Alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/// Challenge validation with the exact caps the browser driver and the
/// Rust solver enforce. A challenge outside the contract is refused
/// before any work is spent. Lives beside [KiwiChallenge] (and the
/// caps and refusals it checks) so every consumer — the solver, the
/// token packer, the tests — validates through one definition.
void validateKiwiChallenge(KiwiChallenge c) {
  if (c.executionProgram != null && c.executionProgram!.isNotEmpty) {
    throw const KiwiSolveError(
        KiwiRefusal.executionUnsupported,
        'an execution-armed challenge needs the browser interpreter; '
        'the native path refuses it');
  }
  final nonceOk =
      c.nonce.length == 44 && c.nonce.endsWith('=') && RegExp(r'^[A-Za-z0-9+/]{43}=$').hasMatch(c.nonce);
  if (!nonceOk) {
    throw const KiwiSolveError.malformed('the nonce is not the standard base64 of 32 bytes');
  }
  if (c.prefix.isEmpty || c.prefix.length > 4096) {
    throw const KiwiSolveError.malformed('the prefix length is outside 1..=4096');
  }
  if (c.salt.isEmpty || c.salt.length > 512 || !RegExp(r'^[A-Za-z0-9+/]+={0,2}$').hasMatch(c.salt)) {
    throw const KiwiSolveError.malformed('the salt is not decodable base64 or is oversized');
  }
  switch (c.algorithm) {
    case KiwiAlgorithm.sha256:
      if (c.targetBits < 1 || c.targetBits > KiwiLimits.shaMaxTargetBits) {
        throw KiwiSolveError(KiwiRefusal.difficultyBeyondCap,
            'target_bits ${c.targetBits} exceeds the sha256 cap ${KiwiLimits.shaMaxTargetBits}');
      }
    case KiwiAlgorithm.argon2id:
      // The issued argon2id contract: difficulty 1..=10 bits and the
      // memory/time/parallelism ranges the core solver enforces. The
      // solve itself runs in the native FFI core (argon2id, the same
      // derivation the verifier re-runs); a core built without the
      // `argon` feature answers kiwiErrArgonUnavailable at solve time.
      if (c.targetBits < 1 || c.targetBits > KiwiLimits.argonMaxTargetBits) {
        throw KiwiSolveError(KiwiRefusal.difficultyBeyondCap,
            'target_bits ${c.targetBits} exceeds the argon2id cap ${KiwiLimits.argonMaxTargetBits}');
      }
      if (c.mKib < 8 ||
          c.mKib > KiwiLimits.argonMaxMibKib ||
          c.mKib < 8 * c.p ||
          c.t < 3 ||
          c.t > 6 ||
          c.p != 1) {
        throw const KiwiSolveError(KiwiRefusal.unsupportedParams,
            'the argon2id parameters are outside the client contract '
            '(m_kib 8..=65536 KiB and at least 8*p, t 3..=6, p = 1)');
      }
    case KiwiAlgorithm.rsw:
      // Bind the nullable modulus to a local once: Dart does not
      // promote public fields, so `c.rswModulus == null ||
      // c.rswModulus.isEmpty` would not compile.
      final rswModulus = c.rswModulus;
      if (c.t < KiwiLimits.rswTMin ||
          c.t > KiwiLimits.rswTMax ||
          c.p != 1 ||
          c.mKib != 0 ||
          rswModulus == null ||
          rswModulus.isEmpty) {
        throw const KiwiSolveError(KiwiRefusal.unsupportedParams,
            'the rsw parameters are outside the client contract');
      }
      final modulus = _strictBase64Decode(rswModulus);
      if (modulus.length != 256 || (modulus[0] & 0x80) == 0 || (modulus[255] & 1) == 0) {
        throw const KiwiSolveError(KiwiRefusal.unsupportedParams,
            'the rsw modulus is not a canonical 2048-bit odd composite');
      }
  }
}

Uint8List _strictBase64Decode(String value) {
  final clean = value.replaceAll('=', '');
  final out = Uint8List(clean.length * 3 ~/ 4);
  var bits = 0;
  var acc = 0;
  var o = 0;
  for (final ch in clean.codeUnits) {
    final idx = _base64Alphabet.indexOf(String.fromCharCode(ch));
    if (idx < 0) throw const KiwiSolveError.malformed('the value is not standard base64');
    acc = (acc << 6) | idx;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}
