/// The shared wire contract, mirrored from protocol/limits.json and the
/// Rust solver crate (packages/kiwicaptcha-solver).
library kiwicaptcha.contracts;

/// The proof-of-work algorithms the protocol issues.
enum KiwiAlgorithm { sha256, argon2id, rsw }

/// Protocol caps, mirrored from protocol/limits.json.
class KiwiLimits {
  static const int maxHashes = 20000000;
  static const int shaMaxTargetBits = 20;
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
    final algorithmName = (json['algorithm'] as String?) ?? 'sha256';
    final KiwiAlgorithm algorithm = switch (algorithmName) {
      'sha256' => KiwiAlgorithm.sha256,
      'argon2id' => KiwiAlgorithm.argon2id,
      'rsw' => KiwiAlgorithm.rsw,
      _ => throw const KiwiSolveError.malformed(
          'the algorithm is not one of sha256, argon2id, rsw'),
    };
    int intOf(String key) {
      final value = json[key];
      if (value is int) return value;
      if (value is num && value.toInt() == value) return value.toInt();
      throw KiwiSolveError.malformed('the key $key is missing or not an integer');
    }

    return KiwiChallenge(
      nonce: json['nonce'] as String?,
      salt: json['salt'] as String?,
      algorithm: algorithm,
      mKib: intOf('mKib'),
      t: intOf('t'),
      p: intOf('p'),
      targetBits: intOf('targetBits'),
      prefix: json['prefix'] as String?,
      ttlSecs: (json['ttlSecs'] as num?)?.toInt() ?? 0,
      minDurationMs: (json['minDurationMs'] as num?)?.toInt() ?? 0,
      executionProgram: json['execution_program'] as String?,
      rswModulus: json['rsw_modulus'] as String?,
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
}

class KiwiSolveError implements Exception {
  final KiwiRefusal refusal;
  final String message;
  const KiwiSolveError(this.refusal, this.message);

  const KiwiSolveError.malformed(String detail)
      : this(KiwiRefusal.malformed, detail);

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
