import 'dart:convert';
import 'dart:typed_data';

import 'challenge.dart';
import 'ffi_bindings.dart';

/// The cooperative-cancellation probe of the Interactive-Client
/// Lifecycle v1 contract (protocol/interactive-client-v1): a cheap,
/// non-blocking zero-argument predicate. When it fires the solver
/// raises the typed [KiwiSolveError.cancelled] and schedules no
/// further CPU work.
typedef IsCancelled = bool Function();

/// Pure-Dart SHA-256 for the low-difficulty fallback. Correctness is
/// pinned against standard vectors in the Dart test suite; it is only
/// ever used below the low-difficulty ceiling, where the expected work
/// is a few hundred hashes.
const List<int> _k = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The cancellation checkpoint cadences of the lifecycle contract:
/// sha256 probes at most every 2048 candidates, rsw at most every 256
/// modular squarings, argon2id between candidate derivations. After a
/// firing probe at most one batch of stale work remains.
const int kiwiShaCancellationBatch = 2048;
const int kiwiRswCancellationBatch = 256;
const int kiwiArgonCancellationBatch = 1;

/// SHA-256 over the concatenation of `chunks` (each chunk is a byte
/// sequence). The chunked shape exists so a preimage built as
/// `prefix || decimal(counter) || salt` never needs a defensive copy of
/// the whole input.
Uint8List kiwiSha256(List<List<int>> chunks) {
  final total = chunks.fold<int>(0, (sum, c) => sum + c.length);
  final h = <int>[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  final padded = Uint8List(((total + 8) ~/ 64 + 1) * 64);
  var offset = 0;
  for (final c in chunks) {
    padded.setAll(offset, c);
    offset += c.length;
  }
  padded[total] = 0x80;
  final bitLen = total * 8;
  for (var i = 0; i < 8; i++) {
    padded[padded.length - 1 - i] = (bitLen >> (8 * i)) & 0xff;
  }
  final w = List<int>.filled(64, 0);
  int rotr(int x, int n) => ((x >> n) | (x << (32 - n))) & 0xffffffff;
  for (var block = 0; block < padded.length; block += 64) {
    for (var i = 0; i < 16; i++) {
      w[i] = (padded[block + i * 4] << 24) |
          (padded[block + i * 4 + 1] << 16) |
          (padded[block + i * 4 + 2] << 8) |
          padded[block + i * 4 + 3];
    }
    for (var i = 16; i < 64; i++) {
      final s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      final s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff;
    }
    var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (var i = 0; i < 64; i++) {
      final s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      final ch = (e & f) ^ ((~e & 0xffffffff) & g);
      final t1 = (hh + s1 + ch + _k[i] + w[i]) & 0xffffffff;
      final s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final t2 = (s0 + maj) & 0xffffffff;
      hh = g; g = f; f = e;
      e = (d + t1) & 0xffffffff;
      d = c; c = b; b = a;
      a = (t1 + t2) & 0xffffffff;
    }
    h[0] = (h[0] + a) & 0xffffffff;
    h[1] = (h[1] + b) & 0xffffffff;
    h[2] = (h[2] + c) & 0xffffffff;
    h[3] = (h[3] + d) & 0xffffffff;
    h[4] = (h[4] + e) & 0xffffffff;
    h[5] = (h[5] + f) & 0xffffffff;
    h[6] = (h[6] + g) & 0xffffffff;
    h[7] = (h[7] + hh) & 0xffffffff;
  }
  final out = Uint8List(32);
  for (var i = 0; i < 8; i++) {
    out[i * 4] = (h[i] >> 24) & 0xff;
    out[i * 4 + 1] = (h[i] >> 16) & 0xff;
    out[i * 4 + 2] = (h[i] >> 8) & 0xff;
    out[i * 4 + 3] = h[i] & 0xff;
  }
  return out;
}

int kiwiLeadingZeroBits(Uint8List digest) {
  var count = 0;
  for (final b in digest) {
    if (b == 0) {
      count += 8;
      continue;
    }
    var m = b;
    while ((m & 0x80) == 0) {
      count++;
      m <<= 1;
    }
    break;
  }
  return count;
}

Uint8List _base64Decode(String value) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  final clean = value.replaceAll('=', '');
  final out = Uint8List(clean.length * 3 ~/ 4);
  var bits = 0, acc = 0, o = 0;
  for (final ch in clean.codeUnits) {
    final idx = alphabet.indexOf(String.fromCharCode(ch));
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

/// Difficulty ceiling of the pure-Dart fallback: at or below this many
/// bits the expected work stays in the hundreds of hashes.
const int kiwiLowDifficultyMaxBits = 8;

/// Solve a validated challenge: low-difficulty sha256 on the Dart side
/// (via kiwiSha256), everything else through the FFI core. Returns the
/// solution; throws [KiwiSolveError] on any refusal.
///
/// [isCancelled] is the cooperative-cancellation probe: checked once
/// before any work is spent, then at the contract cadences — every
/// [kiwiShaCancellationBatch] sha256 candidates, every
/// [kiwiRswCancellationBatch] rsw squarings, between argon2id
/// derivations. A firing probe raises [KiwiSolveError.cancelled].
KiwiSolution solveKiwiChallenge(KiwiChallenge challenge, {IsCancelled? isCancelled}) {
  validateKiwiChallenge(challenge);
  void ensureNotCancelled() {
    final probe = isCancelled;
    if (probe != null && probe()) {
      throw const KiwiSolveError.cancelled();
    }
  }

  // The entry checkpoint: before any work is spent.
  ensureNotCancelled();
  final started = DateTime.now().millisecondsSinceEpoch;
  if (challenge.algorithm == KiwiAlgorithm.sha256 &&
      challenge.targetBits <= kiwiLowDifficultyMaxBits) {
    final salt = _base64Decode(challenge.salt);
    final prefix = utf8.encode(challenge.prefix);
    final cap = 1 << challenge.targetBits;
    for (var counter = 0; counter < cap; counter++) {
      if (counter % kiwiShaCancellationBatch == 0) ensureNotCancelled();
      final digest = kiwiSha256([prefix, utf8.encode('$counter'), salt]);
      if (kiwiLeadingZeroBits(digest) >= challenge.targetBits) {
        return KiwiSolution(
          counter: counter,
          durationMs: DateTime.now().millisecondsSinceEpoch - started,
          hashHex: digest.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
        );
      }
    }
    // The window missed: fall through to the FFI core (same profile,
    // never a weaker one).
  }
  final ffi = KiwiFfi.instance();
  switch (challenge.algorithm) {
    case KiwiAlgorithm.sha256:
      // The batched core search: 2048 candidates per invocation with
      // the probe between invocations, so cancellation stays within
      // the contract's stale-work ceiling.
      final salt = _base64Decode(challenge.salt);
      var start = 0;
      while (start < KiwiLimits.maxHashes) {
        ensureNotCancelled();
        var budget = KiwiLimits.maxHashes - start;
        if (budget > kiwiShaCancellationBatch) budget = kiwiShaCancellationBatch;
        try {
          final counter = ffi.sha256SearchRange(
            prefix: challenge.prefix,
            salt: salt,
            targetBits: challenge.targetBits,
            startCounter: start,
            maxHashes: budget,
          );
          return KiwiSolution(
            counter: counter,
            durationMs: DateTime.now().millisecondsSinceEpoch - started,
            hashHex: '',
          );
        } on KiwiSolveError catch (error) {
          if (error.refusal != KiwiRefusal.exhausted) rethrow;
          start += budget;
        }
      }
      throw const KiwiSolveError(KiwiRefusal.exhausted, 'the core exhausted the search');
    case KiwiAlgorithm.rsw:
      // Validation guarantees the modulus for the rsw profile.
      final modulus = _base64Decode(challenge.rswModulus!);
      final value = ffi.rswBegin(modulus: modulus, prefix: challenge.prefix, nonce: challenge.nonce);
      var remaining = challenge.t;
      while (remaining > 0) {
        ensureNotCancelled();
        var step = remaining;
        if (step > kiwiRswCancellationBatch) step = kiwiRswCancellationBatch;
        ffi.rswSquare(modulus: modulus, value: value, squarings: step);
        remaining -= step;
      }
      final proof = value.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      return KiwiSolution(
        counter: 0,
        durationMs: DateTime.now().millisecondsSinceEpoch - started,
        hashHex: proof,
        rswProof: proof,
      );
    case KiwiAlgorithm.argon2id:
      // One derivation per core invocation: the probe fires between
      // candidate derivations, the contract's argon2id cadence.
      final salt = _base64Decode(challenge.salt);
      var start = 0;
      while (start < KiwiLimits.maxHashes) {
        ensureNotCancelled();
        try {
          final counter = ffi.argon2idRange(
            prefix: challenge.prefix,
            salt: salt,
            mKib: challenge.mKib,
            t: challenge.t,
            p: challenge.p,
            targetBits: challenge.targetBits,
            startCounter: start,
            maxHashes: kiwiArgonCancellationBatch,
          );
          return KiwiSolution(
            counter: counter,
            durationMs: DateTime.now().millisecondsSinceEpoch - started,
            hashHex: '',
          );
        } on KiwiSolveError catch (error) {
          if (error.refusal != KiwiRefusal.exhausted) rethrow;
          start += kiwiArgonCancellationBatch;
        }
      }
      throw const KiwiSolveError(KiwiRefusal.exhausted, 'the core exhausted the search');
  }
}
