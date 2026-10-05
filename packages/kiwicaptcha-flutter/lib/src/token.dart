import 'dart:convert';
import 'dart:typed_data';

import 'challenge.dart';

/// Token assembly and canonical base64, dependency-free.
///
/// The grammar is the shared one:
/// base64(nonce.counter.durationMs.telemetry) with the rsw proof riding
/// as the final 512-hex segment.
const String _alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

String kiwiBase64Encode(List<int> bytes) {
  final out = StringBuffer();
  for (var i = 0; i < bytes.length; i += 3) {
    final b0 = bytes[i];
    final b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    final b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out.write(_alphabet[b0 >> 2]);
    out.write(_alphabet[((b0 & 0x03) << 4) | (b1 >> 4)]);
    out.write(i + 1 < bytes.length ? _alphabet[((b1 & 0x0f) << 2) | (b2 >> 6)] : '=');
    out.write(i + 2 < bytes.length ? _alphabet[b2 & 0x3f] : '=');
  }
  return out.toString();
}

/// Pack the wire token the verify endpoint accepts.
String encodeKiwiToken({
  required String nonce,
  required int counter,
  required int durationMs,
  String telemetry = '{}',
  String? rswProof,
}) {
  if (rswProof != null && !RegExp(r'^[0-9a-f]{512}$').hasMatch(rswProof)) {
    throw const KiwiSolveError.malformed('the rsw proof must be 512 lowercase hex characters');
  }
  final duration = durationMs.clamp(0, KiwiLimits.maxDurationMs);
  var plain = '$nonce.$counter.$duration.$telemetry';
  if (rswProof != null) plain += '.$rswProof';
  return kiwiBase64Encode(utf8.encode(plain));
}

/// Challenge validation with the exact caps the browser driver and the
/// Rust solver enforce. A challenge outside the contract is refused
/// before any work is spent.
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
      // Fail-closed: no vetted pure-Dart Argon2id exists and the FFI
      // core reports argon availability per platform (see ffi_bindings).
      throw const KiwiSolveError(
          KiwiRefusal.argonUnavailable,
          'argon2id is not implemented in this package (fail-closed); '
          'the FFI core reports availability per platform');
    case KiwiAlgorithm.rsw:
      if (c.t < KiwiLimits.rswTMin ||
          c.t > KiwiLimits.rswTMax ||
          c.p != 1 ||
          c.mKib != 0 ||
          c.rswModulus == null ||
          c.rswModulus.isEmpty) {
        throw const KiwiSolveError(KiwiRefusal.unsupportedParams,
            'the rsw parameters are outside the client contract');
      }
      final modulus = _strictBase64Decode(c.rswModulus!);
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
    final idx = _alphabet.indexOf(String.fromCharCode(ch));
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
