import 'dart:convert';

import 'challenge.dart';

/// Token assembly and canonical base64, dependency-free.
///
/// The grammar is the shared one:
/// base64(nonce.counter.durationMs.telemetry) with the rsw proof riding
/// as the final 512-hex segment. Challenge validation lives in
/// challenge.dart ([validateKiwiChallenge]).
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
