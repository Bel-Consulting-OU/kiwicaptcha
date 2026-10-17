import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import 'challenge.dart';
import 'solver.dart';
import 'token.dart';

/// The challenge client: a POST to the challenge endpoint and the
/// provider-shaped siteverify body builder. Verification is a
/// server-to-server call; the app submits the token itself.
class KiwiClient {
  KiwiClient({required this.endpoint, this.sitekey});

  final Uri endpoint;
  final String? sitekey;

  Future<KiwiChallenge> fetchChallenge({
    required String scope,
    String? algorithm,
    String? requestBinding,
  }) async {
    final body = json.encode({
      'scope': scope,
      if (algorithm != null) 'algorithm': algorithm,
      if (sitekey != null) 'sitekey': sitekey,
      if (requestBinding != null) 'request_binding': requestBinding,
    });
    final response = await httpPost(endpoint, body);
    if (response.statusCode != 200) {
      throw KiwiSolveError.malformed('the challenge endpoint answered ${response.statusCode}');
    }
    final decoded = json.decode(response.body);
    if (decoded is! Map<String, dynamic>) {
      throw const KiwiSolveError.malformed(
          'the challenge endpoint did not answer a JSON object');
    }
    return KiwiChallenge.fromJson(decoded);
  }

  static Future<KiwiSiteverifyBody> siteverifyBody(
      String secret, String response, {String? remoteip}) async {
    return KiwiSiteverifyBody(secret: secret, response: response, remoteip: remoteip);
  }
}

/// The siteverify request document (secret, response, optional
/// remoteip), the same body the Rust solver builds.
class KiwiSiteverifyBody {
  final String secret;
  final String response;
  final String? remoteip;

  const KiwiSiteverifyBody({required this.secret, required this.response, this.remoteip});

  String toJson() => json.encode({
        'secret': secret,
        'response': response,
        if (remoteip != null) 'remoteip': remoteip,
      });
}

/// Test hook: when non-null, [httpPost] delegates to it instead of
/// dialing the network. Null in production.
@visibleForTesting
Future<KiwiHttpResponse> Function(Uri url, String body)? debugHttpPostOverride;

/// Test hook: when non-null, the widget solves through it instead of
/// spawning the isolate. Null in production.
@visibleForTesting
KiwiSolution Function(KiwiChallenge challenge)? debugSolveOverride;

Future<KiwiHttpResponse> httpPost(Uri url, String body) async {
  // Materialized through package:http's Client in the app; the
  // indirection keeps this file test-friendly.
  final override = debugHttpPostOverride;
  if (override != null) {
    return override(url, body);
  }
  final client = HttpClient();
  try {
    final request = await client.postUrl(url);
    request.headers.contentType = ContentType.json;
    request.write(body);
    final response = await request.close();
    final text = await response.transform(utf8.decoder).join();
    return KiwiHttpResponse(statusCode: response.statusCode, body: text);
  } finally {
    client.close();
  }
}

class KiwiHttpResponse {
  final int statusCode;
  final String body;
  const KiwiHttpResponse({required this.statusCode, required this.body});
}

/// The KiwiCaptcha widget: acquires, solves and expires a challenge,
/// reports the token, and offers Retry after failure or expiry.
class KiwiCaptcha extends StatefulWidget {
  const KiwiCaptcha({
    super.key,
    required this.endpoint,
    required this.scope,
    this.sitekey,
    this.autoStart = true,
    required this.onVerify,
    this.onError,
    this.onExpire,
  });

  final Uri endpoint;
  final String scope;
  final String? sitekey;
  final bool autoStart;
  final ValueChanged<String> onVerify;
  final ValueChanged<String>? onError;
  final VoidCallback? onExpire;

  @override
  KiwiCaptchaState createState() => KiwiCaptchaState();
}

/// The widget state. Public so an `autoStart: false` widget can be
/// driven through a `GlobalKey<KiwiCaptchaState>`:
///
/// ```dart
/// final key = GlobalKey<KiwiCaptchaState>();
/// KiwiCaptcha(key: key, autoStart: false, ...);
/// ...
/// key.currentState?.start();
/// ```
class KiwiCaptchaState extends State<KiwiCaptcha> {
  String _status = 'Idle';
  double _progress = 0;
  bool _failed = false;

  /// The run generation: every start() increments it, so a late
  /// completion (or TTL expiry) from a superseded run is ignored.
  int _generation = 0;

  @override
  void initState() {
    super.initState();
    if (widget.autoStart) {
      start();
    }
  }

  /// Start (or restart) the challenge flow: fetch, solve and report
  /// the token. Retry calls it after a failure or expiry; a widget
  /// built with `autoStart: false` calls it when the user is ready.
  Future<void> start() => execute();

  /// The explicit action name for [start].
  Future<void> execute() async {
    final generation = ++_generation;
    setState(() {
      _status = 'Working';
      _progress = 0;
      _failed = false;
    });
    try {
      final client = KiwiClient(endpoint: widget.endpoint, sitekey: widget.sitekey);
      final challenge = await client.fetchChallenge(scope: widget.scope);
      final started = DateTime.now().millisecondsSinceEpoch;
      // The solve runs off the UI isolate (compute keeps the widget
      // responsive; low-difficulty work stays in pure Dart, the rest
      // goes through the FFI core). Tests can replace it.
      final solution = debugSolveOverride?.call(challenge) ??
          await compute(_solveIsolate, challenge);
      final token = encodeKiwiToken(
        nonce: challenge.nonce,
        counter: solution.counter,
        durationMs: solution.durationMs > 0
            ? solution.durationMs
            : DateTime.now().millisecondsSinceEpoch - started,
        rswProof: solution.rswProof,
      );
      if (!mounted || generation != _generation) return;
      setState(() {
        _status = 'Success';
        _progress = 1;
      });
      widget.onVerify(token);
      if (challenge.ttlSecs > 0) {
        await Future<void>.delayed(Duration(seconds: challenge.ttlSecs));
        if (!mounted || generation != _generation) return;
        setState(() {
          _status = 'Expired';
          _failed = true;
        });
        widget.onExpire?.call();
      }
    } catch (error) {
      if (!mounted || generation != _generation) return;
      setState(() {
        _status = 'Failed';
        _failed = true;
      });
      widget.onError?.call(error.toString());
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('Security Check'),
        Text(_status),
        LinearProgressIndicator(value: _progress == 0 ? null : _progress),
        if (_failed)
          TextButton(onPressed: start, child: const Text('Retry')),
      ],
    );
  }
}

/// The isolate entry point for compute(): a top-level function.
KiwiSolution _solveIsolate(KiwiChallenge challenge) => solveKiwiChallenge(challenge);
