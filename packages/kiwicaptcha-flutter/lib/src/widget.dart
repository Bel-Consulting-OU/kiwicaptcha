import 'dart:convert';

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
    return KiwiChallenge.fromJson(json.decode(response.body) as Map<String, dynamic>);
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

Future<KiwiHttpResponse> httpPost(Uri url, String body) async {
  // Materialized through package:http's Client in the app; the
  // indirection keeps this file test-friendly.
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
  State<KiwiCaptcha> createState() => _KiwiCaptchaState();
}

class _KiwiCaptchaState extends State<KiwiCaptcha> {
  String _status = 'Idle';
  double _progress = 0;
  bool _failed = false;
  int _attempt = 0;

  @override
  void initState() {
    super.initState();
    if (widget.autoStart) _run();
  }

  Future<void> _run() async {
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
      // goes through the FFI core).
      final solution = await compute(_solveIsolate, challenge);
      final token = encodeKiwiToken(
        nonce: challenge.nonce,
        counter: solution.counter,
        durationMs: solution.durationMs > 0
            ? solution.durationMs
            : DateTime.now().millisecondsSinceEpoch - started,
        rswProof: solution.rswProof,
      );
      if (!mounted) return;
      setState(() {
        _status = 'Success';
        _progress = 1;
      });
      widget.onVerify(token);
      if (challenge.ttlSecs > 0) {
        await Future<void>.delayed(Duration(seconds: challenge.ttlSecs));
        if (!mounted) return;
        setState(() {
          _status = 'Expired';
          _failed = true;
        });
        widget.onExpire?.call();
      }
    } catch (error) {
      if (!mounted) return;
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
          TextButton(onPressed: () => setState(() => _attempt++), child: const Text('Retry')),
      ],
    );
  }
}

/// The isolate entry point for compute(): a top-level function.
KiwiSolution _solveIsolate(KiwiChallenge challenge) => solveKiwiChallenge(challenge);
