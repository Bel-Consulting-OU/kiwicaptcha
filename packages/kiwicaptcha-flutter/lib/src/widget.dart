import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'package:flutter/material.dart';

import 'challenge.dart';
import 'lifecycle.dart';
import 'solver.dart';
import 'token.dart';

/// The capability header a native interactive client MUST send on the
/// challenge POST (protocol/interactive-client-v1): it declares this
/// client cannot run the execution dimension, instead of letting the
/// server infer the v1 compatibility floor from a missing header.
const String kiwiExecutionMaxVersionHeader = 'Kiwi-Execution-Max-Version';

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
    final response = await httpPost(endpoint, body, const {
      kiwiExecutionMaxVersionHeader: '0',
    });
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
Future<KiwiHttpResponse> Function(Uri url, String body, Map<String, String> headers)?
    debugHttpPostOverride;

/// Test hook: when non-null, the widget solves through it instead of
/// spawning the solver isolate. The second argument is the run's
/// cooperative-cancellation probe. Null in production.
@visibleForTesting
Future<KiwiSolution> Function(KiwiChallenge challenge, IsCancelled isCancelled)?
    debugSolveOverride;

Future<KiwiHttpResponse> httpPost(Uri url, String body,
    [Map<String, String> headers = const {}]) async {
  // Materialized through package:http's Client in the app; the
  // indirection keeps this file test-friendly.
  final override = debugHttpPostOverride;
  if (override != null) {
    return override(url, body, headers);
  }
  final client = HttpClient();
  try {
    final request = await client.postUrl(url);
    request.headers.contentType = ContentType.json;
    headers.forEach(request.headers.set);
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
///
/// The run follows the Interactive-Client Lifecycle v1 contract
/// (protocol/interactive-client-v1): the expiry clock starts the
/// moment the challenge JSON parses, the expiry timer races the solve,
/// delivery waits out the challenge's minimum duration, and nothing —
/// solve, timer or delivery — ever emits after the deadline. Only the
/// newest generation (each `start()` mints one) may emit at all.
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
  _KiwiRun? _run;

  @override
  void initState() {
    super.initState();
    if (widget.autoStart) {
      start();
    }
  }

  @override
  void dispose() {
    _run?.cancelSolve();
    _run = null;
    super.dispose();
  }

  /// Start (or restart) the challenge flow: fetch, solve and report
  /// the token. Retry calls it after a failure or expiry; a widget
  /// built with `autoStart: false` calls it when the user is ready.
  /// A newer run cancels the older one cooperatively.
  Future<void> start() => execute();

  /// The explicit action name for [start].
  Future<void> execute() async {
    final run = _KiwiRun(++_generation);
    _run?.cancelSolve();
    _run = run;
    if (!mounted) return;
    setState(() {
      _status = 'Working';
      _progress = 0;
      _failed = false;
    });
    try {
      final client = KiwiClient(endpoint: widget.endpoint, sitekey: widget.sitekey);
      final challenge = await client.fetchChallenge(scope: widget.scope);
      if (!mounted || run.cancelled || run.generation != _generation) return;

      // Interactive-Client Lifecycle v1: the expiry clock starts at
      // parse time — never after solving.
      final receivedAtMs = DateTime.now().millisecondsSinceEpoch;
      final ttlSecs = challenge.ttlSecs;
      final expiresAtMs = kiwiExpiresAtMs(receivedAtMs, ttlSecs);
      bool pastDeadline() =>
          ttlSecs > 0 && DateTime.now().millisecondsSinceEpoch >= expiresAtMs;
      bool cancelledNow() =>
          run.cancelled || run.generation != _generation || pastDeadline();

      if (pastDeadline()) {
        _surfaceExpired(run);
        return;
      }

      // The expiry timer is armed at parse and races the solve; that
      // race is correct and intended by the contract.
      if (ttlSecs > 0) {
        final remaining = expiresAtMs - DateTime.now().millisecondsSinceEpoch;
        run.expiryTimer = Timer(Duration(milliseconds: remaining > 0 ? remaining : 0), () {
          if (run.cancelled || run.expired || run.generation != _generation) return;
          _surfaceExpired(run);
        });
      }

      final started = DateTime.now().millisecondsSinceEpoch;
      // The solve runs off the UI isolate (the isolate carries the
      // deadline and its solver probe is the clock; low-difficulty
      // work stays in pure Dart, the rest goes through the batched FFI
      // core). Tests replace it through the override seam.
      final KiwiSolution solution;
      final override = debugSolveOverride;
      if (override != null) {
        solution = await override(challenge, cancelledNow);
      } else {
        solution = await _solveInIsolate(run, challenge, expiresAtMs);
      }
      if (!mounted || run.cancelled || run.generation != _generation) return;

      final token = encodeKiwiToken(
        nonce: challenge.nonce,
        counter: solution.counter,
        durationMs: solution.durationMs > 0
            ? solution.durationMs
            : DateTime.now().millisecondsSinceEpoch - started,
        rswProof: solution.rswProof,
      );

      // Contract step 6: a solve that finished at/after the deadline
      // is invalidated — the token is never delivered.
      if (pastDeadline()) {
        _surfaceExpired(run);
        return;
      }
      final solveFinishedAtMs = DateTime.now().millisecondsSinceEpoch;

      // Contract step 7: delivery gating. A too-fast solve waits out
      // minSubmitAtMs cancellably, re-checked against the clock at
      // every wake-up; a checkpoint past the deadline is expired.
      var nowMs = solveFinishedAtMs;
      while (true) {
        final decision = kiwiDeliveryDecision(
          receivedAtMs,
          ttlSecs,
          challenge.minDurationMs,
          solveFinishedAtMs,
          nowMs,
          cancelled: run.cancelled || run.generation != _generation,
        );
        if (decision.reason == kiwiReasonCancelled) return;
        if (decision.reason == kiwiReasonExpired) {
          _surfaceExpired(run);
          return;
        }
        if (decision.reason == kiwiReasonDeliver) break;
        final wakeAtMs = decision.deliverAtMs;
        await _waitUntil(run, Duration(milliseconds: wakeAtMs > nowMs ? wakeAtMs - nowMs : 0));
        if (!mounted || run.cancelled || run.generation != _generation) return;
        final real = DateTime.now().millisecondsSinceEpoch;
        // The timer only completes once its instant has passed in
        // whichever clock governs timers; keep that as the floor so a
        // virtual (test) clock advances the gate deterministically.
        nowMs = real > wakeAtMs ? real : wakeAtMs;
      }

      // Contract step 8: the final gate is the clock itself — never
      // onVerify after the deadline.
      if (pastDeadline()) {
        _surfaceExpired(run);
        return;
      }
      setState(() {
        _status = 'Success';
        _progress = 1;
      });
      widget.onVerify(token);
    } on KiwiSolveError catch (error) {
      if (!mounted || run.cancelled || run.expired || run.generation != _generation) {
        return;
      }
      if (error.refusal == KiwiRefusal.cancelled) {
        // The solver's probe fired: this generation lost the expiry
        // race. Surface the typed expired state, never a failure.
        _surfaceExpired(run);
        return;
      }
      setState(() {
        _status = 'Failed';
        _failed = true;
      });
      widget.onError?.call(error.toString());
    } catch (error) {
      if (!mounted || run.cancelled || run.expired || run.generation != _generation) {
        return;
      }
      setState(() {
        _status = 'Failed';
        _failed = true;
      });
      widget.onError?.call(error.toString());
    }
  }

  /// Wait [duration] on a timer the run can cancel: a superseded or
  /// expired generation resumes immediately instead of holding the
  /// delivery gate open.
  Future<void> _waitUntil(_KiwiRun run, Duration duration) {
    final completer = Completer<void>();
    run.deliveryWait = completer;
    run.deliveryTimer = Timer(duration, () {
      if (!completer.isCompleted) completer.complete();
    });
    return completer.future;
  }

  /// Surface the typed expired state exactly once per generation.
  void _surfaceExpired(_KiwiRun run) {
    if (run.cancelled || run.expired || run.generation != _generation || !mounted) {
      return;
    }
    run.expired = true;
    run.cancelSolve();
    setState(() {
      _status = 'Expired';
      _failed = true;
    });
    widget.onExpire?.call();
  }

  /// Run [solveKiwiChallenge] in its own isolate. The isolate carries
  /// only the deadline: its solver probe is the clock, so a solve that
  /// outlives the challenge raises [KiwiSolveError.cancelled] inside
  /// the isolate. Cancellation from this side (a newer generation, an
  /// expired timer, dispose) kills the isolate and completes the
  /// awaiter with the same typed error.
  Future<KiwiSolution> _solveInIsolate(
      _KiwiRun run, KiwiChallenge challenge, int expiresAtMs) async {
    final port = ReceivePort();
    final completer = Completer<KiwiSolution>();
    // Registered before the first suspension point below, so by the
    // time this function can suspend, cancelSolve() always finds a
    // listener on the completer it completes.
    run.solvePort = port;
    run.solveDone = completer;
    port.listen((message) {
      port.close();
      if (completer.isCompleted) return;
      if (message is KiwiSolution) {
        completer.complete(message);
      } else if (message is KiwiSolveError) {
        completer.completeError(message);
      } else {
        completer.completeError(
            KiwiSolveError(KiwiRefusal.solverUnavailable, 'the solver isolate answered $message'));
      }
    });
    Isolate? isolate;
    try {
      isolate = await Isolate.spawn(
        _solveIsolateEntry,
        _SolveRequest(challenge, expiresAtMs, port.sendPort),
      );
    } catch (error) {
      if (!completer.isCompleted) {
        completer.completeError(KiwiSolveError(
            KiwiRefusal.solverUnavailable, 'could not start the solver isolate: $error'));
      }
    }
    if (isolate != null) {
      if (run.cancelled) {
        isolate.kill(priority: Isolate.immediate);
      } else {
        run.solveIsolate = isolate;
      }
    }
    return completer.future;
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

/// One start()-to-outcome run: the generation handle plus everything
/// that must die with it — timers, the solver isolate, the awaiters.
class _KiwiRun {
  final int generation;

  /// Set when the run is superseded, cancelled or expired: no state,
  /// no callback may ever come out of this run afterwards.
  bool cancelled = false;

  /// Set once the expired state has been surfaced for this run.
  bool expired = false;

  Timer? expiryTimer;
  Timer? deliveryTimer;
  Completer<void>? deliveryWait;
  ReceivePort? solvePort;
  Isolate? solveIsolate;
  Completer<KiwiSolution>? solveDone;

  _KiwiRun(this.generation);

  /// Stop everything this run could still do: cancel the timers, kill
  /// the solver isolate, and complete the pending awaiters so the
  /// suspended `execute()` resumes immediately and observes
  /// [cancelled].
  void cancelSolve() {
    cancelled = true;
    expiryTimer?.cancel();
    expiryTimer = null;
    deliveryTimer?.cancel();
    deliveryTimer = null;
    final wait = deliveryWait;
    if (wait != null && !wait.isCompleted) wait.complete();
    deliveryWait = null;
    solveIsolate?.kill(priority: Isolate.immediate);
    solveIsolate = null;
    solvePort?.close();
    solvePort = null;
    final done = solveDone;
    if (done != null && !done.isCompleted) {
      done.completeError(const KiwiSolveError.cancelled());
    }
    solveDone = null;
  }
}

/// The message sent to the solver isolate: the challenge, the absolute
/// deadline (kiwiNoExpiryMs when the challenge has no TTL), and the
/// port the single result or error comes back on.
class _SolveRequest {
  final KiwiChallenge challenge;
  final int expiresAtMs;
  final SendPort port;

  const _SolveRequest(this.challenge, this.expiresAtMs, this.port);
}

/// The solver isolate's entry point: solve with the deadline as the
/// cancellation probe and answer exactly one message.
void _solveIsolateEntry(_SolveRequest request) {
  try {
    final solution = solveKiwiChallenge(
      request.challenge,
      isCancelled: () => DateTime.now().millisecondsSinceEpoch >= request.expiresAtMs,
    );
    request.port.send(solution);
  } on KiwiSolveError catch (error) {
    request.port.send(error);
  } catch (error) {
    request.port.send(KiwiSolveError(KiwiRefusal.solverUnavailable, '$error'));
  }
}
