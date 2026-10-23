import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kiwicaptcha/kiwicaptcha.dart';
import 'package:kiwicaptcha/src/widget.dart' as widget;

void main() {
  const nonce = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
  const salt = 'AAECAw==';
  const prefix = 'kiwi|login|';

  KiwiChallenge shaChallenge({int targetBits = 8}) => KiwiChallenge(
        nonce: nonce,
        salt: salt,
        algorithm: KiwiAlgorithm.sha256,
        mKib: 0,
        t: 1,
        p: 1,
        targetBits: targetBits,
        prefix: prefix,
      );

  group('sha256 primitive', () {
    test('matches the standard vectors', () {
      final abc = kiwiSha256([utf8.encode('abc')]);
      expect(
        abc.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
      final empty = kiwiSha256([Uint8List(0)]);
      expect(
        empty.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
    });

    test('hashes the chunked preimage as one concatenated buffer', () {
      // The low-difficulty solve hashes prefix || decimal(counter) ||
      // salt as three chunks; the digest must equal the single-buffer
      // spelling of the same bytes.
      final chunked = kiwiSha256([
        utf8.encode('kiwi|login|'),
        utf8.encode('7'),
        Uint8List.fromList([1, 2, 3, 4]),
      ]);
      final joined =
          kiwiSha256([utf8.encode('kiwi|login|7'), Uint8List.fromList([1, 2, 3, 4])]);
      expect(chunked, joined);
    });

    test('counts leading zero bits in big-endian order', () {
      expect(kiwiLeadingZeroBits(Uint8List.fromList([0, 0, 1])), 23);
      expect(kiwiLeadingZeroBits(Uint8List.fromList([0x80])), 0);
      expect(kiwiLeadingZeroBits(Uint8List.fromList([0x0f])), 4);
    });
  });

  group('token assembly', () {
    test('packs the documented grammar', () {
      final token = encodeKiwiToken(
          nonce: nonce, counter: 78, durationMs: 1200, telemetry: '{"t":1}');
      final plain = utf8.decode(base64.decode(token));
      expect(plain, '$nonce.78.1200.{"t":1}');
    });

    test('appends the rsw proof as the final segment', () {
      final proof = 'ab' * 256;
      final token = encodeKiwiToken(
          nonce: nonce, counter: 0, durationMs: 900, rswProof: proof);
      expect(utf8.decode(base64.decode(token)).endsWith('.$proof'), isTrue);
    });
  });

  group('challenge validation', () {
    test('accepts a well-formed sha256 challenge', () {
      validateKiwiChallenge(shaChallenge());
    });

    test('refuses a broken nonce and an over-cap difficulty', () {
      expect(
        () => validateKiwiChallenge(shaChallenge().nonce_),
        throwsA(isA<KiwiSolveError>()),
      );
      expect(
        () => validateKiwiChallenge(shaChallenge(targetBits: 21)),
        throwsA(isA<KiwiSolveError>()),
      );
    });

    test('refuses execution-armed challenges outright', () {
      final armed = KiwiChallenge(
        nonce: nonce,
        salt: salt,
        algorithm: KiwiAlgorithm.sha256,
        mKib: 0,
        t: 1,
        p: 1,
        targetBits: 8,
        prefix: prefix,
        executionProgram: 'YQ==',
      );
      expect(() => validateKiwiChallenge(armed), throwsA(isA<KiwiSolveError>()));
    });

    test('accepts a well-formed argon2id challenge', () {
      final argon = KiwiChallenge(
        nonce: nonce,
        salt: salt,
        algorithm: KiwiAlgorithm.argon2id,
        mKib: 64,
        t: 3,
        p: 1,
        targetBits: 5,
        prefix: prefix,
      );
      validateKiwiChallenge(argon);
    });

    test('refuses out-of-contract argon2id parameters', () {
      KiwiChallenge argon({int? targetBits, int? mKib, int? t, int? p}) => KiwiChallenge(
            nonce: nonce,
            salt: salt,
            algorithm: KiwiAlgorithm.argon2id,
            mKib: mKib ?? 64,
            t: t ?? 3,
            p: p ?? 1,
            targetBits: targetBits ?? 5,
            prefix: prefix,
          );
      // Difficulty above the argon2id ceiling is a cap refusal.
      expect(
        () => validateKiwiChallenge(argon(targetBits: KiwiLimits.argonMaxTargetBits + 1)),
        throwsA(
            predicate((e) => e is KiwiSolveError && e.refusal == KiwiRefusal.difficultyBeyondCap)),
      );
      // Memory/time/parallelism outside the issued contract.
      expect(
        () => validateKiwiChallenge(argon(mKib: 4)),
        throwsA(predicate((e) => e is KiwiSolveError && e.refusal == KiwiRefusal.unsupportedParams)),
      );
      expect(
        () => validateKiwiChallenge(argon(t: 2)),
        throwsA(predicate((e) => e is KiwiSolveError && e.refusal == KiwiRefusal.unsupportedParams)),
      );
      expect(
        () => validateKiwiChallenge(argon(p: 2)),
        throwsA(predicate((e) => e is KiwiSolveError && e.refusal == KiwiRefusal.unsupportedParams)),
      );
    });

    test('refuses an rsw challenge without a modulus', () {
      final rsw = KiwiChallenge(
        nonce: nonce,
        salt: salt,
        algorithm: KiwiAlgorithm.rsw,
        mKib: 0,
        t: KiwiLimits.rswTMin,
        p: 1,
        targetBits: 0,
        prefix: prefix,
      );
      expect(
        () => validateKiwiChallenge(rsw),
        throwsA(predicate((e) => e is KiwiSolveError && e.refusal == KiwiRefusal.unsupportedParams)),
      );
    });
  });

  group('low-difficulty solve', () {
    test('finds the known counter on the Dart path', () {
      // The pure-Dart path needs no FFI: keep the override null but the
      // low-difficulty branch never touches the native library.
      final solution = solveKiwiChallenge(shaChallenge(targetBits: 8));
      expect(solution.counter, 45);
      expect(
        solution.hashHex,
        '00f9718e2a0397b3ca8fe75c44499fccee788e243173dadea546bd4e45af6982',
      );
    });

    test('a probe already firing at entry raises the typed cancelled error', () {
      expect(
        () => solveKiwiChallenge(shaChallenge(targetBits: 8), isCancelled: () => true),
        throwsA(predicate((e) => e is KiwiSolveError && e.refusal == KiwiRefusal.cancelled)),
      );
    });

    test('a never-firing probe does not disturb the solve', () {
      final solution = solveKiwiChallenge(
        shaChallenge(targetBits: 8),
        isCancelled: () => false,
      );
      expect(solution.counter, 45);
    });

    test('a mid-solve probe stops within one batch of the fire point (stale-work ceiling)', () {
      // The cooperative-cancellation contract: once the probe fires, the
      // solve must raise KiwiSolveError.cancelled within at most one
      // cancellation batch (kiwiShaCancellationBatch candidates). This
      // is the explicit proof that killing a caller between native FFI
      // invocations cannot leave an unbounded native computation
      // running — the native work is itself batched to the same
      // ceiling, and the Dart probe runs between batches.
      const batch = kiwiShaCancellationBatch;
      // The probe runs at the contract cadence — once at entry
      // (candidate 0), then once per cancellation batch, so the probe
      // checkpoints are candidates 0, 2048, 4096, ... Fire at the
      // candidate-`batch` checkpoint (the third probe call: entry,
      // pre-batch, next pre-batch) — well before this challenge's
      // deterministic solution (counter 978941 ≈ batch 478).
      var probes = 0;
      var fired = false;
      expect(
        () => solveKiwiChallenge(
          // A high target so the search cannot finish before the probe
          // fires; the solve is cancelled mid-search.
          shaChallenge(targetBits: 20),
          isCancelled: () {
            probes++;
            if (!fired && probes >= 3) {
              fired = true;
            }
            return fired;
          },
        ),
        throwsA(predicate((e) => e is KiwiSolveError && e.refusal == KiwiRefusal.cancelled)),
        reason: 'a probe that fires at candidate $batch must cancel the solve',
      );
      // The overshoot bound: the fire (probe call #3) raises inside the
      // same checkpoint — no batch may start after it. Counting
      // checkpoint calls: entry + one per batch + the raising call,
      // plus at most one re-check — i.e. stale work stays within one
      // batch (2 * batch candidates) of the fire point.
      expect(
        probes,
        lessThanOrEqualTo(4),
        reason: 'stale work must stay within the cancellation batch ceiling',
      );
    });
  });

  group('siteverify body', () {
    test('builds the provider-shaped document', () async {
      final body = await KiwiClient.siteverifyBody('s', 'tok', remoteip: '203.0.113.9');
      expect(body.toJson(), '{"secret":"s","response":"tok","remoteip":"203.0.113.9"}');
      final minimal = await KiwiClient.siteverifyBody('s', 'tok');
      expect(minimal.toJson(), '{"secret":"s","response":"tok"}');
    });
  });

  Map<String, dynamic> challengeJson({int targetBits = 8, int? ttlSecs, int? minDurationMs}) =>
      <String, dynamic>{
        'nonce': nonce,
        'salt': salt,
        'algorithm': 'sha256',
        'mKib': 0,
        't': 1,
        'p': 1,
        'targetBits': targetBits,
        'prefix': prefix,
        if (ttlSecs != null) 'ttlSecs': ttlSecs,
        if (minDurationMs != null) 'minDurationMs': minDurationMs,
      };

  group('challenge parsing', () {
    test('fromJson accepts the wire document', () {
      final parsed = KiwiChallenge.fromJson(challengeJson());
      expect(parsed.nonce, nonce);
      expect(parsed.salt, salt);
      expect(parsed.algorithm, KiwiAlgorithm.sha256);
      expect(parsed.ttlSecs, 0);
      expect(parsed.minDurationMs, 0);
    });

    test('fromJson refuses malformed documents', () {
      final documents = <Map<String, dynamic>>[
        challengeJson()..remove('nonce'),
        challengeJson()..remove('salt'),
        challengeJson()..remove('prefix'),
        challengeJson()..remove('t'),
        challengeJson()..['mKib'] = '0',
        challengeJson()..['targetBits'] = 8.5,
        challengeJson()..['algorithm'] = 'md5',
        challengeJson()..['algorithm'] = 7,
        challengeJson()..['execution_program'] = 7,
      ];
      for (final document in documents) {
        expect(() => KiwiChallenge.fromJson(document),
            throwsA(isA<KiwiSolveError>()));
      }
    });
  });

  group('interactive-client lifecycle v1', () {
    test('the deadline helpers carry the safety margin', () {
      expect(kiwiExpiresAtMs(1000000, 30), 1029000);
      expect(kiwiExpiresAtMs(1000000, 0), 9223372036854775807);
      expect(kiwiMinSubmitAtMs(1000000, 5000), 1005000);
      expect(kiwiMinSubmitAtMs(1000000, -5), 1000000);
    });

    test('kiwiDeliveryDecision matches every shared vector', () {
      final file = File('../../protocol/interactive-client-v1/lifecycle-vectors.json');
      final vectors =
          json.decode(file.readAsStringSync()) as List<dynamic>;
      expect(vectors, isNotEmpty, reason: 'the shared vectors must be present');
      for (final entry in vectors) {
        final vector = entry as Map<String, dynamic>;
        final decision = kiwiDeliveryDecision(
          vector['receivedAtMs'] as int,
          vector['ttlSecs'] as int,
          vector['minDurationMs'] as int,
          vector['solveFinishedAtMs'] as int,
          vector['nowMs'] as int,
          cancelled: (vector['cancelled'] as bool?) ?? false,
        );
        final expected = vector['expect'] as Map<String, dynamic>;
        final name = vector['name'] as String;
        expect(decision.deliver, expected['deliver'], reason: name);
        expect(decision.deliverAtMs, expected['deliverAtMs'], reason: name);
        expect(decision.reason, expected['reason'], reason: name);
      }
    });
  });

  group('widget lifecycle', () {
    setUp(() {
      widget.debugHttpPostOverride = null;
      widget.debugSolveOverride = null;
    });

    tearDown(() {
      widget.debugHttpPostOverride = null;
      widget.debugSolveOverride = null;
    });

    KiwiCaptcha captcha({
      GlobalKey<widget.KiwiCaptchaState>? key,
      bool autoStart = true,
      void Function(String)? onVerify,
      void Function(String)? onError,
      void Function()? onExpire,
    }) =>
        KiwiCaptcha(
          key: key,
          endpoint: Uri.parse('https://kiwi.test/challenge'),
          scope: 'login',
          autoStart: autoStart,
          onVerify: onVerify ?? (_) {},
          onError: onError,
          onExpire: onExpire,
        );

    testWidgets('Retry restarts the flow after a failure', (tester) async {
      var calls = 0;
      final verified = <String>[];
      final errors = <String>[];
      widget.debugHttpPostOverride = (url, body, headers) async {
        calls++;
        if (calls == 1) {
          return const widget.KiwiHttpResponse(statusCode: 503, body: 'down');
        }
        return widget.KiwiHttpResponse(
            statusCode: 200, body: json.encode(challengeJson()));
      };
      widget.debugSolveOverride = (challenge, isCancelled) async =>
          const KiwiSolution(counter: 45, durationMs: 1, hashHex: '');

      await tester.pumpWidget(MaterialApp(home: captcha(
        onVerify: verified.add,
        onError: errors.add,
      )));
      await tester.pump();
      await tester.pump();

      expect(find.text('Failed'), findsOneWidget);
      expect(find.text('Retry'), findsOneWidget);
      expect(errors, hasLength(1));

      await tester.tap(find.text('Retry'));
      await tester.pump();
      await tester.pump();

      expect(find.text('Success'), findsOneWidget);
      expect(verified, hasLength(1));
      expect(calls, 2);
    });

    testWidgets('manual start drives an autoStart false widget',
        (tester) async {
      final key = GlobalKey<widget.KiwiCaptchaState>();
      var verified = 0;
      widget.debugHttpPostOverride = (url, body, headers) async =>
          widget.KiwiHttpResponse(
              statusCode: 200, body: json.encode(challengeJson()));
      widget.debugSolveOverride = (challenge, isCancelled) async =>
          const KiwiSolution(counter: 45, durationMs: 1, hashHex: '');

      await tester.pumpWidget(MaterialApp(home: captcha(
        key: key,
        autoStart: false,
        onVerify: (_) => verified++,
      )));

      expect(find.text('Idle'), findsOneWidget);
      expect(key.currentState, isNotNull);

      key.currentState!.start();
      await tester.pump();
      await tester.pump();

      expect(find.text('Success'), findsOneWidget);
      expect(verified, 1);
    });

    testWidgets('the challenge POST declares Kiwi-Execution-Max-Version: 0',
        (tester) async {
      final headersSeen = <Map<String, String>>[];
      var verified = 0;
      widget.debugHttpPostOverride = (url, body, headers) async {
        headersSeen.add(headers);
        return widget.KiwiHttpResponse(
            statusCode: 200, body: json.encode(challengeJson()));
      };
      widget.debugSolveOverride = (challenge, isCancelled) async =>
          const KiwiSolution(counter: 45, durationMs: 1, hashHex: '');

      await tester.pumpWidget(MaterialApp(home: captcha(
        onVerify: (_) => verified++,
      )));
      await tester.pump();
      await tester.pump();

      expect(verified, 1);
      expect(headersSeen, hasLength(1));
      expect(headersSeen.single['Kiwi-Execution-Max-Version'], '0');
    });

    testWidgets('a solve faster than minDurationMs defers delivery',
        (tester) async {
      var verified = 0;
      widget.debugHttpPostOverride = (url, body, headers) async =>
          widget.KiwiHttpResponse(
              statusCode: 200,
              body: json.encode(challengeJson(minDurationMs: 5000)));
      widget.debugSolveOverride = (challenge, isCancelled) async =>
          const KiwiSolution(counter: 45, durationMs: 1, hashHex: '');

      await tester.pumpWidget(MaterialApp(home: captcha(
        onVerify: (_) => verified++,
      )));
      await tester.pump();
      await tester.pump();

      // The solve finished, but the delivery floor holds the token.
      expect(find.text('Working'), findsOneWidget);
      expect(verified, 0);

      await tester.pump(const Duration(seconds: 5));
      await tester.pump();

      expect(find.text('Success'), findsOneWidget);
      expect(verified, 1);
    });

    testWidgets('a solve still running at the deadline never delivers',
        (tester) async {
      var verified = 0;
      var expired = 0;
      final gate = Completer<KiwiSolution>();
      widget.debugHttpPostOverride = (url, body, headers) async =>
          widget.KiwiHttpResponse(
              statusCode: 200,
              body: json.encode(challengeJson(ttlSecs: 2)));
      // The solve outlives the challenge: held until the test opens
      // the gate.
      widget.debugSolveOverride = (challenge, isCancelled) => gate.future;

      await tester.pumpWidget(MaterialApp(home: captcha(
        onVerify: (_) => verified++,
        onExpire: () => expired++,
      )));
      await tester.pump();
      expect(find.text('Working'), findsOneWidget);

      // The expiry timer races the solve and wins.
      await tester.pump(const Duration(seconds: 2));
      expect(find.text('Expired'), findsOneWidget);
      expect(expired, 1);

      // The solve completes after the deadline: suppressed.
      gate.complete(const KiwiSolution(counter: 45, durationMs: 1, hashHex: ''));
      await tester.pump();
      await tester.pump();

      expect(verified, 0);
      expect(find.text('Expired'), findsOneWidget);
      expect(find.text('Retry'), findsOneWidget);
    });

    testWidgets('a superseded run delivers nothing', (tester) async {
      var verified = 0;
      final gate = Completer<widget.KiwiHttpResponse>();
      var calls = 0;
      widget.debugHttpPostOverride = (url, body, headers) {
        calls++;
        if (calls == 1) return gate.future;
        return Future<widget.KiwiHttpResponse>.value(widget.KiwiHttpResponse(
            statusCode: 200, body: json.encode(challengeJson())));
      };
      widget.debugSolveOverride = (challenge, isCancelled) async =>
          const KiwiSolution(counter: 45, durationMs: 1, hashHex: '');
      final key = GlobalKey<widget.KiwiCaptchaState>();

      await tester.pumpWidget(MaterialApp(home: captcha(
        key: key,
        onVerify: (_) => verified++,
      )));
      await tester.pump();
      expect(find.text('Working'), findsOneWidget);

      // A newer generation starts while the first fetch is in flight.
      key.currentState!.start();
      await tester.pump();
      await tester.pump();
      expect(find.text('Success'), findsOneWidget);
      expect(verified, 1);

      // The stale fetch completes: the old run must stay silent.
      gate.complete(widget.KiwiHttpResponse(
          statusCode: 200, body: json.encode(challengeJson())));
      await tester.pump();
      await tester.pump();

      expect(verified, 1);
      expect(find.text('Success'), findsOneWidget);
      expect(find.text('Failed'), findsNothing);
    });

    testWidgets('the solve probe reports cancellation once superseded',
        (tester) async {
      var verified = 0;
      bool probeCancelled = false;
      final gate = Completer<void>();
      var solveCalls = 0;
      widget.debugHttpPostOverride = (url, body, headers) async =>
          widget.KiwiHttpResponse(
              statusCode: 200, body: json.encode(challengeJson()));
      widget.debugSolveOverride = (challenge, isCancelled) async {
        solveCalls++;
        if (solveCalls == 1) {
          await gate.future;
          probeCancelled = isCancelled();
          throw const KiwiSolveError.cancelled();
        }
        return const KiwiSolution(counter: 45, durationMs: 1, hashHex: '');
      };
      final key = GlobalKey<widget.KiwiCaptchaState>();

      await tester.pumpWidget(MaterialApp(home: captcha(
        key: key,
        onVerify: (_) => verified++,
      )));
      await tester.pump();
      expect(find.text('Working'), findsOneWidget);

      key.currentState!.start();
      await tester.pump();
      await tester.pump();
      expect(find.text('Success'), findsOneWidget);
      expect(verified, 1);

      // The stale solve wakes up: its probe must report cancelled, and
      // its typed cancelled error must surface nothing.
      gate.complete();
      await tester.pump();
      await tester.pump();

      expect(probeCancelled, isTrue);
      expect(verified, 1);
      expect(find.text('Success'), findsOneWidget);
      expect(find.text('Failed'), findsNothing);
    });
  });

  group('single terminal outcome per run', () {
    setUp(() {
      widget.debugHttpPostOverride = null;
      widget.debugSolveOverride = null;
    });

    tearDown(() {
      widget.debugHttpPostOverride = null;
      widget.debugSolveOverride = null;
    });

    KiwiCaptcha captcha({
      GlobalKey<widget.KiwiCaptchaState>? key,
      void Function(String)? onVerify,
      void Function(String)? onError,
      void Function()? onExpire,
    }) =>
        KiwiCaptcha(
          key: key,
          endpoint: Uri.parse('https://kiwi.test/challenge'),
          scope: 'login',
          onVerify: onVerify ?? (_) {},
          onError: onError,
          onExpire: onExpire,
        );

    testWidgets('a delivered token survives the armed expiry timer', (tester) async {
      var verified = 0;
      var expired = 0;
      // ttlSecs 2 arms the expiry timer at parse for ~1s (deadline =
      // received + 2s - the 1s safety margin); the solve wins easily.
      widget.debugHttpPostOverride = (url, body, headers) async =>
          widget.KiwiHttpResponse(
              statusCode: 200, body: json.encode(challengeJson(ttlSecs: 2)));
      widget.debugSolveOverride = (challenge, isCancelled) async =>
          const KiwiSolution(counter: 45, durationMs: 1, hashHex: '');

      await tester.pumpWidget(MaterialApp(home: captcha(
        onVerify: (_) => verified++,
        onExpire: () => expired++,
      )));
      await tester.pump();
      await tester.pump();

      expect(find.text('Success'), findsOneWidget);
      expect(verified, 1);

      // Advance well past the TTL: the timer the run armed at parse
      // must have been stopped by the success terminalization.
      await tester.pump(const Duration(seconds: 10));
      await tester.pump();

      expect(verified, 1, reason: 'onVerify must fire exactly once');
      expect(expired, 0, reason: 'a delivered run must never expire');
      expect(find.text('Success'), findsOneWidget);
      expect(find.text('Expired'), findsNothing);
    });

    testWidgets('expiry wins the race and stays terminal', (tester) async {
      var verified = 0;
      var expired = 0;
      final gate = Completer<KiwiSolution>();
      widget.debugHttpPostOverride = (url, body, headers) async =>
          widget.KiwiHttpResponse(
              statusCode: 200, body: json.encode(challengeJson(ttlSecs: 2)));
      widget.debugSolveOverride = (challenge, isCancelled) => gate.future;

      await tester.pumpWidget(MaterialApp(home: captcha(
        onVerify: (_) => verified++,
        onExpire: () => expired++,
      )));
      await tester.pump();
      expect(find.text('Working'), findsOneWidget);

      await tester.pump(const Duration(seconds: 2));
      expect(find.text('Expired'), findsOneWidget);
      expect(expired, 1);
      expect(verified, 0);

      // The late solve and any further clock advances must be no-ops.
      gate.complete(const KiwiSolution(counter: 45, durationMs: 1, hashHex: ''));
      await tester.pump();
      await tester.pump(const Duration(seconds: 10));
      await tester.pump();

      expect(expired, 1, reason: 'onExpire must fire exactly once');
      expect(verified, 0);
      expect(find.text('Expired'), findsOneWidget);
      expect(find.text('Success'), findsNothing);
    });

    testWidgets('a failure is terminal: the armed expiry timer never fires',
        (tester) async {
      var errors = 0;
      var expired = 0;
      var verified = 0;
      widget.debugHttpPostOverride = (url, body, headers) async =>
          widget.KiwiHttpResponse(
              statusCode: 200, body: json.encode(challengeJson(ttlSecs: 2)));
      widget.debugSolveOverride =
          (challenge, isCancelled) async => throw KiwiSolveError.malformed('boom');

      await tester.pumpWidget(MaterialApp(home: captcha(
        onVerify: (_) => verified++,
        onError: (_) => errors++,
        onExpire: () => expired++,
      )));
      await tester.pump();
      await tester.pump();

      expect(find.text('Failed'), findsOneWidget);
      expect(errors, 1);

      // The parse-armed expiry timer outlives a non-terminal failure
      // unless the failure itself stops it.
      await tester.pump(const Duration(seconds: 10));
      await tester.pump();

      expect(errors, 1, reason: 'onError must fire exactly once');
      expect(expired, 0, reason: 'a failed run must never expire');
      expect(verified, 0);
      expect(find.text('Failed'), findsOneWidget);
      expect(find.text('Expired'), findsNothing);
    });

    testWidgets('supersede stops the old run\'s expiry timer', (tester) async {
      var verified = 0;
      var expired = 0;
      final gate = Completer<void>();
      var solveCalls = 0;
      widget.debugHttpPostOverride = (url, body, headers) async =>
          widget.KiwiHttpResponse(
              statusCode: 200, body: json.encode(challengeJson(ttlSecs: 2)));
      widget.debugSolveOverride = (challenge, isCancelled) async {
        solveCalls++;
        if (solveCalls == 1) {
          await gate.future;
          throw const KiwiSolveError.cancelled();
        }
        return const KiwiSolution(counter: 45, durationMs: 1, hashHex: '');
      };
      final key = GlobalKey<widget.KiwiCaptchaState>();

      await tester.pumpWidget(MaterialApp(home: captcha(
        key: key,
        onVerify: (_) => verified++,
        onExpire: () => expired++,
      )));
      await tester.pump();
      expect(find.text('Working'), findsOneWidget);

      // A newer generation starts while the first solve (and its
      // armed expiry timer) is still live.
      key.currentState!.start();
      await tester.pump();
      await tester.pump();
      expect(find.text('Success'), findsOneWidget);
      expect(verified, 1);

      // Past the first run's TTL: its cancelled timer must not flip
      // the delivered UI or emit a late onExpire.
      await tester.pump(const Duration(seconds: 10));
      gate.complete();
      await tester.pump();
      await tester.pump();

      expect(verified, 1);
      expect(expired, 0);
      expect(find.text('Success'), findsOneWidget);
      expect(find.text('Expired'), findsNothing);
    });
  });
}

extension on KiwiChallenge {
  /// Helper for the broken-nonce refusal test.
  KiwiChallenge get nonce_ => KiwiChallenge(
        nonce: 'short',
        salt: salt,
        algorithm: algorithm,
        mKib: mKib,
        t: t,
        p: p,
        targetBits: targetBits,
        prefix: prefix,
      );
}
