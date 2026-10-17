import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kiwicaptcha/kiwicaptcha.dart';
import 'package:kiwicaptcha/src/solver.dart';
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

    test('refuses argon2id fail-closed', () {
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
      expect(
        () => validateKiwiChallenge(argon),
        throwsA(predicate((e) => e is KiwiSolveError && e.refusal == KiwiRefusal.argonUnavailable)),
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
  });

  group('siteverify body', () {
    test('builds the provider-shaped document', () async {
      final body = await KiwiClient.siteverifyBody('s', 'tok', remoteip: '203.0.113.9');
      expect(body.toJson(), '{"secret":"s","response":"tok","remoteip":"203.0.113.9"}');
      final minimal = await KiwiClient.siteverifyBody('s', 'tok');
      expect(minimal.toJson(), '{"secret":"s","response":"tok"}');
    });
  });

  Map<String, dynamic> challengeJson({int targetBits = 8}) => <String, dynamic>{
        'nonce': nonce,
        'salt': salt,
        'algorithm': 'sha256',
        'mKib': 0,
        't': 1,
        'p': 1,
        'targetBits': targetBits,
        'prefix': prefix,
      };

  group('challenge parsing', () {
    test('fromJson accepts the wire document', () {
      final parsed = KiwiChallenge.fromJson(challengeJson());
      expect(parsed.nonce, nonce);
      expect(parsed.salt, salt);
      expect(parsed.algorithm, KiwiAlgorithm.sha256);
      expect(parsed.ttlSecs, 0);
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

  group('widget lifecycle', () {
    setUp(() {
      widget.debugHttpPostOverride = null;
      widget.debugSolveOverride = null;
    });

    tearDown(() {
      widget.debugHttpPostOverride = null;
      widget.debugSolveOverride = null;
    });

    testWidgets('Retry restarts the flow after a failure', (tester) async {
      var calls = 0;
      final verified = <String>[];
      final errors = <String>[];
      widget.debugHttpPostOverride = (url, body) async {
        calls++;
        if (calls == 1) {
          return const widget.KiwiHttpResponse(statusCode: 503, body: 'down');
        }
        return widget.KiwiHttpResponse(
            statusCode: 200, body: json.encode(challengeJson()));
      };
      widget.debugSolveOverride = (challenge) =>
          const KiwiSolution(counter: 45, durationMs: 1, hashHex: '');

      await tester.pumpWidget(MaterialApp(
        home: KiwiCaptcha(
          endpoint: Uri.parse('https://kiwi.test/challenge'),
          scope: 'login',
          onVerify: verified.add,
          onError: errors.add,
        ),
      ));
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
      widget.debugHttpPostOverride = (url, body) async =>
          widget.KiwiHttpResponse(
              statusCode: 200, body: json.encode(challengeJson()));
      widget.debugSolveOverride = (challenge) =>
          const KiwiSolution(counter: 45, durationMs: 1, hashHex: '');

      await tester.pumpWidget(MaterialApp(
        home: KiwiCaptcha(
          key: key,
          endpoint: Uri.parse('https://kiwi.test/challenge'),
          scope: 'login',
          autoStart: false,
          onVerify: (_) => verified++,
        ),
      ));

      expect(find.text('Idle'), findsOneWidget);
      expect(key.currentState, isNotNull);

      key.currentState!.start();
      await tester.pump();
      await tester.pump();

      expect(find.text('Success'), findsOneWidget);
      expect(verified, 1);
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
