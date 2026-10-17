<?php

declare(strict_types=1);

/**
 * Generates the shared hostile wire corpus for the solution-token
 * decoders of every hosted SDK.
 *
 * The table below is expanded once by this script, decoded by the
 * reference PHP decoder, and written as one JSON document. Every
 * language suite reads the identical rows and asserts the same
 * verdict, so an acceptance drift between two hosts fails in the host
 * that moved. Regenerate with:
 *
 *   php packages/kiwicaptcha-php/tests/Fixtures/generate-wire-hostile-corpus.php
 *
 * The expected verdict is the reference decoder's, never a hand
 * written guess.
 */

require __DIR__.'/../../vendor/autoload.php';

use KiwiCaptcha\DecodeError;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Telemetry;

$repo = \dirname(__DIR__, 4);
$nonce = base64_encode(str_repeat("\x00", 32));
$nonceMixed = base64_encode("\xFF\xFF\xFF\xFB\xEF\xBE".str_repeat("\x00", 26));
$hex64 = str_repeat('a', 64);
$hex512 = str_repeat('b', 512);
$trace = 'Y2hlY2stdHJhY2Uta2V5XzEyMzQ1Ng';
$trace10924 = str_repeat('a', 10924);

/** @var list<array{id:string,class:string,raw:string,note:string,telemetry:bool,score:bool,class_override?:string}> $defs */
$defs = [];
$add = static function (string $id, string $class, string $raw, string $note = '', bool $telemetry = false, ?string $classOverride = null, bool $score = false) use (&$defs): void {
    $row = ['id' => $id, 'class' => $class, 'raw' => $raw, 'note' => $note, 'telemetry' => $telemetry, 'score' => $score];
    if ($classOverride !== null) {
        $row['class_override'] = $classOverride;
    }
    $defs[] = $row;
};
$tok = static function (string $id, string $class, string $plain, string $note = '', bool $telemetry = false, ?string $classOverride = null, bool $score = false) use (&$defs, $add): void {
    $add($id, $class, base64_encode($plain), $note, $telemetry, $classOverride, $score);
};

// ── accepted shapes: the positive half of the wire language ──────────
$tok('accept-unarmed', 'accept', "$nonce.42.850.{}", 'the canonical four-segment token', true);
$tok('accept-telemetry', 'accept', "$nonce.42.850.{\"wd\":true,\"me\":3,\"et\":[1,2,3]}", 'ordinary widget telemetry');
$tok('accept-dotted-telemetry', 'accept', "$nonce.1.2.{\"ua\":\"Mozilla/5.0 (X11; Linux x86_64)\"}", 'dots inside a telemetry string are not separators');
$tok('accept-counter-zero', 'accept', "$nonce.0.850.{}", 'the zero counter');
$tok('accept-counter-max', 'accept', "$nonce.19999999.850.{}", 'the last counter the solver can mint');
$tok('accept-duration-zero', 'accept', "$nonce.1.0.{}", 'the zero duration');
$tok('accept-duration-max', 'accept', "$nonce.1.3600000.{}", 'the duration ceiling');
$tok('accept-key-order', 'accept', "$nonce.1.2.{\"b\":2,\"a\":1}", 'object key order is insignificant', true);
$tok('accept-escaped-key', 'accept', "$nonce.1.2.{\"\\u0061\":1}", 'an escaped key decodes to its plain spelling', true);
$tok('accept-surrogate-pair', 'accept', "$nonce.1.2.{\"a\":\"\\ud83d\\ude00\"}", 'a well formed surrogate pair is a scalar value');
$tok('accept-nul-string', 'accept', "$nonce.1.2.{\"a\":\"x\\u0000y\"}", 'a NUL escape inside a string is legal JSON', true);
$tok('accept-whitespace', 'accept', "$nonce.1.2.{ \"a\" : 1 }", 'insignificant JSON whitespace', true);
$tok('accept-trailing-space', 'accept', "$nonce.1.2.{} ", 'trailing JSON whitespace');
$tok('accept-duplicate-top', 'accept', "$nonce.1.2.{\"a\":1,\"a\":2}", 'duplicate top level keys resolve to the last value', true);
$tok('accept-duplicate-nested', 'accept', "$nonce.1.2.{\"a\":{\"b\":1,\"b\":2}}", 'duplicate nested keys resolve to the last value', true);
$tok('accept-duplicate-escaped', 'accept', "$nonce.1.2.{\"\\u0061\":1,\"a\":2}", 'escaped and plain spellings are the same key', true);
$tok('accept-number-integer', 'accept', "$nonce.1.2.{\"a\":1}", 'an integer telemetry value', true);
$tok('accept-number-float', 'accept', "$nonce.1.2.{\"a\":1.0}", 'the float spelling of one');
$tok('accept-number-exponent', 'accept', "$nonce.1.2.{\"a\":1e0}", 'the exponent spelling of one');
$tok('accept-number-big', 'accept', "$nonce.1.2.{\"a\":9007199254740993}", 'an integer above the double precision limit', true);
$tok('accept-width', 'accept', "$nonce.1.2.{".implode(',', array_map(static fn (int $i): string => "\"k$i\":$i", range(1, 200))).'}', 'a wide telemetry object inside the token bound');
// The depth register boundary: 31 and 32 nested containers are inside
// the wire language, 33 is not. The ceiling is
// protocol/limits.json token_max_telemetry_depth.
$tok('accept-depth-31', 'accept', "$nonce.1.2.".str_repeat('{"a":', 31).'1'.str_repeat('}', 31), '31 nested objects, one below the ceiling');
$tok('accept-depth-32', 'accept', "$nonce.1.2.".str_repeat('{"a":', 32).'1'.str_repeat('}', 32), '32 nested objects, the deepest row every host accepts');
$tok('reject-depth-33', 'size', "$nonce.1.2.".str_repeat('{"a":', 33).'1'.str_repeat('}', 33), '33 nested objects, one past the telemetry depth ceiling', false, 'malformed');
// The telemetry scorer's numeric domain: only integer literals are
// timestamps. The same uniform 8ms ladder trips the bot gate when
// spelled as integers and is skipped entirely when spelled as floats
// (PHP is_int, serde_json as_u64). A host that folds 1.0 into 1
// scores the float row as a bot, a verdict split.
$etInteger = '{"et":['.implode(',', array_map(static fn (int $i): string => (string) ($i * 8), range(0, 24))).']}';
$etFloat = '{"et":['.implode(',', array_map(static fn (int $i): string => ($i * 8).'.0', range(0, 24))).']}';
$tok('accept-et-integer', 'accept', "$nonce.1.2.$etInteger", 'uniform timestamps spelled as integer literals are a bot signal', true, null, true);
$tok('accept-et-float', 'accept', "$nonce.1.2.$etFloat", 'uniform timestamps spelled as floats are not timestamps', false, null, true);
$tok('accept-digest-only', 'accept', "$nonce.1.2.{}.$hex64", 'the execution digest alone');
$tok('accept-digest-trace', 'accept', "$nonce.1.2.{}.$hex64:$trace", 'the digest and its base64url trace');
$tok('accept-trace-limit', 'accept', "$nonce.1.2.{}.$hex64:$trace10924", 'the trace exactly at its character ceiling');
$tok('accept-rsw', 'accept', "$nonce.0.2.{}.$hex512", 'the rsw final value as the last segment');
$tok('accept-digest-trace-rsw', 'accept', "$nonce.0.2.{}.$hex64:$trace.$hex512", 'execution evidence and the rsw value compose');
$tok('accept-rsw-dotted-telemetry', 'accept', "$nonce.0.2.{\"ua\":\"Mozilla/5.0 (X11; Linux x86_64)\"}.$hex512", 'dotted telemetry before the rsw segment');

// ── base64 and alphabet strictness ───────────────────────────────────
$raw = base64_encode("$nonce.1.2.{\"a\":1}");
$add('reject-outer-unpadded', 'base64', rtrim($raw, '='), 'the unpadded outer spelling');
$add('reject-outer-extra-pad', 'base64', $raw.'=', 'one padding character too many');
$add('reject-outer-space-middle', 'base64', substr($raw, 0, 10).' '.substr($raw, 10), 'whitespace inside the outer encoding');
$add('reject-outer-leading-space', 'base64', ' '.$raw, 'leading whitespace is not trimmed');
$add('reject-outer-trailing-newline', 'base64', $raw."\n", 'a trailing newline is outside the language');
$add('reject-outer-eq-middle', 'base64', '='.$raw, 'padding before the final quantum');
$add('reject-outer-invalid-char', 'base64', '!'.$raw, 'a character outside the standard alphabet');
$add('reject-outer-4n1', 'base64', 'A', 'a length that cannot encode a byte');
$add('reject-outer-empty', 'base64', '', 'the empty token');
// Outer base64 of ASCII-only plaintext can never use '+' or '/'
// (the high bits of printable ASCII forbid both sextets), so the
// url-safe differential rides a valid UTF-8 telemetry value.
$nonceUtf8 = 'V3UDVOlwdZbi+3SlmME6j3FYoWgyMr4nPIfcZFbgU1c=';
$utf8Plain = "$nonceUtf8.1.2.{\"a\":\"\u{00FF}\"}";
$urlRaw = base64_encode($utf8Plain);
assert(str_contains($urlRaw, '/'));
$tok('accept-utf8-telemetry', 'accept', $utf8Plain, 'a valid UTF-8 telemetry string');
$add('reject-outer-url-alphabet', 'base64', strtr($urlRaw, '+/', '-_'), 'the base64url alphabet is not the wire alphabet');
// One non-canonical pad bit spelling: the final data character's
// unused bits are set, decoding to the same bytes as the canonical form.
$padPlain = "$nonce.1.2.{\"a\":1}";
$canonicalPad = base64_encode($padPlain);
$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
$pos = \strlen($canonicalPad) - 2;
$noncanonicalPad = substr($canonicalPad, 0, $pos).$alphabet[strpos($alphabet, $canonicalPad[$pos]) + 1].'=';
$add('reject-outer-pad-bits', 'base64', $noncanonicalPad, 'non-zero unused bits in the final outer sextet');
$tok('reject-nonce-unpadded', 'base64', substr($nonce, 0, 43).".1.2.{}", 'the nonce must be padded standard base64');
$tok('reject-nonce-url', 'base64', strtr($nonceMixed, '+/', '-_').".1.2.{}", 'the nonce alphabet is standard, not url safe');
$nonceLast = $nonce[42];
$nonceNonCanonical = substr($nonce, 0, 42).$alphabet[strpos($alphabet, $nonceLast) + 1].'=';
$tok('reject-nonce-pad-bits', 'base64', "$nonceNonCanonical.1.2.{}", 'non-canonical nonce final bits');
$tok('reject-nonce-short', 'base64', "abc.1.2.{}", 'a nonce that is not 44 characters');
$shortNonce = base64_encode(str_repeat("\x00", 31));
$tok('reject-nonce-31-bytes', 'base64', "$shortNonce.1.2.{}", 'a shape valid nonce that decodes to 31 bytes');
$tok('reject-trace-padded', 'base64', "$nonce.1.2.{}.$hex64:aGk=", 'a padded trace');
$tok('reject-trace-standard-plus', 'base64', "$nonce.1.2.{}.$hex64:aGk+", 'a standard alphabet character in the trace');
$tok('reject-trace-standard-slash', 'base64', "$nonce.1.2.{}.$hex64:aGk/", 'a standard alphabet slash in the trace');
$tok('reject-trace-bad-bits', 'base64', "$nonce.1.2.{}.$hex64:aGh", 'non-canonical residual bits in the trace');
$tok('reject-trace-4n1', 'base64', "$nonce.1.2.{}.$hex64:a", 'an unpadded length of 4k+1 cannot encode a byte');
$tok('reject-trace-empty', 'base64', "$nonce.1.2.{}.$hex64:", 'a digest with an empty trace');
$tok('reject-trace-over-limit', 'base64', "$nonce.1.2.{}.$hex64:".str_repeat('a', 10925), 'one character over the trace ceiling');
$tok('reject-trace-colon', 'base64', "$nonce.1.2.{}.$hex64:a:b", 'a second colon is not part of the trace alphabet');
$tok('reject-trace-dot', 'base64', "$nonce.1.2.{}.$hex64:ab.cd", 'a dot would change the segment grammar');
$tok('reject-trace-space', 'base64', "$nonce.1.2.{}.$hex64:a b", 'whitespace is not part of the trace alphabet');
$tok('reject-digest-uppercase', 'base64', "$nonce.1.2.{}.".strtoupper($hex64), 'the digest is lowercase hex');
$tok('reject-digest-short', 'base64', "$nonce.1.2.{}.".substr($hex64, 0, 63), 'a 63 character digest');
$tok('reject-digest-nonhex', 'base64', "$nonce.1.2.{}.".str_repeat('g', 64), 'a digest outside the hex alphabet');
$tok('reject-rsw-uppercase', 'base64', "$nonce.0.2.{}.".strtoupper($hex512), 'the rsw value is lowercase hex');
$tok('reject-rsw-short', 'base64', "$nonce.0.2.{}.".substr($hex512, 0, 511), 'a 511 character rsw value');
$tok('reject-rsw-long', 'base64', "$nonce.0.2.{}.$hex512".'b', 'a 513 character rsw value');
$tok('reject-rsw-nonhex', 'base64', "$nonce.0.2.{}.".str_repeat('g', 512), 'an rsw value outside the hex alphabet');

// ── canonicalization ambiguity ───────────────────────────────────────
$tok('reject-bom', 'canonicalization', "$nonce.1.2.\xEF\xBB\xBF{}", 'a UTF-8 BOM before the telemetry object');
$tok('reject-trailing-x', 'canonicalization', "$nonce.1.2.{}x", 'a trailing byte after the object');
$tok('reject-trailing-nul', 'canonicalization', "$nonce.1.2.{}\x00", 'a trailing NUL after the object');
$tok('reject-lone-high-surrogate', 'canonicalization', "$nonce.1.2.{\"a\":\"\\ud800\"}", 'an unpaired high surrogate escape');
$tok('reject-lone-low-surrogate', 'canonicalization', "$nonce.1.2.{\"a\":\"\\udc00\"}", 'an unpaired low surrogate escape');
$tok('reject-telemetry-array', 'canonicalization', "$nonce.1.2.[]", 'an array is not a telemetry object');
$tok('reject-telemetry-string', 'canonicalization', "$nonce.1.2.\"hello\"", 'a string is not a telemetry object');
$tok('reject-telemetry-number', 'canonicalization', "$nonce.1.2.123", 'a number is not a telemetry object');
$tok('reject-telemetry-null', 'canonicalization', "$nonce.1.2.null", 'null is not a telemetry object');
$tok('reject-telemetry-true', 'canonicalization', "$nonce.1.2.true", 'a boolean is not a telemetry object');
$add('reject-invalid-utf8', 'canonicalization', base64_encode("$nonce.1.2.\xFF{}"), 'the plaintext is not valid UTF-8');
$add('reject-overlong-utf8', 'canonicalization', base64_encode("$nonce.1.2.\xC0\xAF{}"), 'an overlong UTF-8 encoding');
$tok('reject-json-trailing-comma', 'canonicalization', "$nonce.1.2.{\"a\":1,}", 'a trailing comma is not JSON');
$tok('reject-json-missing-brace', 'canonicalization', "$nonce.1.2.{\"a\":1", 'an unterminated telemetry object');
$tok('reject-json-unquoted-key', 'canonicalization', "$nonce.1.2.{a:1}", 'an unquoted object key');
$tok('reject-leading-junk', 'canonicalization', "junk.$nonce.1.2.{}", 'a nonce with a prefix');

// ── numeric and size edges ───────────────────────────────────────────
foreach ([
    'counter-20000000' => ['20000000', 'the first counter at the solver ceiling', 'counter'],
    'counter-99999999' => ['99999999', 'eight digits above the ceiling', 'counter'],
    'counter-2pow31' => ['2147483648', '2^31', 'counter'],
    'counter-2pow32' => ['4294967296', '2^32', 'counter'],
    'counter-2pow53' => ['9007199254740992', '2^53, the double precision limit', 'counter'],
    'counter-2pow63' => ['9223372036854775808', '2^63, one past the signed 64 bit range', 'counter'],
    'counter-2pow64' => ['18446744073709551616', '2^64, one past the unsigned 64 bit range', 'counter'],
    'counter-negative' => ['-1', 'a negative counter', 'counter'],
    'counter-plus' => ['+1', 'an explicitly signed counter', 'counter'],
    'counter-leading-zero' => ['01', 'a leading zero counter spelling', 'counter'],
    'counter-fractional' => ['1.5', 'a fractional spelling splits the segment grammar', 'malformed'],
    'counter-exponent' => ['1e0', 'an exponent spelling is not decimal digits', 'counter'],
    'counter-40-digits' => [str_repeat('9', 40), 'forty digits', 'counter'],
    'counter-100-digits' => [str_repeat('9', 100), 'one hundred digits', 'counter'],
] as $id => [$counter, $note, $hint]) {
    $tok($id, 'numeric', "$nonce.$counter.2.{}", $note, false, $hint);
}
foreach ([
    'duration-3600001' => ['3600001', 'one millisecond over the duration ceiling', 'duration'],
    'duration-2pow63' => ['9223372036854775808', '2^63, one past the signed 64 bit range', 'duration'],
    'duration-2pow64' => ['18446744073709551616', '2^64, one past the unsigned 64 bit range', 'duration'],
    'duration-negative' => ['-1', 'a negative duration', 'duration'],
    'duration-plus' => ['+1', 'an explicitly signed duration', 'duration'],
    'duration-leading-zero' => ['01', 'a leading zero duration spelling', 'duration'],
    'duration-empty' => ['', 'an empty duration segment', 'duration'],
    'duration-fractional' => ['1.5', 'a fractional duration splits the segment grammar', 'malformed'],
    'duration-exponent' => ['1e0', 'an exponent duration spelling', 'duration'],
    'duration-40-digits' => [str_repeat('9', 40), 'forty duration digits', 'duration'],
] as $id => [$duration, $note, $hint]) {
    $tok($id, 'numeric', "$nonce.1.$duration.{}", $note, false, $hint);
}
$add('size-at-cap', 'size', str_repeat('A', 32_768), 'a raw token exactly at the 32 KiB bound', false, 'any');
$add('size-over-cap', 'size', str_repeat('A', 32_769), 'a raw token one byte over the bound', false, 'any');
$tok('size-wide-over-cap', 'size', "$nonce.1.2.{".implode(',', array_map(static fn (int $i): string => "\"k$i\":$i", range(1, 4000))).'}', 'a wide object that pushes the encoded token over the bound', false, 'any');

// ── field boundary mutations ─────────────────────────────────────────
$basePlain = "$nonce.42.850.{}";
$flip = static function (string $plain, int $offset, int $mask): string {
    $plain[$offset] = \chr(\ord($plain[$offset]) ^ $mask);
    return $plain;
};
// Every byte of the shortest well formed token, one bit at a time: the
// systematic sweep, not a hand picked sample.
for ($offset = 0; $offset < \strlen($basePlain); ++$offset) {
    $mask = 1 << ($offset % 8);
    $tok('mutation-flip-'.$offset, 'mutation', $flip($basePlain, $offset, $mask), "one bit flipped at plaintext byte $offset");
}
foreach ([
    'truncate-nonce' => 43,
    'truncate-nonce-pad' => 44,
    'truncate-counter' => 46,
    'truncate-duration' => 48,
    'truncate-telemetry-open' => 49,
    'truncate-telemetry-tail' => \strlen($basePlain) - 1,
    'truncate-empty' => 0,
] as $id => $length) {
    $tok($id, 'mutation', substr($basePlain, 0, $length), "the token truncated after plaintext byte $length");
}
foreach ([
    'append-dot' => '.',
    'append-junk-segment' => '.junk',
    'append-nul' => "\x00",
    'append-space' => ' ',
    'append-object' => '{}',
    'append-hex' => '.'.$hex64,
] as $id => $suffix) {
    $tok($id, 'mutation', $basePlain.$suffix, 'bytes appended after the token: '.bin2hex($suffix));
}

// ── suffix grammar and ambiguity ─────────────────────────────────────
$tok('suffix-four-part-hex512', 'suffix', "$nonce.0.2.$hex512", 'a 512 hex telemetry segment is not peeled in the four part shape');
$tok('suffix-five-part-hex512', 'suffix', "$nonce.0.2.{}.$hex512", 'a 512 hex tail peels as the rsw value');
$tok('suffix-digest-in-four-part', 'suffix', "$nonce.1.2.$hex64", 'a 64 hex telemetry segment is not peeled in the four part shape');
$tok('suffix-digest-only-five', 'suffix', "$nonce.1.2.{}.$hex64", 'a 64 hex tail peels as the digest');
$tok('suffix-digest-extra-segment', 'suffix', "$nonce.1.2.{}.$hex64.junk", 'an extra segment after the digest is not execution evidence');
$tok('suffix-rsw-extra-segment', 'suffix', "$nonce.0.2.{}.$hex512.junk", 'an extra segment after the rsw value is rejected');
$tok('suffix-digest-trace-uppercase-rsw', 'suffix', "$nonce.0.2.{}.$hex64:$trace.".strtoupper($hex512), 'uppercase rsw hex beside execution evidence');
$tok('suffix-empty-tail', 'suffix', "$nonce.1.2.{}.", 'an empty final segment');
$tok('suffix-two-trailing-dots', 'suffix', "$nonce.1.2.{}..", 'two empty final segments');
$tok('suffix-colon-telemetry', 'suffix', "$nonce.1.2.{\"a\":\"x:y\"}", 'a colon inside a telemetry string is untouched');
$tok('suffix-hex-in-telemetry', 'suffix', "$nonce.1.2.{\"a\":\"x.$hex64\"}", 'a digest shaped substring inside telemetry stays telemetry');
$tok('suffix-rsw-in-telemetry', 'suffix', "$nonce.1.2.{\"a\":\"x.$hex512\"}", 'an rsw shaped substring inside telemetry cannot be peeled without breaking JSON');

// ── expand the table against the reference decoder ───────────────────
$classify = static function (string $code): string {
    return match ($code) {
        DecodeError::INVALID_BASE64 => 'base64',
        DecodeError::INVALID_UTF8 => 'utf8',
        DecodeError::INVALID_COUNTER, DecodeError::COUNTER_EXCEEDS_SOLVER_MAXIMUM => 'counter',
        DecodeError::INVALID_DURATION => 'duration',
        default => 'malformed',
    };
};

$vectors = [];
foreach ($defs as $def) {
    $row = [
        'id' => $def['id'],
        'attack_class' => $def['class'],
        'raw' => $def['raw'],
        'note' => $def['note'],
    ];
    try {
        $token = SolutionToken::decode($def['raw']);
        $row['expect'] = [
            'verdict' => 'accept',
            'counter' => $token->counter,
            'duration_ms' => $token->durationMs,
            'execution_digest' => $token->executionDigest,
            'execution_trace' => $token->executionTrace,
            'rsw_proof' => $token->rswProof,
        ];
        if ($def['telemetry']) {
            // Object mode keeps an empty telemetry object as {} in
            // the corpus, never the [] an associative decode produces.
            $row['expect']['telemetry'] = json_decode(
                (string) json_encode((object) $token->telemetry, JSON_UNESCAPED_SLASHES),
                false,
            );
        }
        if ($def['score']) {
            // The reference scorer's verdict for this exact decoded
            // telemetry. Every host suite must reproduce it, so a host
            // whose numeric domain differs fails on the corpus row.
            $row['expect']['telemetry_score'] = Telemetry::score($token->telemetry, $token->durationMs);
        }
    } catch (DecodeError $error) {
        $row['expect'] = [
            'verdict' => 'reject',
            'class' => $def['class_override'] ?? $classify($error->getMessage()),
        ];
    }
    $vectors[] = $row;
}

$byClass = [];
$byVerdict = ['accept' => 0, 'reject' => 0];
foreach ($vectors as $vector) {
    $byClass[$vector['attack_class']] = ($byClass[$vector['attack_class']] ?? 0) + 1;
    $byVerdict[$vector['expect']['verdict']] = ($byVerdict[$vector['expect']['verdict']] ?? 0) + 1;
}
ksort($byClass);

$document = [
    '$schema' => 'kiwicaptcha.wire-hostile-corpus/1',
    'format_version' => 1,
    'description' => 'The shared hostile solution-token corpus. Every hosted decoder reads these exact rows and must return the same verdict and the same decoded values. Expected values are produced by the reference PHP SolutionToken decoder; a host that disagrees is the drifting host. Attack classes: accept, base64, canonicalization, numeric, size, mutation, suffix.',
    'reference' => 'packages/kiwicaptcha-php/src/SolutionToken.php',
    'regenerate' => 'php packages/kiwicaptcha-php/tests/Fixtures/generate-wire-hostile-corpus.php',
    'nonce_b64' => $nonce,
    'counts' => ['total' => count($vectors), 'by_verdict' => $byVerdict, 'by_attack_class' => $byClass],
    'vectors' => $vectors,
];

$json = json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)."\n";
$targets = [
    "$repo/protocol/solution-token-v1/wire-hostile-corpus.json",
    "$repo/packages/kiwicaptcha-php/tests/Fixtures/wire-hostile-corpus.json",
    "$repo/packages/kiwicaptcha/tests/fixtures/wire-hostile-corpus.json",
    "$repo/packages/kiwicaptcha-go/testdata/wire-hostile-corpus.json",
    "$repo/packages/kiwicaptcha-python-sdk/tests/fixtures/wire-hostile-corpus.json",
    "$repo/packages/kiwicaptcha-jvm/core/src/test/resources/wire-hostile-corpus.json",
    "$repo/packages/kiwicaptcha-dotnet/tests/KiwiCaptcha.Tests/fixtures/wire-hostile-corpus.json",
    "$repo/packages/kiwicaptcha-node/test/fixtures/wire-hostile-corpus.json",
    "$repo/packages/kiwicaptcha-ruby/test/fixtures/wire-hostile-corpus.json",
    "$repo/packages/kiwicaptcha-elixir/test/fixtures/wire-hostile-corpus.json",
];
foreach ($targets as $target) {
    if (!is_dir(\dirname($target))) {
        mkdir(\dirname($target), 0777, true);
    }
    file_put_contents($target, $json);
}

echo "wrote ".count($vectors)." vectors to ".count($targets)." files\n";
foreach ($byClass as $class => $count) {
    echo "  $class: $count\n";
}
echo "  accept: {$byVerdict['accept']}, reject: {$byVerdict['reject']}\n";
