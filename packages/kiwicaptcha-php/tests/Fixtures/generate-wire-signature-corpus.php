<?php

declare(strict_types=1);

/**
 * Generates the shared challenge-signature corpus for the verifier of
 * every hosted SDK.
 *
 * The table expands a fixed v2 record and a fixed secret into the
 * signature-forgery classes: nibble flips, truncations, appended
 * bytes, a foreign key, a foreign tenant, a reordered canonical, a
 * changed field, and the challenge-segment extraction edge cases.
 * Every row carries the record, the challenge, the verifier's secret
 * and tenant, and the reference verdict. Regenerate with:
 *
 *   php packages/kiwicaptcha-php/tests/Fixtures/generate-wire-signature-corpus.php
 */

require __DIR__.'/../../vendor/autoload.php';

use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;

$repo = \dirname(__DIR__, 4);
$secret = 'signature-corpus-secret-0123456789abcdef';
$otherSecret = 'signature-corpus-other-0123456789abcdefx';
$tenant = 'tenant-a';
$nonce = base64_encode(str_repeat("\x11", 32));
$salt = base64_encode(str_repeat("\x22", 16));
$tag = str_repeat('3', 64);
$issuedAt = 1_800_000_000;
$expiresAt = 1_800_000_120;
$canonical = Issuer::canonicalPayload(
    2,
    $nonce,
    'login',
    $tag,
    $issuedAt,
    $expiresAt,
    PoWAlgorithm::Sha256,
    0,
    1,
    1,
    8,
    $salt,
    0,
    null,
    1,
    null,
    null,
    1,
);
$signature = Issuer::signPayloadV2($canonical, $secret);
$payload = base64_encode($canonical);

$record = static function (string $challenge) use ($nonce, $tag, $salt, $issuedAt, $expiresAt): array {
    return [
        'nonce' => $nonce,
        'scope' => 'login',
        'binding_tag' => $tag,
        'issued_at' => $issuedAt,
        'expires_at' => $expiresAt,
        'algorithm' => 'sha256',
        'm_kib' => 0,
        't' => 1,
        'p' => 1,
        'target_bits' => 8,
        'salt' => $salt,
        'prefix' => $challenge.'|'.$salt.'|',
        'challenge' => $challenge,
        'min_duration_ms' => 0,
        'issued_at_ns' => $issuedAt * 1_000_000,
        'attempts_used' => 0,
        'protocol_version' => 2,
        'region' => null,
        'policy_version' => 1,
        'request_binding' => null,
        'issuer' => null,
        'kid' => 1,
        'hostname' => null,
        'server_mac' => null,
    ];
};

/** @var list<array<string, mixed>> $rows */
$rows = [];
$add = static function (string $id, string $class, string $challenge, string $verdict, string $verifySecret, ?string $verifyTenant = null, string $note = '') use (&$rows, $record): void {
    $rows[] = [
        'id' => $id,
        'attack_class' => $class,
        'record' => $record($challenge),
        'challenge' => $challenge,
        'verify_secret' => $verifySecret,
        'verify_tenant' => $verifyTenant,
        'expect' => $verdict,
        'note' => $note,
    ];
};

// The authentic challenge and the tenant-scoped variant.
$add('valid', 'accept', $payload.'.'.$signature, 'accept', $secret, null, 'the authentic signed challenge');
// The payload/field contract: the base64 payload segment must decode
// to exactly the canonical the signed fields reconstruct. A rewritten
// payload under the authentic signature is refused; a matching payload
// verifies.
$add('payload-matches', 'accept', base64_encode($canonical).'.'.$signature, 'accept', $secret, null, 'the payload segment decodes to the reconstructed canonical');
$add('payload-mismatch', 'canonicalization', base64_encode('v4|attacker-chosen-payload').'.'.$signature, 'reject', $secret, null, 'an attacker-chosen payload under the authentic field signature is refused');
$tenantCanonical = Issuer::canonicalPayload(2, $nonce, 'login', $tag, $issuedAt, $expiresAt, PoWAlgorithm::Sha256, 0, 1, 1, 8, $salt, 0, null, 1, null, null, 1);
$tenantSignature = Issuer::signPayloadV2($tenantCanonical, $secret, $tenant);
$add('valid-tenant', 'accept', base64_encode($tenantCanonical).'.'.$tenantSignature, 'accept', $secret, $tenant, 'the tenant scoped signature verifies under its tenant');
$add('wrong-tenant', 'binding', $payload.'.'.$tenantSignature, 'reject', $secret, null, 'a tenant scoped signature cannot verify globally');
$add('wrong-secret', 'signature', $payload.'.'.Issuer::signPayloadV2($canonical, $otherSecret), 'reject', $secret, null, 'a signature under a different key');
$add('wrong-tenant-expected', 'binding', $payload.'.'.$tenantSignature, 'reject', $secret, 'tenant-b', 'a tenant signature presented to another tenant');

// Nibble flips across the whole signature.
foreach ([0, 1, 2, 3, 4, 8, 16, 24, 32, 40, 48, 56, 60, 61, 62, 63] as $position) {
    $flipped = $signature;
    $flipped[$position] = $flipped[$position] === '0' ? '1' : '0';
    $add('flip-'.$position, 'signature', $payload.'.'.$flipped, 'reject', $secret, null, "one nibble flipped at signature position $position");
}

// Truncation, extension, case, alphabet and empty signatures.
foreach ([0, 1, 2, 31, 32, 63] as $length) {
    $add('truncate-'.$length, 'signature', $payload.'.'.substr($signature, 0, $length), 'reject', $secret, null, "the signature truncated to $length characters");
}
$add('signature-appended', 'signature', $payload.'.'.$signature.'00', 'reject', $secret, null, 'two hex characters appended to the signature');
$add('signature-long-65', 'signature', $payload.'.'.$signature.'0', 'reject', $secret, null, 'one hex character past the signature length');
$add('signature-long-128', 'signature', $payload.'.'.$signature.str_repeat('0', 64), 'reject', $secret, null, 'a doubled signature length');
$add('signature-uppercase', 'canonicalization', $payload.'.'.strtoupper($signature), 'reject', $secret, null, 'the same tag bytes in uppercase hex');
$add('signature-nonhex', 'signature', $payload.'.'.str_repeat('g', 64), 'reject', $secret, null, 'a signature outside the hex alphabet');
$add('signature-empty', 'signature', $payload.'.', 'reject', $secret, null, 'an empty signature segment');

// The challenge segment grammar: the tag is the segment after the last
// dot, and the payload is everything before it. An extra middle segment
// makes the payload segment no longer the canonical base64, so the
// strict payload check refuses it; a last-segment-only comparison would
// accept it.
$add('extra-middle-segment', 'canonicalization', $payload.'.junk.'.$signature, 'reject', $secret, null, 'the payload segment before the tag is no longer the canonical base64');
$add('extra-empty-segment', 'canonicalization', $payload.'..'.$signature, 'reject', $secret, null, 'an empty middle segment makes the payload segment malformed');
$add('duplicated-signature', 'canonicalization', $payload.'.'.$signature.'.'.$signature, 'reject', $secret, null, 'the payload segment would include the first signature');
$add('no-dot', 'canonicalization', $signature, 'reject', $secret, null, 'a challenge with no dot carries no tag');
$add('tag-then-junk', 'canonicalization', $payload.'.'.$signature.'.junk', 'reject', $secret, null, 'junk after the tag is the extracted tag and fails');

// A signature over a different canonical: a changed field, a reordered
// field, an appended segment and every field-boundary truncation.
$add('scope-changed', 'canonicalization', $payload.'.'.Issuer::signPayloadV2(
    Issuer::canonicalPayload(2, $nonce, 'signup', $tag, $issuedAt, $expiresAt, PoWAlgorithm::Sha256, 0, 1, 1, 8, $salt, 0, null, 1, null, null, 1),
    $secret,
), 'reject', $secret, null, 'a signature over a different scope');
$add('tag-changed', 'canonicalization', $payload.'.'.Issuer::signPayloadV2(
    Issuer::canonicalPayload(2, $nonce, 'login', str_repeat('4', 64), $issuedAt, $expiresAt, PoWAlgorithm::Sha256, 0, 1, 1, 8, $salt, 0, null, 1, null, null, 1),
    $secret,
), 'reject', $secret, null, 'a signature over a different binding tag');
$fields = explode('|', $canonical);
$reorderedFields = $fields;
[$reorderedFields[2], $reorderedFields[3]] = [$reorderedFields[3], $reorderedFields[2]];
$reordered = implode('|', $reorderedFields);
$add('field-order-changed', 'canonicalization', $payload.'.'.Issuer::signPayloadV2($reordered, $secret), 'reject', $secret, null, 'an HMAC over a reordered canonical');
$add('payload-appended', 'canonicalization', $payload.'.'.Issuer::signPayloadV2($canonical.'|x', $secret), 'reject', $secret, null, 'a signature over the canonical with an appended segment');
foreach (range(1, 17) as $keep) {
    $add('payload-truncate-'.$keep, 'canonicalization', $payload.'.'.Issuer::signPayloadV2(implode('|', \array_slice($fields, 0, $keep)), $secret), 'reject', $secret, null, "a signature over the first $keep canonical fields");
}

$byClass = [];
foreach ($rows as $row) {
    $byClass[$row['attack_class']] = ($byClass[$row['attack_class']] ?? 0) + 1;
}
ksort($byClass);

$document = [
    '$schema' => 'kiwicaptcha.wire-signature-corpus/1',
    'format_version' => 1,
    'description' => 'The shared hostile challenge-signature corpus. Each row carries a stored v2 record, the challenge string a storage writer could present, the verifier secret and tenant, and the reference verdict. Every hosted verifier must return the same verdict. The payload segment before the final dot must decode to the canonical the signed fields reconstruct, so a rewritten payload is refused even under an authentic field signature. Attack classes: signature, canonicalization, binding.',
    'reference' => 'packages/kiwicaptcha-php/src/Verifier.php',
    'regenerate' => 'php packages/kiwicaptcha-php/tests/Fixtures/generate-wire-signature-corpus.php',
    'counts' => ['total' => count($rows), 'by_attack_class' => $byClass],
    'vectors' => $rows,
];

$json = json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)."\n";
$targets = [
    "$repo/protocol/solution-token-v1/wire-signature-corpus.json",
    "$repo/packages/kiwicaptcha-php/tests/Fixtures/wire-signature-corpus.json",
    "$repo/packages/kiwicaptcha/tests/fixtures/wire-signature-corpus.json",
    "$repo/packages/kiwicaptcha-go/testdata/wire-signature-corpus.json",
    "$repo/packages/kiwicaptcha-python-sdk/tests/fixtures/wire-signature-corpus.json",
    "$repo/packages/kiwicaptcha-jvm/core/src/test/resources/wire-signature-corpus.json",
    "$repo/packages/kiwicaptcha-dotnet/tests/KiwiCaptcha.Tests/fixtures/wire-signature-corpus.json",
    "$repo/packages/kiwicaptcha-node/test/fixtures/wire-signature-corpus.json",
    "$repo/packages/kiwicaptcha-ruby/test/fixtures/wire-signature-corpus.json",
    "$repo/packages/kiwicaptcha-elixir/test/fixtures/wire-signature-corpus.json",
];
foreach ($targets as $target) {
    if (!is_dir(\dirname($target))) {
        mkdir(\dirname($target), 0777, true);
    }
    file_put_contents($target, $json);
}

echo "wrote ".count($rows)." signature vectors to ".count($targets)." files\n";
foreach ($byClass as $class => $count) {
    echo "  $class: $count\n";
}
