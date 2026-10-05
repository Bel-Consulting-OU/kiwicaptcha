<?php

declare(strict_types=1);

// PHP-issued golden vector generator for the Ruby and Elixir SDKs.
// Drives the real kiwicaptcha-php Issuer, Rsw and SolutionToken so the
// committed records, challenges and MACs are authentic issuance output.
// Regenerate with:
//   php /tmp/kiwi-golden/gen_golden.php > golden-php-vectors.json

require '/Users/sabelakhoua/IdeaProjects/kiwicaptcha-standalone/packages/kiwicaptcha-php/vendor/autoload.php';

use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\BindingMode;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Rsw;
use KiwiCaptcha\SolutionToken;

const SECRET = '0123456789abcdef0123456789abcdef';
const CLIENT_IP = '203.0.113.7';
const RSW_MODULUS = 'sL1Mk2YZ4BnznBgWe2YB3uOZ+KFN/VETl1T0H9zuWkP54/nAN8sgPhqozDrRCVQxdJc5IDgkh9EemAGzYjku+zqv2fdryfy5iHbtQEhkHJVt+5f/6yxrZDvHUMhgDRAmLe7rRjEIZC8GqcfcbQyVECgxzNfd3FE+ATeuxc8wKafjUtQ/rvizFBJCo5L0r4U67JDooXVt4yTLtRsoFK3WZBOKIOSZ+E0vZJDt2ddeDSluS/qaqZ5C3dSVeaSyaelX8dGpmovr8xClC+9SKsFnMc+6m9WBo2CsCSpJGk3LZM2847HM5/r2gfmNdN5zRecjEY5MLLEQ/34JinuMtMJpuw==';
const RSW_LAMBDA = 'WF6mSbMM8Az5zgwLPbMA73HM/FCm/qiJy6p6D+53LSH88fzgG+WQHw1UZh1ohKoYukuckBwSQ+iPTADZsRyXfZ1X7Pu15P5cxDt2oCQyDkq2/cv/9ZY1sh3jqGQwBogTFvd1oxiEMheDVOPuNoZKiBQY5mvu7iifAJvXYueYFNMcEwMJdHQi8lgNFBJMwNN+267oViuNdvXRtCLx0MeOSiIPOvDNnLU0Ba4bJg5mTXLY9llIMPtOuHU5BiN8E7IY8kKCdYlpJTgGqv+uu5aNS/SPQl3sMR8dIo3zn7wZhcsMyzJ1n/dLZHNSwXs3QX6XQU+Bx8OVz5pmJYPTJUdsEA==';

function leadingZeroBits(string $digest): int
{
    $count = 0;
    for ($i = 0, $n = strlen($digest); $i < $n; $i++) {
        $byte = ord($digest[$i]);
        if ($byte === 0) {
            $count += 8;
            continue;
        }
        while (($byte & 0x80) === 0) {
            $count++;
            $byte <<= 1;
        }
        break;
    }
    return $count;
}

function solveSha(string $prefix, string $saltB64, int $targetBits): int
{
    $salt = base64_decode($saltB64);
    for ($counter = 0; $counter < 20_000_000; $counter++) {
        $digest = hash('sha256', $prefix . (string) $counter . $salt, true);
        if (leadingZeroBits($digest) >= $targetBits) {
            return $counter;
        }
    }
    throw new RuntimeException('no proof below the solver ceiling');
}

function mint(Config $config, ?string $region = null): ChallengeRecord
{
    $storage = new ArrayStorage();
    $issuer = new Issuer($config, $storage, null, $region);
    $challenge = $issuer->issue(
        'login',
        '',
        null,
        null,
        $config->algorithm === PoWAlgorithm::Rsw ? ChallengeRecord::RSW_IDENTITY_PROTOCOL_VERSION : ChallengeRecord::BASE_PROTOCOL_VERSION,
    );
    return $storage->find($challenge->nonce);
}

function tokenFor(ChallengeRecord $record, int $counter, int $durationMs, array $telemetry, ?string $rswProof = null): string
{
    return SolutionToken::create($record->nonce, $counter, $durationMs, $telemetry, null, null, $rswProof)->encode();
}

$records = [];

// 1. sha_plain: unarmed v2, region eu, policy 1, min duration 500, the
//    sealed record-metadata MAC (m=1) every issuance commits.
$config = new Config(
    secretKey: SECRET,
    algorithm: PoWAlgorithm::Sha256,
    targetBits: 8,
    minDurationMs: 500,
    bindingMode: BindingMode::None,
);
$record = mint($config, 'eu');
$counter = solveSha($record->prefix, $record->salt, $record->targetBits);
$records[] = [
    'name' => 'sha_plain',
    'record' => $record->toArray(),
    'token_b64' => tokenFor($record, $counter, 1500, ['v' => 1]),
    'expected' => ['ok' => true],
    'verify_opts' => ['expected_scope' => 'login', 'region' => 'eu'],
];

// 2. sha_bound: request-bound, issuer prod, policy epoch 2, kid 2.
$config = new Config(
    secretKey: SECRET,
    algorithm: PoWAlgorithm::Sha256,
    targetBits: 8,
    minDurationMs: 0,
    policyVersion: 2,
    issuer: 'prod',
    kid: 2,
);
$storage = new ArrayStorage();
$issuer = new Issuer($config, $storage);
$challenge = $issuer->issue('signup', CLIENT_IP, 'tx-1234', null, ChallengeRecord::BASE_PROTOCOL_VERSION);
$record = $storage->find($challenge->nonce);
$counter = solveSha($record->prefix, $record->salt, $record->targetBits);
$records[] = [
    'name' => 'sha_bound',
    'record' => $record->toArray(),
    'token_b64' => tokenFor($record, $counter, 1500, ['v' => 1]),
    'expected' => ['ok' => true],
    'verify_opts' => [
        'expected_scope' => 'signup',
        'client_ip' => CLIENT_IP,
        'expected_request_binding' => 'tx-1234',
        'expected_issuer' => 'prod',
        'expected_policy_version' => 2,
        'secrets_by_kid' => ['2' => SECRET],
    ],
];

// 3. sha_decoy_v3: the decoy surface armed under a pinned field name.
$config = new Config(
    secretKey: SECRET,
    algorithm: PoWAlgorithm::Sha256,
    targetBits: 8,
    minDurationMs: 0,
    bindingMode: BindingMode::None,
);
$storage = new ArrayStorage();
$issuer = new Issuer($config, $storage);
$challenge = $issuer->issueWithDecoyField('comment', '', true, null, null, 'decoy_field_a1b2c3d4e5f60718');
$record = $storage->find($challenge->nonce);
$counter = solveSha($record->prefix, $record->salt, $record->targetBits);
$records[] = [
    'name' => 'sha_decoy_v3',
    'record' => $record->toArray(),
    'token_b64' => tokenFor($record, $counter, 1500, ['v' => 1]),
    'expected' => ['ok' => true, 'decoyField' => 'decoy_field_a1b2c3d4e5f60718'],
    'verify_opts' => ['expected_scope' => 'comment'],
];

// 4. sha_execution_v4: the execution dimension armed. The Ruby and
//    Elixir SDKs carry no browser-trace walker, so the armed dimension
//    fails closed with execution_mismatch (the documented deviation).
$config = new Config(
    secretKey: SECRET,
    algorithm: PoWAlgorithm::Sha256,
    targetBits: 8,
    minDurationMs: 0,
    executionKey: str_repeat('execution-key-', 3),
    bindingMode: BindingMode::None,
);
$storage = new ArrayStorage();
$issuer = new Issuer($config, $storage);
$challenge = $issuer->issueWithExecutionField('checkout', '', true, null, null, 'submit', 1);
$record = $storage->find($challenge->nonce);
$counter = solveSha($record->prefix, $record->salt, $record->targetBits);
$records[] = [
    'name' => 'sha_execution_v4',
    'record' => $record->toArray(),
    'token_b64' => tokenFor($record, $counter, 1500, ['v' => 1]),
    'expected' => ['ok' => false, 'code' => 'execution_mismatch'],
    'verify_opts' => ['expected_scope' => 'checkout'],
];

// 5. argon2id: within the ceilings, authentic and unsupported by the
//    SDK runtimes (no native Argon2id), so the pinned verdict is the
//    cores' unsupported mapping.
$config = new Config(
    secretKey: SECRET,
    algorithm: PoWAlgorithm::Argon2id,
    mKib: 64,
    t: 3,
    targetBits: 4,
    argon2TargetBits: 4,
    minDurationMs: 0,
    bindingMode: BindingMode::None,
);
$record = mint($config);
$records[] = [
    'name' => 'argon2id',
    'record' => $record->toArray(),
    'token_b64' => tokenFor($record, 21, 1500, ['v' => 1]),
    'expected' => ['ok' => false, 'code' => 'unsupported_argon2_params'],
    'verify_opts' => ['expected_scope' => 'login'],
];

// 6. rsw: the identity-armed v5 record under the shared committed
//    trapdoor (validated here by the PHP Rsw gate before issuance).
$config = new Config(
    secretKey: SECRET,
    algorithm: PoWAlgorithm::Rsw,
    targetBits: 1,
    rswModulusN: RSW_MODULUS,
    rswLambda: RSW_LAMBDA,
    rswT: 10_000,
    minDurationMs: 0,
    bindingMode: BindingMode::None,
);
$record = mint($config);
$trapdoor = new Rsw(RSW_MODULUS, RSW_LAMBDA);
$proof = $trapdoor->expectedProofHex($record->prefix, $record->nonce, $record->t);
$records[] = [
    'name' => 'rsw',
    'record' => $record->toArray(),
    'token_b64' => tokenFor($record, 0, 1500, ['v' => 1], $proof),
    'expected' => ['ok' => true],
    'verify_opts' => [
        'expected_scope' => 'login',
        'rsw' => ['modulus_n' => RSW_MODULUS, 'lambda' => RSW_LAMBDA],
    ],
];

// 7. tampered_signature: the authentic sha_plain challenge with one
//    flipped signature nibble, re-prefix and re-recorded PHP-side.
$config = new Config(
    secretKey: SECRET,
    algorithm: PoWAlgorithm::Sha256,
    targetBits: 8,
    minDurationMs: 500,
    bindingMode: BindingMode::None,
);
$record = mint($config, 'eu');
$pos = strpos($record->challenge, '.s') !== false ? strrpos($record->challenge, '.') + 1 : strrpos($record->challenge, '.') + 1;
$sig = substr($record->challenge, $pos);
$flip = $sig[0] === 'a' ? 'b' : 'a';
$tampered = substr($record->challenge, 0, $pos) . $flip . substr($sig, 1);
$array = $record->toArray();
$array['challenge'] = $tampered;
$array['prefix'] = $tampered . '|' . $record->salt . '|';
$records[] = [
    'name' => 'tampered_signature',
    'record' => $array,
    'token_b64' => tokenFor($record, $record->minDurationMs >= 0 ? solveSha($tampered . '|' . $record->salt . '|', $record->salt, $record->targetBits) : 0, 1500, ['v' => 1]),
    'expected' => ['ok' => false, 'code' => 'bad_signature'],
    'verify_opts' => [],
];

$out = [
    '$schema' => 'kiwicaptcha.golden-server-sdk-vectors/1',
    'format_version' => 1,
    'provenance' => [
        'issuer' => 'kiwicaptcha-php Issuer (the canonical PHP core), run live',
        'generator' => 'tools/generate_golden_vectors.php in this package, php 8.5.10, kiwicaptcha-php src at this repository commit',
        'secret' => SECRET,
        'notes' => [
            'Every record is minted by the real PHP Issuer with its sealed record-metadata MAC.',
            'The rsw trapdoor pair is the shared committed fixture; the PHP Rsw gate validates it before issuance.',
            'sha_execution_v4 pins the Ruby and Elixir fail-closed mapping: no browser-trace walker, so the armed dimension answers execution_mismatch.',
            'argon2id pins the unsupported_argon2_params mapping: no native Argon2id in the Ruby and Elixir runtimes.',
        ],
    ],
    'hkdf' => [
        'secret' => SECRET,
        'challenge_hex' => bin2hex(hash_hkdf('sha256', SECRET, 32, 'kiwi/v2/challenge-sign', 'kiwicaptcha/deploy-salt/v1')),
        'ip_bind_hex' => bin2hex(hash_hkdf('sha256', SECRET, 32, 'kiwi/v2/ip-bind', 'kiwicaptcha/deploy-salt/v1')),
        'result_hex' => bin2hex(hash_hkdf('sha256', SECRET, 32, 'kiwi/v2/result-token', 'kiwicaptcha/deploy-salt/v1')),
        'server_state_hex' => bin2hex(hash_hkdf('sha256', SECRET, 32, 'kiwi/v2/server-state', 'kiwicaptcha/deploy-salt/v1')),
    ],
    // The canonical payload spellings and the server-state MAC inputs,
    // pinned byte-exact against the cross-SDK fixture the Node suite
    // carries (same secret, same fixed field values).
    'canonical' => [
        'base' => 'v4|2|bm9uY2UtcmV2aXNpb24tMy10ZXN0LXZlY3Rvcg==|login|tag456|111|222|sha256|0|1|1|8|c2FsdC1yZXZpc2lvbi0z|5|eu|2|bind-1|prod|3',
        'signature_hex' => hash_hmac('sha256', 'v4|2|bm9uY2UtcmV2aXNpb24tMy10ZXN0LXZlY3Rvcg==|login|tag456|111|222|sha256|0|1|1|8|c2FsdC1yZXZpc2lvbi0z|5|eu|2|bind-1|prod|3', hash_hkdf('sha256', SECRET, 32, 'kiwi/v2/challenge-sign', 'kiwicaptcha/deploy-salt/v1')),
        'v3_decoy' => 'v4|3|bm9uY2UtcmV2aXNpb24tMy10ZXN0LXZlY3Rvcg==|login|tag456|111|222|sha256|0|1|1|8|c2FsdC1yZXZpc2lvbi0z|5||1|||1|d=billing_address_line_a3f9c21d8e5b7401',
        'v4_execution' => 'v4|4|bm9uY2UtcmV2aXNpb24tMy10ZXN0LXZlY3Rvcg==|login|tag456|111|222|sha256|0|1|1|8|c2FsdC1yZXZpc2lvbi0z|5||1|||1|e=1,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'v5_identity' => 'v4|5|bm9uY2UtcmV2aXNpb24tMy10ZXN0LXZlY3Rvcg==|login|tag456|111|222|sha256|0|1|1|8|c2FsdC1yZXZpc2lvbi0z|5||1|||1|r=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    ],
    'server_state_mac' => [
        'key_hex' => bin2hex(hash_hkdf('sha256', SECRET, 32, 'kiwi/v2/server-state', 'kiwicaptcha/deploy-salt/v1')),
        "record_meta_input" => "kiwi/record-meta/v1\n12:bm9uY2Uuc2ln\n1700000000123456\n1:12:example.test",
        "record_meta_hex" => hash_hmac("sha256", "kiwi/record-meta/v1\n12:bm9uY2Uuc2ln\n1700000000123456\n1:12:example.test", hash_hkdf("sha256", SECRET, 32, "kiwi/v2/server-state", "kiwicaptcha/deploy-salt/v1")),
        "consumed_result_input" => "kiwi/consumed-result/v1\n12:bm9uY2Uuc2ln\n1\n1:6:bind-9\n1:4:op-7",
        "consumed_result_hex" => hash_hmac("sha256", "kiwi/consumed-result/v1\n12:bm9uY2Uuc2ln\n1\n1:6:bind-9\n1:4:op-7", hash_hkdf("sha256", SECRET, 32, "kiwi/v2/server-state", "kiwicaptcha/deploy-salt/v1")),
    ],
    'records' => $records,
];

echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
