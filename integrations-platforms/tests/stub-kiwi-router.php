<?php

declare(strict_types=1);

/**
 * The stub kiwi deployment for the live matrix: a faithful miniature
 * of the verifier sidecar's POST /verify plus the compat surface.
 * JSON body contract: {"token","scope","remoteip"} with an optional
 * bearer. Form body contract (KIWI_VERIFY_MODE=compat): response,
 * secret, remoteip. Tokens: "good" (and only the known scopes)
 * verifies, "stale" fails with timeout-or-duplicate, anything else
 * fails with invalid-input-response. Set STUB_BEARER to require the
 * bearer on the json surface and STUB_SECRET to require the secret
 * on the compat surface; the token "boom" answers 500.
 */

$raw = file_get_contents('php://input');
$contentType = (string) ($_SERVER['CONTENT_TYPE'] ?? '');

if (str_contains($contentType, 'application/json')) {
    $bearer = getenv('STUB_BEARER') ?: '';
    if ($bearer !== '' && ($_SERVER['HTTP_AUTHORIZATION'] ?? '') !== 'Bearer '.$bearer) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo "{\"success\":false,\"error-codes\":[\"bad-bearer\"]}\n";
        exit;
    }
    $parsed = json_decode((string) $raw, true);
    $token = is_array($parsed) ? (string) ($parsed['token'] ?? '') : '';
    $scope = is_array($parsed) ? (string) ($parsed['scope'] ?? '') : '';
    $ok = $token === 'good' && in_array($scope, ['login', 'signup', 'comment', 'form', 'checkout'], true);
} else {
    parse_str((string) $raw, $form);
    $token = (string) ($form['response'] ?? '');
    $secret = (string) ($form['secret'] ?? '');
    $expected = getenv('STUB_SECRET') ?: '';
    if ($expected !== '' && !hash_equals($expected, $secret)) {
        http_response_code(200);
        header('Content-Type: application/json');
        echo "{\"success\":false,\"error-codes\":[\"bad-secret\"]}\n";
        exit;
    }
    $ok = $token === 'good';
}

if ($token === '') {
    http_response_code(200);
    header('Content-Type: application/json');
    echo "{\"success\":false,\"error-codes\":[\"missing-input-response\"]}\n";
    exit;
}
if ($token === 'boom') {
    http_response_code(500);
    exit;
}
header('Content-Type: application/json');
if ($ok) {
    echo json_encode([
        'success' => true,
        'challenge_ts' => gmdate('Y-m-d\TH:i:s\Z'),
        'hostname' => 'gateway.test',
        'error-codes' => [],
    ])."\n";
} elseif ($token === 'stale') {
    echo "{\"success\":false,\"error-codes\":[\"timeout-or-duplicate\"]}\n";
} else {
    echo "{\"success\":false,\"error-codes\":[\"invalid-input-response\"]}\n";
}
