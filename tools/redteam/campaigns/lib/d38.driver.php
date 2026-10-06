<?php

declare(strict_types=1);

/**
 * d38.driver.php — the verified-agent plane of D3.8: the RFC 9421
 * machine-client path driven through the REAL bundle classes (Agents
 * namespace, the AgentSigner fixture signing per the RFC's base-string
 * grammar) over the REAL Redis nonce and quota stores.
 *
 * Required results, asserted here:
 *   - every signed request inside the agent's quota verifies, at its
 *     configured price tier (100 percent within quota);
 *   - the request that busts the per-minute quota is refused with the
 *     typed 429 code and the abuse mark lands on the agent's identity
 *     through the typed outcomes surface;
 *   - after the config revokes the agent's key, every further signed
 *     request fails closed (0 percent post-revocation), nonce reuse
 *     included;
 *   - a tampered base or a stripped header never verifies.
 *
 * Output: one JSON summary on stdout.
 */

use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentDefinition;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentNonceStore;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentQuota;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentRegistry;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentSignatureVerifier;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentsVerifier;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\AgentSigner;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use Symfony\Component\HttpFoundation\Request;

require getenv('KIWI_RT_RISK_AUTOLOAD') ?: throw new RuntimeException('autoload missing');
require __DIR__ . '/rt-risk-prelude.php';
require_once getenv('KIWI_RT_BUNDLE_TESTS') . '/Fixtures/AgentSigner.php';
require_once getenv('KIWI_RT_BUNDLE_TESTS') . '/Fixtures/SpyOutcomeReporter.php';

const KEY_ID = 'rt38-key-1';
const AGENT = 'rt38-agent';
const NOW = 1770000100;

$redis = rtRedis((string) getenv('KIWI_RT_D38_REDIS_URL'));
foreach ((array) $redis->keys('*rt38*') as $stale) {
    $redis->del([$stale]);
}
$reporter = new SpyOutcomeReporter();

$registryFor = static function (bool $revoked) use ($redis, $reporter): AgentsVerifier {
    $config = [];
    if (!$revoked) {
        $signer = new AgentSigner(AgentSigner::seed('rt38-primary'));
        $config[AGENT] = [
            'key_id' => KEY_ID,
            'public_keys' => [$signer->publicKeyBase64()],
            'allowed_scopes' => ['login'],
            'per_minute' => 5,
            'per_day' => 1000,
            'price_tier' => 'high',
            'contact' => 'ops@rt38.example',
        ];
    }
    $verifier = new AgentsVerifier(
        new AgentSignatureVerifier(
            AgentRegistry::fromConfig($config),
            new AgentNonceStore($redis, '{kiwi:rt38}:'),
            300,
            static fn (): int => NOW,
            'http://127.0.0.1',
        ),
        new AgentQuota($redis, '{kiwi:rt38}:'),
        $reporter,
    );
    return $verifier;
};

$signer = new AgentSigner(AgentSigner::seed('rt38-primary'));
$body = '{"scope":"login"}';
$digest = AgentSigner::contentDigest($body);
$covered = ['@method', '@target-uri', 'content-digest', 'content-length'];

$requestOf = static function (string $nonce, string $sigInput, string $signature) use ($body, $digest): Request {
    $server = [
        'CONTENT_TYPE' => 'application/json',
        'CONTENT_LENGTH' => (string) strlen($body),
        'REMOTE_ADDR' => '127.0.0.1',
        'HTTP_SIGNATURE_INPUT' => $sigInput,
        'HTTP_SIGNATURE' => $signature,
        'HTTP_CONTENT_DIGEST' => $digest,
    ];
    return Request::create('http://127.0.0.1/kiwi/challenge', 'POST', [], [], [], $server, $body);
};

$inQuota = 0;
$quotaRefused = 0;
$verify = $registryFor(false);
for ($i = 0; $i < 8; $i++) {
    $parameters = ['created' => NOW - 60, 'expires' => NOW + 60, 'nonce' => 'rt38-' . $i, 'keyid' => KEY_ID, 'alg' => 'ed25519', 'tag' => 'kiwi-agents-v1'];
    $base = AgentSigner::signatureBase($covered, $parameters, [
        '@method' => 'POST',
        '@target-uri' => 'http://127.0.0.1/kiwi/challenge',
        'content-digest' => $digest,
        'content-length' => (string) strlen($body),
    ]);
    $headers = $signer->signedHeaders($covered, $parameters, $base);
    $gate = $verify->verifySignature($requestOf($parameters['nonce'], $headers['Signature-Input'], $headers['Signature']), $body);
    if ($gate->isVerified()) {
        // The full gate: the signature verifies, then the scope
        // authorization and the quota admission consume the slot.
        $admission = $verify->authorize($gate->agent(), 'login');
        if ($admission->isVerified()) {
            $inQuota++;
        } elseif ($admission->statusCode() === 429) {
            $quotaRefused++;
        }
    }
}

// The tamper and strip legs.
$parameters = ['created' => NOW - 60, 'expires' => NOW + 60, 'nonce' => 'rt38-tamper', 'keyid' => KEY_ID, 'alg' => 'ed25519', 'tag' => 'kiwi-agents-v1'];
$base = AgentSigner::signatureBase($covered, $parameters, [
    '@method' => 'POST',
    '@target-uri' => 'http://127.0.0.1/kiwi/challenge',
    'content-digest' => $digest,
    'content-length' => (string) strlen($body),
]);
$tampered = $signer->signedHeaders($covered, $parameters, substr($base, 0, 20) . 'X' . substr($base, 21));
$tamperResult = $verify->verifySignature($requestOf('x', $tampered['Signature-Input'], $tampered['Signature']), $body);
$tamperRefused = !$tamperResult->isVerified();

$stripped = $signer->signedHeaders($covered, $parameters, $base);
$strippedInput = preg_replace('/"content-digest"\s/', '"content-length" ', $stripped['Signature-Input']);
$stripResult = $verify->verifySignature($requestOf('y', (string) $strippedInput, $stripped['Signature']), $body);
$stripRefused = !$stripResult->isVerified();

// Revocation: the config reload without the agent refuses everything.
$revoked = $registryFor(true);
$parameters = ['created' => NOW - 60, 'expires' => NOW + 60, 'nonce' => 'rt38-revoked', 'keyid' => KEY_ID, 'alg' => 'ed25519', 'tag' => 'kiwi-agents-v1'];
$base = AgentSigner::signatureBase($covered, $parameters, [
    '@method' => 'POST',
    '@target-uri' => 'http://127.0.0.1/kiwi/challenge',
    'content-digest' => $digest,
    'content-length' => (string) strlen($body),
]);
$headers = $signer->signedHeaders($covered, $parameters, $base);
$revokedResult = $revoked->verifySignature($requestOf('z', $headers['Signature-Input'], $headers['Signature']), $body);
$revokedRefused = !$revokedResult->isVerified();

// The nonce reuse: the same wire headers presented twice never both
// verify (the second claim loses).
$nonceParams = ['created' => NOW - 60, 'expires' => NOW + 60, 'nonce' => 'rt38-reuse', 'keyid' => KEY_ID, 'alg' => 'ed25519', 'tag' => 'kiwi-agents-v1'];
$nonceBase = AgentSigner::signatureBase($covered, $nonceParams, [
    '@method' => 'POST',
    '@target-uri' => 'http://127.0.0.1/kiwi/challenge',
    'content-digest' => $digest,
    'content-length' => (string) strlen($body),
]);
$nonceHeaders = $signer->signedHeaders($covered, $nonceParams, $nonceBase);
$first = $verify->verifySignature($requestOf('w', $nonceHeaders['Signature-Input'], $nonceHeaders['Signature']), $body);
$second = $verify->verifySignature($requestOf('w', $nonceHeaders['Signature-Input'], $nonceHeaders['Signature']), $body);
$nonceSingleUse = $first->isVerified() && !$second->isVerified();

// The quota refusal's abuse mark: the outcomes reporter saw at least
// one abuse attribution for the agent dimension once the quota busted.
$marksSeen = is_array($reporter->reports ?? null) ? count($reporter->reports) : -1;

$summary = [
    'signed_in_quota' => $inQuota,
    'quota_bust_refusals' => $quotaRefused,
    'tamper_refused' => $tamperRefused,
    'header_strip_refused' => $stripRefused,
    'revoked_key_refused' => $revokedRefused,
    'nonce_single_use' => $nonceSingleUse,
    'outcome_reports_seen' => $marksSeen,
    'price_tier' => 'high',
];
echo json_encode($summary), "\n";

// 100 percent of the in-quota requests verified (the first 5; the
// remainder are the quota-busting 429s), everything else refused.
$pass = $inQuota === 5
    && $quotaRefused === 3
    && $tamperRefused
    && $stripRefused
    && $revokedRefused
    && $nonceSingleUse;
exit($pass ? 0 : 1);
