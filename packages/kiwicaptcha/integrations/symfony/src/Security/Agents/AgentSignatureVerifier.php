<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Agents;

use Symfony\Component\HttpFoundation\Request;

/**
 * The RFC 9421 Ed25519 verifier of the verified-agents plane.
 *
 * The signature base is built exactly per RFC 9421 §2.3: one line
 * per covered component, each line the quoted component identifier,
 * one space, the component value, one line feed. The final line is
 * the quoted @signature-params identifier, one space and the
 * serialized signature parameters (the inner list of the
 * Signature-Input value, re-serialized canonically). Derived
 * components follow §2.2: @method is the request method and
 * @target-uri is the absolute request target. Header field values
 * follow §2.1: obs-folded whitespace is never accepted here because
 * each of the covered headers must arrive as exactly one field
 * line, trimmed of surrounding whitespace.
 *
 * The covered set is fixed: @method, @target-uri and the RFC 9530
 * content-digest always; content-length additionally whenever a
 * request body is present. Anything else in the covered list is
 * refused (this verifier cannot derive it, so it must not pretend
 * to), and a body-bearing request without a covered, matching
 * content-digest is refused — the header-strip defense.
 *
 * The signature parameters are enforced, not advisory. The alg must
 * be exactly "ed25519" (any other value, including a lookalike,
 * fails closed — the alg-confusion defense). The tag must be this
 * plane's fixed tag, created must sit inside the ±skew window,
 * expires must be honored. The nonce is single-use through the
 * Redis ledger, claimed only after the signature itself verified.
 * Key ids resolve to configured agents with rotation-capable key
 * sets: every configured public key of the agent is tried, so a
 * rotation window verifies under either key.
 *
 * Failure mapping: every refusal carries a typed code and an HTTP
 * status (401 for everything here); no path can surface a raw
 * exception to the caller, and no unverifiable input can verify.
 */
final class AgentSignatureVerifier
{
    /** The default created-parameters skew window, ± seconds. */
    public const DEFAULT_CLOCK_SKEW_SECS = 300;

    /** The required signature tag: signatures of any other plane do not verify here. */
    public const REQUIRED_TAG = 'kiwi-agents-v1';

    /** The only accepted alg parameter value. */
    public const REQUIRED_ALG = 'ed25519';

    public const CODE_MALFORMED = 'AGENT_SIGNATURE_MALFORMED';
    public const CODE_UNKNOWN_KEY = 'AGENT_UNKNOWN_KEY';
    public const CODE_ALG_REJECTED = 'AGENT_ALG_REJECTED';
    public const CODE_COVERAGE_INVALID = 'AGENT_COVERAGE_INVALID';
    public const CODE_SKEW = 'AGENT_SIGNATURE_SKEW';
    public const CODE_EXPIRED = 'AGENT_SIGNATURE_EXPIRED';
    public const CODE_INVALID = 'AGENT_SIGNATURE_INVALID';
    public const CODE_REPLAYED = 'AGENT_SIGNATURE_REPLAYED';
    public const CODE_NONCE_UNAVAILABLE = 'AGENT_NONCE_UNAVAILABLE';

    private const METHOD = '@method';
    private const TARGET_URI = '@target-uri';
    private const CONTENT_DIGEST = 'content-digest';
    private const CONTENT_LENGTH = 'content-length';

    /**
     * The RFC 9530 digest algorithms this verifier computes. The
     * strongest present in the header wins nothing extra: the
     * request verifies when any one provided algorithm matches the
     * recomputed digest of the exact body bytes.
     */
    private const DIGEST_ALGORITHMS = ['sha-256' => 'sha256', 'sha-512' => 'sha512'];

    /**
     * @param int              $clockSkewSecs the ± window the created
     *                                        parameter must sit inside
     * @param \Closure|null    $now           the epoch-seconds clock
     *                                        override for tests
     */
    public function __construct(
        private readonly AgentRegistry $agents,
        private readonly AgentNonceStore $nonceStore,
        private readonly int $clockSkewSecs = self::DEFAULT_CLOCK_SKEW_SECS,
        private readonly ?\Closure $now = null,
    ) {
    }

    /**
     * Verifies one request's Signature-Input / Signature pair
     * against the configured agents and consumes its nonce.
     */
    public function verify(Request $request, string $rawBody): AgentGateResult
    {
        foreach (['signature-input', 'signature', self::CONTENT_DIGEST] as $singularHeader) {
            if (\count($request->headers->all($singularHeader)) > 1) {
                return $this->refused(self::CODE_MALFORMED, sprintf('The %s header must appear at most once.', $singularHeader));
            }
        }
        $signatureInputRaw = $request->headers->get('Signature-Input');
        $signatureRaw = $request->headers->get('Signature');
        if (!\is_string($signatureInputRaw) || !\is_string($signatureRaw)) {
            return $this->refused(self::CODE_MALFORMED, 'The request must carry one Signature-Input and one Signature header.');
        }

        $parser = new StructuredFieldsSubsetParser();
        try {
            $input = $parser->parseSignatureInput($signatureInputRaw);
            [$signatureLabel, $signatureBytes] = $parser->parseSignature($signatureRaw);
        } catch (\InvalidArgumentException $e) {
            return $this->refused(self::CODE_MALFORMED, 'The signature headers are malformed: '.$e->getMessage());
        }
        if ($signatureLabel !== $input->label) {
            return $this->refused(self::CODE_MALFORMED, 'The Signature label must match the Signature-Input label.');
        }

        $alg = $input->parameter('alg');
        if (!\is_string($alg) || $alg !== self::REQUIRED_ALG) {
            return $this->refused(self::CODE_ALG_REJECTED, 'The signature alg parameter must name ed25519.');
        }
        $tag = $input->parameter('tag');
        if (!\is_string($tag) || $tag !== self::REQUIRED_TAG) {
            return $this->refused(self::CODE_MALFORMED, 'The signature tag parameter must name '.self::REQUIRED_TAG.'.');
        }

        $keyId = $input->parameter('keyid');
        if (!\is_string($keyId) || $keyId === '') {
            return $this->refused(self::CODE_MALFORMED, 'The signature parameters must carry a keyid.');
        }
        $agent = $this->agents->agentByKeyId($keyId);
        if ($agent === null) {
            return $this->refused(self::CODE_UNKNOWN_KEY, 'The presented key id is not configured.');
        }

        $nonce = $input->parameter('nonce');
        if (!\is_string($nonce) || preg_match(AgentNonceStore::NONCE_PATTERN, $nonce) !== 1) {
            return $this->refused(self::CODE_MALFORMED, 'The signature nonce parameter is required, 1-128 characters of [A-Za-z0-9._~+=-].');
        }
        $created = $input->parameter('created');
        $expires = $input->parameter('expires');
        if (!\is_int($created) || !\is_int($expires)) {
            return $this->refused(self::CODE_MALFORMED, 'The signature parameters must carry integer created and expires values.');
        }

        $now = (int) ($this->now !== null ? ($this->now)() : time());
        if (\abs($now - $created) > $this->clockSkewSecs) {
            return $this->refused(self::CODE_SKEW, sprintf('The signature created parameter is outside the ±%d second window.', $this->clockSkewSecs));
        }
        if ($expires <= $now || $expires < $created) {
            return $this->refused(self::CODE_EXPIRED, 'The signature has expired.');
        }

        $bodyPresent = $rawBody !== '';
        $coverage = $this->coverage($input->covered, $bodyPresent);
        if ($coverage !== null) {
            return $this->refused(self::CODE_COVERAGE_INVALID, $coverage);
        }

        // The covered content-length is an integrity commitment, not
        // a passthrough: the declared length must equal the actual
        // body length, so a body-swapping proxy that leaves the
        // signed framing intact while replacing the bytes (the
        // digest catches that too) or replays the framing around a
        // different length is refused here.
        if (\in_array(self::CONTENT_LENGTH, $input->covered, true)) {
            $declaredLength = $request->headers->get(self::CONTENT_LENGTH);
            if (!\is_string($declaredLength) || ctype_digit($declaredLength) !== true || (int) $declaredLength !== \strlen($rawBody)) {
                return $this->refused(self::CODE_INVALID, 'The covered content-length does not match the request body.');
            }
        }

        $digestHeader = $request->headers->get(self::CONTENT_DIGEST);
        if ($digestHeader !== null && !$this->contentDigestMatches($digestHeader, $rawBody)) {
            return $this->refused(self::CODE_INVALID, 'The content-digest does not match the request body.');
        }

        $base = $this->signatureBase($request, $input, $rawBody);
        if (!$this->signatureVerifies($signatureBytes, $base, $agent)) {
            return $this->refused(self::CODE_INVALID, 'The signature does not verify.');
        }

        try {
            if (!$this->nonceStore->claim($agent->keyId, $nonce)) {
                return $this->refused(self::CODE_REPLAYED, 'The signature nonce was already used.');
            }
        } catch (\Throwable) {
            return $this->refused(
                self::CODE_NONCE_UNAVAILABLE,
                'The nonce ledger is unavailable; the signature cannot be confirmed single-use.',
            );
        }

        return AgentGateResult::verified(new VerifiedAgentRequest($agent, $input->label));
    }

    /**
     * The signature base per RFC 9421 §2.3: one line per covered
     * component in the Signature-Input order, then the
     * @signature-params line carrying the serialized parameters.
     * Component identifiers serialize in the exact case they were
     * covered with (the covered set was already validated to the
     * fixed lowercase identifiers).
     */
    public function signatureBase(Request $request, SignatureInputParameters $input, string $rawBody): string
    {
        $lines = [];
        foreach ($input->covered as $component) {
            $lines[] = sprintf('"%s" %s', $component, $this->componentValue($request, $component, $rawBody));
        }
        $lines[] = sprintf('"@signature-params" %s', $input->serializedInnerList());

        return implode("\n", $lines)."\n";
    }

    /**
     * One covered component's value: the derived @method and
     * @target-uri per RFC 9421 §2.2, the covered header field values
     * trimmed per §2.1 (each covered header arrived as exactly one
     * field line, enforced by the singularity check).
     */
    private function componentValue(Request $request, string $component, string $rawBody): string
    {
        return match ($component) {
            self::METHOD => $request->getMethod(),
            self::TARGET_URI => $request->getScheme().'://'.$request->getHttpHost().$request->getRequestUri(),
            self::CONTENT_DIGEST => trim((string) $request->headers->get(self::CONTENT_DIGEST, '')),
            self::CONTENT_LENGTH => trim((string) $request->headers->get(self::CONTENT_LENGTH, (string) \strlen($rawBody))),
            default => throw new \LogicException(sprintf('The covered component "%s" was not validated', $component)),
        };
    }

    /**
     * Validates the covered-component list against the fixed set:
     * @method, @target-uri and content-digest are always required;
     * content-length is required exactly when a body is present;
     * unknown components, derived-component parameters and
     * duplicates are refused. Returns the refusal message or null
     * when the coverage is valid.
     *
     * @param list<string> $covered
     */
    private function coverage(array $covered, bool $bodyPresent): ?string
    {
        if (\count($covered) !== \count(array_unique($covered))) {
            return 'The covered component list must not repeat a component.';
        }
        foreach ($covered as $component) {
            if (!\in_array($component, [self::METHOD, self::TARGET_URI, self::CONTENT_DIGEST, self::CONTENT_LENGTH], true)) {
                return sprintf('The covered component "%s" is not part of the verified-agents signing profile.', $component);
            }
        }
        foreach ([self::METHOD, self::TARGET_URI, self::CONTENT_DIGEST] as $required) {
            if (!\in_array($required, $covered, true)) {
                return sprintf('The signature must cover "%s".', $required);
            }
        }
        if ($bodyPresent && !\in_array(self::CONTENT_LENGTH, $covered, true)) {
            return 'The signature must cover "content-length" when a request body is present.';
        }

        return null;
    }

    /**
     * The RFC 9530 content-digest check: the header is a dictionary
     * of algorithm=:base64-digest: entries; the request passes when
     * at least one entry matches the digest of the exact raw body
     * bytes under this verifier's implemented algorithms. The
     * comparison is constant-time over the raw digest bytes.
     */
    private function contentDigestMatches(string $header, string $rawBody): bool
    {
        foreach (explode(',', $header) as $entry) {
            $entry = trim($entry);
            if ($entry === '' || preg_match('/^([a-z0-9-]+)=:([A-Za-z0-9+\/]*={0,2}):$/D', $entry, $m) !== 1) {
                return false;
            }
            $algorithm = self::DIGEST_ALGORITHMS[$m[1]] ?? null;
            if ($algorithm === null) {
                continue;
            }
            $provided = base64_decode($m[2], true);
            if ($provided !== false && hash_equals(hash($algorithm, $rawBody, true), $provided)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The detached Ed25519 verification against every configured
     * public key of the agent (the rotation window): any one match
     * verifies.
     */
    private function signatureVerifies(string $signatureBytes, string $base, AgentDefinition $agent): bool
    {
        foreach ($agent->publicKeys as $publicKey) {
            if (sodium_crypto_sign_verify_detached($signatureBytes, $base, $publicKey)) {
                return true;
            }
        }

        return false;
    }

    private function refused(string $code, string $message): AgentGateResult
    {
        return AgentGateResult::refused(401, $code, $message);
    }
}
