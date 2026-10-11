<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use BelConsulting\KiwiCaptchaBundle\EventSubscriber\FirstAttemptLoginGuard;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\Storage\PrincipalNetworkTagStoreInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * The step-up session restore: after a factor completes, a pending
 * token is unwrapped back into the real authenticated token and the
 * network bucket is recorded so the next login from the same network
 * is no longer novel. Without the restore a legitimate user on a novel
 * network would stay pending forever and be stepped up on every login.
 */
final class SessionRestorer
{
    /** The restore-failure counter the metrics exporter carries. */
    public const RESTORE_FAILURES_METRIC = 'kiwi_step_up_restore_failures_total';

    public function __construct(
        private readonly RiskIdentityFactory $identityFactory,
        private readonly ?TokenStorageInterface $tokenStorage = null,
        private readonly ?PrincipalNetworkTagStoreInterface $principalNetworks = null,
        private readonly ?ClientIpResolver $clientIpResolver = null,
        private readonly ?RequestStack $requestStack = null,
        private readonly ?LoggerInterface $logger = null,
        private readonly ?AsnDataset $asnDataset = null,
        private readonly ?\BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie $continuity = null,
        private readonly ?\BelConsulting\KiwiCaptchaBundle\Risk\TrustedDeviceCookie $device = null,
        private readonly ?\KiwiCaptcha\Risk\Metrics\RiskMetrics $metrics = null,
    ) {
    }

    /**
     * Restore the wrapped token and record the network bucket. No-op
     * when the current token is not pending (a plain step-up inside an
     * already-authenticated session) or when a seam is missing.
     *
     * $demandId is the exact demand the completed factor finalizes. A
     * pending token unwraps only when its own demand identity equals
     * it. Two pending logins of one session hold two demands, so the
     * completion of one can never restore the other, however equal the
     * principal, the scope or the session look. The gate sits before
     * every effect of the restore (the unwrap, the session rotation,
     * the trust bindings and the device mint); a refused restore
     * writes nothing and changes nothing.
     */
    public function restore(string $principalPseudonym, ?Request $request = null, ?string $demandId = null): void
    {
        try {
            $token = $this->tokenStorage?->getToken();
            if ($token instanceof StepUpPendingToken) {
                // The pending token's principal must be the one that
                // completed the step-up: a stolen ticket for another
                // account can never upgrade this session.
                // The token carries the raw user identifier; the
                // challenge carries the 32-hex principal pseudonym.
                // Compare like with like or every restore fails.
                // An empty pseudonym on either side is a refusal, not
                // a pass-through: an unresolvable challenge principal
                // or an unresolvable pending identifier cannot be
                // proven equal, and unwrapping anyway would hand the
                // session to whoever the challenge could not name.
                $pendingRaw = $token->getUserIdentifier();
                $pendingPrincipal = $this->identityFactory->principalId($pendingRaw);
                if ($principalPseudonym === '' || $pendingPrincipal === '') {
                    $this->metrics?->increment(self::RESTORE_FAILURES_METRIC);
                    $this->logger?->warning('kiwi step-up session restore refused: empty pseudonym');

                    return;
                }
                if (!hash_equals($pendingPrincipal, $principalPseudonym)) {
                    $this->metrics?->increment(self::RESTORE_FAILURES_METRIC);
                    $this->logger?->warning('kiwi step-up session restore refused: principal mismatch');

                    return;
                }
                // The exact-demand gate: the completed challenge names
                // the demand it finalizes and the pending token carries
                // the demand it was wrapped under. Only their equality
                // opens the session; an unstamped token, an unnamed
                // demand and any mismatch all refuse, fail closed.
                $pendingDemand = $token->demandId();
                if ($pendingDemand === null || $demandId === null || !hash_equals($pendingDemand, $demandId)) {
                    $this->metrics?->increment(self::RESTORE_FAILURES_METRIC);
                    $this->logger?->warning('kiwi step-up session restore refused: demand mismatch');

                    return;
                }
                $this->tokenStorage?->setToken($token->getWrapped());
            }
            $request ??= $this->requestStack?->getCurrentRequest();
            // Rotate the session id on the privilege upgrade so a
            // fixation captured before the step-up cannot ride the new
            // session. Runs after the request-stack fallback so a caller
            // that omitted the request still gets the rotation.
            if ($token instanceof StepUpPendingToken && $request !== null && $request->hasSession()) {
                $session = $request->getSession();
                if ($session->isStarted()) {
                    $session->migrate(true);
                }
            }
            if ($request === null || $this->principalNetworks === null || $principalPseudonym === '') {
                return;
            }
            $ip = $this->clientIpResolver !== null
                ? $this->clientIpResolver->resolve($request)
                : (string) ($request->getClientIp() ?? '');
            if ($ip === '') {
                return;
            }
            // Session and device bindings first, each in its own try:
            // the identity-bound tags are the stronger continuity
            // signal, so a failed network-tag write must never mask
            // them (nor they mask the network records that follow).
            if ($this->continuity !== null) {
                try {
                    $sessionValue = $this->continuity->read($request);
                    if ($sessionValue !== null) {
                        $sessionPseudonym = $this->identityFactory->sessionId($sessionValue);
                        $this->principalNetworks->recordPrincipalNetworkTag($principalPseudonym, 'session:'.$sessionPseudonym, trusted: true);
                    }
                } catch (\Throwable $e) {
                    $this->logger?->warning('kiwi step-up session restore: session binding failed: {message}', [
                        'message' => $e->getMessage(),
                    ]);
                }
            }
            if ($this->device !== null) {
                try {
                    // The trusted-device binding mints the cookie when
                    // the browser presented none: the completed step-up
                    // is the trust event, so the value is bound under
                    // the principal (trusted) and staged for the
                    // response subscriber to issue. The next login then
                    // carries a binding identity even after the
                    // continuity cookie expired. The pseudonym derives
                    // under the device context, never the session one.
                    $deviceValue = $this->device->read($request) ?? $this->device->mint();
                    $devicePseudonym = $this->identityFactory->deviceId($deviceValue);
                    $this->principalNetworks->recordPrincipalNetworkTag($principalPseudonym, 'device:'.$devicePseudonym, trusted: true);
                    $request->attributes->set(FirstAttemptLoginGuard::DEVICE_MINT_ATTRIBUTE, $deviceValue);
                } catch (\Throwable $e) {
                    $this->logger?->warning('kiwi step-up session restore: device binding failed: {message}', [
                        'message' => $e->getMessage(),
                    ]);
                }
            }
            try {
                $network = self::networkBucket($ip);
                if ($network !== '') {
                    // The completed factor is the trust event: the
                    // restore binds the network with the trust flag
                    // minted, exactly like the engine's post-Allow
                    // learn history, so the next login from this
                    // network rides the established history.
                    $this->principalNetworks->recordPrincipalNetworkTag($principalPseudonym, $network, trusted: true);
                }
            } catch (\Throwable $e) {
                $this->logger?->warning('kiwi step-up session restore: network record failed: {message}', [
                    'message' => $e->getMessage(),
                ]);
            }
            try {
                $asn = $this->asnBucket($ip);
                if ($asn !== '') {
                    $this->principalNetworks->recordPrincipalNetworkTag($principalPseudonym, 'asn:'.$asn, trusted: true);
                }
            } catch (\Throwable $e) {
                $this->logger?->warning('kiwi step-up session restore: asn record failed: {message}', [
                    'message' => $e->getMessage(),
                ]);
            }
        } catch (\Throwable $e) {
            $this->logger?->warning('kiwi step-up session restore failed: {message}', [
                'message' => $e->getMessage(),
            ]);
        }
    }

    /** The same network bucket spelling as the engine. */
    private static function networkBucket(string $ip): string
    {
        $packed = inet_pton($ip);
        if ($packed === false) {
            return '';
        }
        if (\strlen($packed) === 4) {
            return bin2hex("\x04".$packed);
        }

        return bin2hex("\x06".substr($packed, 0, 8));
    }

    /**
     * The ASN tag spelling of the engine's novel-network gate
     * ({@see \KiwiCaptcha\Risk\AdaptiveRiskEngine}): the ASN number when
     * the dataset resolved one, else the bucket id. The restorer must
     * record exactly the key the engine later looks up — compare like
     * with like, or the second login stays novel forever.
     */
    private function asnBucket(string $ip): string
    {
        if ($this->asnDataset === null) {
            return '';
        }
        try {
            $info = $this->asnDataset->lookup($ip);

            return (string) ($info->asn ?? $info->bucket);
        } catch (\Throwable) {
            return '';
        }
    }
}
