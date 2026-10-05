<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The fail-closed default of the success-trust gate: the risk store
 * exposes no readable windowed failure ratio or spread state today, so
 * the gate cannot prove that the identity is below the failure
 * threshold. Unproven means no session or source credit, never silent
 * credit: a credential stuffer with valid stolen credentials must not
 * farm source trust through the bridge while the evidence is
 * unreadable. The principal credit is unconditional and unaffected.
 *
 * This is the documented extension point: when the store grows a public
 * ratio/spread accessor, a data-backed gate replaces this binding (see
 * {@see OutcomeTrustGateInterface}) and the bridge needs no change.
 */
final class FailClosedOutcomeTrustGate implements OutcomeTrustGateInterface
{
    public function allowsSessionSourceCredit(string $principalPseudonym, ?string $targetPseudonym): bool
    {
        return false;
    }
}
