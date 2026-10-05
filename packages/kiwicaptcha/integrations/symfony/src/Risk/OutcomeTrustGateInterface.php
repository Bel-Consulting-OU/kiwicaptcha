<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The success-trust rule of the outcomes plane: an authenticationSuccess
 * always credits the principal. It credits the session and the source
 * only when the identity's windowed failure ratio is below the
 * deployment threshold and the target was not under spread attack.
 *
 * The authoritative home of the rule is the core's apply-feedback path
 * (the Rust and PHP engines); this interface is the bridge-level gate
 * that decides which identity material a bridge report carries at all.
 * The risk store exposes no public accessor for the windowed failure
 * ratio today, so the default binding is the fail-closed
 * {@see FailClosedOutcomeTrustGate}: without readable evidence the
 * session rides no report, and the principal credit (unconditional per
 * the rule) is untouched. When the store grows a ratio accessor, a
 * data-backed implementation replaces the default binding here and
 * nothing else changes.
 */
interface OutcomeTrustGateInterface
{
    /**
     * True when this authentication success may also credit the session
     * and the source dimension of the identity.
     *
     * @param string $principalPseudonym the 128-bit principal pseudonym
     *                                   the report addresses
     * @param string|null $targetPseudonym the target pseudonym of the
     *                                     same flow when one was
     *                                     derived, null otherwise
     */
    public function allowsSessionSourceCredit(string $principalPseudonym, ?string $targetPseudonym): bool;
}
