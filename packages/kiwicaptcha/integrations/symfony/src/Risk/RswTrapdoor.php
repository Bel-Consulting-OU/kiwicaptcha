<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The rsw time-lock trapdoor of the adaptive risk ladder: the modulus
 * the client squares against and the secret lambda the server verifies
 * through, plus the sequential squaring cost T. The pair is the same
 * material the issuance-side rsw algorithm uses
 * (kiwi_captcha.rsw_modulus_n / rsw_lambda / rsw_t); configuring it
 * arms the adaptive rsw rung (change.md 1.4: RSW is a first-class rung
 * whenever a trapdoor is configured). The lambda never leaves the
 * server configuration and never reaches a record or a client.
 *
 * A deployment without a trapdoor cannot serve the rung: the resolver
 * then maps the Rsw action onto the interactive step-up, never onto a
 * weaker silent challenge. The mapping lives in
 * {@see RiskProfileResolver::effectiveAction()}.
 */
final class RswTrapdoor
{
    public function __construct(
        public readonly string $modulusN,
        public readonly string $lambda,
        public readonly int $t,
    ) {
        if ($modulusN === '' || $lambda === '') {
            throw new \InvalidArgumentException('the rsw trapdoor requires both the modulus and the lambda');
        }
        if ($t < 1) {
            throw new \InvalidArgumentException(sprintf('the rsw sequential cost must be positive, got %d', $t));
        }
    }
}
