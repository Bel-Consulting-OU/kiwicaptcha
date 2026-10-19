<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * Raised when an Rsw risk action reaches the challenge-profile mapping
 * of a deployment that configured no rsw trapdoor. The correct handling
 * is the interactive step-up: {@see RiskProfileResolver::effectiveAction()}
 * resolves Rsw to StepUp before any profile is selected. This typed
 * error marks the direct-mapping path that bypassed that resolution, so
 * the rung can never silently collapse onto a weaker challenge.
 */
final class RswTrapdoorUnavailable extends \LogicException
{
}
