<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The typed refusal of a demand-bound challenge admission: the demand
 * the challenge names refused it (absent, superseded, not open,
 * expired, already holding a live challenge, or the challenge would
 * outlive it). Nothing was stored, so the begin lane answers a
 * retryable refusal, never a half-created challenge behind a refused
 * admission.
 */
final class StepUpDemandAdmissionRefused extends \RuntimeException
{
}
