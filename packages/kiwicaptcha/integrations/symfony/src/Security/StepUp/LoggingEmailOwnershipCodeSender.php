<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Psr\Log\LoggerInterface;

/**
 * The default delivery seam: logs the delivery instead of mailing, so
 * a deployment without a bound mailer keeps the factor observable and
 * testable. Replace the service binding for real delivery; the code is
 * the only secret and the address the only personal data on the call.
 */
final class LoggingEmailOwnershipCodeSender implements EmailOwnershipCodeSenderInterface
{
    public function __construct(private readonly ?LoggerInterface $logger = null)
    {
    }

    public function send(string $email, string $code, int $ttlSecs): void
    {
        $this->logger?->info('kiwi email-ownership step-up code generated', [
            'recipient' => $email,
            'expires_in' => $ttlSecs,
        ]);
    }
}
