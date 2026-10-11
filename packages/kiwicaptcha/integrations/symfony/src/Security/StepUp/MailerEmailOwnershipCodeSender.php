<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Psr\Log\LoggerInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

/**
 * The mailer-backed delivery seam of the anonymous email-ownership
 * factor: hands the code to Symfony Messenger-backed mailer transport
 * addressed to the presented address, which is the identity proof the
 * factor exists to verify. The extension auto-wires this adapter when
 * the symfony/mailer component is installed and no explicit sender is
 * bound; a production build refuses the logging default, so this (or
 * an application sender) always serves production.
 *
 * The From identity is build-time configuration (derived from the
 * canonical public origin), never a request value, so no client input
 * reaches a mail header beyond the recipient itself. The delivery log
 * carries the address only as the truncated keyed HMAC of
 * {@see LoggingEmailOwnershipCodeSender::hashForLog()}, never raw.
 */
final class MailerEmailOwnershipCodeSender implements EmailOwnershipCodeSenderInterface
{
    public function __construct(
        private readonly MailerInterface $mailer,
        private readonly string $fromAddress,
        private readonly string $hashKey = '',
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function send(string $email, string $code, int $ttlSecs): void
    {
        $minutes = max(1, (int) ceil($ttlSecs / 60));
        $message = (new Email())
            ->from($this->fromAddress)
            ->to($email)
            ->subject('Your verification code')
            ->text(sprintf(
                "Your verification code is %s. It expires in %d minute(s).\n\nIf you did not request this code, you can ignore this message.",
                $code,
                $minutes,
            ));
        $this->mailer->send($message);
        $this->logger?->info('kiwi email-ownership step-up code delivered', [
            'recipient' => LoggingEmailOwnershipCodeSender::hashForLog($email, $this->hashKey),
            'expires_in' => $ttlSecs,
        ]);
    }
}
