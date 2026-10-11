<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Psr\Log\LoggerInterface;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * The mailer-backed delivery seam of the email one-time-passcode
 * handler. The extension auto-wires this adapter when the
 * symfony/mailer component is installed and no explicit sender is
 * bound. A production build refuses the logging default, so this
 * adapter (or an application sender) always serves production.
 *
 * The handler seam carries pseudonyms only, so the adapter resolves
 * the recipient from the pending login itself: the token storage holds
 * the {@see StepUpPendingToken} during step-up, and the wrapped token
 * behind it carries the authenticated user. The user's identifier
 * serves as the delivery address when it is an email shape. Anything
 * else refuses the delivery fail-closed, and the begin() call then
 * answers the typed delivery failure. An application whose principal
 * identifier is not an address binds its own
 * {@see StepUpCodeSenderInterface} with its own lookup.
 *
 * The From identity is build-time configuration (derived from the
 * canonical public origin), never a request value. The delivery log
 * carries no identifier at all beyond the pseudonyms the context
 * already holds.
 */
final class MailerStepUpCodeSender implements StepUpCodeSenderInterface
{
    public function __construct(
        private readonly MailerInterface $mailer,
        private readonly string $fromAddress,
        private readonly ?TokenStorageInterface $tokenStorage = null,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function send(string $code, StepUpContext $context, int $ttlSecs): void
    {
        $address = $this->recipientAddress();
        if ($address === null) {
            throw new \RuntimeException(sprintf(
                'The mailer step-up sender resolved no email-shaped delivery address for the pending login (scope %s); bind an explicit %s when the principal identifier is not the delivery address',
                $context->scope,
                StepUpCodeSenderInterface::class,
            ));
        }
        $minutes = max(1, (int) ceil($ttlSecs / 60));
        $message = (new Email())
            ->from($this->fromAddress)
            ->to($address)
            ->subject('Your verification code')
            ->text(sprintf(
                "Your verification code is %s. It expires in %d minute(s).\n\nIf you did not request this code, you can ignore this message.",
                $code,
                $minutes,
            ));
        try {
            $this->mailer->send($message);
        } catch (TransportExceptionInterface $e) {
            throw new \RuntimeException('The step-up code mailer transport refused the delivery: '.$e->getMessage(), 0, $e);
        }
        $this->logger?->info('kiwi step-up code delivered', [
            'scope' => $context->scope,
            'principal' => $context->principalPseudonym,
            'expires_in' => $ttlSecs,
        ]);
    }

    /**
     * The email-shaped identifier of the pending login's authenticated
     * user, read through the wrapped token behind a pending one; null
     * when nothing resolvable is authenticated.
     */
    private function recipientAddress(): ?string
    {
        $token = $this->tokenStorage?->getToken();
        $user = match (true) {
            $token instanceof StepUpPendingToken => $token->getWrapped()->getUser(),
            $token !== null && method_exists($token, 'getUser') => $token->getUser(),
            default => null,
        };
        $identifier = null;
        if ($user instanceof UserInterface) {
            $identifier = $user->getUserIdentifier();
        } elseif (\is_string($user) && $user !== '') {
            $identifier = $user;
        } elseif (\is_object($user) && method_exists($user, 'getUserIdentifier')) {
            $identifier = (string) $user->getUserIdentifier();
        }
        if (!\is_string($identifier) || filter_var($identifier, \FILTER_VALIDATE_EMAIL) === false) {
            return null;
        }

        return $identifier;
    }
}
