<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipDeliveryMetadata;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipStepUp;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\MailerEmailOwnershipCodeSender;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationDigest;
use BelConsulting\KiwiCaptchaBundle\Tests\CapturingEmailOwnershipSender;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\RawMessage;

/**
 * The demand binding of the challenge wire shape and the delivery
 * identity of the mailer sender. An authorizing challenge names the
 * demand its proof finalizes; a demandless proof authorizes nothing;
 * the records of the earlier wire shape fail closed during the drain.
 * The delivered code carries a server-minted Message-ID whose local
 * part is dot-atom safe: the base64url demand id, a dot, the escalation
 * generation.
 */
final class StepUpDemandBindingTest extends TestCase
{
    private const MASTER = 'kiwi-step-up-master-0123456789abcdef';

    /** The server clock of the test, advanced explicitly. */
    private int $now = 1700000000;

    // ── item 12: the challenge demand binding ───────────────────────

    public function testAnAuthorizingChallengeCarriesItsDemandIdOnTheWire(): void
    {
        $challenge = StepUpChallenge::begin(
            'challengeid000000000001',
            StepUpChallengeKind::EmailOwnership,
            str_repeat('a', 32),
            null,
            'signup',
            null,
            EmailOwnershipStepUp::KIND,
            $this->now,
            600,
            5,
            null,
            null,
            str_repeat('s', 64),
            false,
            false,
            null,
            'demandid0000000000000000001',
        );
        $wire = $challenge->toArray();
        self::assertSame('demandid0000000000000000001', $wire['demand_id']);
        $decoded = StepUpChallenge::fromArray($wire);
        self::assertSame('demandid0000000000000000001', $decoded->demandId);
    }

    public function testAV1RecordFailsClosedDuringTheDrain(): void
    {
        $record = [
            'v' => 1,
            'id' => 'challengeid000000000001',
            'kind' => 'email_otp',
            'principal' => str_repeat('a', 32),
            'target' => null,
            'scope' => 'login',
            'return_path' => null,
            'reason' => 'post_solve_step_up_required',
            'created_at' => $this->now,
            'expires_at' => $this->now + 300,
            'attempts' => 0,
            'max_attempts' => 5,
            'code_hash' => str_repeat('c', 64),
            'ceremony' => null,
            'session_hash' => str_repeat('s', 64),
            'client_secret_hash' => null,
            'bootstrap' => 0,
            'target_owned' => false,
            'subject' => str_repeat('a', 32),
        ];
        $this->expectException(\BelConsulting\KiwiCaptchaBundle\Security\StepUp\MalformedStepUpChallengeException::class);
        StepUpChallenge::fromArray($record);
    }

    public function testAnEnrollmentCreationCarriesNoDemandId(): void
    {
        try {
            StepUpChallenge::begin(
                'creationid000000000001',
                StepUpChallengeKind::WebAuthn,
                str_repeat('a', 32),
                null,
                'login',
                null,
                'post_solve_step_up_required',
                $this->now,
                300,
                5,
                str_repeat('h', 64),
                'creation',
                str_repeat('s', 64),
                false,
                false,
                null,
                'demandid0000000000000000001',
            );
            self::fail('the non-authorizing creation ceremony never binds a demand');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('never binds a demand id', $e->getMessage());
        }
    }

    public function testAMalformedDemandIdRefusesTheRecord(): void
    {
        $challenge = StepUpChallenge::begin(
            'challengeid000000000002',
            StepUpChallengeKind::EmailOwnership,
            str_repeat('a', 32),
            null,
            'signup',
            null,
            EmailOwnershipStepUp::KIND,
            $this->now,
            600,
            5,
            null,
            null,
            null,
        );
        $wire = $challenge->toArray();
        $wire['demand_id'] = 'not a demand id; contains spaces and colon:';
        $this->expectException(\BelConsulting\KiwiCaptchaBundle\Security\StepUp\MalformedStepUpChallengeException::class);
        StepUpChallenge::fromArray($wire);
    }

    public function testTheCompletionRefusesAChallengeOfAnotherDemand(): void
    {
        $store = new ArrayStepUpChallengeStore(fn (): int => $this->now);
        $sender = new CapturingEmailOwnershipSender();
        $factor = new EmailOwnershipStepUp(
            $store,
            new \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket(self::MASTER),
            $sender,
            null,
            null,
            'signup',
            self::MASTER,
            600,
            5,
            100,
            100,
            3600,
            ['signup' => true],
            now: fn (): int => $this->now,
        );
        $digest = StepUpOperationDigest::none('signup');
        $sibling = StepUpDemand::mint(\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(), 'signup', null, null, 'decision-1', $this->now, 600, StepUpOperationBindingKind::None, $digest);
        $store->createRootDemand($sibling, 600);

        $begin = $factor->begin(Request::create('/kiwi/step-up/email/begin', 'POST', [
            'demand' => $sibling->id,
            'email' => 'visitor@example.com',
        ]));
        self::assertSame(200, $begin->getStatusCode(), (string) $begin->getContent());
        $body = json_decode((string) $begin->getContent(), true);
        $code = $sender->lastCode();
        self::assertNotNull($code);

        // Complete against another live demand of the same scope:
        // the proof is bound to the demand it began against, and a
        // crossed demand finalizes nothing.
        $other = StepUpDemand::mint(\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(), 'signup', null, null, 'decision-2', $this->now, 600, StepUpOperationBindingKind::None, StepUpOperationDigest::none('signup:x'));
        $store->createDemand($other, 600);
        $complete = $factor->complete(Request::create('/kiwi/step-up/email/complete', 'POST', [
            'demand' => $other->id,
            'kiwi_step_up_ticket' => $body['challenge'],
            'code' => $code,
        ]));
        self::assertSame(422, $complete->getStatusCode(), 'a crossed demand completes nothing');
        $payload = json_decode((string) $complete->getContent(), true);
        self::assertSame('unknown_challenge', $payload['failure_code']);
    }

    // ── item 13: the delivery identity and its Message-ID ───────────

    public function testTheDeliveryMetadataMintsDotAtomSafeIdentities(): void
    {
        $delivery = new EmailOwnershipDeliveryMetadata('demandid0000000000000000001', 2, 1);
        self::assertSame('demandid0000000000000000001.2.1', $delivery->reservationId());
        self::assertSame('kiwi.demandid0000000000000000001.2', $delivery->messageIdLocalPart());
        self::assertStringNotContainsString(':', $delivery->messageIdLocalPart(), 'a colon is not valid in a dot-atom Message-ID local part');
    }

    public function testTheMailerSenderStampsTheMessageId(): void
    {
        if (!interface_exists('\\Symfony\\Component\\Mailer\\MailerInterface')) {
            self::markTestSkipped('symfony/mailer is not installed; the mailer sender is never wired');
        }
        $messages = [];
        $mailer = new class ($messages) implements MailerInterface {
            /** @param list<array{0: RawMessage, 1: mixed|null}> $messages */
            public function __construct(private array &$messages)
            {
            }

            public function send(RawMessage $message, mixed $envelope = null): void
            {
                $this->messages[] = [$message, $envelope];
            }
        };
        $sender = new MailerEmailOwnershipCodeSender($mailer, 'codes@example.com', 'redaction-key');
        $sender->send('visitor@example.com', '123456', 600, new EmailOwnershipDeliveryMetadata('demandid0000000000000000001', 2, 1));

        self::assertCount(1, $messages);
        $email = $messages[0][0];
        self::assertInstanceOf(Email::class, $email);
        $messageIdBody = $email->getHeaders()->get('Message-ID')->getBody();
        $messageId = is_array($messageIdBody) ? ($messageIdBody[0] ?? '') : (string) $messageIdBody;
        self::assertSame('kiwi.demandid0000000000000000001.2@example.com', $messageId, 'the Message-ID names the demand and its generation');
        self::assertDoesNotMatchRegularExpression('/[<>\s@]*@.*:/i', (string) $messageId);
    }

    public function testAFromWithoutAUsableDomainRefusesTheDelivery(): void
    {
        if (!interface_exists('\\Symfony\\Component\\Mailer\\MailerInterface')) {
            self::markTestSkipped('symfony/mailer is not installed; the mailer sender is never wired');
        }
        $messages = [];
        $mailer = new class ($messages) implements MailerInterface {
            /** @param list<array{0: RawMessage, 1: mixed|null}> $messages */
            public function __construct(private array &$messages)
            {
            }

            public function send(RawMessage $message, mixed $envelope = null): void
            {
                $this->messages[] = [$message, $envelope];
            }
        };
        $sender = new MailerEmailOwnershipCodeSender($mailer, 'code-runner', 'redaction-key');
        try {
            $sender->send('visitor@example.com', '123456', 600, new EmailOwnershipDeliveryMetadata('demandid0000000000000000001', 0, 1));
            self::fail('a From identity without a domain cannot stamp a Message-ID');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString('Message-ID domain', $e->getMessage());
        }
        self::assertCount(0, $messages, 'nothing was handed off');
    }

    public function testTheReservationIdRidesTheGenerationBoundIdentity(): void
    {
        $delivery = new EmailOwnershipDeliveryMetadata('demandid0000000000000000001', 0, 2);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9.:-]+$/', $delivery->reservationId(), 'the reservation id is dot-atom safe for the store key family');
    }

    // ── the demand's stored lineage on the wire ─────────────────────

    public function testTheLineageRidesTheDemandWireAndEarlierShapesFailClosed(): void
    {
        $lineage = hash('sha256', 'lineage-wire');
        $demand = StepUpDemand::mint(
            'demandid0000000000000000001',
            'signup',
            null,
            null,
            null,
            $this->now,
            600,
            StepUpOperationBindingKind::None,
            '',
            null,
            null,
            false,
            null,
            null,
            null,
            $lineage,
        );
        $wire = $demand->toArray();
        self::assertSame(5, $wire['v'], 'the lineage is part of the v5 wire shape');
        self::assertSame($lineage, $wire['lineage_hash']);
        $decoded = StepUpDemand::fromArray($wire);
        self::assertNotNull($decoded);
        self::assertSame($lineage, $decoded->lineageHash);
        self::assertSame($wire, $decoded->toArray(), 'the record round-trips byte-identically');

        // A v4 record (the shape before the lineage) decodes as absent:
        // the store never funds a demand of the earlier shape.
        $v4 = $wire;
        $v4['v'] = 4;
        self::assertNull(StepUpDemand::fromArray($v4), 'a v4 record must decode as absent');

        // A v5 record without the key is not a decodable demand either:
        // the lineage is load-bearing, so its absence is corruption.
        $missing = $wire;
        unset($missing['lineage_hash']);
        self::assertNull(StepUpDemand::fromArray($missing), 'a v5 record without its lineage must decode as absent');

        // A lineage that is not the 64-hex hash shape is refused too.
        $malformed = $wire;
        $malformed['lineage_hash'] = 'not-a-lineage';
        self::assertNull(StepUpDemand::fromArray($malformed), 'a malformed lineage must decode as absent');

        // The explicit null is the stateless mint's legitimate shape: a
        // demand that bound no lineage stays decodable.
        $stateless = $demand->withLease(null)->toArray();
        $stateless['lineage_hash'] = null;
        self::assertNotNull(StepUpDemand::fromArray($stateless), 'a stateless demand carries an explicit null lineage');
    }

    public function testTheSessionLineageIsShapeValidated(): void
    {
        $storage = new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage();
        $storage->setId('lineage-shape-session-000001');
        $session = new \Symfony\Component\HttpFoundation\Session\Session($storage);
        $session->start();
        $request = Request::create('/kiwi/step-up/begin');
        $request->setSession($session);

        $minted = StepUpSessionBinding::lineage($request);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', $minted, 'the minted lineage is 32 lowercase hex chars');
        self::assertSame($minted, StepUpSessionBinding::lineage($request), 'the session carries the lineage across calls');
        self::assertSame(hash('sha256', $minted), StepUpSessionBinding::lineageHash($request), 'the history identity is the lineage hash');

        // A session value outside the minted shape is never adopted: a
        // hostile or corrupt string is replaced by a fresh mint.
        $session->set(StepUpSessionBinding::LINEAGE_KEY, 'not-a-lineage');
        $replaced = StepUpSessionBinding::lineage($request);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', $replaced, 'a malformed session value is replaced by a fresh mint');
        self::assertNotSame('not-a-lineage', $replaced);
        self::assertSame($replaced, $session->get(StepUpSessionBinding::LINEAGE_KEY), 'the fresh lineage is stored in the session');

        // No started session: no lineage, no history identity.
        $sessionless = Request::create('/kiwi/step-up/begin');
        self::assertSame('', StepUpSessionBinding::lineage($sessionless));
        self::assertNull(StepUpSessionBinding::lineageHash($sessionless));
    }
}
