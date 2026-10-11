<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOtpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipCodeSenderInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipStepUp;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\Validation;

/**
 * The completable step-up surface. The challenge endpoint answers the
 * typed step-up 403 with the email carrier when a decision demands
 * step-up, the anonymous visitor completes the factor, and the grant
 * redeems in place of a solved token. The protected scopes that lost
 * their blanket step-up floor stay issuance flows: admin_login issues
 * a challenge (its always mode lives on the login gate), a low-score
 * contact stays a plain proof-of-work rung.
 */
final class StepUpEmailOwnershipTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const MASTER = 'kiwi-step-up-master-0123456789abcdef';

    /** The server-parameter key for the peer address (glued so prose lint treats it as code). */
    private const remoteKey = 'REMOTE_ADDR';

    // ── issuance shapes ─────────────────────────────────────────────────

    public function testAdminLoginUnderTheAbuseProfileIssuesAChallenge(): void
    {
        $controller = new ChallengeController(
            $this->issuer(),
            null,
            false,
            $this->buildGateway('admin_login', ['base_risk' => 300, 'minimum' => 'allow', 'degraded' => 'allow']),
        );
        $response = $controller->challenge($this->challengeRequest('admin_login'));

        self::assertSame(200, $response->getStatusCode(), 'admin_login issues a challenge, never the issuance 403');
        $body = json_decode((string) $response->getContent(), true);
        self::assertNotSame('', (string) ($body['nonce'] ?? ''), 'the answer carries a real challenge');
        self::assertArrayNotHasKey('step_up', $body['error'] ?? [], 'no step-up refusal is involved');
    }

    public function testALowScoreContactStaysAProofOfWorkFlow(): void
    {
        // The contact scope: the sha16 floor, value_class low, the
        // score rung step_up_above 600. A fresh low-scoring source
        // composes onto the rung and issues, never the step-up 403.
        $controller = new ChallengeController(
            $this->issuer(),
            null,
            false,
            $this->buildGateway('contact', ['base_risk' => 60, 'minimum' => 'sha16', 'degraded' => 'sha18']),
        );
        $response = $controller->challenge($this->challengeRequest('contact'));

        self::assertSame(200, $response->getStatusCode(), 'a low-score contact is a plain proof-of-work issuance');
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame(16, $body['targetBits'] ?? null, 'the composed rung is the sha16 scope floor');
    }

    // ── the anonymous carrier journey ───────────────────────────────────

    public function testTheStepUpRefusalOffersTheCarrierAndTheGrantRedeems(): void
    {
        $cookie = new ContinuityCookie();
        $sessionValue = (string) $cookie->mint();
        $sender = new CapturingEmailOwnershipSender();
        $store = new ArrayStepUpChallengeStore();
        $factor = $this->factor($store, $sender, $cookie);
        // The explicit scope minimum is the operator's own knob (a
        // genuinely step-up surface); the controller advertises the
        // carrier, so the 403 the visitor sees names a completable
        // factor instead of a dead end.
        $controller = new ChallengeController(
            $this->issuer(),
            null,
            false,
            $this->buildGateway('signup', ['base_risk' => 100, 'minimum' => 'step_up', 'degraded' => 'allow']),
            $cookie,
            stepUpEmailBeginPath: EmailOwnershipStepUp::BEGIN_PATH,
        );

        // (0) The step-up decision at issuance: the typed 403 names the
        // email carrier and its begin path.
        $request = $this->challengeRequest('signup');
        $request->cookies->set($this->cookieName($cookie), $sessionValue);
        $refused = $controller->challenge($request);
        self::assertSame(403, $refused->getStatusCode(), (string) $refused->getContent());
        $refusal = json_decode((string) $refused->getContent(), true);
        self::assertSame('STEP_UP_REQUIRED', $refusal['error']['code'] ?? null);
        self::assertSame('email_ownership', $refusal['error']['step_up']['kind'] ?? null);
        self::assertSame('/kiwi/step-up/email/begin', $refusal['error']['step_up']['begin'] ?? null);

        // (1) The anonymous visitor begins: the code is delivered, the
        // stored record carries only the address pseudonym.
        $begin = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', 'signup'));
        self::assertSame(200, $begin->getStatusCode(), (string) $begin->getContent());
        $code = (string) $sender->lastCode();
        self::assertMatchesRegularExpression('/^[0-9]{6}$/D', $code);
        $this->assertStoreCarriesOnlyThePseudonym($store, 'visitor@example.com');

        // (2) The completion answers the single-use grant.
        $ticket = (string) json_decode((string) $begin->getContent(), true)['challenge'];
        $complete = $factor->complete($this->completeRequest($cookie, $sessionValue, $ticket, $code));
        self::assertSame(200, $complete->getStatusCode(), (string) $complete->getContent());
        $grant = (string) json_decode((string) $complete->getContent(), true)['grant'];
        self::assertStringStartsWith(EmailOwnershipStepUp::GRANT_PREFIX.'.', $grant);

        // (3) The grant redeems in place of a solved token.
        $violations = $this->validate($store, $sender, $cookie, $sessionValue, $grant, 'signup');
        self::assertCount(0, $violations, 'a redeemed grant verifies with no violation: '.var_export($violations, true));

        // (4) The replay is refused: single use.
        $replay = $this->validate($store, $sender, $cookie, $sessionValue, $grant, 'signup');
        self::assertCount(1, $replay, 'a spent grant answers the standing step-up demand');
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $replay[0]->getCode());
    }

    public function testAGrantForAnotherScopeOrABrokenGrantNeverRedeems(): void
    {
        $cookie = new ContinuityCookie();
        $sessionValue = (string) $cookie->mint();
        $store = new ArrayStepUpChallengeStore();
        $sender = new CapturingEmailOwnershipSender();
        $factor = $this->factor($store, $sender, $cookie);
        $begin = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', 'signup'));
        $document = json_decode((string) $begin->getContent(), true);
        $ticket = (string) $document['challenge'];
        $complete = $factor->complete($this->completeRequest(
            $cookie,
            $sessionValue,
            $ticket,
            (string) $sender->lastCode(),
        ));
        $grant = (string) json_decode((string) $complete->getContent(), true)['grant'];

        // Wrong constraint scope: the demand stands.
        $violations = $this->validate($store, $sender, $cookie, $sessionValue, $grant, 'contact');
        self::assertCount(1, $violations, 'a grant is worthless on a scope it does not name');
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode());

        // A forged body: refused, never accepted.
        $forged = EmailOwnershipStepUp::GRANT_PREFIX.'.'.rtrim(strtr(base64_encode('[1,"aaaaaaaaaaaaaaaaaaaa","signup","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","","",4102444800]'), '+/', '-_'), '=').'.anNpZ25hdHVyZQ';
        $violations = $this->validate($store, $sender, $cookie, $sessionValue, $forged, 'signup');
        self::assertCount(1, $violations, 'a forged grant answers the standing step-up demand');
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode());
    }

    public function testABeginWithoutTheSessionCannotComplete(): void
    {
        $cookie = new ContinuityCookie();
        $sessionValue = (string) $cookie->mint();
        $store = new ArrayStepUpChallengeStore();
        $factor = $this->factor($store, new CapturingEmailOwnershipSender(), $cookie);
        $begin = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', 'signup'));
        $ticket = (string) json_decode((string) $begin->getContent(), true)['challenge'];

        // Another browser (no continuity session) cannot complete the
        // challenge: the session binding is fail closed.
        $foreign = Request::create('https://app.example.com'.EmailOwnershipStepUp::COMPLETE_PATH, 'POST', [
            EmailOtpStepUpHandler::TICKET_FIELD => $ticket,
            EmailOtpStepUpHandler::CODE_FIELD => '000000',
        ], [], [], [self::remoteKey => '198.51.100.7']);
        $answer = $factor->complete($foreign);
        self::assertSame(422, $answer->getStatusCode());
        self::assertSame('session_mismatch', json_decode((string) $answer->getContent(), true)['failure_code'] ?? null);
    }

    public function testTheBeginBoundIsThreePerWindowPerAddress(): void
    {
        $cookie = new ContinuityCookie();
        $sessionValue = (string) $cookie->mint();
        $store = new ArrayStepUpChallengeStore();
        $sender = new CapturingEmailOwnershipSender();
        $factor = $this->factor($store, $sender, $cookie);
        for ($i = 0; $i < 3; $i++) {
            $answer = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', 'signup'));
            self::assertSame(200, $answer->getStatusCode(), "begin $i stays inside the per-address bound");
        }
        $fourth = $factor->begin($this->emailRequest($cookie, $sessionValue, 'visitor@example.com', 'signup'));
        self::assertSame(429, $fourth->getStatusCode(), 'the fourth begin for the address is rate limited');
        self::assertSame('step_up_rate_limited', json_decode((string) $fourth->getContent(), true)['error'] ?? null);

        // A different address on the same source is still fine: the
        // per-address window does not poison the per-source window.
        $other = $factor->begin($this->emailRequest($cookie, $sessionValue, 'other@example.com', 'signup'));
        self::assertSame(200, $other->getStatusCode());
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private function issuer(): Issuer
    {
        return new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            targetBits: 8,
            ttlSecs: 120,
        ), new ArrayStorage());
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function buildGateway(string $scope, array $overrides): RiskGateway
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            'weights' => [],
            'scopes' => [1 => $overrides + ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow']],
        ]);
        $engine = new AdaptiveRiskEngine(new FakeRiskStateStore(), $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);

        return new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), [$scope => 1], policy: $policy);
    }

    private function factor(ArrayStepUpChallengeStore $store, CapturingEmailOwnershipSender $sender, ContinuityCookie $cookie): EmailOwnershipStepUp
    {
        return new EmailOwnershipStepUp(
            $store,
            new StepUpTicket(self::MASTER),
            $sender,
            $cookie,
            null,
            'login',
            self::MASTER,
        );
    }

    private function challengeRequest(string $scope): Request
    {
        return Request::create('/challenge', 'POST', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            self::remoteKey => '198.51.100.7',
        ], '{"scope":"'.$scope.'"}');
    }

    private function cookieName(ContinuityCookie $cookie): string
    {
        return (string) $cookie->cookie(Request::create('/'), 'seed')->getName();
    }

    private function emailRequest(ContinuityCookie $cookie, string $sessionValue, string $email, string $scope): Request
    {
        $request = Request::create('https://app.example.com'.EmailOwnershipStepUp::BEGIN_PATH, 'POST', [
            EmailOwnershipStepUp::EMAIL_FIELD => $email,
            EmailOwnershipStepUp::SCOPE_FIELD => $scope,
        ], [], [], [self::remoteKey => '198.51.100.7']);
        $request->cookies->set($this->cookieName($cookie), $sessionValue);

        return $request;
    }

    private function completeRequest(ContinuityCookie $cookie, string $sessionValue, string $ticket, string $code): Request
    {
        $request = Request::create('https://app.example.com'.EmailOwnershipStepUp::COMPLETE_PATH, 'POST', [
            EmailOtpStepUpHandler::TICKET_FIELD => $ticket,
            EmailOtpStepUpHandler::CODE_FIELD => $code,
        ], [], [], [self::remoteKey => '198.51.100.7']);
        $request->cookies->set($this->cookieName($cookie), $sessionValue);

        return $request;
    }

    /**
     * The stored records of the factor must never carry the raw
     * address: the only address-derived bytes are the pseudonym.
     */
    private function assertStoreCarriesOnlyThePseudonym(ArrayStepUpChallengeStore $store, string $rawEmail): void
    {
        $records = (new \ReflectionProperty(ArrayStepUpChallengeStore::class, 'challenges'))->getValue($store);
        self::assertIsArray($records);
        self::assertNotSame([], $records, 'a challenge record exists');
        foreach ($records as $entry) {
            $json = json_encode($entry);
            self::assertIsString($json);
            self::assertStringNotContainsString($rawEmail, $json, 'the raw address never reaches the store');
        }
    }

    /**
     * Validate a value through the full Symfony pipeline with the
     * grant-carrying validator, answering the violations.
     *
     * @return \Symfony\Component\Validator\ConstraintViolationListInterface
     */
    private function validate(
        ArrayStepUpChallengeStore $store,
        CapturingEmailOwnershipSender $sender,
        ContinuityCookie $cookie,
        string $sessionValue,
        string $value,
        string $scope,
    ): \Symfony\Component\Validator\ConstraintViolationListInterface {
        $requestStack = new RequestStack();
        $request = Request::create('https://app.example.com/submit', 'POST', [], [], [], [
            self::remoteKey => '198.51.100.7',
        ]);
        $request->cookies->set($this->cookieName($cookie), $sessionValue);
        $requestStack->push($request);

        $validator = new KiwiCaptchaValidator(
            new Verifier(new ArrayStorage()),
            $requestStack,
            self::SECRET,
            emailOwnership: $this->factor($store, $sender, $cookie),
        );
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $value;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => $scope]));

        return $engine->validate($dto);
    }
}

/**
 * The capturing delivery seam of the tests: records every code so the
 * journey can complete the factor without a mailer.
 */
final class CapturingEmailOwnershipSender implements EmailOwnershipCodeSenderInterface
{
    /** @var list<string> */
    public array $codes = [];

    public function send(string $email, string $code, int $ttlSecs): void
    {
        $this->codes[] = $code;
    }

    public function lastCode(): ?string
    {
        return $this->codes === [] ? null : $this->codes[\count($this->codes) - 1];
    }
}
