<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaDoctorCommand;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\ProtectionProfileDefaults;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\RecipeConfigTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\TestKernel;
use KiwiCaptcha\Challenge;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Yaml\Yaml;

/**
 * Validation of the recipes-contrib package
 * (recipes-contrib/bel-consulting/kiwicaptcha-symfony/1.0/): the
 * manifest, the copied config/routes files and the fixture skeleton
 * must be coherent with each other and with the bundle's Configuration.
 * The recipe's config/packages/kiwicaptcha.yaml is processed through
 * the bundle's `Configuration` with the `%env()` placeholders resolved
 * to test values, exactly like a container resolves them at runtime.
 * A kernel booted with the recipe's exact config values proves the
 * install experience end to end.
 */
final class RecipePackageValidationTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function recipeDir(): string
    {
        return \dirname(__DIR__, 5).'/recipes-contrib/bel-consulting/kiwicaptcha-symfony/1.0';
    }

    private function recipeFile(string $relative): string
    {
        $path = $this->recipeDir().'/'.$relative;
        if (!is_file($path)) {
            self::markTestSkipped(sprintf('the recipe package is not present at %s', $path));
        }

        return $path;
    }

    /**
     * @return array<string, mixed> the decoded recipe manifest
     */
    private function manifest(): array
    {
        $manifest = json_decode((string) file_get_contents($this->recipeFile('manifest.json')), true);
        self::assertIsArray($manifest, 'manifest.json must be valid JSON');

        return $manifest;
    }

    /**
     * The recipe's config/packages/kiwicaptcha.yaml with every %env()%
     * placeholder resolved to a test value (the container resolves the
     * same placeholders at compile time; the values here stand in for
     * the .env the manifest generates).
     *
     * @return array<string, mixed>
     */
    private function recipeConfigResolved(): array
    {
        $raw = Yaml::parseFile($this->recipeFile('config/packages/kiwicaptcha.yaml'));
        self::assertIsArray($raw, 'the recipe config must parse as YAML');
        $config = $raw['kiwi_captcha'] ?? null;
        self::assertIsArray($config, 'the recipe config must carry the kiwi_captcha root key');
        $manifest = $this->manifest();
        $envValues = [
            'KIWI_SECRET_KEY' => self::SECRET,
        ];
        foreach (array_keys($manifest['env'] ?? []) as $key) {
            if (!isset($envValues[$key])) {
                $envValues[$key] = 'recipe-test-value-'.$key;
            }
        }
        foreach ($config as $k => $v) {
            if (\is_string($v)) {
                $config[$k] = preg_replace_callback('/%env\(([A-Z0-9_]+)\)%/', static function (array $m) use ($envValues): string {
                    return $envValues[$m[1]];
                }, $v);
            }
        }

        return $config;
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return array<string, mixed>
     */
    private function process(array $config, array $overlay = []): array
    {
        $layers = $overlay === [] ? [$config] : [$config, $overlay];
        $processed = (new Processor())->processConfiguration(
            new Configuration(),
            ProtectionProfileDefaults::stack($layers),
        );

        return ProtectionProfileDefaults::finalize($processed, $layers);
    }

    public function testManifestJsonIsValidAndDeclaresTheRecipeContract(): void
    {
        $manifest = $this->manifest();

        self::assertSame(
            ['BelConsulting\\KiwiCaptchaBundle\\KiwiCaptchaBundle' => ['all']],
            $manifest['bundles'],
            'the manifest must register the bundle for every environment',
        );
        self::assertSame(['config/' => '%CONFIG_DIR%/'], $manifest['copy-from-recipe'], 'the manifest copies the config directory');
        self::assertSame(['KIWI_SECRET_KEY'], array_keys($manifest['env']), 'the manifest declares exactly the env key the config references');
    }

    public function testEveryConfigEnvPlaceholderIsDeclaredInTheManifest(): void
    {
        $yaml = (string) file_get_contents($this->recipeFile('config/packages/kiwicaptcha.yaml'));
        preg_match_all('/%env\(([A-Z0-9_]+)\)%/', $yaml, $matches);
        $used = array_values(array_unique($matches[1]));

        self::assertSame(['KIWI_SECRET_KEY'], $used, 'the recipe config references exactly the manifest-declared env key');
    }

    public function testRecipeConfigProcessesCleanlyThroughTheBundleConfiguration(): void
    {
        $processed = $this->process($this->recipeConfigResolved());

        self::assertSame('balanced', $processed['protection_profile']);
        self::assertSame(self::SECRET, $processed['secret_key'], 'the %env()% secret placeholder resolves into the processed config');
        self::assertSame('https://captcha.example.com', $processed['public_base_url'], 'the literal public origin processes cleanly');
        self::assertSame('redis://127.0.0.1:6379/0', $processed['redis_dsn'], 'the literal DSN processes cleanly');
        self::assertSame(18, $processed['difficulty_bits'], 'the balanced profile defaults apply');
        self::assertFalse($processed['risk']['enabled'], 'balanced keeps risk off');
    }

    public function testRecipeConfigWithAProdProfileOverlayProcessesCleanly(): void
    {
        // The recipe file plus a prod overlay that switches the profile:
        // the same layered processing a real app performs with
        // config/packages/prod/kiwicaptcha.yaml.
        $processed = $this->process($this->recipeConfigResolved(), ['protection_profile' => 'high_abuse']);

        self::assertSame('high_abuse', $processed['protection_profile'], 'the later profile layer wins');
        self::assertSame(self::SECRET, $processed['secret_key'], 'the recipe values survive the overlay');
        self::assertSame('redis://127.0.0.1:6379/0', $processed['redis_dsn']);
        self::assertTrue($processed['risk']['enabled'], 'high_abuse enables the risk engine');
        self::assertSame(5, $processed['rate_limit'], 'high_abuse derives the tightened per-source limit');
    }

    public function testRoutesYamlParsesAsTheBundleRouteImport(): void
    {
        $routes = Yaml::parseFile($this->recipeFile('config/routes/kiwicaptcha.yaml'));
        self::assertSame(
            ['kiwi_captcha' => ['resource' => '@KiwiCaptchaBundle/Resources/config/routes.php']],
            $routes,
            'the recipe routes import the bundle route file',
        );
    }

    public function testFixtureComposerJsonIsValid(): void
    {
        $fixture = json_decode((string) file_get_contents($this->recipeFile('tests/Fixtures/composer.json')), true);
        self::assertIsArray($fixture, 'the fixture composer.json must be valid JSON');
        self::assertSame('project', $fixture['type']);
        foreach (['symfony/flex', 'predis/predis', 'bel-consulting/kiwicaptcha-symfony'] as $required) {
            self::assertArrayHasKey($required, $fixture['require'], 'the fixture must require '.$required);
        }
    }

    public function testRecipeShapedConfigBootsAKernelAndPassesDoctorWithTheDsn(): void
    {
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('TEST_REDIS_URL / KC_REDIS_URL not set — the recipe-shaped boot test needs a real Redis');
        }

        // The manifest generates the secret into .env; the real container
        // resolves the %env()% placeholder from the process environment.
        putenv(RecipeConfigTestKernel::SECRET_ENV.'='.self::SECRET);
        $kernel = new RecipeConfigTestKernel('test', true, $url);
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');

        try {
            // The %env()% secret resolved end to end: the core Config the
            // extension built carries the real secret, not the
            // placeholder string.
            $config = $container->get('kiwi_captcha.config');
            self::assertSame(self::SECRET, $config->secretKey, 'the recipe %env()% secret resolves into the wired core config');

            $storage = $container->get(StorageInterface::class);
            self::assertInstanceOf(RedisStorage::class, $storage, 'the recipe DSN builds the atomic challenge storage');

            $client = $container->get('kiwi_captcha.redis.dsn');
            self::assertInstanceOf(\Predis\Client::class, $client);
            $client->flushdb();

            $tester = new CommandTester($container->get(KiwiCaptchaDoctorCommand::class));
            $tester->execute([]);
            self::assertSame(Command::SUCCESS, $tester->getStatusCode(), 'no FAIL means exit 0');
            $display = $tester->getDisplay();
            self::assertStringContainsString('[PASS] Redis reachability', $display, 'the recipe DSN client answers PING');
            self::assertStringContainsString('[PASS] Storage atomicity', $display);
            self::assertStringNotContainsString('[FAIL]', $display);

            // The full install experience: an HTTP challenge issued by
            // the recipe-shaped kernel solves and verifies.
            $browser = new KernelBrowser($kernel);
            $browser->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json'], content: '{"scope":"login"}');
            self::assertSame(200, $browser->getResponse()->getStatusCode(), 'the recipe-shaped kernel serves the challenge endpoint');
            $data = json_decode($browser->getResponse()->getContent(), true);
            $challenge = $this->challengeFromData($data);
            $this->waitOutMinDuration($challenge);

            $verifier = $container->get('kiwi_captcha.verifier');
            $nowNs = (int) (microtime(true) * 1_000_000) + 1_000_000;
            $outcome = $verifier->verify($this->solveToken($challenge), self::SECRET, 'login', '127.0.0.1', $nowNs);
            self::assertTrue($outcome->isOk(), sprintf('the recipe-shaped round trip must verify, got %s', $outcome->code()));
        } finally {
            $kernel->shutdown();
            putenv(RecipeConfigTestKernel::SECRET_ENV);
        }
    }

    /**
     * The bundle contract that shaped the recipe: this version validates
     * the DSN shape at container build time, before %env()% placeholders
     * resolve, so the recipe ships a literal DSN. The day the extension
     * resolves placeholders before validating, this refusal disappears
     * and the recipe can return to the %env()% form.
     */
    public function testEnvPlaceholderDsnIsRefusedAtContainerBuildTime(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'dev');
        try {
            (new KiwiCaptchaExtension())->load([[
                'secret_key' => self::SECRET,
                'redis_dsn' => '%env(KIWI_REDIS_DSN)%',
            ]], $container);
            self::fail('an unresolved %env()% DSN must fail closed at container build time');
        } catch (\LogicException $e) {
            self::assertStringContainsString('redis_dsn', $e->getMessage(), 'the refusal names the offending option');
            self::assertStringContainsString('redis://', $e->getMessage(), 'the refusal states the accepted shape');
        }
    }

    /**
     * @param array<string, mixed> $data
     */
    private function challengeFromData(array $data): Challenge
    {
        return new Challenge(
            nonce: (string) $data['nonce'],
            challenge: (string) $data['challenge'],
            salt: (string) $data['salt'],
            algorithm: PoWAlgorithm::from((string) $data['algorithm']),
            mKib: (int) $data['mKib'],
            t: (int) $data['t'],
            p: (int) $data['p'],
            targetBits: (int) $data['targetBits'],
            ttlSecs: (int) $data['ttlSecs'],
            minDurationMs: (int) $data['minDurationMs'],
            prefix: (string) $data['prefix'],
        );
    }

    private function solveToken(Challenge $challenge): string
    {
        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
    }

    private function waitOutMinDuration(Challenge $challenge): void
    {
        usleep(($challenge->minDurationMs + 10) * 1000);
    }
}
