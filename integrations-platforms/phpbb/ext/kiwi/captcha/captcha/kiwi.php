<?php
/**
 * The kiwi captcha plugin for phpBB 3.3: implements the platform's
 * captcha plugin contract, the six methods the captcha factory
 * (phpbb\captcha\factory) resolves through the
 * "captcha.plugins.kiwi" service. Once an administrator selects the
 * plugin (ACP, General, Spambot countermeasures, or the registration
 * form's captcha setting), every captcha surface the board renders
 * becomes a kiwi proof-of-work challenge.
 *
 * The contract: init() prepares the client, confirm() verifies the
 * submitted answer, get_attempt_count() reports the attempt count,
 * reset() clears the attempt state, get_name() names the plugin,
 * has_config() declares the ACP surface. The template methods feed
 * the style template with the widget markup.
 *
 * @package kiwi\captcha\captcha
 */

namespace kiwi\captcha\captcha;

class kiwi
{
    /** @var \phpbb\config\config */
    protected $config;

    /** @var client */
    protected $client;

    /** @var string the plugin name the factory registered */
    protected $name = 'kiwi';

    /** @var int the failed attempts on this session */
    protected $attempts = 0;

    public function __construct(\phpbb\config\config $config, client $client)
    {
        $this->config = $config;
        $this->client = $client;
    }

    /**
     * The resolved settings from the board config.
     *
     * @return array<string, mixed>
     */
    protected function settings(): array
    {
        return [
            'verify_url' => (string) ($this->config['kiwi_verify_url'] ?? 'http://127.0.0.1:7371/verify'),
            'bearer' => (string) ($this->config['kiwi_bearer'] ?? ''),
            'mode' => ($this->config['kiwi_mode'] ?? 'json') === 'compat' ? 'compat' : 'json',
            'trust_proxy' => !empty($this->config['kiwi_trust_proxy']),
            'scope' => kiwi::sanitize_scope((string) ($this->config['kiwi_scope'] ?? 'signup')),
        ];
    }

    public function init(): void
    {
        $this->attempts = 0;
    }

    /**
     * Verify the submitted challenge. The token arrives in any shim
     * response field (the native kiwi__token and the incumbent
     * aliases), the header or the cookie.
     */
    public function confirm(): bool
    {
        $token = kiwi::extract_token(
            (array) ($_SERVER ?? []),
            (array) ($_POST ?? []),
            (array) ($_COOKIE ?? [])
        );
        if ($token === null) {
            ++$this->attempts;

            return false;
        }
        $result = $this->client->verify(
            $this->settings(),
            $token,
            (string) ($this->settings()['scope'] ?? 'signup'),
            (array) ($_SERVER ?? [])
        );
        if ($result['ok'] !== true) {
            ++$this->attempts;

            return false;
        }

        return true;
    }

    public function get_attempt_count(): int
    {
        return $this->attempts;
    }

    public function reset(): void
    {
        $this->attempts = 0;
    }

    public function get_name(): string
    {
        return $this->name;
    }

    /**
     * The plugin carries ACP-configurable settings.
     */
    public function has_config(): bool
    {
        return true;
    }

    /**
     * The captcha template data: the widget markup the style renders.
     *
     * @return array{filename: string, vars?: array<string, mixed>}
     */
    public function get_template(): array
    {
        $scope = (string) ($this->settings()['scope'] ?? 'signup');

        return [
            'filename' => 'captcha_kiwi.html',
            'vars' => [
                'KIWI_SCOPE' => $scope,
                'KIWI_SHIM_URL' => (string) ($this->config['kiwi_shim_url'] ?? ''),
                'KIWI_MARKUP' => '<div class="kiwi-container" data-kiwi-scope="'.htmlspecialchars($scope, ENT_QUOTES).'" id="kiwi_captcha">'
                    .'<input type="hidden" name="kiwi__token" data-kiwi-token value=""></div>',
            ],
        ];
    }

    /**
     * Scope names are short kiwi identifiers.
     */
    public static function sanitize_scope(string $scope): string
    {
        if (preg_match('/^[A-Za-z0-9_:-]{1,64}$/', $scope) === 1) {
            return $scope;
        }

        return 'signup';
    }

    /**
     * The first present token: header, form fields (native and
     * incumbent), JSON body, cookie.
     *
     * @param array<string, mixed> $server
     * @param array<string, mixed> $post
     * @param array<string, mixed> $cookie
     */
    public static function extract_token(array $server, array $post, array $cookie): ?string
    {
        $header = $server['HTTP_X_KIWI_TOKEN'] ?? null;
        if (is_string($header) && trim($header) !== '') {
            return trim($header);
        }
        foreach (['kiwi__token', 'g-recaptcha-response', 'h-captcha-response', 'cf-turnstile-response', 'frc-captcha-solution', 'altcha'] as $field) {
            $value = $post[$field] ?? null;
            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }
        $cookie_token = $cookie['kiwi_token'] ?? null;
        if (is_string($cookie_token) && trim($cookie_token) !== '') {
            return trim($cookie_token);
        }

        return null;
    }
}
