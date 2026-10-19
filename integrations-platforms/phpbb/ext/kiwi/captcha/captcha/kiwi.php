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

    /** @var ?string the typed refusal code of the last confirm() */
    protected $last_code = null;

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
            'trusted_proxies' => (string) ($this->config['kiwi_trusted_proxies'] ?? ''),
            'scope' => kiwi::sanitize_scope((string) ($this->config['kiwi_scope'] ?? 'signup')),
        ];
    }

    public function init(): void
    {
        $this->attempts = 0;
    }

    /**
     * Verify the submitted challenge. The token authority rule decides
     * first: the collected source values must agree, and a
     * token_source_conflict refusal counts as a failed confirmation
     * with the typed code exposed through get_last_code().
     */
    public function confirm(): bool
    {
        $resolution = kiwi::resolve_token(
            (array) ($_SERVER ?? []),
            (array) ($_POST ?? []),
            (array) ($_COOKIE ?? [])
        );
        $this->last_code = $resolution['code'];
        $token = $resolution['token'];
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

    /**
     * The typed refusal code of the last confirm(): null, or the
     * corpus code token_source_conflict when the request carried two
     * or more distinct token values.
     */
    public function get_last_code(): ?string
    {
        return $this->last_code;
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
     * The token authority rule (the shared decision corpus): every
     * non-empty value is collected from all sources — the X-Kiwi-Token
     * header (php merges repeated header lines into one comma-joined
     * value; the token alphabet has no comma, so the split loses
     * nothing), the shim form fields (a repeated form key arrives as an
     * array) and the kiwi_token cookie — repeated values included. One
     * distinct value verifies however many sources carry it; two or
     * more distinct values refuse with the typed
     * token_source_conflict code before any token is verified, so a
     * trusted gateway's header can never be shadowed by an
     * attacker-controlled form field or cookie.
     *
     * @param array<string, mixed> $server
     * @param array<string, mixed> $post
     * @param array<string, mixed> $cookie
     *
     * @return array{token: ?string, code: ?string} the single distinct
     *         token, or the typed refusal code
     *         (token_source_conflict) with a null token
     */
    public static function resolve_token(array $server, array $post, array $cookie): array
    {
        $distinct = [];
        foreach (self::token_candidates($server, $post, $cookie) as $candidate) {
            $candidate = trim((string) $candidate);
            if ($candidate === '') {
                continue;
            }
            $distinct[$candidate] = true;
            if (count($distinct) > 1) {
                return ['token' => null, 'code' => 'token_source_conflict'];
            }
        }
        if ($distinct === []) {
            return ['token' => null, 'code' => null];
        }

        return ['token' => (string) array_key_first($distinct), 'code' => null];
    }

    /**
     * Every raw token candidate of the closed source list: the header
     * lines (comma-split), the shim form fields (string or array) and
     * the kiwi_token cookie.
     *
     * @param array<string, mixed> $server
     * @param array<string, mixed> $post
     * @param array<string, mixed> $cookie
     *
     * @return list<string>
     */
    protected static function token_candidates(array $server, array $post, array $cookie): array
    {
        $candidates = [];
        $header = $server['HTTP_X_KIWI_TOKEN'] ?? null;
        if (is_string($header)) {
            foreach (explode(',', $header) as $part) {
                $candidates[] = $part;
            }
        }
        foreach (['kiwi__token', 'g-recaptcha-response', 'h-captcha-response', 'cf-turnstile-response', 'frc-captcha-solution', 'altcha'] as $field) {
            $value = $post[$field] ?? null;
            if (is_string($value)) {
                $candidates[] = $value;
            } elseif (is_array($value)) {
                foreach ($value as $item) {
                    if (is_string($item)) {
                        $candidates[] = $item;
                    }
                }
            }
        }
        $cookie_token = $cookie['kiwi_token'] ?? null;
        if (is_string($cookie_token)) {
            $candidates[] = $cookie_token;
        }

        return $candidates;
    }
}
