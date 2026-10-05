<?php
/**
 * KiwiCaptcha settings: the WordPress Settings API page plus the
 * option schema. Every knob the plugin needs lives in one option row
 * (kiwicaptcha_options): the kiwi deployment surfaces, the bearer
 * secret, the per-form scopes and the per-form enable switches.
 *
 * @package kiwicaptcha
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The settings registry. Static methods only; WordPress loads the
 * plugin file once per request and the option store is the state.
 */
final class KiwiCaptcha_Settings
{
    public const OPTION_KEY = 'kiwicaptcha_options';

    /**
     * The defaults, also the schema: verify_url and shim_url point at
     * the deployment, mode selects the wire format, one scope and one
     * enabled flag per protected form.
     */
    public static function defaults(): array
    {
        return [
            'verify_url' => 'http://127.0.0.1:7371/verify',
            'shim_url' => '',
            'bearer' => '',
            'mode' => 'json',
            'trust_proxy' => false,
            'enabled_login' => true,
            'enabled_signup' => true,
            'enabled_comment' => false,
            'enabled_checkout' => false,
            'scope_login' => 'login',
            'scope_signup' => 'signup',
            'scope_comment' => 'comment',
            'scope_checkout' => 'checkout',
        ];
    }

    /**
     * The stored options merged over the defaults, so a key added in a
     * later version always reads defined.
     */
    public static function all(): array
    {
        $stored = function_exists('get_option') ? get_option(self::OPTION_KEY, []) : [];
        $stored = is_array($stored) ? $stored : [];

        return array_merge(self::defaults(), $stored);
    }

    public static function init(): void
    {
        add_action('admin_menu', [__CLASS__, 'registerMenu']);
        add_action('admin_init', [__CLASS__, 'registerSettings']);
    }

    public static function registerMenu(): void
    {
        add_options_page(
            'KiwiCaptcha',
            'KiwiCaptcha',
            'manage_options',
            'kiwicaptcha',
            [__CLASS__, 'renderPage']
        );
    }

    public static function registerSettings(): void
    {
        register_setting('kiwicaptcha', self::OPTION_KEY, [
            'type' => 'array',
            'sanitize_callback' => [__CLASS__, 'sanitize'],
            'default' => self::defaults(),
        ]);

        add_settings_section('kiwicaptcha_deployment', 'KiwiCaptcha deployment', '__return_false', 'kiwicaptcha');
        add_settings_field('verify_url', 'Verify URL', [__CLASS__, 'fieldVerifyUrl'], 'kiwicaptcha', 'kiwicaptcha_deployment');
        add_settings_field('shim_url', 'Shim script URL', [__CLASS__, 'fieldShimUrl'], 'kiwicaptcha', 'kiwicaptcha_deployment');
        add_settings_field('bearer', 'Bearer secret', [__CLASS__, 'fieldBearer'], 'kiwicaptcha', 'kiwicaptcha_deployment');
        add_settings_field('mode', 'Wire format', [__CLASS__, 'fieldMode'], 'kiwicaptcha', 'kiwicaptcha_deployment');
        add_settings_field('trust_proxy', 'Trust X-Forwarded-For', [__CLASS__, 'fieldTrustProxy'], 'kiwicaptcha', 'kiwicaptcha_deployment');

        add_settings_section('kiwicaptcha_forms', 'Protected forms', '__return_false', 'kiwicaptcha');
        foreach (['login', 'signup', 'comment', 'checkout'] as $form) {
            add_settings_field('enabled_'.$form, ucfirst($form).' form', [__CLASS__, 'fieldForm'], 'kiwicaptcha', 'kiwicaptcha_forms', ['form' => $form]);
        }
    }

    public static function renderPage(): void
    {
        echo '<div class="wrap"><h1>KiwiCaptcha</h1><form action="options.php" method="post">';
        settings_fields('kiwicaptcha');
        do_settings_sections('kiwicaptcha');
        submit_button();
        echo '</form></div>';
    }

    public static function fieldVerifyUrl(): void
    {
        $all = self::all();
        printf(
            '<input class="regular-text" type="url" name="%s[verify_url]" value="%s">',
            esc_attr(self::OPTION_KEY),
            esc_attr($all['verify_url'])
        );
        echo '<p class="description">The sidecar endpoint or the siteverify route.</p>';
    }

    public static function fieldShimUrl(): void
    {
        $all = self::all();
        printf(
            '<input class="regular-text" type="url" name="%s[shim_url]" value="%s">',
            esc_attr(self::OPTION_KEY),
            esc_attr($all['shim_url'])
        );
        echo '<p class="description">The deployment compat loader, e.g. https://kiwi.example.com/kiwi-captcha/api.js?compat=recaptcha. Empty disables the widget markup.</p>';
    }

    public static function fieldBearer(): void
    {
        $all = self::all();
        printf(
            '<input class="regular-text" type="password" name="%s[bearer]" value="%s" autocomplete="off">',
            esc_attr(self::OPTION_KEY),
            esc_attr($all['bearer'])
        );
    }

    public static function fieldMode(): void
    {
        $all = self::all();
        printf(
            '<select name="%s[mode]"><option value="json"%s>json (sidecar /verify)</option><option value="compat"%s>compat (siteverify: response/secret)</option></select>',
            esc_attr(self::OPTION_KEY),
            $all['mode'] === 'json' ? ' selected' : '',
            $all['mode'] === 'compat' ? ' selected' : ''
        );
    }

    public static function fieldTrustProxy(): void
    {
        $all = self::all();
        printf(
            '<input type="checkbox" name="%s[trust_proxy]" value="1"%s> honor X-Forwarded-For as the client ip',
            esc_attr(self::OPTION_KEY),
            $all['trust_proxy'] ? ' checked' : ''
        );
    }

    /**
     * @param array{form: string} $args
     */
    public static function fieldForm(array $args): void
    {
        $form = $args['form'];
        $all = self::all();
        printf(
            '<label><input type="checkbox" name="%1$s[enabled_%2$s]" value="1"%3$s> protect</label> ',
            esc_attr(self::OPTION_KEY),
            esc_attr($form),
            $all['enabled_'.$form] ? ' checked' : ''
        );
        printf(
            'scope <input type="text" name="%1$s[scope_%2$s]" value="%3$s" class="small-text">',
            esc_attr(self::OPTION_KEY),
            esc_attr($form),
            esc_attr($all['scope_'.$form])
        );
    }

    /**
     * The sanitize callback: whitelists every key, trims the strings,
     * validates the mode and keeps the booleans boolean.
     */
    public static function sanitize($input): array
    {
        $input = is_array($input) ? $input : [];
        $clean = self::defaults();
        foreach (['verify_url', 'shim_url', 'bearer'] as $key) {
            if (isset($input[$key]) && is_string($input[$key])) {
                $clean[$key] = sanitize_text_field($input[$key]);
            }
        }
        if (isset($input['mode']) && in_array($input['mode'], ['json', 'compat'], true)) {
            $clean['mode'] = (string) $input['mode'];
        }
        $clean['trust_proxy'] = !empty($input['trust_proxy']);
        foreach (['login', 'signup', 'comment', 'checkout'] as $form) {
            $clean['enabled_'.$form] = !empty($input['enabled_'.$form]);
            if (isset($input['scope_'.$form]) && is_string($input['scope_'.$form]) && preg_match('/^[A-Za-z0-9_:-]{1,64}$/', $input['scope_'.$form]) === 1) {
                $clean['scope_'.$form] = $input['scope_'.$form];
            }
        }

        return $clean;
    }
}
