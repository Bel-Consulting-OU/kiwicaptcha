<?php
/**
 * The client side: the widget markup the shims render into, the
 * [kiwi_captcha] shortcode, and the script tag. The markup keeps the
 * incumbent conventions (a g-recaptcha-style container plus the hidden
 * native token field), so the shims and ordinary theme styles work.
 *
 * @package kiwicaptcha
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Markup and asset emission. Static methods.
 */
final class KiwiCaptcha_Form
{
    /**
     * The form markup: the hidden native token field, the shim
     * container and the shim script tag (only when a shim URL is
     * configured; an empty shim_url means the admin serves the script
     * some other way and the shortcode prints the container only).
     */
    public static function markup(string $scope, string $shimUrl = ''): string
    {
        $scope = self::sanitizeScope($scope);
        $html = '<div class="kiwi-container" data-kiwi-scope="'.esc_attr($scope).'">';
        $html .= '<input type="hidden" name="kiwi__token" data-kiwi-token value="">';
        $html .= '<div class="kiwi-widget" data-kiwi-widget data-kiwi-started="1" data-state="idle" role="group" aria-label="KiwiCaptcha security check"></div>';
        $html .= '</div>';
        if ($shimUrl !== '') {
            $html .= '<script src="'.esc_url($shimUrl).'" defer></script>';
        }

        return $html;
    }

    /**
     * The [kiwi_captcha scope="comment"] shortcode. The scope
     * attribute defaults to the comment form's scope.
     *
     * @param array<string, mixed>|string $atts
     */
    public static function shortcode($atts): string
    {
        $atts = function_exists('shortcode_atts')
            ? shortcode_atts(['scope' => (string) KiwiCaptcha_Settings::all()['scope_comment']], $atts, 'kiwi_captcha')
            : ['scope' => is_array($atts) && isset($atts['scope']) ? (string) $atts['scope'] : 'comment'];
        $settings = KiwiCaptcha_Settings::all();

        return self::markup((string) $atts['scope'], (string) $settings['shim_url']);
    }

    /**
     * The scope value a form uses, resolved from the stored options.
     */
    public static function scopeFor(string $form): string
    {
        $all = KiwiCaptcha_Settings::all();
        $scope = $all['scope_'.$form] ?? '';

        return self::sanitizeScope(is_string($scope) ? $scope : '');
    }

    /**
     * Scope names are short Kiwi identifiers: letters, digits,
     * underscore, dash and the action-suffix colon.
     */
    public static function sanitizeScope(string $scope): string
    {
        if (preg_match('/^[A-Za-z0-9_:-]{1,64}$/', $scope) === 1) {
            return $scope;
        }

        return 'login';
    }

    /**
     * The login-page script hookup: prints the shim script tag on
     * wp-login.php when a shim URL is configured. Registered on the
     * login_footer action.
     */
    public static function printLoginScript(): void
    {
        $settings = KiwiCaptcha_Settings::all();
        if ((string) $settings['shim_url'] === '') {
            return;
        }
        echo '<script src="'.esc_url((string) $settings['shim_url']).'" defer></script>';
    }
}
