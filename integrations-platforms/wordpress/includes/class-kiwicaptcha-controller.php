<?php
/**
 * The WordPress hook surface: login, registration, comments,
 * WooCommerce checkout, the shortcode registration and the settings
 * page. Every guard follows the same shape: skip when the form is not
 * enabled, evaluate the token, and answer the platform's native
 * failure vocabulary (WP_Error for auth and registration, wp_die for
 * comments, a wc notice for checkout).
 *
 * @package kiwicaptcha
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The controller. Static methods registered as WordPress callbacks.
 */
final class KiwiCaptcha_Controller
{
    public static function init(): void
    {
        add_filter('authenticate', [__CLASS__, 'guardLogin'], 30, 3);
        add_filter('registration_errors', [__CLASS__, 'guardRegistration'], 10, 3);
        add_action('pre_comment_on_post', [__CLASS__, 'guardComment']);
        add_action('init', [__CLASS__, 'registerShortcode']);
        add_action('login_enqueue_scripts', [__CLASS__, 'maybePrintLoginScript'], 5);
        add_action('woocommerce_checkout_process', [__CLASS__, 'guardCheckout']);
        KiwiCaptcha_Settings::init();
    }

    public static function registerShortcode(): void
    {
        add_shortcode('kiwi_captcha', [KiwiCaptcha_Form::class, 'shortcode']);
    }

    public static function maybePrintLoginScript(): void
    {
        if (KiwiCaptcha_Settings::all()['enabled_login']) {
            add_action('login_footer', [KiwiCaptcha_Form::class, 'printLoginScript']);
        }
    }

    /**
     * The authenticate filter runs at priority 30, after the core
     * username/password check at 20, so a wrong password still reports
     * its own error and a missing or failed captcha reports ours.
     *
     * @param WP_User|WP_Error|null $user
     * @param string                $username
     * @param string                $password
     *
     * @return WP_User|WP_Error|null
     */
    public static function guardLogin($user, $username, $password)
    {
        if ($user instanceof WP_Error) {
            return $user;
        }
        $settings = KiwiCaptcha_Settings::all();
        if (!$settings['enabled_login']) {
            return $user;
        }
        $outcome = KiwiCaptcha_Client::evaluate(
            $settings,
            KiwiCaptcha_Form::scopeFor('login'),
            $_SERVER ?? [],
            $_POST ?? []
        );
        if ($outcome['ok']) {
            return $user;
        }

        return new WP_Error(
            'kiwi_captcha_failed',
            __('<strong>Error:</strong> the security check did not pass. Solve the challenge and try again.'),
            ['status' => $outcome['status']]
        );
    }

    /**
     * The registration_errors filter: append our error to the collected
     * ones, so the registration screen shows every problem at once.
     *
     * @param WP_Error $errors
     * @param string   $sanitized_user_login
     * @param string   $user_email
     *
     * @return WP_Error
     */
    public static function guardRegistration($errors, $sanitized_user_login, $user_email)
    {
        $settings = KiwiCaptcha_Settings::all();
        if (!$settings['enabled_signup']) {
            return $errors;
        }
        $outcome = KiwiCaptcha_Client::evaluate(
            $settings,
            KiwiCaptcha_Form::scopeFor('signup'),
            $_SERVER ?? [],
            $_POST ?? []
        );
        if (!$outcome['ok']) {
            $errors->add('kiwi_captcha_failed', __('The security check did not pass. Solve the challenge and try again.'));
        }

        return $errors;
    }

    /**
     * The pre_comment_on_post action: wp_die stops the comment with a
     * back link, the documented pattern for pre-save comment guards.
     */
    public static function guardComment(): void
    {
        $settings = KiwiCaptcha_Settings::all();
        if (!$settings['enabled_comment']) {
            return;
        }
        $outcome = KiwiCaptcha_Client::evaluate(
            $settings,
            KiwiCaptcha_Form::scopeFor('comment'),
            $_SERVER ?? [],
            $_POST ?? []
        );
        if ($outcome['ok']) {
            return;
        }
        wp_die(
            '<p>'.esc_html__('The security check did not pass. Solve the challenge and try again.').'</p>',
            'KiwiCaptcha',
            ['response' => $outcome['status'], 'back_link' => true]
        );
    }

    /**
     * The WooCommerce checkout guard, gated on WooCommerce itself so
     * the hook registers inert without it. A wc_add_notice with the
     * error flag blocks the checkout and renders the message.
     */
    public static function guardCheckout(): void
    {
        if (!class_exists('WooCommerce')) {
            return;
        }
        $settings = KiwiCaptcha_Settings::all();
        if (!$settings['enabled_checkout']) {
            return;
        }
        $outcome = KiwiCaptcha_Client::evaluate(
            $settings,
            KiwiCaptcha_Form::scopeFor('checkout'),
            $_SERVER ?? [],
            $_POST ?? []
        );
        if ($outcome['ok']) {
            return;
        }
        wc_add_notice(__('The security check did not pass. Solve the challenge and try again.'), 'error');
    }
}
