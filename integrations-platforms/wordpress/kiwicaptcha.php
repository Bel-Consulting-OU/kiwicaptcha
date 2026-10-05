<?php
/**
 * Plugin Name: KiwiCaptcha
 * Plugin URI: https://kiwicaptcha.example
 * Description: Proof-of-work CAPTCHA for login, registration, comments and WooCommerce checkout, verified against your self-hosted KiwiCaptcha deployment. Incumbent widget markup (reCAPTCHA, hCaptcha, Turnstile, ALTCHA, Friendly Captcha) keeps working through the deployment's shims.
 * Version: 1.0.0
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Author: KiwiCaptcha contributors
 * License: MIT
 * Text Domain: kiwicaptcha
 *
 * The plugin is server-to-server only: it never calls a third-party
 * captcha host. Verification goes to the configured kiwi deployment
 * (the verifier sidecar's /verify or the deployment's siteverify
 * route), and the client side loads the deployment's own shim script.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('KIWICAPTCHA_VERSION')) {
    define('KIWICAPTCHA_VERSION', '1.0.0');
}
if (!defined('KIWICAPTCHA_DIR')) {
    define('KIWICAPTCHA_DIR', plugin_dir_path(__FILE__));
}

require_once KIWICAPTCHA_DIR.'includes/class-kiwicaptcha-settings.php';
require_once KIWICAPTCHA_DIR.'includes/class-kiwicaptcha-client.php';
require_once KIWICAPTCHA_DIR.'includes/class-kiwicaptcha-form.php';
require_once KIWICAPTCHA_DIR.'includes/class-kiwicaptcha-controller.php';

KiwiCaptcha_Controller::init();
