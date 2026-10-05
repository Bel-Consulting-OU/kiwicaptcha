<?php
/**
 * The ACP language entries for the kiwi captcha plugin.
 */

if (!defined('IN_PHPBB')) {
    exit;
}

$lang = array_merge($lang ?? [], [
    'CAPTCHA_KIWI_TITLE' => 'KiwiCaptcha',
    'CAPTCHA_KIWI_TITLE_EXPLAIN' => 'Proof-of-work CAPTCHA verified against a self-hosted KiwiCaptcha deployment.',
    'KIWI_VERIFY_URL' => 'Verify URL',
    'KIWI_VERIFY_URL_EXPLAIN' => 'The deployment endpoint: the verifier sidecar /verify or a siteverify route.',
    'KIWI_BEARER' => 'Bearer secret',
    'KIWI_BEARER_EXPLAIN' => 'Set only when the deployment requires its bearer credential.',
    'KIWI_SHIM_URL' => 'Shim script URL',
    'KIWI_SHIM_URL_EXPLAIN' => 'The deployment compat loader, e.g. https://kiwi.example.com/kiwi-captcha/api.js?compat=recaptcha.',
    'KIWI_SCOPE' => 'Scope',
    'KIWI_SCOPE_EXPLAIN' => 'The challenge scope the board sends, e.g. signup.',
    'KIWI_MODE' => 'Wire format',
    'KIWI_MODE_JSON' => 'json (sidecar /verify)',
    'KIWI_MODE_COMPAT' => 'compat (siteverify: response/secret)',
    'KIWI_TRUST_PROXY' => 'Trust X-Forwarded-For',
]);
