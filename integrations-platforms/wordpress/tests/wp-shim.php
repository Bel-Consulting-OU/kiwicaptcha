<?php

declare(strict_types=1);

/**
 * The WordPress function shim layer: the small surface the plugin
 * actually touches, implemented as an in-memory test double. Loaded
 * before the plugin file in tests; nothing here is used in WordPress
 * itself.
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__.'/');
}

$GLOBALS['kiwi_test'] = [
    'options' => [],
    'filters' => [],
    'actions' => [],
    'shortcodes' => [],
    'http' => [],       // canned wp_remote_post responses keyed by URL
    'http_log' => [],   // recorded requests
    'die' => null,      // the last wp_die payload
    'notices' => [],    // wc_add_notice calls
    'settings_registered' => 0,
    'sections' => [],
    'fields' => [],
];

function add_filter(string $tag, callable $callback, int $priority = 10, int $accepted_args = 1): bool
{
    $GLOBALS['kiwi_test']['filters'][$tag][] = compact('callback', 'priority', 'accepted_args');

    return true;
}

function apply_filters(string $tag, $value, ...$args)
{
    foreach ($GLOBALS['kiwi_test']['filters'][$tag] ?? [] as $entry) {
        $value = call_user_func_array($entry['callback'], array_merge([$value], $args));
    }

    return $value;
}

function add_action(string $tag, callable $callback, int $priority = 10, int $accepted_args = 1): bool
{
    $GLOBALS['kiwi_test']['actions'][$tag][] = compact('callback', 'priority', 'accepted_args');

    return true;
}

function do_action(string $tag, ...$args): void
{
    foreach ($GLOBALS['kiwi_test']['actions'][$tag] ?? [] as $entry) {
        call_user_func_array($entry['callback'], $args);
    }
}

function add_shortcode(string $tag, callable $callback): bool
{
    $GLOBALS['kiwi_test']['shortcodes'][$tag] = $callback;

    return true;
}

function do_shortcode(string $content): string
{
    foreach ($GLOBALS['kiwi_test']['shortcodes'] as $tag => $callback) {
        if (strpos($content, "[{$tag}") !== false) {
            return (string) $callback([]);
        }
    }

    return $content;
}

function shortcode_atts(array $defaults, $atts, string $shortcode = ''): array
{
    $atts = is_array($atts) ? $atts : [];

    return array_merge($defaults, array_intersect_key($atts, $defaults));
}

function get_option(string $name, $default = false)
{
    return $GLOBALS['kiwi_test']['options'][$name] ?? $default;
}

function update_option(string $name, $value): bool
{
    $GLOBALS['kiwi_test']['options'][$name] = $value;

    return true;
}

function register_setting(string $group, string $name, array $args = []): void
{
    ++$GLOBALS['kiwi_test']['settings_registered'];
}

function add_settings_section(string $id, string $title, $callback, string $page): void
{
    $GLOBALS['kiwi_test']['sections'][$id] = $title;
}

function add_settings_field(string $id, string $title, $callback, string $page, string $section, array $args = []): void
{
    $GLOBALS['kiwi_test']['fields'][$id] = $title;
}

function settings_fields(string $group): void
{
}

function do_settings_sections(string $page): void
{
}

function submit_button(): void
{
}

function add_options_page(string $title, string $menu, string $cap, string $slug, $callback): void
{
}

function wp_remote_post(string $url, array $args = [])
{
    $GLOBALS['kiwi_test']['http_log'][] = ['url' => $url, 'args' => $args];
    if (isset($GLOBALS['kiwi_test']['http'][$url])) {
        return $GLOBALS['kiwi_test']['http'][$url];
    }

    return ['response' => ['code' => 0], 'body' => ''];
}

function wp_remote_retrieve_body($response): string
{
    return is_array($response) ? (string) ($response['body'] ?? '') : '';
}

function wp_remote_retrieve_response_code($response): int
{
    return is_array($response) ? (int) ($response['response']['code'] ?? 0) : 0;
}

function is_wp_error($thing): bool
{
    return $thing instanceof WP_Error;
}

function wp_json_encode($data)
{
    return json_encode($data);
}

function wp_die($message = '', $title = '', $args = [])
{
    $GLOBALS['kiwi_test']['die'] = ['message' => $message, 'title' => $title, 'args' => $args];
    throw new KiwiTestDie();
}

class KiwiTestDie extends Exception
{
}

class WP_Error
{
    public $codes = [];

    public $messages = [];

    public $errors_data = [];

    public function __construct($code = '', $message = '', $data = [])
    {
        if ($code !== '') {
            $this->codes[] = $code;
            $this->messages[$code] = $message;
            $this->errors_data[$code] = $data;
        }
    }

    public function add(string $code, string $message, $data = []): void
    {
        $this->codes[] = $code;
        $this->messages[$code] = $message;
        $this->errors_data[$code] = $data;
    }

    public function get_error_code()
    {
        return $this->codes[0] ?? '';
    }
}

class WP_User
{
    public $ID = 1;
}

function wc_add_notice(string $message, string $type = 'notice'): void
{
    $GLOBALS['kiwi_test']['notices'][] = ['message' => $message, 'type' => $type];
}

function sanitize_text_field($str): string
{
    return is_string($str) ? trim(strip_tags($str)) : '';
}

function esc_attr($str): string
{
    return htmlspecialchars((string) $str, ENT_QUOTES);
}

function esc_url(string $url): string
{
    return $url;
}

function esc_html($str): string
{
    return htmlspecialchars((string) $str, ENT_QUOTES);
}

function wp_unslash($value)
{
    return $value;
}

function __($text, $domain = null): string
{
    return $text;
}

function plugin_dir_path(string $file): string
{
    return rtrim(dirname($file), '/').'/';
}

class WooCommerce
{
}

function esc_html__($text, $domain = null): string
{
    return htmlspecialchars((string) $text, ENT_QUOTES);
}

function esc_attr__($text, $domain = null): string
{
    return htmlspecialchars((string) $text, ENT_QUOTES);
}
