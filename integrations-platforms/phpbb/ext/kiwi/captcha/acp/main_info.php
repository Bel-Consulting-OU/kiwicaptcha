<?php
/**
 * The ACP module metadata for the kiwi captcha extension: one
 * "settings" mode under the Extensions tab. phpBB discovers this file
 * (acp/main_info.php) when the extension is enabled, so no separate
 * metadata declaration is needed.
 *
 * @package kiwi\captcha\acp
 */

namespace kiwi\captcha\acp;

class main_info
{
    /**
     * The module descriptor phpBB's ACP module manager consumes.
     *
     * @return array<string, mixed>
     */
    public function module()
    {
        return [
            'filename' => '\kiwi\captcha\acp\main_module',
            'title' => 'ACP_KIWI_SETTINGS',
            'modes' => [
                'settings' => [
                    'title' => 'ACP_KIWI_SETTINGS',
                    'auth' => 'ext_kiwi/captcha && acl_a_board',
                    'cat' => ['ACP_CAT_DOT_MODS'],
                ],
            ],
        ];
    }
}
