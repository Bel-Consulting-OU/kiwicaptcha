<?php
/**
 * The ACP settings page: reads and writes every config key the
 * captcha plugin consumes (kiwi_verify_url, kiwi_bearer, kiwi_mode,
 * kiwi_trusted_proxies, kiwi_scope and kiwi_shim_url).
 *
 * @package kiwi\captcha\acp
 */

namespace kiwi\captcha\acp;

class main_module
{
    /** @var string the form action phpBB assigns */
    public $u_action;

    /** @var string the template the module renders */
    public $tpl_name;

    /** @var string the page title language key */
    public $page_title;

    /**
     * The module entry point phpBB calls.
     *
     * @param int    $id   the module id
     * @param string $mode the mode name (settings)
     */
    public function main($id, $mode)
    {
        global $config, $request, $template, $user;

        $this->tpl_name = 'acp_kiwi_settings';
        $this->page_title = 'ACP_KIWI_SETTINGS';

        add_form_key('kiwi_captcha');

        if ($request->is_set_post('submit')) {
            if (!check_form_key('kiwi_captcha')) {
                trigger_error($user->lang('FORM_INVALID') . adm_back_link($this->u_action), E_USER_WARNING);
            }

            $wireMode = $request->variable('kiwi_mode', 'json');
            $config->set('kiwi_verify_url', $request->variable('kiwi_verify_url', 'http://127.0.0.1:7371/verify'));
            $config->set('kiwi_bearer', $request->variable('kiwi_bearer', ''));
            $config->set('kiwi_mode', $wireMode === 'compat' ? 'compat' : 'json');
            $config->set('kiwi_trusted_proxies', $request->variable('kiwi_trusted_proxies', ''));
            $config->set('kiwi_scope', $request->variable('kiwi_scope', 'signup'));
            $config->set('kiwi_shim_url', $request->variable('kiwi_shim_url', ''));

            trigger_error($user->lang('ACP_KIWI_SETTINGS_SAVED') . adm_back_link($this->u_action));
        }

        $template->assign_vars([
            'KIWI_VERIFY_URL' => (string) ($config['kiwi_verify_url'] ?? 'http://127.0.0.1:7371/verify'),
            'KIWI_BEARER' => (string) ($config['kiwi_bearer'] ?? ''),
            'KIWI_SHIM_URL' => (string) ($config['kiwi_shim_url'] ?? ''),
            'KIWI_SCOPE' => (string) ($config['kiwi_scope'] ?? 'signup'),
            'KIWI_TRUSTED_PROXIES' => (string) ($config['kiwi_trusted_proxies'] ?? ''),
            'S_KIWI_MODE_JSON' => ($config['kiwi_mode'] ?? 'json') !== 'compat',
            'S_KIWI_MODE_COMPAT' => ($config['kiwi_mode'] ?? 'json') === 'compat',
            'U_ACTION' => $this->u_action,
        ]);
    }
}
