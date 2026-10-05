<?php
/**
 * @package     KiwiCaptcha
 * @subpackage  plg_captcha_kiwicaptcha
 *
 * The Joomla captcha plugin: it implements the platform's captcha
 * plugin contract, the three event methods the core Captcha factory
 * invokes on the active captcha plugin:
 *
 *   onInit()          one-time client setup: emit the shim script tag
 *   onDisplay()       the widget markup for a form
 *   onCheckAnswer()   the server-side verification, boolean answer
 *
 * Verification goes to the configured kiwi deployment through
 * Kiwi\Plugin\Captcha\Kiwicaptcha\KiwiClient, the framework-free
 * client this plugin ships in src/.
 */

defined('_JEXEC') or die;

require_once __DIR__.'/src/KiwiClient.php';

use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\Plugin\Captcha\Kiwicaptcha\KiwiClient;

/**
 * The KiwiCaptcha captcha plugin.
 */
class PlgCaptchaKiwicaptcha extends CMSPlugin
{
    /**
     * Load the plugin language files automatically.
     *
     * @var boolean
     */
    protected $autoloadLanguage = true;

    /**
     * The application object, injected by Joomla 4+ when present.
     *
     * @var \Joomla\CMS\Application\CMSApplicationInterface|null
     */
    protected $app;

    /**
     * The plugin params as one array, the shape KiwiClient consumes.
     *
     * @return array<string, mixed>
     */
    protected function clientParams(): array
    {
        return [
            'verify_url' => (string) $this->params->get('verify_url', 'http://127.0.0.1:7371/verify'),
            'bearer' => (string) $this->params->get('bearer', ''),
            'mode' => $this->params->get('mode', 'json') === 'compat' ? 'compat' : 'json',
            'trust_proxy' => (string) $this->params->get('trust_proxy', '0') === '1',
        ];
    }

    /**
     * onInit: the one-time client setup. Emits the shim script tag
     * into the document head when a shim URL is configured; without
     * one, the form author is expected to load the deployment script
     * some other way.
     *
     * @param  string  $id  The id of the widget container.
     *
     * @return boolean
     */
    public function onInit($id = 'kiwicaptcha_1'): bool
    {
        $shimUrl = (string) $this->params->get('shim_url', '');
        if ($shimUrl === '' || !Factory::getDocument()) {
            return true;
        }
        $doc = Factory::getDocument();
        $doc->addScript($shimUrl, ['defer' => true]);

        return true;
    }

    /**
     * onDisplay: the widget markup. The container carries the scope so
     * the shim renders into it, plus the hidden native token field the
     * form submits.
     *
     * @param  string  $name   The name of the form field.
     * @param  string  $id     The id of the form field.
     * @param  string  $class  Extra classes for the container.
     *
     * @return string the widget html
     */
    public function onDisplay($name = null, $id = 'kiwicaptcha_1', $class = ''): string
    {
        $scope = KiwiClient::sanitizeScope((string) $this->params->get('scope', 'login'));
        $classAttr = htmlspecialchars('kiwi-container '.(string) $class, ENT_QUOTES, 'UTF-8');

        return '<div class="'.$classAttr.'" id="'.htmlspecialchars((string) $id, ENT_QUOTES, 'UTF-8').'"'
            .' data-kiwi-scope="'.htmlspecialchars($scope, ENT_QUOTES, 'UTF-8').'">'
            .'<input type="hidden" name="kiwi__token" data-kiwi-token value="">'
            .'</div>';
    }

    /**
     * onCheckAnswer: the server-side verification. The core Captcha
     * dispatcher passes the request's answer value; the client also
     * reads the header and the cookie, so any shim surface works.
     *
     * @param  string|null  $code  The answer value from the form.
     *
     * @return boolean true when the challenge verified
     */
    public function onCheckAnswer($code = null): bool
    {
        $app = $this->app ?? null;
        $input = $app !== null && property_exists($app, 'input') ? $app->input : null;
        $server = $input !== null && isset($input->server) ? (array) $input->server->getRaw() : ($_SERVER ?? []);
        $post = $input !== null && isset($input->post) ? (array) $input->post->getRaw() : ($_POST ?? []);
        $cookie = (array) ($_COOKIE ?? []);

        $token = KiwiClient::extractToken($server, $post, $cookie, is_string($code) ? $code : null);
        if ($token === null) {
            return false;
        }

        return KiwiClient::verify(
            $this->clientParams(),
            $token,
            KiwiClient::sanitizeScope((string) $this->params->get('scope', 'login')),
            $server
        )['ok'];
    }
}
