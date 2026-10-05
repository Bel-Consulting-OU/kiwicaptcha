<?php

declare(strict_types=1);

namespace Drupal\kiwicaptcha\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * The settings form: the deployment surfaces, the bearer secret, the
 * wire format and a scope plus enable switch per protected form.
 */
final class SettingsForm extends ConfigFormBase
{
    public const SETTINGS = 'kiwicaptcha.settings';

    public function getFormId(): string
    {
        return 'kiwicaptcha_settings';
    }

    /**
     * @return list<string>
     */
    protected function getEditableConfigNames(): array
    {
        return [self::SETTINGS];
    }

    public function buildForm(array $form, FormStateInterface $form_state): array
    {
        $config = $this->config(self::SETTINGS);

        $form['deployment'] = [
            '#type' => 'details',
            '#title' => $this->t('KiwiCaptcha deployment'),
            '#open' => true,
        ];
        $form['deployment']['verify_url'] = [
            '#type' => 'url',
            '#title' => $this->t('Verify URL'),
            '#default_value' => $config->get('verify_url'),
            '#description' => $this->t('The sidecar endpoint or the siteverify route.'),
            '#required' => true,
        ];
        $form['deployment']['shim_url'] = [
            '#type' => 'url',
            '#title' => $this->t('Shim script URL'),
            '#default_value' => $config->get('shim_url'),
            '#description' => $this->t('The deployment compat loader, for example https://kiwi.example.com/kiwi-captcha/api.js?compat=recaptcha.'),
        ];
        $form['deployment']['bearer'] = [
            '#type' => 'password',
            '#title' => $this->t('Bearer secret'),
            '#default_value' => $config->get('bearer'),
            '#description' => $this->t('Stored in configuration; prefer a secrets override in production.'),
        ];
        $form['deployment']['mode'] = [
            '#type' => 'select',
            '#title' => $this->t('Wire format'),
            '#options' => [
                'json' => $this->t('json (sidecar /verify)'),
                'compat' => $this->t('compat (siteverify: response/secret)'),
            ],
            '#default_value' => $config->get('mode') ?: 'json',
        ];
        $form['deployment']['trust_proxy'] = [
            '#type' => 'checkbox',
            '#title' => $this->t('Honor X-Forwarded-For as the client ip'),
            '#default_value' => (bool) $config->get('trust_proxy'),
        ];

        $form['forms'] = [
            '#type' => 'details',
            '#title' => $this->t('Protected forms'),
            '#open' => true,
        ];
        foreach (['login' => 'Login', 'signup' => 'Registration', 'comment' => 'Comments', 'contact' => 'Contact forms'] as $scope => $title) {
            $form['forms']['enabled_'.$scope] = [
                '#type' => 'checkbox',
                '#title' => $title,
                '#default_value' => (bool) $config->get('enabled_'.$scope),
            ];
            $form['forms']['scope_'.$scope] = [
                '#type' => 'textfield',
                '#title' => $this->t('@title scope', ['@title' => $title]),
                '#default_value' => $config->get('scope_'.$scope) ?: $scope,
                '#states' => [
                    'visible' => [
                        ':input[name="enabled_'.$scope.'"]' => ['checked' => true],
                    ],
                ],
            ];
        }

        return parent::buildForm($form, $form_state);
    }

    public function submitForm(array &$form, FormStateInterface $form_state): void
    {
        $config = $this->config(self::SETTINGS);
        $config
            ->set('verify_url', (string) $form_state->getValue('verify_url'))
            ->set('shim_url', (string) $form_state->getValue('shim_url'))
            ->set('bearer', (string) $form_state->getValue('bearer'))
            ->set('mode', (string) $form_state->getValue('mode'))
            ->set('trust_proxy', (bool) $form_state->getValue('trust_proxy'));
        foreach (['login', 'signup', 'comment', 'contact'] as $scope) {
            $config
                ->set('enabled_'.$scope, (bool) $form_state->getValue('enabled_'.$scope))
                ->set('scope_'.$scope, (string) $form_state->getValue('scope_'.$scope));
        }
        $config->save();

        parent::submitForm($form, $form_state);
    }
}
