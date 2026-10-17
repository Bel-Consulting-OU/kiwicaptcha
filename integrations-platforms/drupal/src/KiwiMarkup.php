<?php

declare(strict_types=1);

namespace Drupal\kiwicaptcha;

/**
 * The widget markup builder: the render element the form_alter
 * attaches and the theme variables the template consumes. The markup
 * keeps the shim contract: a scoped container with the hidden native
 * token field.
 */
final class KiwiMarkup
{
    /**
     * The form render element: the kiwicaptcha_widget theme hook with
     * its scope and shim_url variables. The #kiwi_scope value also
     * rides the element so the validate handler knows which scope it
     * guards.
     *
     * @return array<string, mixed>
     */
    public static function renderElement(string $scope, string $shimUrl = ''): array
    {
        $sanitized = self::sanitizeScope($scope);

        return [
            '#theme' => 'kiwicaptcha_widget',
            '#scope' => $sanitized,
            '#shim_url' => $shimUrl,
            '#kiwi_scope' => $sanitized,
        ];
    }

    /**
     * The theme variables for the kiwicaptcha_widget template.
     *
     * @return array<string, string>
     */
    public static function themeVariables(string $scope, string $shimUrl): array
    {
        return [
            'scope' => self::sanitizeScope($scope),
            'shim_url' => $shimUrl,
        ];
    }

    /**
     * Scope names are short kiwi identifiers.
     */
    public static function sanitizeScope(string $scope): string
    {
        if (preg_match('/^[A-Za-z0-9_:-]{1,64}$/', $scope) === 1) {
            return $scope;
        }

        return 'login';
    }
}
