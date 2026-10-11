<?php

declare(strict_types=1);

/**
 * rt.kernel.routes.php — the routes of the red-team product kernel:
 * the login page, the firewall's check path, the protected account
 * page and the step-up begin/complete paths the bundle's controller
 * serves (the application registers its own routes for the configured
 * begin_path/complete_path, exactly as the bundle documents).
 */

use KiwiRt\RtAccountPageController;
use KiwiRt\RtLoginPageController;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

return static function (RoutingConfigurator $routes): void {
    // The bundle's own routes (the challenge endpoint and friends):
    // a deployment that configures framework.router imports the
    // bundle's routes file manually, exactly as the extension's
    // prepend hook documents.
    $routes->import(
        __DIR__ . '/../../../../packages/kiwicaptcha/integrations/symfony/src/Resources/config/routes.php',
        'php',
    );
    $routes->add('rt_login', '/login')
        ->controller([RtLoginPageController::class, 'login']);
    $routes->add('rt_login_check', '/login_check')
        ->controller([RtLoginPageController::class, 'login'])
        ->methods(['POST']);
    $routes->add('rt_account', '/account')
        ->controller([RtAccountPageController::class, 'account']);
    $routes->add('rt_step_up_begin', '/step-up/begin')
        ->controller([\BelConsulting\KiwiCaptchaBundle\Controller\StepUpController::class, 'begin']);
    $routes->add('rt_step_up_complete', '/step-up/complete')
        ->controller([\BelConsulting\KiwiCaptchaBundle\Controller\StepUpController::class, 'complete']);
};
