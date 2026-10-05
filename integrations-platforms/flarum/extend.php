<?php

/*
 * This file is part of kiwi/flarum-captcha.
 *
 * The extender wiring: the api middleware guards the registration
 * endpoint, the forum frontend ships the client asset, and the
 * settings drive the verify call.
 */

use Flarum\Extend;
use Kiwi\FlarumCaptcha\Api\Middleware\VerifySignupMiddleware;

return [
    (new Extend\Frontend('forum'))
        ->js(__DIR__.'/js/dist/forum.js'),

    (new Extend\Middleware('api'))
        ->add(VerifySignupMiddleware::class),

    (new Extend\Settings())
        ->serializeToForum('kiwiSignupScope', 'kiwi-signup-scope'),
];
