<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support\CheckApp\BeforeRoutingWithoutToken;

use CakeDC\OAuthServer\Test\Support\CheckApp\BeforeRouting\Application as BeforeRouting;

/**
 * An application for `oauth check` that runs CSRF protection and authentication before routing, without the
 * plugin's Token authenticator (its resources live in another application).
 */
class Application extends BeforeRouting
{
    /**
     * @return list<string>
     */
    protected function authenticators(): array
    {
        return ['Authentication.Session'];
    }
}
