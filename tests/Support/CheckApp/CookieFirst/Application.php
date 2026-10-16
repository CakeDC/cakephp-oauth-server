<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support\CheckApp\CookieFirst;

use CakeDC\OAuthServer\Test\Support\CheckApp\CheckApplication;

/**
 * An application for `oauth check`: a remember-me Cookie authenticator before the Token one.
 */
class Application extends CheckApplication
{
    /**
     * @return list<string>
     */
    protected function authenticators(): array
    {
        return ['Authentication.Cookie', 'CakeDC/OAuthServer.Token'];
    }
}
