<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support\CheckApp\SessionFirst;

use CakeDC\OAuthServer\Test\Support\CheckApp\CheckApplication;

/**
 * An application for `oauth check`: SessionFirst.
 */
class Application extends CheckApplication
{
    /**
     * @return list<string>
     */
    protected function authenticators(): array
    {
        return ['Authentication.Session', 'CakeDC/OAuthServer.Token'];
    }
}
