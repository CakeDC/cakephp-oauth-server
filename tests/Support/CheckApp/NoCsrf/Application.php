<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support\CheckApp\NoCsrf;

use CakeDC\OAuthServer\Test\Support\CheckApp\CheckApplication;

/**
 * An application for `oauth check`: NoCsrf.
 */
class Application extends CheckApplication
{
    /**
     * @return bool
     */
    protected function withCsrf(): bool
    {
        return false;
    }

    /**
     * @return list<string>
     */
    protected function authenticators(): array
    {
        return ['CakeDC/OAuthServer.Token', 'Authentication.Session'];
    }
}
