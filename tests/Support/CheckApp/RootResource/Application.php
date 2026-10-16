<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support\CheckApp\RootResource;

use CakeDC\OAuthServer\Test\Support\CheckApp\CheckApplication;

/**
 * An application for `oauth check` whose Token authenticator is for a resource at the host root.
 */
class Application extends CheckApplication
{
    /**
     * @return string
     */
    protected function resource(): string
    {
        return 'http://localhost';
    }

    /**
     * @return list<string>
     */
    protected function authenticators(): array
    {
        return ['CakeDC/OAuthServer.Token'];
    }
}
