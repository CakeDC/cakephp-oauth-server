<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support\CheckApp\TokenHeader;

use Authentication\AuthenticationService;
use Authentication\AuthenticationServiceInterface;
use CakeDC\OAuthServer\Test\Support\CheckApp\CheckApplication;
use Psr\Http\Message\ServerRequestInterface;

/**
 * An application for `oauth check` whose Token authenticator reads another header than Authorization.
 */
class Application extends CheckApplication
{
    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return \Authentication\AuthenticationServiceInterface
     */
    public function getAuthenticationService(ServerRequestInterface $request): AuthenticationServiceInterface
    {
        $service = new AuthenticationService();
        $service->loadAuthenticator('CakeDC/OAuthServer.Token', [
            'resource' => 'http://localhost/api',
            'header' => 'X-Api-Token',
        ]);
        $service->loadAuthenticator('Authentication.Session');

        return $service;
    }

    /**
     * @return list<string>
     */
    protected function authenticators(): array
    {
        return [];
    }
}
