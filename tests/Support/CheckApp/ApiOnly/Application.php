<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support\CheckApp\ApiOnly;

use Authentication\AuthenticationService;
use Authentication\AuthenticationServiceInterface;
use CakeDC\OAuthServer\Test\Support\CheckApp\CheckApplication;
use Psr\Http\Message\ServerRequestInterface;

/**
 * An application for `oauth check` that loads the Token authenticator for its API paths only.
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
        if (str_starts_with($request->getUri()->getPath(), '/api')) {
            $service->loadAuthenticator('CakeDC/OAuthServer.Token', ['resource' => 'http://localhost/api']);
        }
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
