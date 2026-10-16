<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support\CheckApp\TwoPaths;

use Authentication\AuthenticationService;
use Authentication\AuthenticationServiceInterface;
use CakeDC\OAuthServer\Test\Support\CheckApp\CheckApplication;
use Psr\Http\Message\ServerRequestInterface;

/**
 * An application for `oauth check` with Token before Session at /mcp, and Session before Token at /api.
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
        $token = ['resource' => 'http://localhost/api'];
        if (str_starts_with($request->getUri()->getPath(), '/mcp')) {
            $service->loadAuthenticator('CakeDC/OAuthServer.Token', $token);
            $service->loadAuthenticator('Authentication.Session');
        } else {
            $service->loadAuthenticator('Authentication.Session');
            $service->loadAuthenticator('CakeDC/OAuthServer.Token', $token);
        }

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
