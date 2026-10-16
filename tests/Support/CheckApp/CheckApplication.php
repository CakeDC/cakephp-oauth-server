<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support\CheckApp;

use Authentication\AuthenticationService;
use Authentication\AuthenticationServiceInterface;
use Authentication\AuthenticationServiceProviderInterface;
use Cake\Http\BaseApplication;
use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\MiddlewareQueue;
use CakeDC\OAuthServer\OAuthServer;
use Psr\Http\Message\ServerRequestInterface;

/**
 * An application for `oauth check` to inspect; the subclasses vary the CSRF middleware and the authenticators.
 */
abstract class CheckApplication extends BaseApplication implements AuthenticationServiceProviderInterface
{
    /**
     * @return void
     */
    public function bootstrap(): void
    {
    }

    /**
     * @param \Cake\Http\MiddlewareQueue $middlewareQueue The queue.
     * @return \Cake\Http\MiddlewareQueue
     */
    public function middleware(MiddlewareQueue $middlewareQueue): MiddlewareQueue
    {
        if ($this->withCsrf()) {
            $csrf = new CsrfProtectionMiddleware();
            $csrf->skipCheckCallback(fn(ServerRequestInterface $request): bool => OAuthServer::csrfSkip($request));
            $middlewareQueue->add($csrf);
        }

        return $middlewareQueue;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return \Authentication\AuthenticationServiceInterface
     */
    public function getAuthenticationService(ServerRequestInterface $request): AuthenticationServiceInterface
    {
        $service = new AuthenticationService();
        foreach ($this->authenticators() as $name) {
            $service->loadAuthenticator($name, $name === 'Authentication.Session' ? [] : [
                'resource' => $this->resource(),
            ]);
        }

        return $service;
    }

    /**
     * @return bool
     */
    protected function withCsrf(): bool
    {
        return true;
    }

    /**
     * @return string
     */
    protected function resource(): string
    {
        return 'http://localhost/api';
    }

    /**
     * @return list<string>
     */
    abstract protected function authenticators(): array;
}
