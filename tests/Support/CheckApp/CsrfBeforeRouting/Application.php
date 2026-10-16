<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support\CheckApp\CsrfBeforeRouting;

use Authentication\Middleware\AuthenticationMiddleware;
use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\MiddlewareQueue;
use Cake\Routing\Middleware\RoutingMiddleware;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Test\Support\CheckApp\CheckApplication;
use Psr\Http\Message\ServerRequestInterface;

/**
 * An application for `oauth check` that runs CSRF protection before routing and authentication after it.
 */
class Application extends CheckApplication
{
    /**
     * @param \Cake\Http\MiddlewareQueue $middlewareQueue The queue.
     * @return \Cake\Http\MiddlewareQueue
     */
    public function middleware(MiddlewareQueue $middlewareQueue): MiddlewareQueue
    {
        $csrf = new CsrfProtectionMiddleware();
        $csrf->skipCheckCallback(fn(ServerRequestInterface $request): bool => OAuthServer::csrfSkip($request));

        return $middlewareQueue
            ->add($csrf)
            ->add(new RoutingMiddleware($this))
            ->add(new AuthenticationMiddleware($this));
    }

    /**
     * @return list<string>
     */
    protected function authenticators(): array
    {
        return ['CakeDC/OAuthServer.Token', 'Authentication.Session'];
    }
}
