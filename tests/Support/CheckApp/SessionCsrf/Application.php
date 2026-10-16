<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support\CheckApp\SessionCsrf;

use Cake\Http\Middleware\SessionCsrfProtectionMiddleware;
use Cake\Http\MiddlewareQueue;
use Cake\Routing\Middleware\RoutingMiddleware;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Test\Support\CheckApp\CheckApplication;
use Psr\Http\Message\ServerRequestInterface;

/**
 * An application for `oauth check` that keeps its CSRF token in the session.
 */
class Application extends CheckApplication
{
    /**
     * @param \Cake\Http\MiddlewareQueue $middlewareQueue The queue.
     * @return \Cake\Http\MiddlewareQueue
     */
    public function middleware(MiddlewareQueue $middlewareQueue): MiddlewareQueue
    {
        $csrf = new SessionCsrfProtectionMiddleware();
        $csrf->skipCheckCallback(fn(ServerRequestInterface $request): bool => OAuthServer::csrfSkip($request));

        return $middlewareQueue->add(new RoutingMiddleware($this))->add($csrf);
    }

    /**
     * @return list<string>
     */
    protected function authenticators(): array
    {
        return ['CakeDC/OAuthServer.Token', 'Authentication.Session'];
    }
}
