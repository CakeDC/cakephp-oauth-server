<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support\CheckApp\SkipAll;

use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\MiddlewareQueue;
use Cake\Routing\Middleware\RoutingMiddleware;
use CakeDC\OAuthServer\Test\Support\CheckApp\CheckApplication;

/**
 * An application for `oauth check` whose CSRF callback skips every request.
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
        $csrf->skipCheckCallback(fn(): bool => true);

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
