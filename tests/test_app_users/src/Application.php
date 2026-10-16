<?php
declare(strict_types=1);

namespace UsersTestApp;

use Cake\Error\Middleware\ErrorHandlerMiddleware;
use Cake\Http\BaseApplication;
use Cake\Http\Middleware\BodyParserMiddleware;
use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\MiddlewareQueue;
use Cake\Routing\Middleware\RoutingMiddleware;
use Cake\Routing\RouteBuilder;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\OAuthServerPlugin;
use CakeDC\Users\UsersPlugin;
use Psr\Http\Message\ServerRequestInterface;

/**
 * A host application that uses cakedc/users for login, sessions and RBAC.
 */
class Application extends BaseApplication
{
    /**
     * @return void
     */
    public function bootstrap(): void
    {
        $this->addPlugin(UsersPlugin::class);
        $this->addPlugin(OAuthServerPlugin::class);
    }

    /**
     * @param \Cake\Http\MiddlewareQueue $middlewareQueue The queue.
     * @return \Cake\Http\MiddlewareQueue
     */
    public function middleware(MiddlewareQueue $middlewareQueue): MiddlewareQueue
    {
        $csrf = new CsrfProtectionMiddleware();
        $csrf->skipCheckCallback(fn(ServerRequestInterface $request): bool => OAuthServer::csrfSkip($request));

        $middlewareQueue
            ->add(new ErrorHandlerMiddleware())
            ->add(new RoutingMiddleware($this))
            ->add(new BodyParserMiddleware())
            ->add($csrf);

        // cakedc/users adds its authentication, RBAC authorization and request check middleware.
        return $this->pluginMiddleware($middlewareQueue);
    }

    /**
     * @param \Cake\Routing\RouteBuilder $routes The builder.
     * @return void
     */
    public function routes(RouteBuilder $routes): void
    {
        $routes->scope('/', function (RouteBuilder $builder): void {
            $builder->connect('/api/me', ['controller' => 'Pages', 'action' => 'me']);
        });
    }
}
