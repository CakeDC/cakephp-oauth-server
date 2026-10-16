<?php
declare(strict_types=1);

namespace TestApp;

use ArrayAccess;
use Authentication\AuthenticationService;
use Authentication\AuthenticationServiceInterface;
use Authentication\AuthenticationServiceProviderInterface;
use Authentication\Identity;
use Authentication\Middleware\AuthenticationMiddleware;
use Authorization\AuthorizationService;
use Authorization\AuthorizationServiceInterface;
use Authorization\AuthorizationServiceProviderInterface;
use Authorization\Middleware\AuthorizationMiddleware;
use Authorization\Policy\MapResolver;
use Cake\Core\Configure;
use Cake\Error\Middleware\ErrorHandlerMiddleware;
use Cake\Http\BaseApplication;
use Cake\Http\Middleware\BodyParserMiddleware;
use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\MiddlewareQueue;
use Cake\Routing\Middleware\RoutingMiddleware;
use Cake\Routing\RouteBuilder;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\OAuthServerPlugin;
use Psr\Http\Message\ServerRequestInterface;

/**
 * A host application with the usual middleware: CSRF, session authentication, the plugin's token
 * authenticator and an authorization middleware that requires a check on every action.
 */
class Application extends BaseApplication implements
    AuthenticationServiceProviderInterface,
    AuthorizationServiceProviderInterface
{
    /**
     * @return void
     */
    public function bootstrap(): void
    {
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

        return $middlewareQueue
            ->add(new ErrorHandlerMiddleware())
            ->add(new RoutingMiddleware($this))
            ->add(new BodyParserMiddleware())
            ->add($csrf)
            ->add(new AuthenticationMiddleware($this))
            ->add(new AuthorizationMiddleware($this, [
                'requireAuthorizationCheck' => true,
                'identityAttribute' => Configure::read('TestApp.identityAttribute', 'identity'),
            ]));
    }

    /**
     * @param \Cake\Routing\RouteBuilder $routes The builder.
     * @return void
     */
    public function routes(RouteBuilder $routes): void
    {
        $routes->scope('/', function (RouteBuilder $builder): void {
            $builder->connect('/login', ['controller' => 'Pages', 'action' => 'login']);
            $builder->connect('/api/me', ['controller' => 'Pages', 'action' => 'me']);
            // Deeper API routes, and a sibling whose name starts with "api".
            $builder->connect('/api/**', ['controller' => 'Pages', 'action' => 'me']);
            $builder->connect('/apix/**', ['controller' => 'Pages', 'action' => 'me']);
            // A session route that changes state.
            // Routes whose first segment is a free parameter: an encoded slash must not reach them as a path,
            // and a path that looks like a resource's (/mcp/account/delete) must not carry its token there.
            $builder->connect('/{tenant}/account/delete', ['controller' => 'Pages', 'action' => 'deleteAccount']);
            $builder->connect('/{slug}', ['controller' => 'Pages', 'action' => 'deleteAccount'])
                ->setPatterns(['slug' => '[^/]+']);
            $builder->connect('/account/delete', ['controller' => 'Pages', 'action' => 'deleteAccount']);
            $builder->fallbacks();
        });
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return \Authentication\AuthenticationServiceInterface
     */
    public function getAuthenticationService(ServerRequestInterface $request): AuthenticationServiceInterface
    {
        $config = ['identityAttribute' => Configure::read('TestApp.identityAttribute', 'identity')];
        $key = Configure::read('TestApp.identityKey');
        if (is_string($key)) {
            // A host whose people are keyed by another column than `id`.
            $config['identityClass'] = fn(array|ArrayAccess $data): Identity => new Identity($data, [
                'fieldMap' => ['id' => $key],
            ]);
        }
        $service = new AuthenticationService($config);
        // Tests may point the authenticator at another resource or give it other paths.
        $token = (array)Configure::read('TestApp.tokenAuthenticator', ['resource' => 'http://localhost/api']);
        if (Configure::read('TestApp.sessionFirst') === true) {
            // A host that got the order wrong: the session is tried before the token.
            $service->loadAuthenticator('Authentication.Session', ['sessionKey' => 'Auth']);
            $service->loadAuthenticator('CakeDC/OAuthServer.Token', $token);

            return $service;
        }
        // The token comes first: a session cookie must not hide a revoked or foreign bearer token.
        $service->loadAuthenticator('CakeDC/OAuthServer.Token', $token);
        $service->loadAuthenticator('Authentication.Session', ['sessionKey' => 'Auth']);

        return $service;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return \Authorization\AuthorizationServiceInterface
     */
    public function getAuthorizationService(ServerRequestInterface $request): AuthorizationServiceInterface
    {
        return new AuthorizationService(new MapResolver());
    }
}
