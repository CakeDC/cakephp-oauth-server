<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Controller;

use Cake\Controller\Controller;
use Cake\Http\Exception\ServiceUnavailableException;
use Cake\Http\Response;
use Cake\Routing\Router;
use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuthServer\Log\CakeLogger;
use CakeDC\OAuthServer\OAuthServer;
use Closure;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Throwable;

/**
 * Hands every OAuth request to the matching core handler.
 *
 * The controller extends Cake's base controller, never the host's, so the host's components and
 * middleware-like hooks cannot change how the endpoints behave.
 */
class OAuthController extends Controller
{
    /**
     * GET {metadataPath}.
     *
     * @return \Cake\Http\Response
     */
    public function metadata(): Response
    {
        return $this->dispatchTo(
            fn(AuthorizationServer $server): RequestHandlerInterface => $server->metadataHandler(),
        );
    }

    /**
     * GET and POST {prefix}/authorize.
     *
     * @return \Cake\Http\Response
     */
    public function authorize(): Response
    {
        $response = $this->dispatchTo(
            fn(AuthorizationServer $server): RequestHandlerInterface => $server->authorizeHandler(),
        );

        // The consent page and its error pages use the consent layout.
        return $this->withPageCsp($response, false);
    }

    /**
     * POST {prefix}/token.
     *
     * @return \Cake\Http\Response
     */
    public function token(): Response
    {
        return $this->dispatchTo(fn(AuthorizationServer $server): RequestHandlerInterface => $server->tokenHandler());
    }

    /**
     * POST {prefix}/register.
     *
     * @return \Cake\Http\Response
     */
    public function register(): Response
    {
        return $this->dispatchTo(
            fn(AuthorizationServer $server): RequestHandlerInterface => $server->registerHandler(),
        );
    }

    /**
     * POST {prefix}/revoke.
     *
     * @return \Cake\Http\Response
     */
    public function revoke(): Response
    {
        return $this->dispatchTo(fn(AuthorizationServer $server): RequestHandlerInterface => $server->revokeHandler());
    }

    /**
     * POST {prefix}/introspect.
     *
     * @return \Cake\Http\Response
     */
    public function introspect(): Response
    {
        return $this->dispatchTo(
            fn(AuthorizationServer $server): RequestHandlerInterface => $server->introspectHandler(),
        );
    }

    /**
     * GET and POST {prefix}/connections.
     *
     * @return \Cake\Http\Response
     */
    public function connections(): Response
    {
        $response = $this->dispatchTo(
            fn(AuthorizationServer $server): RequestHandlerInterface => $server->connectionsHandler(),
        );
        // After an action the core sends the person back to the page (303) with an application-relative path,
        // which needs the base directory. The login redirect (302) was built with Router::url() and has it.
        $location = $response->getHeaderLine('Location');
        if (
            $response->getStatusCode() === 303
            && str_starts_with($location, '/')
            && !str_starts_with($location, '//')
        ) {
            $response = $response->withHeader('Location', Router::url($location));
        }

        // The page itself (200, or 422 after a refused token) uses the connections layout; every other
        // HTML response is the error page, which renders with the consent layout.
        $page = in_array($response->getStatusCode(), [200, 422], true);

        return $this->withPageCsp($response, $page);
    }

    /**
     * Runs a core handler on this request.
     *
     * Skips the host's `cakephp/authorization` check when that plugin is in use: the endpoints decide for
     * themselves who may do what.
     *
     * @param \Closure(\CakeDC\OAuth\Server\AuthorizationServer): \Psr\Http\Server\RequestHandlerInterface $pick
     *   Chooses the handler.
     * @return \Cake\Http\Response
     */
    private function dispatchTo(Closure $pick): Response
    {
        $authorization = $this->request->getAttribute('authorization');
        if (is_object($authorization) && method_exists($authorization, 'skipAuthorization')) {
            $authorization->skipAuthorization();
        }
        try {
            $server = OAuthServer::forRequest($this->request);
        } catch (Throwable $e) {
            return $this->unavailable($e);
        }

        return $this->toCakeResponse($pick($server)->handle($this->request));
    }

    /**
     * The answer of every endpoint while the `OAuthServer` configuration is invalid: 503, and the reason in the
     * `oauth` log. The machine endpoints answer JSON; the consent and connections pages raise the exception the
     * application's error page renders. The rest of the application is not affected.
     *
     * @param \Throwable $error Why the server could not be built.
     * @return \Cake\Http\Response
     * @throws \Cake\Http\Exception\ServiceUnavailableException On the consent and connections pages.
     */
    private function unavailable(Throwable $error): Response
    {
        (new CakeLogger())->error(
            'The OAuth endpoint {path} is unavailable: the OAuth server configuration is invalid. {message}',
            [
                'path' => $this->request->getUri()->getPath(),
                'message' => $error->getMessage(),
                'exception' => $error,
            ],
        );
        if (in_array($this->request->getParam('action'), ['authorize', 'connections'], true)) {
            throw new ServiceUnavailableException(
                __d('oauth_server', 'The authorization service is not available right now. Try again later.'),
            );
        }

        return $this->response
            ->withStatus(503)
            ->withType('application/json')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache')
            ->withStringBody((string)json_encode([
                'error' => 'temporarily_unavailable',
                'error_description' => 'The authorization server is not available right now.',
            ]));
    }

    /**
     * Extends the page's Content-Security-Policy when an application layout is configured.
     *
     * @param \Cake\Http\Response $response The core's response.
     * @param bool $connections True for the connections page, false for the consent and error pages.
     * @return \Cake\Http\Response
     */
    private function withPageCsp(Response $response, bool $connections): Response
    {
        if (!$response->hasHeader('Content-Security-Policy')) {
            return $response;
        }
        $csp = OAuthServer::pageCsp($connections);

        return $csp === null ? $response : $response->withHeader('Content-Security-Policy', $csp);
    }

    /**
     * $response as a Cake response.
     *
     * @param \Psr\Http\Message\ResponseInterface $response The core's response.
     * @return \Cake\Http\Response
     */
    private function toCakeResponse(ResponseInterface $response): Response
    {
        if ($response instanceof Response) {
            return $response;
        }
        $converted = (new Response())
            ->withStatus($response->getStatusCode(), $response->getReasonPhrase())
            ->withBody($response->getBody());
        foreach ($response->getHeaders() as $name => $values) {
            $converted = $converted->withHeader($name, $values);
        }

        return $converted;
    }
}
