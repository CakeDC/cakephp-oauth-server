<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer;

use Cake\Http\ResponseFactory;
use Cake\Http\ServerRequest;
use Cake\Http\StreamFactory;
use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Http\HttpResponder;
use CakeDC\OAuth\Server\Token\ValidatedToken;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Http\RequestPaths;
use CakeDC\OAuthServer\Identity\OAuthIdentity;
use CakeDC\OAuthServer\Server\ServerFactory;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;

/**
 * Static entry point of the plugin for code that has no container at hand.
 */
final class OAuthServer
{
    private const CORE_STYLE_SRC = "style-src 'unsafe-inline'";

    private static ?AuthorizationServer $server = null;

    /**
     * The server, built once from `Configure::read('OAuthServer')`.
     *
     * @return \CakeDC\OAuth\Server\AuthorizationServer
     */
    public static function server(): AuthorizationServer
    {
        return self::$server ??= (new ServerFactory(PluginConfig::fromConfigure()))->create();
    }

    /**
     * A server whose pages render with $request.
     *
     * @internal Used by the plugin's controller; not part of the public API.
     * @param \Cake\Http\ServerRequest $request The current request.
     * @return \CakeDC\OAuth\Server\AuthorizationServer
     */
    public static function forRequest(ServerRequest $request): AuthorizationServer
    {
        return (new ServerFactory(PluginConfig::fromConfigure()))->create($request);
    }

    /**
     * Forgets the built server, for example after changing the configuration in a test.
     *
     * @return void
     */
    public static function reset(): void
    {
        self::$server = null;
    }

    /**
     * Whether $request needs no CSRF token: it goes to an endpoint OAuth clients call (token, register,
     * revoke, introspect), or it carries a valid bearer token of this server where that token is accepted.
     * Use it in CsrfProtectionMiddleware::skipCheckCallback(), with RoutingMiddleware before that middleware.
     *
     * An Authorization header is not an ambient credential: a page on another site cannot make the browser
     * attach a valid token. So a request skips the check for its bearer token only when all of this holds:
     *
     * - the token has this server's access or personal prefix (`<prefix>_at_`, `<prefix>_pat_`) and validates
     *   (the core's TokenValidator, without recording a use) for a declared resource; a garbage, expired or
     *   revoked token with the right prefix is CSRF checked like any other request;
     * - that resource's token paths cover the request: by default the path of the resource, or
     *   `OAuthServer.tokenPaths` for every resource, or $paths. A resource at the host root has no path of its own;
     * - both the request path and the static part of the template of the route that matched it are within those
     *   paths (see TokenAuthenticator); a request that was not routed yet (CSRF middleware before
     *   RoutingMiddleware) is never skipped for a bearer token.
     *
     * The consent and connections pages are session pages and are never skipped, with or without a bearer token.
     * Paths are compared after the normalisation the router applies, and a path with `%2F`, an empty segment or
     * `.` / `..` segments is never skipped. When the configuration cannot be read or the server cannot be built,
     * nothing is skipped and no error escapes.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param list<string>|null $paths Path prefixes where a bearer token of any declared resource is accepted, when
     *   the application's Token authenticator uses custom `paths`; null for the configured ones.
     * @return bool
     */
    public static function csrfSkip(ServerRequestInterface $request, ?array $paths = null): bool
    {
        try {
            return self::skipsCsrf($request, $paths);
        } catch (Throwable) {
            // A broken configuration, a server that cannot be built or a failing lookup never skips the check.
            return false;
        }
    }

    /**
     * csrfSkip(), allowed to throw.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param list<string>|null $paths Path prefixes, or null for the configured ones.
     * @return bool
     */
    private static function skipsCsrf(ServerRequestInterface $request, ?array $paths): bool
    {
        $config = PluginConfig::fromConfigure();
        $prefix = $config->routePrefix();
        $path = RequestPaths::normalize($request->getUri()->getPath());
        if ($path === null) {
            return false;
        }
        foreach (['token', 'register', 'revoke', 'introspect'] as $endpoint) {
            if ($path === RequestPaths::normalize($prefix . '/' . $endpoint)) {
                return true;
            }
        }
        foreach (['authorize', 'connections'] as $page) {
            if (strtolower($path) === strtolower((string)RequestPaths::normalize($prefix . '/' . $page))) {
                return false;
            }
        }
        $token = self::bearerToken($request);
        if ($token === null) {
            return false;
        }
        $own = $config->tokenPrefix();
        if (!str_starts_with($token, $own . '_at_') && !str_starts_with($token, $own . '_pat_')) {
            return false;
        }
        if ($paths !== null) {
            $paths = array_values(array_filter(array_map(RequestPaths::normalize(...), $paths), 'is_string'));
        }
        $resources = [];
        foreach ($config->resourcePaths() as $resource => $resourcePaths) {
            if (RequestPaths::routedWithin($request, $paths ?? $resourcePaths)) {
                $resources[] = $resource;
            }
        }
        if ($resources === []) {
            return false;
        }
        // Only now is the server needed: a request without such a token never builds it.
        $validator = self::server()->tokenValidator();
        foreach ($resources as $resource) {
            if ($validator->validate($token, $resource, false) instanceof ValidatedToken) {
                return true;
            }
        }

        return false;
    }

    /**
     * The bearer token of the Authorization header, or null.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return string|null
     */
    private static function bearerToken(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine('Authorization');
        if (preg_match('/^Bearer +([A-Za-z0-9\-._~+\/]+=*) *\z/i', $header, $matches) !== 1) {
            return null;
        }

        return $matches[1];
    }

    /**
     * The Content-Security-Policy a page needs when its layout is the application's, or null when the
     * page uses the plugin's own layout (the core's policy is then right as it is).
     *
     * The core sets the policy `default-src 'none'; style-src 'unsafe-inline'; ...` on every page. An
     * application layout normally links stylesheets, images and fonts of the same origin, so this adds
     * `style-src 'self'`, `img-src 'self' data:` and `font-src 'self'`. It never touches `script-src`
     * (layout scripts do not run), `frame-ancestors` or `base-uri`. The pages' controller applies the
     * result with `withHeader('Content-Security-Policy', ...)` after the core built the response.
     *
     * @internal Used by the plugin's controller; not part of the public API.
     * @param bool $connections True for the connections page, false for the consent and error pages.
     * @return string|null
     */
    public static function pageCsp(bool $connections = false): ?string
    {
        $config = PluginConfig::fromConfigure();
        $layout = $connections ? $config->connectionsLayout() : $config->consentLayout();
        if (!is_string($layout)) {
            return null;
        }
        $core = (new HttpResponder(new ResponseFactory(), new StreamFactory()))
            ->page('')
            ->getHeaderLine('Content-Security-Policy');
        if (!str_contains($core, self::CORE_STYLE_SRC)) {
            // The core's policy changed shape: keep it rather than guess.
            return null;
        }

        return str_replace(
            self::CORE_STYLE_SRC,
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'",
            $core,
        );
    }

    /**
     * The validated token of a request authenticated by TokenAuthenticator, also through
     * cakephp/authorization's IdentityDecorator; null otherwise.
     */
    public static function token(ServerRequestInterface $request): ?ValidatedToken
    {
        return OAuthIdentity::fromRequest($request);
    }

    /**
     * RBAC rules (cakedc/auth) that let every OAuth endpoint through; the endpoints decide access
     * themselves (login for the consent and connections pages, client authentication for the rest).
     *
     * @return list<array<string, mixed>>
     */
    public static function rbacPermissions(): array
    {
        return [
            [
                'role' => '*',
                'plugin' => 'CakeDC/OAuthServer',
                'controller' => 'OAuth',
                'action' => '*',
                'bypassAuth' => true,
            ],
        ];
    }
}
