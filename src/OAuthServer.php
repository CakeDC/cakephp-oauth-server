<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer;

use Cake\Http\ResponseFactory;
use Cake\Http\ServerRequest;
use Cake\Http\StreamFactory;
use Cake\Routing\Router;
use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Http\HttpResponder;
use CakeDC\OAuth\Server\Token\ValidatedToken;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Http\RequestPaths;
use CakeDC\OAuthServer\Identity\OAuthIdentity;
use CakeDC\OAuthServer\Log\CakeLogger;
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
     * revoke, introspect), or it is on the routes of a resource and carries either no credential a browser
     * attaches by itself or a valid bearer token of this server.
     * Use it in CsrfProtectionMiddleware::skipCheckCallback(), with RoutingMiddleware before that middleware.
     *
     * CSRF protects ambient credentials: what a browser sends by itself when a page on another site posts to this
     * one. An Authorization header with a bearer token is not one (no page can make the browser attach it). On the
     * routes of a resource a request is therefore skipped when:
     *
     * - it carries no cookie (neither a `Cookie` header nor cookie parameters), no HTTP Basic or Digest
     *   credentials (`PHP_AUTH_USER`, `PHP_AUTH_DIGEST`), no user the web server authenticated (`REMOTE_USER`) and
     *   no Authorization header with another scheme than `Bearer`. Then CSRF protects nothing, and the Token
     *   authenticator or the route answers: 401 with its challenge for an expired, revoked, foreign or made up
     *   token, so clients learn to refresh or to sign in again (MCP clients POST every message). The application's
     *   login page, `OAuthServer.login.url`, is never skipped this way, even when the token paths cover it;
     * - or it carries a cookie and a bearer token with this server's access or personal prefix (`<prefix>_at_`,
     *   `<prefix>_pat_`) that validates (the core's TokenValidator, without recording a use) for a resource whose
     *   paths cover it. A garbage, expired or revoked token sent with a cookie is CSRF checked like any other
     *   request, so it cannot carry a session request past CSRF.
     *
     * The routes of a resource are its token paths: by default the path of the resource, or `OAuthServer.tokenPaths`
     * for every resource, or $paths. A resource at the host root has no path of its own. Both the request path and
     * the static part of the template of the route that matched it must be within those paths (see
     * TokenAuthenticator); a request that was not routed yet (CSRF middleware before RoutingMiddleware) is never
     * skipped there.
     *
     * The consent and connections pages are session pages and are never skipped, whatever the request carries.
     * Paths are compared after the normalisation the router applies, and a path with `%2F`, an empty segment or
     * `.` / `..` segments is never skipped.
     *
     * It never throws. The client endpoints are found where the plugin connected them, so they are skipped with
     * any configuration, a broken one included (they then answer 503). The server is built only for a request
     * with a cookie and a bearer token with this server's prefix within the token paths, because only that token
     * needs validating; when the configuration cannot be read, the server cannot be built or the lookup fails,
     * that request is not skipped and a warning goes to the `oauth` log (never the token). So is a request whose
     * token paths or login page cannot be read.
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
        } catch (Throwable $e) {
            // Only the resource branches can fail, and they never skip the check then.
            (new CakeLogger())->warning(
                'CSRF protection was not skipped for a request to {path}: {message}',
                ['path' => $request->getUri()->getPath(), 'message' => $e->getMessage(), 'exception' => $e],
            );

            return false;
        }
    }

    /**
     * csrfSkip(), allowed to throw where it reads the resources, the login page or the token.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param list<string>|null $paths Path prefixes, or null for the configured ones.
     * @return bool
     */
    private static function skipsCsrf(ServerRequestInterface $request, ?array $paths): bool
    {
        $config = PluginConfig::fromConfigure();
        // Where the routes are, whatever the rest of the configuration says.
        $prefix = $config->lenientRouting()['prefix'];
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
        if ($paths !== null) {
            $paths = array_values(array_filter(array_map(RequestPaths::normalize(...), $paths), 'is_string'));
        }
        if (!self::carriesAmbientCredentials($request)) {
            // Nothing a browser attaches by itself, so CSRF protects nothing: on the routes of a resource the Token
            // authenticator or the route answers, with its 401 and challenge. The login signs people in without a
            // session, so it stays checked.
            return self::resourcesCovering($request, $config, $paths) !== []
                && !self::isLoginPage($request, $config);
        }
        $token = self::bearerToken($request);
        if ($token === null) {
            return false;
        }
        $own = $config->configuredTokenPrefix();
        if ($own === null || !str_starts_with($token, $own . '_at_') && !str_starts_with($token, $own . '_pat_')) {
            return false;
        }
        $resources = self::resourcesCovering($request, $config, $paths);
        if ($resources === []) {
            return false;
        }
        // Only now is the server needed: a request without a cookie, or without such a token, never builds it.
        $validator = self::server()->tokenValidator();
        try {
            foreach ($resources as $resource) {
                if ($validator->validate($token, $resource, false) instanceof ValidatedToken) {
                    return true;
                }
            }
        } catch (Throwable $e) {
            // A failing lookup: its message could quote the query, so the log gets the class and place only.
            (new CakeLogger())->warning(
                'CSRF protection was not skipped for a bearer request to {path}: the token could not be validated.',
                ['path' => $request->getUri()->getPath(), 'exception' => $e],
            );
        }

        return false;
    }

    /**
     * The declared resources whose token paths ($paths for all of them when given) cover $request as routed.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param \CakeDC\OAuthServer\Config\PluginConfig $config The configuration.
     * @param list<string>|null $paths Normalized path prefixes, or null for the configured ones.
     * @return list<string>
     */
    private static function resourcesCovering(
        ServerRequestInterface $request,
        PluginConfig $config,
        ?array $paths,
    ): array {
        $resources = [];
        foreach ($config->resourcePaths() as $resource => $resourcePaths) {
            if (RequestPaths::routedWithin($request, $paths ?? $resourcePaths)) {
                $resources[] = $resource;
            }
        }

        return $resources;
    }

    /**
     * Whether $request carries something a browser sends by itself to this site, which a page on another site
     * could make it send: a cookie, HTTP Basic or Digest credentials, a user the web server authenticated, or an
     * Authorization header of another scheme than Bearer.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return bool
     */
    private static function carriesAmbientCredentials(ServerRequestInterface $request): bool
    {
        if ($request->getHeaderLine('Cookie') !== '' || $request->getCookieParams() !== []) {
            return true;
        }
        $authorization = $request->getHeaderLine('Authorization');
        if ($authorization !== '' && preg_match('/^Bearer(?:[ \t]|$)/i', $authorization) !== 1) {
            return true;
        }
        $server = $request->getServerParams();
        foreach (['PHP_AUTH_USER', 'PHP_AUTH_DIGEST', 'REMOTE_USER'] as $name) {
            if (isset($server[$name]) && $server[$name] !== '') {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether $request goes to the application's login page (`OAuthServer.login.url`), compared like the consent
     * page: after normalisation, base directory included, in any case.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param \CakeDC\OAuthServer\Config\PluginConfig $config The configuration.
     * @return bool
     */
    private static function isLoginPage(ServerRequestInterface $request, PluginConfig $config): bool
    {
        $login = $config->login()['url'];
        if (is_array($login) && !isset($login['_name'])) {
            // As SessionUserContext builds it: Router::url() would fill plugin and prefix from the current request.
            $login += ['plugin' => false, 'prefix' => false];
        }
        $path = parse_url(Router::url($login), PHP_URL_PATH);
        $login = is_string($path) ? RequestPaths::normalize($path) : null;
        $here = RequestPaths::fullPath($request);

        return $login === null || $here === null || strtolower($login) === strtolower($here);
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
     * The rule lists the endpoint actions one by one, so an action added to the controller later does not
     * inherit the bypass by accident.
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
                'action' => ['metadata', 'authorize', 'token', 'register', 'revoke', 'introspect', 'connections'],
                'bypassAuth' => true,
            ],
        ];
    }
}
