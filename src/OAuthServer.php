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
use InvalidArgumentException;
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
     * revoke, introspect), or it is on the routes of a resource and carries either a bearer token of this server
     * or no credential at all.
     * Use it in CsrfProtectionMiddleware::skipCheckCallback(), with RoutingMiddleware before that middleware.
     *
     * CSRF protects ambient credentials: what a browser sends by itself when a page on another site posts to this
     * one. On the routes of a resource a request is therefore skipped when:
     *
     * - it carries `Authorization: Bearer <token>` with this server's access or personal prefix (`<prefix>_at_`,
     *   `<prefix>_pat_`), whatever else it carries. Only the prefix is read; the token is never looked up. A page on
     *   another site cannot make a browser attach an Authorization header unless this application approves a CORS
     *   preflight with credentials for that site, and an application that does has given that site everything CSRF
     *   protects already. The Token authenticator answers the request: a valid token runs as its owner, an expired,
     *   revoked, foreign or made up one gets 401 with its challenge, so clients learn to refresh or to sign in again
     *   (MCP clients POST every message). With the Token authenticator before the session, cookie and form
     *   authenticators (`oauth check` fails otherwise) the session is never consulted for such a request;
     * - or it carries no Authorization header at all, no cookie other than the CSRF middleware's own (named by
     *   `OAuthServer.csrfCookieName`, default `csrfToken`: the middleware sets it on any GET, so clients with a
     *   cookie jar send it back, and it proves nothing), no HTTP Basic or Digest credentials (`PHP_AUTH_USER`,
     *   `PHP_AUTH_DIGEST`) and no user the web server authenticated (`REMOTE_USER`). Then CSRF protects nothing, and
     *   the route answers (an MCP endpoint's 401 starts a client's discovery).
     *
     * Everything else keeps the check: a session, remember-me or load balancer cookie without a bearer token of this
     * server, another Authorization scheme, another server's token.
     *
     * The routes of a resource are its token paths: by default the path of the resource, or `OAuthServer.tokenPaths`
     * for every resource, or $paths. A resource at the host root has no path of its own. Both the request path and
     * the static part of the template of the route that matched it must be within those paths (see
     * TokenAuthenticator); a request that was not routed yet (CSRF middleware before RoutingMiddleware) is never
     * skipped there.
     *
     * The consent and connections pages are session pages and are never skipped, whatever the request carries, and
     * neither is the application's login page (`OAuthServer.login.url`) when the token paths cover it: its path, and
     * for a URL array also every route to the same action (plugin, prefix, controller, action and the positional
     * values the array gives), such as a fallback route. Paths are compared after the normalisation the router
     * applies, and a path with `%2F`, an empty segment or `.` / `..` segments is never skipped.
     *
     * It never throws and never builds the server. The client endpoints are found where the plugin connected them,
     * so they are skipped with any configuration, a broken one included (they then answer 503). When the resources,
     * the issuer or the token paths cannot be read, nothing else is skipped and a warning goes to the `oauth` log
     * (never the token); so is a request without a token whose login page cannot be told.
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
     * csrfSkip(), allowed to throw where it reads the resources or the login page.
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
        $bearer = self::carriesBearerOfThisServer($request, $config);
        if (!$bearer && !self::carriesNoCredential($request, $config)) {
            return false;
        }
        if ($paths !== null) {
            $paths = array_values(array_filter(array_map(RequestPaths::normalize(...), $paths), 'is_string'));
        }
        if (!self::onResourceRoutes($request, $config, $paths)) {
            return false;
        }
        if ($bearer) {
            try {
                return !self::isLoginPage($request, $config);
            } catch (Throwable) {
                // Which page is the login cannot be told; no page on another site can send this request, so it is
                // no login CSRF either.
                return true;
            }
        }

        // The login signs people in without a session, so it stays checked.
        return !self::isLoginPage($request, $config);
    }

    /**
     * Whether the route that matched $request lies within the token paths of a declared resource ($paths for all of
     * them when given).
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param \CakeDC\OAuthServer\Config\PluginConfig $config The configuration.
     * @param list<string>|null $paths Normalized path prefixes, or null for the configured ones.
     * @return bool
     */
    private static function onResourceRoutes(ServerRequestInterface $request, PluginConfig $config, ?array $paths): bool
    {
        foreach ($config->resourcePaths() as $resourcePaths) {
            if (RequestPaths::routedWithin($request, $paths ?? $resourcePaths)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether $request carries `Authorization: Bearer <token>` where the token has this server's access or personal
     * prefix. Only the prefix is read: the token is never looked up.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param \CakeDC\OAuthServer\Config\PluginConfig $config The configuration.
     * @return bool
     */
    private static function carriesBearerOfThisServer(ServerRequestInterface $request, PluginConfig $config): bool
    {
        $token = self::bearerToken($request);
        $own = $token === null ? null : $config->configuredTokenPrefix();

        return $token !== null && $own !== null
            && (str_starts_with($token, $own . '_at_') || str_starts_with($token, $own . '_pat_'));
    }

    /**
     * Whether $request carries nothing a browser could send by itself: no Authorization header, no HTTP Basic or
     * Digest credentials PHP took from one, no user the web server authenticated, and no cookie but the CSRF
     * middleware's own. A configured cookie name that is not one leaves no cookie to ignore.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param \CakeDC\OAuthServer\Config\PluginConfig $config The configuration.
     * @return bool
     */
    private static function carriesNoCredential(ServerRequestInterface $request, PluginConfig $config): bool
    {
        if ($request->hasHeader('Authorization')) {
            return false;
        }
        $server = $request->getServerParams();
        foreach (['PHP_AUTH_USER', 'PHP_AUTH_DIGEST', 'REMOTE_USER'] as $name) {
            if (isset($server[$name]) && $server[$name] !== '') {
                return false;
            }
        }
        $names = array_map('strval', array_keys($request->getCookieParams()));
        // Cookie values hold no `;` or `,`, so this splits several Cookie headers too.
        foreach (preg_split('/[;,]/', $request->getHeaderLine('Cookie')) ?: [] as $pair) {
            if (trim($pair) !== '') {
                $names[] = trim(explode('=', $pair, 2)[0]);
            }
        }
        if ($names === []) {
            return true;
        }
        try {
            $csrf = $config->csrfCookieName();
        } catch (InvalidArgumentException) {
            return false;
        }

        return array_diff($names, [$csrf]) === [];
    }

    /**
     * Whether $request goes to the application's login page (`OAuthServer.login.url`): its path, compared like the
     * consent page (after normalisation, base directory included, in any case), or for a URL array also any route to
     * the same action.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param \CakeDC\OAuthServer\Config\PluginConfig $config The configuration.
     * @return bool
     * @throws \InvalidArgumentException When that cannot be told: the setting cannot be read, its named route does
     *   not exist, or its path cannot be compared.
     */
    private static function isLoginPage(ServerRequestInterface $request, PluginConfig $config): bool
    {
        $login = $config->login()['url'];
        if (is_string($login)) {
            return self::isAtPath($request, Router::url($login));
        }
        if (isset($login['_name'])) {
            $route = Router::getRouteCollection()->named()[(string)$login['_name']] ?? null;
            if ($route === null) {
                throw new InvalidArgumentException(sprintf(
                    'no route is named "%s", the name of the login (OAuthServer.login.url).',
                    (string)$login['_name'],
                ));
            }
            $action = $route->defaults;
        } else {
            // As SessionUserContext builds it: Router::url() would fill plugin and prefix from the current request.
            $login += ['plugin' => false, 'prefix' => false];
            $action = $login;
        }
        if (self::isRoutedTo($request, $action)) {
            return true;
        }
        try {
            $url = Router::url($login);
        } catch (Throwable) {
            // No route builds it; the action decided.
            return false;
        }

        return self::isAtPath($request, $url);
    }

    /**
     * Whether $request is at the path of $url, after normalisation, base directory included, in any case. A URL
     * without a path is the root.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param string $url The URL, as Router::url() builds it.
     * @return bool
     * @throws \InvalidArgumentException When the path of $url cannot be compared.
     */
    private static function isAtPath(ServerRequestInterface $request, string $url): bool
    {
        $path = parse_url($url, PHP_URL_PATH);
        $login = $path === false ? null : RequestPaths::normalize($path ?? '/');
        if ($login === null) {
            throw new InvalidArgumentException('the path of the login URL (OAuthServer.login.url) cannot be compared.');
        }
        $here = RequestPaths::fullPath($request);

        return $here === null || strtolower($login) === strtolower($here);
    }

    /**
     * Whether the router sent $request to the action $action names: the same plugin, prefix, controller and action
     * (in any case), with the positional values $action gives first among the passed ones.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param array<array-key, mixed> $action A URL array, or the defaults of a route.
     * @return bool
     */
    private static function isRoutedTo(ServerRequestInterface $request, array $action): bool
    {
        $params = $request->getAttribute('params');
        if (!is_array($params) || !is_string($action['controller'] ?? null)) {
            return false;
        }
        $name = fn(mixed $value): string => is_string($value) ? strtolower($value) : '';
        foreach (['plugin', 'prefix', 'controller'] as $key) {
            if ($name($params[$key] ?? null) !== $name($action[$key] ?? null)) {
                return false;
            }
        }
        if ($name($params['action'] ?? null) !== $name($action['action'] ?? 'index')) {
            return false;
        }
        $passed = is_array($params['pass'] ?? null) ? array_values($params['pass']) : [];
        $given = array_values(array_filter($action, 'is_int', ARRAY_FILTER_USE_KEY));
        foreach ($given as $position => $value) {
            $was = $passed[$position] ?? null;
            if (!is_scalar($value) || !is_scalar($was) || (string)$value !== (string)$was) {
                return false;
            }
        }

        return true;
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
