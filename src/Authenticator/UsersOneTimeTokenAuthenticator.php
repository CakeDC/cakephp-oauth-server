<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Authenticator;

use Authentication\Authenticator\Result;
use Authentication\Authenticator\ResultInterface;
use CakeDC\Auth\Authenticator\OneTimeTokenAuthenticator;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Http\RequestPaths;
use Psr\Http\Message\ServerRequestInterface;

/**
 * cakedc/auth's one-time login (`CakeDC/Auth.OneTimeToken`), except on the plugin's routes.
 *
 * That authenticator reads a `token` parameter from the query or the body of every request and looks it up in
 * the users table. RFC 7009 and RFC 7662 name the parameter of `/oauth/revoke` and `/oauth/introspect` `token`
 * too, so without this a refresh token sent there would be compared with the users' login tokens, and land in
 * clear in the query log (debug, DebugKit, `log => true`). The cakedc/users integration puts this class in place
 * of cakedc/auth's when the application uses that one; it behaves the same everywhere else.
 *
 * @internal
 */
class UsersOneTimeTokenAuthenticator extends OneTimeTokenAuthenticator
{
    /**
     * @inheritDoc
     */
    public function authenticate(ServerRequestInterface $request): ResultInterface
    {
        if (self::isPluginRoute($request)) {
            return new Result(null, Result::FAILURE_CREDENTIALS_MISSING);
        }

        return parent::authenticate($request);
    }

    /**
     * Whether $request goes to the plugin: by the route that matched it, or before routing, by its path below
     * the route prefix.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return bool
     */
    private static function isPluginRoute(ServerRequestInterface $request): bool
    {
        $params = $request->getAttribute('params');
        if (is_array($params) && isset($params['controller'])) {
            return ($params['plugin'] ?? null) === 'CakeDC/OAuthServer';
        }
        $path = RequestPaths::normalize($request->getUri()->getPath());
        $prefix = RequestPaths::normalize(PluginConfig::fromConfigure()->lenientRouting()['prefix']);

        return $path === null || $prefix === null || RequestPaths::within(strtolower($path), [strtolower($prefix)]);
    }
}
