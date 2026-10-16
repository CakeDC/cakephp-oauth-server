<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Integration;

use Cake\Core\Configure;
use Cake\Http\ServerRequest;
use CakeDC\Auth\Authenticator\OneTimeTokenAuthenticator;
use CakeDC\Auth\Rbac\Rbac;
use CakeDC\Auth\Rbac\RbacInterface;
use CakeDC\OAuthServer\Authenticator\UsersOneTimeTokenAuthenticator;
use CakeDC\OAuthServer\Config\PluginConfig;
use Throwable;

/**
 * Wires the plugin into cakedc/users: authenticator and RBAC rules.
 *
 * @internal
 */
final class UsersIntegration
{
    /**
     * cakedc/auth's one-time login authenticator, which the integration replaces with
     * UsersOneTimeTokenAuthenticator.
     */
    private const ONE_TIME_TOKEN = ['CakeDC/Auth.OneTimeToken', OneTimeTokenAuthenticator::class];

    private const GUARDED_ONE_TIME_TOKEN = 'CakeDC/OAuthServer.UsersOneTimeToken';

    /**
     * Registers the token authenticator (in front of the others) and the RBAC rules provider, keeping
     * what the application set, and keeps cakedc/auth's one-time login from reading the tokens sent to the
     * OAuth endpoints.
     *
     * The authenticator validates against `OAuthServer.users.resource` when set, otherwise against the
     * server's default resource, and only below `OAuthServer.users.paths` or `OAuthServer.tokenPaths` when
     * set, otherwise below the path of that resource.
     *
     * It never throws: the authenticator is registered whatever the configuration says, and resolves it on the
     * first bearer token of this server. An invalid `users` or `tokenPaths` setting keeps the server from being
     * built, and a resource at the host root without paths is refused by the authenticator itself, so in both
     * cases every token of this server gets 401 while the rest of the application keeps working; `oauth check`
     * reports the setting to fix.
     *
     * @return void
     */
    public static function apply(): void
    {
        if (!Configure::check('Auth.Authenticators.OAuthServerToken')) {
            $settings = [
                // Its own class name, so the alias does not clash with the `Token` authenticator of cakedc/users.
                'className' => 'CakeDC/OAuthServer.OAuthServerToken',
                'skipTwoFactorVerify' => true,
            ] + self::tokenSettings();
            // First in line: the first authenticator that succeeds wins, so a session cookie sent along with a
            // revoked or foreign bearer token would otherwise run as the session user, the token unchecked.
            $others = Configure::read('Auth.Authenticators');
            $others = is_array($others) ? $others : [];
            Configure::write('Auth.Authenticators', ['OAuthServerToken' => $settings] + $others);
        }
        if (in_array(Configure::read('Auth.Authenticators.OneTimeToken.className'), self::ONE_TIME_TOKEN, true)) {
            Configure::write('Auth.Authenticators.OneTimeToken.className', self::GUARDED_ONE_TIME_TOKEN);
        }
        // Rules cannot be put in Configure: cakedc/auth replaces them when it loads `config/permissions.php`.
        // The RbacPolicy of cakedc/users hands its `adapter` settings to Rbac.
        if (Configure::read('Auth.RbacPolicy.adapter.permissions_provider_class') === null) {
            Configure::write('Auth.RbacPolicy.adapter.permissions_provider_class', RbacPermissionsProvider::class);
        }
    }

    /**
     * The `resource` and `paths` of the integration's Token authenticator; none of them when the settings cannot
     * be read (the server cannot be built then, so the authenticator refuses every token of this server).
     *
     * @return array<string, mixed>
     */
    private static function tokenSettings(): array
    {
        try {
            $config = PluginConfig::fromConfigure();
            $settings = [];
            $resource = $config->usersResource();
            if ($resource !== null) {
                $settings['resource'] = $resource;
            }
            $paths = $config->usersPaths();
            if ($paths !== null) {
                $settings['paths'] = $paths;
            }

            return $settings;
        } catch (Throwable) {
            return [];
        }
    }

    /**
     * Whether the one-time login authenticator of cakedc/auth (which reads `token` from every request) is the
     * plugin's guarded one, or the reason it is not.
     *
     * @return string|null Null when it is guarded or not configured; otherwise what `oauth check` warns about.
     */
    public static function oneTimeTokenWarning(): ?string
    {
        $configured = Configure::read('Auth.Authenticators.OneTimeToken');
        if ($configured === null) {
            return null;
        }
        $class = is_array($configured) ? ($configured['className'] ?? null) : $configured;
        if ($class === self::GUARDED_ONE_TIME_TOKEN || $class === UsersOneTimeTokenAuthenticator::class) {
            return null;
        }

        return sprintf(
            'the one-time login authenticator (Auth.Authenticators.OneTimeToken, %s) reads a "token" parameter '
            . 'on every route, so tokens sent to the revoke and introspect endpoints reach the users table and the '
            . 'query log; use %s or load CakeDC/Users before this plugin',
            is_string($class) ? $class : 'no className',
            self::GUARDED_ONE_TIME_TOKEN,
        );
    }

    /**
     * Whether RBAC lets an anonymous request reach the token endpoint.
     *
     * @return array{0: 'pass'|'warn'|'fail', 1: string}
     */
    public static function rbacReport(): array
    {
        if (!class_exists(Rbac::class)) {
            return ['warn', 'cakedc/auth is not installed'];
        }
        $path = PluginConfig::fromConfigure()->lenientRouting()['prefix'] . '/token';
        $adapter = Configure::read('Auth.RbacPolicy.adapter');
        $adapter = is_array($adapter) ? $adapter : [];
        $class = $adapter['className'] ?? Rbac::class;
        unset($adapter['className']);
        $rbac = is_string($class) && is_a($class, RbacInterface::class, true) ? new $class($adapter) : null;
        if ($rbac === null) {
            return ['warn', 'the RBAC adapter is not a cakedc/auth Rbac; its rules were not inspected'];
        }
        $request = (new ServerRequest(['url' => $path]))->withAttribute('params', [
            'plugin' => 'CakeDC/OAuthServer',
            'controller' => 'OAuth',
            'action' => 'token',
            'prefix' => null,
            'pass' => [],
        ]);

        return $rbac->checkPermissions([], $request)
            ? ['pass', 'RBAC lets the OAuth endpoints through']
            : ['fail', 'RBAC denies the OAuth endpoints; add OAuthServer::rbacPermissions() to config/permissions.php'];
    }
}
