<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Integration;

use Cake\Core\Configure;
use Cake\Http\ServerRequest;
use CakeDC\Auth\Rbac\Rbac;
use CakeDC\Auth\Rbac\RbacInterface;
use CakeDC\OAuthServer\Config\PluginConfig;
use InvalidArgumentException;

/**
 * Wires the plugin into cakedc/users: authenticator and RBAC rules.
 *
 * @internal
 */
final class UsersIntegration
{
    /**
     * Registers the token authenticator (in front of the others) and the RBAC rules provider, keeping
     * what the application set.
     *
     * The authenticator validates against `OAuthServer.users.resource` when set, otherwise against the
     * server's default resource, and only below `OAuthServer.users.paths` or `OAuthServer.tokenPaths` when
     * set, otherwise below the path of that resource.
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
            ];
            $config = PluginConfig::fromConfigure();
            $resource = $config->usersResource();
            if ($resource !== null) {
                $settings['resource'] = $resource;
            }
            $paths = $config->effectiveUsersPaths();
            if (is_string($paths)) {
                // Without this the authenticator would throw on every web request, the login page included.
                throw new InvalidArgumentException(
                    'The cakedc/users integration cannot register the Token authenticator: ' . $paths . '.',
                );
            }
            if ($config->usersPaths() !== null) {
                $settings['paths'] = $paths;
            }
            // First in line: the first authenticator that succeeds wins, so a session cookie sent along with a
            // revoked or foreign bearer token would otherwise run as the session user, the token unchecked.
            $others = Configure::read('Auth.Authenticators');
            $others = is_array($others) ? $others : [];
            Configure::write('Auth.Authenticators', ['OAuthServerToken' => $settings] + $others);
        }
        // Rules cannot be put in Configure: cakedc/auth replaces them when it loads `config/permissions.php`.
        // The RbacPolicy of cakedc/users hands its `adapter` settings to Rbac.
        if (Configure::read('Auth.RbacPolicy.adapter.permissions_provider_class') === null) {
            Configure::write('Auth.RbacPolicy.adapter.permissions_provider_class', RbacPermissionsProvider::class);
        }
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
        $path = PluginConfig::fromConfigure()->routePrefix() . '/token';
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
