<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Command;

use Authentication\AuthenticationService;
use Authentication\AuthenticationServiceProviderInterface;
use Authentication\Authenticator\SessionAuthenticator;
use Cake\Cache\Cache;
use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Cake\Core\App;
use Cake\Core\Configure;
use Cake\Core\Exception\CakeException;
use Cake\Core\Plugin;
use Cake\Database\Connection;
use Cake\Database\Driver\Mysql;
use Cake\Datasource\ConnectionManager;
use Cake\Http\BaseApplication;
use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\MiddlewareQueue;
use Cake\Http\ServerRequest;
use Cake\Log\Engine\BaseLog;
use Cake\Log\Log;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\Routing\Exception\MissingRouteException;
use Cake\Routing\Router;
use Cake\Utility\Inflector;
use Cake\Utility\Security;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuthServer\Authenticator\TokenAuthenticator;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Identity\OrmUserProvider;
use CakeDC\OAuthServer\Integration\UsersIntegration;
use ReflectionProperty;
use Throwable;

/**
 * `bin/cake oauth check`: tells what is missing for the server to work.
 *
 * It never prints secrets, token values or hashes.
 */
class OAuthCheckCommand extends Command
{
    use LocatorAwareTrait;

    private const TABLES = ['oauth_clients', 'oauth_authorization_codes', 'oauth_tokens', 'oauth_consents'];

    private const MIN_SECRET_LENGTH = 32;

    /**
     * @inheritDoc
     */
    public static function defaultName(): string
    {
        return 'oauth check';
    }

    /**
     * @inheritDoc
     */
    public function execute(Arguments $args, ConsoleIo $io): int
    {
        $failed = false;
        foreach ($this->checks() as $name => $probe) {
            try {
                [$status, $message] = $probe();
            } catch (Throwable $e) {
                [$status, $message] = ['fail', $e->getMessage()];
            }
            $tag = ['pass' => 'success', 'warn' => 'warning', 'fail' => 'error'][$status];
            $io->out(sprintf('<%s>[%s] %s: %s</%s>', $tag, strtoupper($status), $name, $message, $tag));
            $failed = $failed || $status === 'fail';
        }

        return $failed ? static::CODE_ERROR : static::CODE_SUCCESS;
    }

    /**
     * The checks, in order.
     *
     * @return array<string, callable(): array{0: 'pass'|'warn'|'fail', 1: string}>
     */
    protected function checks(): array
    {
        $config = PluginConfig::fromConfigure();

        return [
            'Secret' => fn(): array => $this->secret(),
            'Configuration' => function () use ($config): array {
                $server = $config->serverConfig();
                new TokenGenerator($server->tokenPrefix);

                return [
                    'pass',
                    sprintf(
                        '%d resource(s), endpoints under %s',
                        count($server->resources->all()),
                        $server->endpointUrl(''),
                    ),
                ];
            },
            'Issuer' => fn(): array => $this->issuer($config),
            'Tables' => fn(): array => $this->tables(),
            'Users' => function () use ($config): array {
                $settings = $config->userProvider();
                if ($settings['className'] !== OrmUserProvider::class) {
                    return ['pass', 'custom user provider'];
                }
                $table = $this->fetchTable($settings['table']);

                return $table->hasFinder($settings['finder'])
                    ? ['pass', sprintf('%s with finder "%s"', $settings['table'], $settings['finder'])]
                    : ['fail', sprintf('%s has no finder "%s"', $settings['table'], $settings['finder'])];
            },
            'Users integration' => function () use ($config): array {
                if (!Plugin::isLoaded('CakeDC/Users')) {
                    return ['pass', 'cakedc/users is not loaded'];
                }
                $paths = $config->usersPaths();
                $resource = $config->usersResource();

                return ['pass', sprintf(
                    'the Token authenticator validates %s below %s',
                    $resource ?? 'the default resource',
                    $paths === null ? 'the path of its resource' : implode(', ', $paths),
                )];
            },
            'Login URL' => fn(): array => $this->loginUrl($config),
            'CSRF' => fn(): array => $this->csrf($config),
            'Authenticators' => fn(): array => $this->authenticators(),
            'RBAC' => fn(): array => Plugin::isLoaded('CakeDC/Users')
                ? UsersIntegration::rbacReport()
                : ['pass', 'cakedc/users is not loaded'],
            'Rate limiting' => function () use ($config): array {
                $cache = $config->rateLimitCache();
                if ($cache === null) {
                    return ['warn', 'disabled ("rateLimit.cache" is null); the token endpoints are not throttled'];
                }

                return Cache::getConfig($cache) === null
                    ? ['fail', sprintf('the cache configuration "%s" does not exist', $cache)]
                    : ['pass', sprintf('cache "%s"', $cache)];
            },
            'Client metadata documents' => function () use ($config): array {
                if (!$config->serverConfig()->cimdEnabled) {
                    return ['pass', 'disabled'];
                }
                if (!extension_loaded('curl')) {
                    return ['fail', 'enabled but ext-curl is not installed'];
                }
                if ($config->rateLimitCache() === null) {
                    return [
                        'warn',
                        'enabled, but "rateLimit.cache" is null: there is no fetch budget and no negative cache',
                    ];
                }

                return ['pass', 'enabled'];
            },
            'Logging' => fn(): array => $this->logging(),
        ];
    }

    /**
     * Where the secret comes from and whether it is long enough.
     *
     * @return array{0: 'pass'|'warn'|'fail', 1: string}
     */
    private function secret(): array
    {
        $secret = Configure::read('OAuthServer.secret');
        if ($secret !== null) {
            return is_string($secret) && strlen($secret) >= self::MIN_SECRET_LENGTH
                ? ['pass', 'OAuthServer.secret is set']
                : [
                    'fail',
                    sprintf('OAuthServer.secret must be a string of at least %d characters', self::MIN_SECRET_LENGTH),
                ];
        }
        try {
            $salt = Security::getSalt();
        } catch (CakeException) {
            $salt = '';
        }
        if (strlen($salt) < self::MIN_SECRET_LENGTH) {
            return [
                'fail',
                sprintf(
                    'OAuthServer.secret is not set and Security.salt is missing or shorter than %d characters; '
                    . 'set a real Security.salt or OAuthServer.secret',
                    self::MIN_SECRET_LENGTH,
                ),
            ];
        }

        return ['warn', 'derived from Security.salt; set OAuthServer.secret to rotate it without changing the salt'];
    }

    /**
     * The issuer: https, and its path against the application's base path.
     *
     * @param \CakeDC\OAuthServer\Config\PluginConfig $config The configuration.
     * @return array{0: 'pass'|'warn'|'fail', 1: string}
     */
    private function issuer(PluginConfig $config): array
    {
        $issuer = $config->issuer();
        $warnings = [];
        if (!str_starts_with($issuer, 'https://')) {
            $warnings[] = 'uses plain http; only acceptable for local development';
        }
        $path = rtrim((string)parse_url($issuer, PHP_URL_PATH), '/');
        $base = Configure::read('App.base');
        if ($path !== '') {
            $warnings[] = 'has a path, so the RFC 8414 metadata document must be served from the host root '
                . '(add a rewrite for /.well-known/oauth-authorization-server' . $path . ')';
        }
        if (!is_string($base)) {
            // `App.base` false means Cake detects the base directory per request: the CLI cannot know it.
            if ($path !== '') {
                $warnings[] = 'App.base is detected at runtime, so the issuer path cannot be compared with it '
                    . 'on the CLI; make sure it is the base directory of the application';
            }
        } elseif ($path !== rtrim($base, '/')) {
            $warnings[] = sprintf(
                'path "%s" differs from App.base "%s"; set OAuthServer.issuer to the https URL of the application',
                $path,
                rtrim($base, '/'),
            );
        }

        return $warnings === [] ? ['pass', $issuer] : ['warn', $issuer . ' ' . implode('; ', $warnings)];
    }

    /**
     * The four tables, the family column and, on MySQL and MariaDB, the binary collation.
     *
     * @return array{0: 'pass'|'warn'|'fail', 1: string}
     */
    private function tables(): array
    {
        $connection = ConnectionManager::get('default');
        if (!$connection instanceof Connection) {
            return ['warn', 'the default connection is not a database connection; tables not inspected'];
        }
        $collection = $connection->getSchemaCollection();
        $missing = array_diff(self::TABLES, $collection->listTables());
        if ($missing !== []) {
            return [
                'fail',
                'missing ' . implode(', ', $missing) . '; copy the plugin migration into the application '
                . '(config/Migrations) and run bin/cake migrations migrate',
            ];
        }
        if (!in_array('family_started_at', $collection->describe('oauth_tokens')->columns(), true)) {
            return [
                'fail',
                'oauth_tokens has no family_started_at column; copy the current plugin migration into the '
                . 'application and run bin/cake migrations migrate',
            ];
        }
        if ($connection->getDriver() instanceof Mysql) {
            $list = "'" . implode("', '", self::TABLES) . "'";
            $rows = $connection->execute(
                'SELECT TABLE_NAME AS t, COLUMN_NAME AS c FROM information_schema.COLUMNS '
                . 'WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (' . $list . ') '
                . "AND COLLATION_NAME IS NOT NULL AND COLLATION_NAME <> 'utf8mb4_bin'",
            )->fetchAll('assoc') ?: [];
            if ($rows !== []) {
                $columns = array_map(fn(array $row): string => $row['t'] . '.' . $row['c'], $rows);

                return [
                    'fail',
                    'these columns are not utf8mb4_bin, so subjects match case-insensitively: '
                    . implode(', ', $columns),
                ];
            }
        }

        return ['pass', 'all four tables exist'];
    }

    /**
     * Whether something writes the `oauth` log scope.
     *
     * @return array{0: 'pass'|'warn'|'fail', 1: string}
     */
    private function logging(): array
    {
        if (Log::getConfig('oauth') !== null) {
            return ['pass', 'the "oauth" log engine is configured'];
        }
        foreach (Log::configured() as $name) {
            // The console engines ConsoleIo adds for this very run do not persist anything.
            if ($name === 'stdout' || $name === 'stderr') {
                continue;
            }
            $engine = Log::engine($name);
            $scopes = $engine instanceof BaseLog ? $engine->scopes() : null;
            if ($scopes === [] || is_array($scopes) && in_array('oauth', $scopes, true)) {
                return ['pass', sprintf('the "%s" log engine receives the oauth scope', $name)];
            }
        }

        return ['warn', 'no log engine handles the "oauth" scope, so security events are not recorded'];
    }

    /**
     * The resolved login URL; a local string URL must also match a route.
     *
     * @param \CakeDC\OAuthServer\Config\PluginConfig $config The configuration.
     * @return array{0: 'pass'|'warn'|'fail', 1: string}
     */
    private function loginUrl(PluginConfig $config): array
    {
        $login = $config->login()['url'];
        // Throws for an array URL that no route builds.
        $url = Router::url($login);
        if (is_string($login) && str_starts_with($url, '/')) {
            try {
                $params = Router::parseRequest(new ServerRequest(['url' => (string)strtok($url, '?')]));
            } catch (MissingRouteException) {
                $params = null;
            }
            if ($params !== null) {
                // Fallback routes match any path: the controller has to exist as well.
                $plugin = is_string($params['plugin'] ?? null) ? $params['plugin'] . '.' : '';
                $prefix = is_string($params['prefix'] ?? null) ? '/' . Inflector::camelize($params['prefix']) : '';
                $controller = is_string($params['controller'] ?? null) ? $params['controller'] : '';
                $params = App::className($plugin . $controller, 'Controller' . $prefix, 'Controller') === null
                    ? null
                    : $params;
            }
            if ($params === null) {
                return ['warn', $url . ' matches no route or controller of the application: people would get a 404'];
            }
        }

        return ['pass', $url];
    }

    /**
     * A new instance of the application class, or a reason why there is none.
     *
     * @return \Cake\Http\BaseApplication|string
     */
    private function application(): BaseApplication|string
    {
        $class = Configure::read('App.namespace') . '\\Application';
        if (!class_exists($class)) {
            return 'could not find the application class to inspect it';
        }
        // Building an application replaces the global plugin collection; put the running one back.
        $plugins = Plugin::getCollection();
        try {
            $app = new $class(CONFIG);
        } finally {
            Plugin::setCollection($plugins);
        }

        return $app instanceof BaseApplication ? $app : 'the application class is not a BaseApplication';
    }

    /**
     * Whether the application's CSRF middleware skips the token endpoint.
     *
     * @param \CakeDC\OAuthServer\Config\PluginConfig $config The configuration.
     * @return array{0: 'pass'|'warn'|'fail', 1: string}
     */
    private function csrf(PluginConfig $config): array
    {
        $app = $this->application();
        if (is_string($app)) {
            return ['warn', $app . '; its middleware was not inspected'];
        }
        $queue = $app->middleware(new MiddlewareQueue());
        foreach ($queue as $middleware) {
            if (!$middleware instanceof CsrfProtectionMiddleware) {
                continue;
            }
            $callback = (new ReflectionProperty(CsrfProtectionMiddleware::class, 'skipCheckCallback'))
                ->getValue($middleware);
            $request = new ServerRequest([
                'url' => $config->routePrefix() . '/token',
                'environment' => ['REQUEST_METHOD' => 'POST'],
            ]);

            return is_callable($callback) && $callback($request) === true
                ? ['pass', 'the token, register, revoke and introspect endpoints are skipped']
                : ['fail', 'add OAuthServer::csrfSkip($request) to the CsrfProtectionMiddleware skipCheckCallback'];
        }

        return [
            'warn',
            'no CsrfProtectionMiddleware in the queue; the consent and connections pages rely on Cake\'s CSRF '
            . 'protection, add it and use OAuthServer::csrfSkip() in its skipCheckCallback',
        ];
    }

    /**
     * The order of the authenticators: the plugin's Token authenticator must come before the session one, or
     * a session cookie would hide a revoked or foreign bearer token.
     *
     * @return array{0: 'pass'|'warn'|'fail', 1: string}
     */
    private function authenticators(): array
    {
        $names = $this->authenticatorNames();
        if (is_string($names)) {
            return ['warn', $names];
        }
        $token = null;
        $session = null;
        foreach ($names as $position => $class) {
            if ($token === null && is_a($class, TokenAuthenticator::class, true)) {
                $token = $position;
            }
            if ($session === null && is_a($class, SessionAuthenticator::class, true)) {
                $session = $position;
            }
        }
        if ($token === null) {
            return [
                'warn',
                'no Token authenticator (CakeDC/OAuthServer.Token) in the authentication service, so the tokens '
                . 'issued here are not accepted by this application (fine when your resources live elsewhere)',
            ];
        }
        if ($session !== null && $session < $token) {
            return [
                'warn',
                'the Session authenticator comes before the Token authenticator: a session cookie sent with a '
                . 'revoked or foreign bearer token would run as the session user; load the Token one first',
            ];
        }

        return ['pass', $session === null ? 'the Token authenticator is loaded' : 'Token comes before Session'];
    }

    /**
     * The authenticator classes of the application's authentication service, in order; or a reason why they
     * cannot be told. Builds the service with a probe request, like the middleware does.
     *
     * @return list<class-string>|string
     */
    private function authenticatorNames(): array|string
    {
        $app = $this->application();
        if (!is_string($app) && $app instanceof AuthenticationServiceProviderInterface) {
            $service = $app->getAuthenticationService(new ServerRequest(['url' => '/']));
            $classes = [];
            if ($service instanceof AuthenticationService) {
                foreach ($service->authenticators() as $authenticator) {
                    $classes[] = $authenticator::class;
                }

                return $classes;
            }

            return 'the authentication service is not an AuthenticationService; its authenticators were not inspected';
        }
        $configured = Configure::read('Auth.Authenticators');
        if (Plugin::isLoaded('CakeDC/Users') && is_array($configured)) {
            // cakedc/users builds its own service from this configuration.
            $classes = [];
            foreach ($configured as $name => $settings) {
                $class = is_array($settings) ? ($settings['className'] ?? null) : null;
                $classes[] = is_string($class)
                    ? self::authenticatorClass($class)
                    : (string)$name;
            }

            return array_values(array_filter($classes, 'class_exists'));
        }

        return is_string($app)
            ? $app . '; its authenticators were not inspected'
            : 'the application does not provide an authentication service; its authenticators were not inspected';
    }

    /**
     * The class an authenticator name from the configuration resolves to.
     *
     * @param string $name Plugin syntax or class name.
     * @return string
     */
    private static function authenticatorClass(string $name): string
    {
        [$plugin, $class] = pluginSplit($name);
        if ($plugin !== null) {
            $class = str_replace('/', '\\', $plugin) . '\\Authenticator\\' . $class . 'Authenticator';
        }

        return class_exists($class) ? $class : $name;
    }
}
