<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Command;

use Cake\Cache\Cache;
use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
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
use Cake\Routing\Router;
use Cake\Utility\Security;
use CakeDC\OAuth\Server\Token\TokenGenerator;
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
            'Login URL' => fn(): array => ['pass', Router::url($config->login()['url'])],
            'CSRF' => fn(): array => $this->csrf($config),
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
        $base = is_string($base) ? rtrim($base, '/') : '';
        if ($path !== '') {
            $warnings[] = 'has a path, so the RFC 8414 metadata document must be served from the host root '
                . '(add a rewrite for /.well-known/oauth-authorization-server' . $path . ')';
        }
        if ($path !== $base) {
            $warnings[] = sprintf(
                'path "%s" differs from App.base "%s"; set OAuthServer.issuer to the https URL of the application',
                $path,
                $base,
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
     * Whether the application's CSRF middleware skips the token endpoint.
     *
     * @param \CakeDC\OAuthServer\Config\PluginConfig $config The configuration.
     * @return array{0: 'pass'|'warn'|'fail', 1: string}
     */
    private function csrf(PluginConfig $config): array
    {
        $class = Configure::read('App.namespace') . '\\Application';
        if (!class_exists($class)) {
            return ['warn', 'could not find the application class to inspect its middleware'];
        }
        // Building an application replaces the global plugin collection; put the running one back.
        $plugins = Plugin::getCollection();
        try {
            $app = new $class(CONFIG);
        } finally {
            Plugin::setCollection($plugins);
        }
        if (!$app instanceof BaseApplication) {
            return ['warn', 'the application class is not a BaseApplication; its middleware was not inspected'];
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

        return ['pass', 'no CsrfProtectionMiddleware in the queue'];
    }
}
