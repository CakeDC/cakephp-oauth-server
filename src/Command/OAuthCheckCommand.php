<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Command;

use Authentication\AuthenticationService;
use Authentication\AuthenticationServiceProviderInterface;
use Authentication\Authenticator\SessionAuthenticator;
use Authentication\Identifier\IdentifierCollection;
use Authentication\Middleware\AuthenticationMiddleware;
use Cake\Cache\Cache;
use Cake\Cache\Engine\ArrayEngine;
use Cake\Cache\Engine\NullEngine;
use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Cake\Core\App;
use Cake\Core\Configure;
use Cake\Core\Exception\CakeException;
use Cake\Core\Plugin;
use Cake\Database\Driver\Mysql;
use Cake\Http\BaseApplication;
use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\Middleware\SessionCsrfProtectionMiddleware;
use Cake\Http\MiddlewareQueue;
use Cake\Http\ServerRequest;
use Cake\Log\Engine\BaseLog;
use Cake\Log\Log;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\Routing\Exception\MissingRouteException;
use Cake\Routing\Middleware\RoutingMiddleware;
use Cake\Routing\Router;
use Cake\Utility\Inflector;
use Cake\Utility\Security;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuthServer\Authenticator\TokenAuthenticator;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Identity\OrmUserProvider;
use CakeDC\OAuthServer\Integration\UsersIntegration;
use CakeDC\OAuthServer\Server\ServerFactory;
use ReflectionClass;
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

    /**
     * The columns of each table, as the plugin's migrations create them.
     */
    private const COLUMNS = [
        'oauth_clients' => [
            'id', 'client_id', 'client_id_hash', 'type', 'application_type', 'name', 'client_uri', 'logo_uri',
            'redirect_uris', 'grant_types', 'scopes', 'token_endpoint_auth_method', 'secret_hash',
            'allow_introspection', 'metadata', 'metadata_fetched_at', 'metadata_expires_at', 'last_used_at',
            'revoked_at', 'created', 'modified',
        ],
        'oauth_authorization_codes' => [
            'id', 'code_hash', 'oauth_client_id', 'subject', 'redirect_uri', 'resource', 'scopes', 'code_challenge',
            'family_id', 'expires_at', 'used_at', 'created',
        ],
        'oauth_tokens' => [
            'id', 'token_hash', 'type', 'family_id', 'parent_id', 'oauth_client_id', 'subject', 'subject_type',
            'resource', 'scopes', 'name', 'expires_at', 'used_at', 'revoked_at', 'last_used_at', 'family_started_at',
            'created', 'modified',
        ],
        'oauth_consents' => [
            'id', 'subject', 'oauth_client_id', 'resource', 'resource_hash', 'scopes', 'created', 'modified',
        ],
    ];

    /**
     * The unique keys each table needs: lookups by hash and the one consent per person, client and resource.
     */
    private const UNIQUE = [
        'oauth_clients' => [['client_id_hash']],
        'oauth_authorization_codes' => [['code_hash']],
        'oauth_tokens' => [['token_hash']],
        'oauth_consents' => [['subject', 'oauth_client_id', 'resource_hash']],
    ];

    /**
     * Other indexes the queries rely on, with the migration that adds each: without one a query scans the table.
     */
    private const INDEXES = [
        'oauth_authorization_codes' => [
            [
                ['subject'],
                '20261017120000_AddOAuthCodesSubjectIndex',
                'which revoking a person or a connection uses to delete their pending codes',
            ],
        ],
    ];

    /**
     * The ORM tables of the four database tables.
     */
    private const TABLE_CLASSES = [
        'oauth_clients' => 'CakeDC/OAuthServer.OauthClients',
        'oauth_authorization_codes' => 'CakeDC/OAuthServer.OauthAuthorizationCodes',
        'oauth_tokens' => 'CakeDC/OAuthServer.OauthTokens',
        'oauth_consents' => 'CakeDC/OAuthServer.OauthConsents',
    ];

    /**
     * The middleware of the application, built once per run, or why it could not be inspected.
     *
     * @var list<object>|string|null
     */
    private array|string|null $middleware = null;

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
                // Built like the endpoints build it (no request, no I/O): what fails here makes them answer 503.
                $server = (new ServerFactory($config))->create()->config();
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
                $paths = $config->effectiveUsersPaths();
                if (is_string($paths)) {
                    return ['fail', $paths];
                }
                $paths = $config->usersPaths();
                $resource = $config->usersResource();
                $message = sprintf(
                    'the Token authenticator validates %s below %s',
                    $resource ?? 'the default resource',
                    $paths === null ? 'the path of its resource' : implode(', ', $paths),
                );
                $oneTimeToken = UsersIntegration::oneTimeTokenWarning();

                return $oneTimeToken === null ? ['pass', $message] : ['warn', $message . '; but ' . $oneTimeToken];
            },
            'Login URL' => fn(): array => $this->loginUrl($config),
            'Routes' => fn(): array => $this->routes($config),
            'Middleware' => fn(): array => $this->middlewareOrder(),
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
                if (Cache::getConfig($cache) === null) {
                    return ['fail', sprintf('the cache configuration "%s" does not exist', $cache)];
                }
                $forgetful = self::forgetfulCache($cache);

                return $forgetful === null
                    ? ['pass', sprintf('cache "%s"', $cache)]
                    : ['warn', $forgetful . ', so nothing is throttled; use a cache all PHP processes share'];
            },
            'Client metadata documents' => function () use ($config): array {
                if (!$config->serverConfig()->cimdEnabled) {
                    return ['pass', 'disabled'];
                }
                if (!extension_loaded('curl')) {
                    return ['fail', 'enabled but ext-curl is not installed'];
                }
                $cache = $config->rateLimitCache();
                if ($cache === null) {
                    return [
                        'warn',
                        'enabled, but "rateLimit.cache" is null: there is no fetch budget and no negative cache',
                    ];
                }
                $forgetful = Cache::getConfig($cache) === null ? null : self::forgetfulCache($cache);

                return $forgetful === null
                    ? ['pass', 'enabled']
                    : ['warn', 'enabled, but ' . $forgetful . ': there is no fetch budget and no negative cache'];
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
     * The four tables on the connection of the plugin's ORM tables: present, with the columns and unique keys of
     * the current migrations, and on MySQL and MariaDB with the binary collation.
     *
     * @return array{0: 'pass'|'warn'|'fail', 1: string}
     */
    private function tables(): array
    {
        $connection = $this->fetchTable(self::TABLE_CLASSES['oauth_tokens'])->getConnection();
        $where = sprintf(' (connection "%s")', $connection->configName());
        $missing = [];
        $columns = [];
        $unique = [];
        $indexes = [];
        foreach (self::TABLE_CLASSES as $name => $class) {
            $collection = $this->fetchTable($class)->getConnection()->getSchemaCollection();
            if (!in_array($name, $collection->listTables(), true)) {
                $missing[] = $name;
                continue;
            }
            $schema = $collection->describe($name);
            foreach (array_diff(self::COLUMNS[$name], $schema->columns()) as $column) {
                $columns[] = $name . '.' . $column;
            }
            // A unique index is reflected as a unique constraint or a unique index, depending on the database.
            $keys = [];
            $covered = [];
            foreach (array_merge($schema->constraints(), $schema->indexes()) as $key) {
                $definition = $schema->getConstraint($key) ?? $schema->getIndex($key);
                $covered[] = (array)($definition['columns'] ?? []);
                if (($definition['type'] ?? null) === 'unique') {
                    $keys[] = (array)$definition['columns'];
                }
            }
            foreach (self::UNIQUE[$name] as $key) {
                if (!in_array($key, $keys, true)) {
                    $unique[] = $name . ' (' . implode(', ', $key) . ')';
                }
            }
            foreach (self::INDEXES[$name] ?? [] as [$indexColumns, $migration, $why]) {
                if (!in_array($indexColumns, $covered, true)) {
                    $indexes[] = sprintf(
                        'no index on %s (%s), %s; run bin/cake migrations migrate -p CakeDC/OAuthServer, or copy '
                        . 'config/Migrations/%s.php into the application\'s config/Migrations and run '
                        . 'bin/cake migrations migrate',
                        $name,
                        implode(', ', $indexColumns),
                        $why,
                        $migration,
                    );
                }
            }
        }
        // The two ways the installation documents; an application uses one of them, never both.
        $migrate = 'run bin/cake migrations migrate -p CakeDC/OAuthServer, or copy the plugin migrations into the '
            . 'application (config/Migrations) and run bin/cake migrations migrate';
        if ($missing !== []) {
            return ['fail', 'missing ' . implode(', ', $missing) . '; ' . $migrate . $where];
        }
        if ($columns !== []) {
            return [
                'fail',
                'missing columns ' . implode(', ', $columns) . '; run bin/cake migrations migrate -p '
                . 'CakeDC/OAuthServer, or copy the current plugin migrations into the application '
                . '(config/Migrations) and run bin/cake migrations migrate' . $where,
            ];
        }
        if ($unique !== []) {
            return [
                'fail',
                'missing unique keys on ' . implode(', ', $unique) . '; without them a hash could match two rows. '
                . 'Recreate the tables with the plugin migration' . $where,
            ];
        }
        if ($connection->getDriver() instanceof Mysql) {
            $list = "'" . implode("', '", array_keys(self::TABLE_CLASSES)) . "'";
            $rows = $connection->execute(
                'SELECT TABLE_NAME AS t, COLUMN_NAME AS c FROM information_schema.COLUMNS '
                . 'WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (' . $list . ') '
                . "AND COLLATION_NAME IS NOT NULL AND COLLATION_NAME <> 'utf8mb4_bin'",
            )->fetchAll('assoc') ?: [];
            if ($rows !== []) {
                $names = array_map(fn(array $row): string => $row['t'] . '.' . $row['c'], $rows);

                return [
                    'fail',
                    'these columns are not utf8mb4_bin, so subjects match case-insensitively: '
                    . implode(', ', $names),
                ];
            }
        }

        if ($indexes !== []) {
            return ['warn', implode('; ', $indexes) . $where];
        }

        return ['pass', 'all four tables exist'];
    }

    /**
     * Why the cache $name keeps nothing from one request to the next (an Array or Null engine), or null.
     *
     * @param string $name A configured cache.
     * @return string|null
     */
    private static function forgetfulCache(string $name): ?string
    {
        $engine = Cache::pool($name);
        if (!$engine instanceof ArrayEngine && !$engine instanceof NullEngine) {
            return null;
        }

        return sprintf(
            'the cache "%s" uses %s, which keeps nothing from one request to the next',
            $name,
            (new ReflectionClass($engine))->getShortName(),
        );
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
     * The application's middleware, in order: its own queue, then what its plugins add (as the server does).
     *
     * @return list<object>|string The middleware, or why it could not be inspected.
     */
    private function middlewareList(): array|string
    {
        if ($this->middleware !== null) {
            return $this->middleware;
        }
        $app = $this->application();
        if (is_string($app)) {
            return $this->middleware = $app;
        }
        $queue = $app->middleware(new MiddlewareQueue());
        // The new application has no plugins of its own; the running ones are the application's.
        foreach (Plugin::getCollection()->with('middleware') as $plugin) {
            $queue = $plugin->middleware($queue);
        }
        $list = [];
        foreach ($queue as $middleware) {
            $list[] = $middleware;
        }

        return $this->middleware = $list;
    }

    /**
     * Whether RoutingMiddleware runs before the CSRF and authentication middleware: before routing there is no
     * matched route, so no request on a resource's routes is skipped by csrfSkip() and the Token authenticator
     * refuses every token of this server. That fails when a Token authenticator is loaded (the application's own
     * tokens cannot work) and warns otherwise.
     *
     * @return array{0: 'pass'|'warn'|'fail', 1: string}
     */
    private function middlewareOrder(): array
    {
        $list = $this->middlewareList();
        if (is_string($list)) {
            return ['warn', $list . '; its middleware was not inspected'];
        }
        $routed = false;
        $early = [];
        $authenticationEarly = false;
        foreach ($list as $middleware) {
            if ($middleware instanceof RoutingMiddleware) {
                $routed = true;
            } elseif (!$routed && $middleware instanceof AuthenticationMiddleware) {
                $authenticationEarly = true;
                $early[] = 'AuthenticationMiddleware runs before RoutingMiddleware: the Token authenticator refuses '
                    . 'every token of this server there';
            } elseif (!$routed && self::isCsrf($middleware)) {
                $early[] = (new ReflectionClass($middleware))->getShortName() . ' runs before RoutingMiddleware: '
                    . 'no request on a resource\'s routes is skipped there';
            }
        }
        if ($early !== []) {
            $chain = $this->authenticatorChain();
            if (is_array($chain) && $chain[1] !== []) {
                return [
                    'fail',
                    implode('; ', $early) . '; the Token authenticator is loaded, so '
                    . ($authenticationEarly
                        ? 'no token of this server works'
                        : 'every POST, PUT, PATCH or DELETE with a token of this server gets 403')
                    . '; add RoutingMiddleware first',
                ];
            }

            return ['warn', implode('; ', $early) . '; add RoutingMiddleware first'];
        }

        return $routed
            ? ['pass', 'RoutingMiddleware runs before the CSRF and authentication middleware']
            : ['warn', 'no RoutingMiddleware in the queue; the OAuth routes and the token paths need it'];
    }

    /**
     * Whether $middleware is one of Cake's CSRF middleware.
     *
     * @param object $middleware The middleware.
     * @return bool
     */
    private static function isCsrf(object $middleware): bool
    {
        return $middleware instanceof CsrfProtectionMiddleware
            || $middleware instanceof SessionCsrfProtectionMiddleware;
    }

    /**
     * Whether the application's CSRF middleware skips the token endpoint and nothing a session uses: the consent
     * and connections pages, the home page and the login.
     *
     * @param \CakeDC\OAuthServer\Config\PluginConfig $config The configuration.
     * @return array{0: 'pass'|'warn'|'fail', 1: string}
     */
    private function csrf(PluginConfig $config): array
    {
        $list = $this->middlewareList();
        if (is_string($list)) {
            return ['warn', $list . '; its middleware was not inspected'];
        }
        foreach ($list as $middleware) {
            if (!self::isCsrf($middleware)) {
                continue;
            }
            $name = (new ReflectionClass($middleware))->getShortName();
            $callback = (new ReflectionProperty($middleware, 'skipCheckCallback'))->getValue($middleware);
            $skips = fn(string $path): bool => is_callable($callback) && $callback(new ServerRequest([
                'url' => $path,
                'environment' => ['REQUEST_METHOD' => 'POST'],
            ])) === true;
            $prefix = $config->lenientRouting()['prefix'];
            if (!$skips($prefix . '/token')) {
                return ['fail', 'add OAuthServer::csrfSkip($request) to the ' . $name . ' skipCheckCallback'];
            }
            $session = array_values(array_filter(
                array_unique([$prefix . '/authorize', $prefix . '/connections', '/', $this->loginPath($config)]),
                fn(?string $path): bool => $path !== null && $skips($path),
            ));
            if ($session !== []) {
                return [
                    'fail',
                    sprintf(
                        'the %s skipCheckCallback also skips session routes (%s), which must stay CSRF checked; '
                        . 'use OAuthServer::csrfSkip($request)',
                        $name,
                        implode(', ', $session),
                    ),
                ];
            }

            return ['pass', 'the token, register, revoke and introspect endpoints are skipped'];
        }

        return [
            'warn',
            'no CsrfProtectionMiddleware in the queue; the consent and connections pages rely on Cake\'s CSRF '
            . 'protection, add it and use OAuthServer::csrfSkip() in its skipCheckCallback',
        ];
    }

    /**
     * The path of the login URL when it is on this site, or null.
     *
     * @param \CakeDC\OAuthServer\Config\PluginConfig $config The configuration.
     * @return string|null
     */
    private function loginPath(PluginConfig $config): ?string
    {
        try {
            $url = Router::url($config->login()['url']);
        } catch (Throwable) {
            return null;
        }

        return str_starts_with($url, '/') && !str_starts_with($url, '//') ? (string)strtok($url, '?') : null;
    }

    /**
     * Whether `<prefix>/token` reaches the plugin's controller, or another route of the application takes it.
     *
     * @param \CakeDC\OAuthServer\Config\PluginConfig $config The configuration.
     * @return array{0: 'pass'|'warn'|'fail', 1: string}
     */
    private function routes(PluginConfig $config): array
    {
        $path = $config->lenientRouting()['prefix'] . '/token';
        try {
            $params = Router::parseRequest(new ServerRequest([
                'url' => $path,
                'environment' => ['REQUEST_METHOD' => 'POST'],
            ]));
        } catch (MissingRouteException) {
            return ['fail', $path . ' matches no route; the plugin\'s routes are not loaded'];
        }
        if (
            ($params['plugin'] ?? null) !== 'CakeDC/OAuthServer'
            || ($params['controller'] ?? null) !== 'OAuth'
            || ($params['action'] ?? null) !== 'token'
        ) {
            return [
                'fail',
                sprintf(
                    '%s goes to %s, not to the plugin; a route of the application connected before the plugin\'s '
                    . 'takes it',
                    $path,
                    implode('.', array_filter([
                        is_string($params['plugin'] ?? null) ? $params['plugin'] : null,
                        is_string($params['controller'] ?? null) ? $params['controller'] : null,
                        is_string($params['action'] ?? null) ? $params['action'] : null,
                    ])),
                ),
            ];
        }

        return ['pass', $path . ' reaches the plugin'];
    }

    /**
     * The order of the authenticators: the plugin's Token authenticator must come before the session one, or
     * a session cookie would hide a revoked or foreign bearer token.
     *
     * @return array{0: 'pass'|'warn'|'fail', 1: string}
     */
    private function authenticators(): array
    {
        $chain = $this->authenticatorChain();
        if (is_string($chain)) {
            return ['warn', $chain];
        }
        [$names, $tokenAuthenticators] = $chain;
        foreach ($tokenAuthenticators as $authenticator) {
            try {
                $authenticator->resolve();
            } catch (Throwable $e) {
                // It is built, but refuses every token of this server with 401.
                return ['fail', 'the Token authenticator refuses every token: ' . $e->getMessage()];
            }
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
     * The authenticator classes of the application's authentication service, in order, and its Token
     * authenticators; or a reason why they cannot be told. Builds the service with a probe request, like the
     * middleware does.
     *
     * @return array{0: list<class-string>, 1: list<\CakeDC\OAuthServer\Authenticator\TokenAuthenticator>}|string
     */
    private function authenticatorChain(): array|string
    {
        $app = $this->application();
        if (!is_string($app) && $app instanceof AuthenticationServiceProviderInterface) {
            // Probe at the bearer paths: an app may load the Token authenticator for its API paths only.
            $first = null;
            foreach (PluginConfig::fromConfigure()->bearerPaths() ?: ['/'] as $probe) {
                $service = $app->getAuthenticationService(new ServerRequest(['url' => $probe]));
                if (!$service instanceof AuthenticationService) {
                    break;
                }
                $classes = [];
                $tokens = [];
                foreach ($service->authenticators() as $authenticator) {
                    $classes[] = $authenticator::class;
                    if ($authenticator instanceof TokenAuthenticator) {
                        $tokens[] = $authenticator;
                    }
                }
                $first ??= [$classes, $tokens];
                if ($tokens !== []) {
                    return [$classes, $tokens];
                }
            }
            if ($first !== null) {
                return $first;
            }

            return 'the authentication service is not an AuthenticationService; its authenticators were not inspected';
        }
        $configured = Configure::read('Auth.Authenticators');
        if (Plugin::isLoaded('CakeDC/Users') && is_array($configured)) {
            // cakedc/users builds its own service from this configuration.
            $classes = [];
            $tokens = [];
            foreach ($configured as $name => $settings) {
                $class = is_array($settings) ? ($settings['className'] ?? null) : null;
                $class = is_string($class) ? self::authenticatorClass($class) : (string)$name;
                if (!class_exists($class)) {
                    continue;
                }
                $classes[] = $class;
                if (is_array($settings) && is_a($class, TokenAuthenticator::class, true)) {
                    unset($settings['className']);
                    $tokens[] = new $class(new IdentifierCollection(), $settings);
                }
            }

            return [$classes, $tokens];
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
