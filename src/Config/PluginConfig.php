<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Config;

use Cake\Core\Configure;
use Cake\Core\Exception\CakeException;
use Cake\Core\Plugin;
use Cake\Utility\Security;
use CakeDC\OAuth\Server\Client\Cimd\DnsResolverInterface;
use CakeDC\OAuth\Server\Client\Cimd\HttpTransportInterface;
use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Resource\ResourceIdentifier;
use CakeDC\OAuthServer\Http\RequestPaths;
use CakeDC\OAuthServer\Identity\OrmUserProvider;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;

/**
 * The `OAuthServer` configuration: core settings for the server, plus the plugin's own.
 *
 * @internal
 */
final class PluginConfig
{
    private const PLUGIN_SECTIONS = [
        'userProvider' => ['className', 'table', 'finder', 'displayField', 'canAuthorize', 'scopes', 'forClient'],
        'login' => ['url', 'redirectParam', 'identityAttribute'],
        'consent' => ['layout'],
        'connections' => ['enabled', 'layout'],
        'services' => ['clock', 'transport', 'dns'],
        'users' => ['resource', 'paths'],
        'tokenPaths' => [],
    ];

    private const SERVICE_TYPES = [
        'clock' => ClockInterface::class,
        'transport' => HttpTransportInterface::class,
        'dns' => DnsResolverInterface::class,
    ];

    private ?ServerConfig $serverConfig = null;

    private ?ServerConfig $pathConfig = null;

    /**
     * @param array<string, mixed> $settings The `OAuthServer` configuration.
     */
    public function __construct(private readonly array $settings)
    {
    }

    /**
     * Reads `Configure::read('OAuthServer')`.
     *
     * @return self
     */
    public static function fromConfigure(): self
    {
        $settings = Configure::read('OAuthServer');

        return new self(is_array($settings) ? $settings : []);
    }

    /**
     * The core server settings, with the application's base URL as issuer and a secret derived from
     * the security salt unless configured.
     *
     * @return \CakeDC\OAuth\Server\Config\ServerConfig
     * @throws \InvalidArgumentException
     */
    public function serverConfig(): ServerConfig
    {
        return $this->serverConfig ??= $this->buildServerConfig(null);
    }

    /**
     * The core settings, with $secret or the configured or derived one.
     *
     * @param string|null $secret A fixed secret, or null for the configured one.
     * @return \CakeDC\OAuth\Server\Config\ServerConfig
     * @throws \InvalidArgumentException
     */
    private function buildServerConfig(?string $secret): ServerConfig
    {
        $core = array_diff_key($this->settings, self::PLUGIN_SECTIONS);
        $configured = isset($core['issuer']);
        $core['issuer'] = $this->checkedIssuer(
            $configured ? $core['issuer'] : Configure::read('App.fullBaseUrl'),
            $configured,
        );
        if ($secret !== null) {
            $core['secret'] = $secret;
        } elseif (!isset($core['secret'])) {
            $core['secret'] = self::derivedSecret();
        }
        if (isset($core['rateLimit']) && is_array($core['rateLimit'])) {
            unset($core['rateLimit']['cache']);
        }
        $core['connections'] = (bool)($this->section('connections')['enabled'] ?? true);

        return ServerConfig::fromArray($core);
    }

    /**
     * The core settings with a fixed placeholder secret, for what does not depend on the secret: paths,
     * prefixes and resources. The core only exposes them on a ServerConfig; the placeholder is used for
     * reading them alone and never reaches a token or a signature.
     *
     * @return \CakeDC\OAuth\Server\Config\ServerConfig
     * @throws \InvalidArgumentException For an invalid issuer, route prefix or resource setting.
     */
    private function pathConfig(): ServerConfig
    {
        return $this->pathConfig ??= $this->buildServerConfig(str_repeat('x', 32));
    }

    /**
     * The route prefix and the metadata path, validated by the core without touching the secret.
     *
     * Routing must not depend on the secret, so a missing or weak `Security.salt` cannot break boot.
     *
     * @return array{prefix: string, metadata: string}
     * @throws \InvalidArgumentException For an invalid issuer, route prefix or resource setting.
     */
    public function routing(): array
    {
        $server = $this->pathConfig();

        return ['prefix' => $server->routePrefix, 'metadata' => $server->metadataPath()];
    }

    /**
     * The prefix of the tokens this server issues, validated without touching the secret.
     *
     * @return string
     * @throws \InvalidArgumentException
     */
    public function tokenPrefix(): string
    {
        return $this->pathConfig()->tokenPrefix;
    }

    /**
     * The canonical issuer, validated without touching the secret.
     *
     * @return string
     * @throws \InvalidArgumentException
     */
    public function issuer(): string
    {
        return $this->pathConfig()->issuer;
    }

    /**
     * Like routing(), but never throws: an invalid setting leaves the metadata path null and the prefix at
     * `/oauth`. For the CLI, where `oauth check` reports the problem.
     *
     * @return array{prefix: string, metadata: string|null}
     */
    public function lenientRouting(): array
    {
        try {
            return $this->routing();
        } catch (InvalidArgumentException) {
            return ['prefix' => '/oauth', 'metadata' => null];
        }
    }

    /**
     * The canonical issuer, or an error that names the setting to fix.
     *
     * @param mixed $issuer The raw issuer.
     * @param bool $configured Whether `OAuthServer.issuer` was set.
     * @return string
     * @throws \InvalidArgumentException
     */
    private function checkedIssuer(mixed $issuer, bool $configured): string
    {
        $raw = is_string($issuer) ? $issuer : '';
        try {
            $canonical = ResourceIdentifier::canonicalize($raw);
            if (parse_url($canonical, PHP_URL_QUERY) !== null) {
                throw new InvalidArgumentException('The issuer must not have a query.');
            }
            ResourceIdentifier::assertSecure($canonical, 'issuer');

            return $canonical;
        } catch (InvalidArgumentException $e) {
            throw $this->issuerError($e, $raw, $configured);
        }
    }

    /**
     * An error that names the setting to fix, without credentials.
     *
     * @param \InvalidArgumentException $previous The core's error.
     * @param string $raw The issuer as configured.
     * @param bool $configured Whether `OAuthServer.issuer` was set.
     * @return \InvalidArgumentException
     */
    private function issuerError(
        InvalidArgumentException $previous,
        string $raw,
        bool $configured,
    ): InvalidArgumentException {
        $safe = (string)preg_replace('#^([a-z][a-z0-9+.-]*://)[^/?\#]*@#i', '$1', $raw);
        $message = $safe === $raw ? $previous->getMessage() : str_replace($raw, $safe, $previous->getMessage());
        $setting = $configured ? 'OAuthServer.issuer' : 'App.fullBaseUrl (the default issuer)';

        return new InvalidArgumentException(
            sprintf(
                'The OAuth issuer is invalid: %s Fix %s; it must be an absolute https URL '
                . '(http is allowed on localhost only), or set OAuthServer.issuer.',
                $message,
                $setting,
            ),
            0,
            // The core's exception carries the raw issuer, so it is only chained when it has no credentials.
            $safe === $raw ? $previous : null,
        );
    }

    /**
     * The secret derived from the security salt.
     *
     * @return string
     * @throws \InvalidArgumentException
     */
    private static function derivedSecret(): string
    {
        try {
            $salt = Security::getSalt();
        } catch (CakeException) {
            $salt = '';
        }
        if (strlen($salt) < 32) {
            throw new InvalidArgumentException(
                'Security.salt is missing or shorter than 32 characters, so no safe OAuth secret can be derived '
                . 'from it. Set a real Security.salt or set OAuthServer.secret.',
            );
        }

        return hash('sha256', $salt . '|cakedc-oauth-server');
    }

    /**
     * How people are found.
     *
     * @return array{className: object|string, table: string, finder: string, displayField: string|null, canAuthorize: callable|null, scopes: callable|null, forClient: callable|null}
     */
    public function userProvider(): array
    {
        $section = $this->section('userProvider');
        $users = Plugin::isLoaded('CakeDC/Users');
        $table = $section['table'] ?? null;
        if ($table === null) {
            $configured = $users ? Configure::read('Users.table') : null;
            $usersTable = is_string($configured) && $configured !== '' ? $configured : 'CakeDC/Users.Users';
            $table = $users ? $usersTable : 'Users';
        }

        return [
            'className' => $section['className'] ?? OrmUserProvider::class,
            'table' => (string)$table,
            'finder' => (string)($section['finder'] ?? 'active'),
            'displayField' => isset($section['displayField'])
                ? (string)$section['displayField']
                : ($users ? 'username' : null),
            'canAuthorize' => self::callable($section, 'canAuthorize'),
            'scopes' => self::callable($section, 'scopes'),
            'forClient' => self::callable($section, 'forClient'),
        ];
    }

    /**
     * Where anonymous people sign in.
     *
     * @return array{url: array<string, mixed>|string, redirectParam: string, identityAttribute: string}
     */
    public function login(): array
    {
        $section = $this->section('login');
        $url = $section['url'] ?? (Plugin::isLoaded('CakeDC/Users')
            ? ['plugin' => 'CakeDC/Users', 'controller' => 'Users', 'action' => 'login', 'prefix' => false]
            : '/login');

        return [
            'url' => is_array($url) ? $url : (string)$url,
            'redirectParam' => (string)($section['redirectParam'] ?? 'redirect'),
            'identityAttribute' => (string)($section['identityAttribute'] ?? 'identity'),
        ];
    }

    /**
     * The resource the Token authenticator that the cakedc/users integration registers validates against,
     * or null for the server's default resource.
     *
     * @return string|null
     */
    public function usersResource(): ?string
    {
        $resource = $this->section('users')['resource'] ?? null;
        if ($resource !== null && !is_string($resource)) {
            throw new InvalidArgumentException('"OAuthServer.users.resource" must be a resource identifier.');
        }

        return $resource;
    }

    /**
     * The path prefixes the Token authenticator of the cakedc/users integration authenticates in:
     * `OAuthServer.users.paths`, else `OAuthServer.tokenPaths`, else null (the path of its resource).
     *
     * @return list<string>|null
     */
    public function usersPaths(): ?array
    {
        return self::pathList($this->section('users')['paths'] ?? null, 'OAuthServer.users.paths')
            ?? $this->tokenPaths();
    }

    /**
     * The path prefixes configured in `OAuthServer.tokenPaths`, or null when it is not set.
     *
     * @return list<string>|null
     * @throws \InvalidArgumentException
     */
    public function tokenPaths(): ?array
    {
        return self::pathList($this->settings['tokenPaths'] ?? null, 'OAuthServer.tokenPaths');
    }

    /**
     * Where a bearer token of this server is expected: `OAuthServer.tokenPaths` when set, otherwise the paths
     * of the declared resources. A resource at the host root contributes nothing: covering every route takes
     * an explicit `OAuthServer.tokenPaths = ['/']`.
     *
     * @return list<string>
     * @throws \InvalidArgumentException For an invalid resource or `tokenPaths` setting.
     */
    public function bearerPaths(): array
    {
        $configured = $this->tokenPaths();
        if ($configured !== null) {
            return $configured;
        }

        return array_values(array_unique(array_merge(...array_values($this->resourcePaths()))));
    }

    /**
     * Where a bearer token of each declared resource is expected, which is where CSRF protection is skipped
     * for it: `OAuthServer.tokenPaths` for every resource when set, otherwise the path of the resource itself.
     * A resource at the host root gets no path by itself. Read without touching the secret.
     *
     * @return array<string, list<string>> Path prefixes by resource identifier.
     * @throws \InvalidArgumentException For an invalid resource or `tokenPaths` setting.
     */
    public function resourcePaths(): array
    {
        $configured = $this->tokenPaths();
        $paths = [];
        foreach ($this->pathConfig()->resources->all() as $resource) {
            $path = RequestPaths::ofResource($resource->identifier);
            $paths[$resource->identifier] = $configured ?? ($path === '/' ? [] : [$path]);
        }

        return $paths;
    }

    /**
     * The identifier of the server's default resource, validated without touching the secret.
     *
     * @return string
     * @throws \InvalidArgumentException For an invalid resource setting.
     */
    public function defaultResourceIdentifier(): string
    {
        return $this->pathConfig()->resources->defaultResource()->identifier;
    }

    /**
     * The path prefixes the cakedc/users integration's Token authenticator will authenticate in, or the reason
     * there is none.
     *
     * @return list<string>|string The prefixes, or an error message naming the settings to fix.
     * @throws \InvalidArgumentException For an invalid `users` or `tokenPaths` setting.
     */
    public function effectiveUsersPaths(): array|string
    {
        $paths = $this->usersPaths();
        if ($paths !== null) {
            return $paths;
        }
        $resource = $this->usersResource() ?? $this->defaultResourceIdentifier();
        $path = RequestPaths::ofResource($resource);
        if ($path === '/') {
            return sprintf(
                'the resource "%s" is at the host root, so its token would be accepted on every route; set '
                . 'OAuthServer.users.paths or OAuthServer.tokenPaths (["/"] to accept it everywhere)',
                $resource,
            );
        }

        return [$path];
    }

    /**
     * A list of path prefixes setting, normalized.
     *
     * @param mixed $value The raw setting.
     * @param string $setting Setting name, for the error.
     * @return list<string>|null
     * @throws \InvalidArgumentException
     */
    private static function pathList(mixed $value, string $setting): ?array
    {
        if ($value === null) {
            return null;
        }
        $paths = [];
        foreach (is_array($value) ? $value : [] as $path) {
            $normalized = is_string($path) && str_starts_with($path, '/') ? RequestPaths::normalize($path) : null;
            if ($normalized === null) {
                $paths = [];
                break;
            }
            $paths[] = $normalized;
        }
        if ($paths === []) {
            throw new InvalidArgumentException(
                sprintf('"%s" must be a non-empty list of path prefixes that start with "/".', $setting),
            );
        }

        return $paths;
    }

    /**
     * Layout of the consent and error pages: null for the plugin's, false for none.
     *
     * @return string|false|null
     */
    public function consentLayout(): string|false|null
    {
        return self::layout($this->section('consent')['layout'] ?? null, 'consent');
    }

    /**
     * Layout of the connections page: null for the plugin's, false for none.
     *
     * @return string|false|null
     */
    public function connectionsLayout(): string|false|null
    {
        return self::layout($this->section('connections')['layout'] ?? null, 'connections');
    }

    /**
     * The Cake cache configuration for rate limiting; null disables it.
     *
     * @return string|null
     */
    public function rateLimitCache(): ?string
    {
        $rateLimit = $this->settings['rateLimit'] ?? [];
        if (!is_array($rateLimit) || !array_key_exists('cache', $rateLimit)) {
            return 'default';
        }

        return $rateLimit['cache'] === null ? null : (string)$rateLimit['cache'];
    }

    /**
     * Replacement services (advanced; used by tests).
     *
     * @return array<string, object>
     */
    public function services(): array
    {
        $services = [];
        foreach ($this->section('services') as $key => $service) {
            $type = self::SERVICE_TYPES[$key];
            if (!$service instanceof $type) {
                throw new InvalidArgumentException(
                    sprintf('"OAuthServer.services.%s" must be an instance of %s.', $key, $type),
                );
            }
            $services[$key] = $service;
        }

        return $services;
    }

    /**
     * Path prefix of the endpoints below the issuer, as validated by the core.
     *
     * @return string
     * @throws \InvalidArgumentException
     */
    public function routePrefix(): string
    {
        return $this->routing()['prefix'];
    }

    /**
     * Path of the authorization server metadata, as the core serves it.
     *
     * @return string
     * @throws \InvalidArgumentException
     */
    public function metadataPath(): string
    {
        return $this->routing()['metadata'];
    }

    /**
     * A plugin section, failing on unknown keys.
     *
     * @param string $name Section name.
     * @return array<string, mixed>
     * @throws \InvalidArgumentException
     */
    private function section(string $name): array
    {
        $section = $this->settings[$name] ?? [];
        // `connections` accepts true or false as shorthand for its `enabled` key.
        if ($name === 'connections' && is_bool($section)) {
            return ['enabled' => $section];
        }
        if (!is_array($section)) {
            throw new InvalidArgumentException(sprintf('"OAuthServer.%s" must be an array.', $name));
        }
        $unknown = array_diff(array_keys($section), self::PLUGIN_SECTIONS[$name]);
        if ($unknown !== []) {
            throw new InvalidArgumentException(
                sprintf('Unknown setting "OAuthServer.%s.%s".', $name, implode('", "', $unknown)),
            );
        }

        /** @var array<string, mixed> $section */
        return $section;
    }

    /**
     * A callable setting, or null.
     *
     * @param array<string, mixed> $section Section.
     * @param string $key Setting name.
     * @return callable|null
     * @throws \InvalidArgumentException
     */
    private static function callable(array $section, string $key): ?callable
    {
        $value = $section[$key] ?? null;
        if ($value !== null && !is_callable($value)) {
            throw new InvalidArgumentException(sprintf('"OAuthServer.userProvider.%s" must be callable.', $key));
        }

        return $value;
    }

    /**
     * A layout setting.
     *
     * @param mixed $value The raw setting.
     * @param string $section Section name, for the error.
     * @return string|false|null
     * @throws \InvalidArgumentException
     */
    private static function layout(mixed $value, string $section): string|false|null
    {
        if ($value !== null && $value !== false && !is_string($value)) {
            throw new InvalidArgumentException(
                sprintf('"OAuthServer.%s.layout" must be a layout name, false or null.', $section),
            );
        }

        return $value;
    }
}
