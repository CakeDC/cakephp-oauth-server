<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Config;

use Cake\Core\Configure;
use Cake\Utility\Security;
use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Resource\ResourceIdentifier;
use CakeDC\OAuthServer\Identity\OrmUserProvider;
use InvalidArgumentException;

/**
 * The `OAuthServer` configuration: core settings for the server, plus the plugin's own.
 */
final class PluginConfig
{
    private const PLUGIN_SECTIONS = [
        'userProvider' => ['className', 'table', 'finder', 'displayField', 'canAuthorize', 'scopes', 'forClient'],
        'login' => ['url', 'redirectParam', 'identityAttribute'],
        'consent' => ['layout'],
        'connections' => ['enabled', 'layout'],
        'services' => ['clock', 'transport', 'dns'],
    ];

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
        $core = array_diff_key($this->settings, self::PLUGIN_SECTIONS);
        $core += [
            'issuer' => ResourceIdentifier::canonicalize((string)Configure::read('App.fullBaseUrl')),
            'secret' => hash('sha256', Security::getSalt() . '|cakedc-oauth-server'),
        ];
        if (isset($core['rateLimit']) && is_array($core['rateLimit'])) {
            unset($core['rateLimit']['cache']);
        }
        $core['connections'] = (bool)($this->section('connections')['enabled'] ?? true);

        return ServerConfig::fromArray($core);
    }

    /**
     * How people are found.
     *
     * @return array{className: object|string, table: string, finder: string, displayField: string|null, canAuthorize: callable|null, scopes: callable|null, forClient: callable|null}
     */
    public function userProvider(): array
    {
        $section = $this->section('userProvider');

        return [
            'className' => $section['className'] ?? OrmUserProvider::class,
            'table' => (string)($section['table'] ?? 'Users'),
            'finder' => (string)($section['finder'] ?? 'active'),
            'displayField' => isset($section['displayField']) ? (string)$section['displayField'] : null,
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
        $url = $section['url'] ?? '/login';

        return [
            'url' => is_array($url) ? $url : (string)$url,
            'redirectParam' => (string)($section['redirectParam'] ?? 'redirect'),
            'identityAttribute' => (string)($section['identityAttribute'] ?? 'identity'),
        ];
    }

    /**
     * Layout of the consent and error pages: null for the plugin's, false for none.
     *
     * @return string|false|null
     */
    public function consentLayout(): string|false|null
    {
        return self::layout($this->section('consent')['layout'] ?? null);
    }

    /**
     * Layout of the connections page: null for the plugin's, false for none.
     *
     * @return string|false|null
     */
    public function connectionsLayout(): string|false|null
    {
        return self::layout($this->section('connections')['layout'] ?? null);
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
        return array_filter($this->section('services'), 'is_object');
    }

    /**
     * Path prefix of the endpoints below the issuer, as validated by the core.
     *
     * @return string
     * @throws \InvalidArgumentException
     */
    public function routePrefix(): string
    {
        return $this->serverConfig()->routePrefix;
    }

    /**
     * Path of the authorization server metadata, as the core serves it.
     *
     * @return string
     * @throws \InvalidArgumentException
     */
    public function metadataPath(): string
    {
        return $this->serverConfig()->metadataPath();
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
     * @return string|false|null
     */
    private static function layout(mixed $value): string|false|null
    {
        return $value === false || $value === null ? $value : (string)$value;
    }
}
