<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Server;

use Cake\Cache\Cache;
use Cake\Http\ResponseFactory;
use Cake\Http\ServerRequest;
use Cake\Http\StreamFactory;
use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Client\Cimd\DnsResolverInterface;
use CakeDC\OAuth\Server\Client\Cimd\HttpTransportInterface;
use CakeDC\OAuth\Server\Http\ClientIp;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Event\CakeEventDispatcher;
use CakeDC\OAuthServer\Identity\OrmUserProvider;
use CakeDC\OAuthServer\Identity\SessionUserContext;
use CakeDC\OAuthServer\Log\CakeLogger;
use CakeDC\OAuthServer\Storage\OrmStorage;
use CakeDC\OAuthServer\View\CakeConnectionsRenderer;
use CakeDC\OAuthServer\View\CakeConsentRenderer;
use CakeDC\OAuthServer\View\CakeErrorPageRenderer;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Builds the core authorization server with the plugin's Cake implementations.
 */
final class ServerFactory
{
    /**
     * @param \CakeDC\OAuthServer\Config\PluginConfig $config Configuration.
     */
    public function __construct(private readonly PluginConfig $config)
    {
    }

    /**
     * A server; pages render with $request (its CSRF token and base path) when given.
     *
     * @param \Cake\Http\ServerRequest|null $request The current request.
     * @return \CakeDC\OAuth\Server\AuthorizationServer
     * @throws \InvalidArgumentException For an invalid configuration.
     */
    public function create(?ServerRequest $request = null): AuthorizationServer
    {
        $users = $this->userProvider();
        $login = $this->config->login();
        $services = $this->config->services();
        $cache = $this->config->rateLimitCache();
        $clock = $services['clock'] ?? null;
        $transport = $services['transport'] ?? null;
        $dns = $services['dns'] ?? null;

        return new AuthorizationServer(
            $this->config->serverConfig(),
            new OrmStorage(),
            $users,
            new SessionUserContext(
                $users,
                $login['url'],
                $login['redirectParam'],
                $login['identityAttribute'],
                $users instanceof OrmUserProvider ? $users->keyField(...) : 'id',
            ),
            new ResponseFactory(),
            new StreamFactory(),
            events: new CakeEventDispatcher(),
            cache: $cache === null ? null : Cache::pool($cache),
            clock: $clock instanceof ClockInterface ? $clock : null,
            logger: new CakeLogger(),
            transport: $transport instanceof HttpTransportInterface ? $transport : null,
            dns: $dns instanceof DnsResolverInterface ? $dns : null,
            consentRenderer: new CakeConsentRenderer($request, $this->config->consentLayout()),
            connectionsRenderer: new CakeConnectionsRenderer($request, $this->config->connectionsLayout()),
            errorPageRenderer: new CakeErrorPageRenderer($request, $this->config->consentLayout()),
            clientIp: self::clientIp(...),
        );
    }

    /**
     * The client address used for rate limiting: Cake's, or 'unknown' where Cake has none.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return string
     */
    public static function clientIp(ServerRequestInterface $request): string
    {
        if (!$request instanceof ServerRequest) {
            return ClientIp::fromServerParams($request);
        }
        $ip = $request->clientIp();

        // Cake answers '' without REMOTE_ADDR (CLI, integration tests); the core uses 'unknown'.
        return $ip !== '' ? $ip : 'unknown';
    }

    /**
     * The configured user provider: the ORM provider, another class built with the same settings,
     * or an instance.
     *
     * @return \CakeDC\OAuth\Server\Owner\UserProviderInterface
     * @throws \InvalidArgumentException
     */
    public function userProvider(): UserProviderInterface
    {
        $settings = $this->config->userProvider();
        $class = $settings['className'];
        if ($class instanceof UserProviderInterface) {
            return $class;
        }
        if ($class === OrmUserProvider::class) {
            return new OrmUserProvider($settings);
        }
        $provider = is_string($class) && class_exists($class) ? new $class($settings) : null;
        if (!$provider instanceof UserProviderInterface) {
            throw new InvalidArgumentException(
                '"OAuthServer.userProvider.className" must implement UserProviderInterface.',
            );
        }

        return $provider;
    }
}
