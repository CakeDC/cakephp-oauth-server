<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Config;

use Cake\Core\Configure;
use Cake\TestSuite\TestCase;
use Cake\Utility\Security;
use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Identity\OrmUserProvider;
use InvalidArgumentException;

class PluginConfigTest extends TestCase
{
    public function testCoreSettingsWithCakeDefaults(): void
    {
        $config = PluginConfig::fromConfigure();
        $server = $config->serverConfig();

        $this->assertInstanceOf(ServerConfig::class, $server);
        $this->assertSame('http://localhost', $server->issuer);
        $this->assertSame(hash('sha256', Security::getSalt() . '|cakedc-oauth-server'), $server->secret);
        $this->assertSame('test', $server->tokenPrefix);
        $this->assertFalse($server->cimdEnabled);
        $this->assertTrue($server->connections);
        $this->assertSame('/oauth', $config->routePrefix());
        $this->assertSame('/.well-known/oauth-authorization-server', $config->metadataPath());
    }

    public function testPluginSettingsAreNotPassedToTheCore(): void
    {
        $config = new PluginConfig([
            'resources' => ['https://example.com/mcp' => ['scopes' => ['a' => 'A']]],
            'issuer' => 'https://example.com',
            'connections' => ['enabled' => false, 'layout' => 'default'],
            'consent' => ['layout' => false],
            'rateLimit' => ['cache' => 'oauth', 'token' => [5, 60]],
            'login' => ['url' => ['controller' => 'Users', 'action' => 'login']],
        ]);

        $this->assertFalse($config->serverConfig()->connections);
        $this->assertSame([5, 60], $config->serverConfig()->rateLimits['token']);
        $this->assertSame('default', $config->connectionsLayout());
        $this->assertFalse($config->consentLayout());
        $this->assertSame('oauth', $config->rateLimitCache());
        $this->assertSame(['controller' => 'Users', 'action' => 'login'], $config->login()['url']);
        $this->assertSame('redirect', $config->login()['redirectParam']);
    }

    public function testConnectionsAcceptsABooleanShorthand(): void
    {
        $resources = ['https://example.com/mcp' => ['scopes' => ['a' => 'A']]];
        $off = new PluginConfig(['resources' => $resources, 'issuer' => 'https://example.com', 'connections' => false]);
        $on = new PluginConfig(['resources' => $resources, 'issuer' => 'https://example.com', 'connections' => true]);

        $this->assertFalse($off->serverConfig()->connections);
        $this->assertNull($off->connectionsLayout());
        $this->assertTrue($on->serverConfig()->connections);
        $this->assertNull($on->connectionsLayout());
    }

    public function testPathsComeFromTheCore(): void
    {
        $config = new PluginConfig([
            'resources' => ['https://example.com/base/mcp' => ['scopes' => ['a' => 'A']]],
            'issuer' => 'https://Example.com/base/',
            'routePrefix' => '/auth',
        ]);

        $this->assertSame('/auth', $config->routePrefix());
        $this->assertSame('/.well-known/oauth-authorization-server/base', $config->metadataPath());
    }

    public function testUserProviderDefaults(): void
    {
        $provider = (new PluginConfig(['resources' => []]))->userProvider();

        $this->assertSame(OrmUserProvider::class, $provider['className']);
        $this->assertSame('Users', $provider['table']);
        $this->assertSame('active', $provider['finder']);
        $this->assertNull($provider['canAuthorize']);
    }

    public function testRateLimitCacheCanBeDisabled(): void
    {
        $this->assertSame('default', (new PluginConfig([]))->rateLimitCache());
        $this->assertNull((new PluginConfig(['rateLimit' => ['cache' => null]]))->rateLimitCache());
        $this->assertNull(PluginConfig::fromConfigure()->rateLimitCache());
    }

    public function testRejectsUnknownPluginSettings(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('userProvider.tabel');

        (new PluginConfig(['userProvider' => ['tabel' => 'Users']]))->userProvider();
    }

    public function testInvalidCoreSettingsFailClearly(): void
    {
        Configure::write('OAuthServer.lifetimes', ['acess' => 1]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('acess');
        PluginConfig::fromConfigure()->serverConfig();
    }
}
