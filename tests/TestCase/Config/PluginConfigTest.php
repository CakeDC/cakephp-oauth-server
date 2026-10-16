<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Config;

use Cake\Core\Configure;
use Cake\TestSuite\TestCase;
use Cake\Utility\Security;
use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Identity\OrmUserProvider;
use DateTimeImmutable;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use ReflectionProperty;
use stdClass;

class PluginConfigTest extends TestCase
{
    private string $salt;

    protected function setUp(): void
    {
        parent::setUp();
        $this->salt = Security::getSalt();
    }

    protected function tearDown(): void
    {
        Security::setSalt($this->salt);
        parent::tearDown();
    }

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

    public function testHttpBaseUrlNamesTheSettingToFix(): void
    {
        Configure::write('App.fullBaseUrl', 'http://app.ddev.site');

        try {
            PluginConfig::fromConfigure()->serverConfig();
            $this->fail('Expected an exception.');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('App.fullBaseUrl', $e->getMessage());
            $this->assertStringContainsString('OAuthServer.issuer', $e->getMessage());
            $this->assertNotNull($e->getPrevious());
        }
    }

    public function testEmptyBaseUrlNamesTheSettingToFix(): void
    {
        Configure::write('App.fullBaseUrl', '');

        foreach (['serverConfig', 'routePrefix', 'metadataPath'] as $method) {
            try {
                PluginConfig::fromConfigure()->{$method}();
                $this->fail('Expected an exception.');
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('App.fullBaseUrl', $e->getMessage());
            }
        }
    }

    public function testBadConfiguredIssuerNamesTheIssuerSetting(): void
    {
        Configure::write('OAuthServer.issuer', 'http://example.com');

        try {
            PluginConfig::fromConfigure()->serverConfig();
            $this->fail('Expected an exception.');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('Fix OAuthServer.issuer', $e->getMessage());
            $this->assertStringNotContainsString('App.fullBaseUrl', $e->getMessage());
        }
    }

    public function testExplicitIssuerAndSecretOverrideTheDefaults(): void
    {
        $secret = str_repeat('s', 40);
        Configure::write('App.fullBaseUrl', 'http://app.ddev.site');
        Configure::write('OAuthServer.issuer', 'https://auth.example.com');
        Configure::write('OAuthServer.secret', $secret);

        $server = PluginConfig::fromConfigure()->serverConfig();

        $this->assertSame('https://auth.example.com', $server->issuer);
        $this->assertSame($secret, $server->secret);
    }

    public function testShortSaltIsRefusedWithoutAConfiguredSecret(): void
    {
        Security::setSalt('too-short');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('OAuthServer.secret');
        PluginConfig::fromConfigure()->serverConfig();
    }

    public function testMissingSaltIsRefusedWithoutAConfiguredSecret(): void
    {
        $property = new ReflectionProperty(Security::class, '_salt');
        $property->setValue(null, null);

        try {
            PluginConfig::fromConfigure()->serverConfig();
            $this->fail('Expected an exception.');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('Security.salt', $e->getMessage());
        }
    }

    public function testShortSaltIsFineWithAConfiguredSecret(): void
    {
        Security::setSalt('short');
        Configure::write('OAuthServer.secret', str_repeat('k', 32));

        $this->assertSame(str_repeat('k', 32), PluginConfig::fromConfigure()->serverConfig()->secret);
    }

    public function testServerConfigIsBuiltOnce(): void
    {
        $config = PluginConfig::fromConfigure();

        $this->assertSame($config->serverConfig(), $config->serverConfig());
    }

    public function testServicesAreValidated(): void
    {
        $clock = new class implements ClockInterface {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable();
            }
        };

        $this->assertSame(['clock' => $clock], (new PluginConfig(['services' => ['clock' => $clock]]))->services());

        try {
            (new PluginConfig(['services' => ['clock' => new stdClass()]]))->services();
            $this->fail('Expected an exception.');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('OAuthServer.services.clock', $e->getMessage());
        }
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('OAuthServer.services.cache');
        (new PluginConfig(['services' => ['cache' => $clock]]))->services();
    }

    public function testLayoutsMustBeNamesFalseOrNull(): void
    {
        $this->assertSame('app', (new PluginConfig(['consent' => ['layout' => 'app']]))->consentLayout());
        $this->assertNull((new PluginConfig([]))->consentLayout());

        try {
            (new PluginConfig(['consent' => ['layout' => true]]))->consentLayout();
            $this->fail('Expected an exception.');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('OAuthServer.consent.layout', $e->getMessage());
        }
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('OAuthServer.connections.layout');
        (new PluginConfig(['connections' => ['layout' => 1]]))->connectionsLayout();
    }

    public function testCimdRateLimitPassesThroughToTheCore(): void
    {
        $config = new PluginConfig([
            'resources' => ['https://example.com/mcp' => ['scopes' => ['a' => 'A']]],
            'issuer' => 'https://example.com',
            'rateLimit' => ['cache' => null, 'cimd' => [3, 30]],
        ]);

        $this->assertSame([3, 30], $config->serverConfig()->rateLimits['cimd']);
    }

    public function testUnknownLoginAndConsentSettingsThrow(): void
    {
        try {
            (new PluginConfig(['login' => ['ulr' => '/x']]))->login();
            $this->fail('Expected an exception.');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('login.ulr', $e->getMessage());
        }
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('consent.layuot');
        (new PluginConfig(['consent' => ['layuot' => 'x']]))->consentLayout();
    }

    public function testNonCallableSettingsNameTheKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('OAuthServer.userProvider.forClient');
        (new PluginConfig(['userProvider' => ['forClient' => 'nope']]))->userProvider();
    }
}
