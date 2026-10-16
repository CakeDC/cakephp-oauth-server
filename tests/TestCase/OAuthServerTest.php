<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase;

use Cake\Core\Configure;
use Cake\Core\Container;
use Cake\Http\ServerRequest;
use Cake\TestSuite\TestCase;
use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\OAuthServerPlugin;
use CakeDC\OAuthServer\Storage\OrmStorage;

class OAuthServerTest extends TestCase
{
    /**
     * @var string
     */
    private string $original = '';

    /**
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->original = serialize(Configure::read('OAuthServer'));
        OAuthServer::reset();
    }

    /**
     * @return void
     */
    protected function tearDown(): void
    {
        Configure::write('OAuthServer', unserialize($this->original));
        OAuthServer::reset();
        parent::tearDown();
    }

    /**
     * @return void
     */
    public function testBuildsTheServerOnceFromTheConfiguration(): void
    {
        $server = OAuthServer::server();

        $this->assertInstanceOf(AuthorizationServer::class, $server);
        $this->assertSame($server, OAuthServer::server());
        $this->assertInstanceOf(OrmStorage::class, $server->storage());
        $this->assertSame('http://localhost', $server->config()->issuer);

        OAuthServer::reset();
        $this->assertNotSame($server, OAuthServer::server());
        $this->assertNotSame(OAuthServer::server(), OAuthServer::forRequest(new ServerRequest()));
    }

    /**
     * @return void
     */
    public function testResetPicksUpChangedConfiguration(): void
    {
        $this->assertSame('http://localhost', OAuthServer::server()->config()->issuer);

        Configure::write('OAuthServer.issuer', 'http://localhost/sub');
        $this->assertSame('http://localhost', OAuthServer::server()->config()->issuer);
        OAuthServer::reset();
        $this->assertSame('http://localhost/sub', OAuthServer::server()->config()->issuer);
    }

    /**
     * @return void
     */
    public function testTheServerIsInTheContainer(): void
    {
        $container = new Container();
        (new OAuthServerPlugin())->services($container);

        $this->assertSame(OAuthServer::server(), $container->get(AuthorizationServer::class));
    }

    /**
     * @return void
     */
    public function testCsrfSkipCoversTheEndpointsClientsCall(): void
    {
        $request = fn(string $path): ServerRequest => new ServerRequest(['url' => $path]);

        foreach (['/oauth/token', '/oauth/register', '/oauth/revoke', '/oauth/introspect'] as $path) {
            $this->assertTrue(OAuthServer::csrfSkip($request($path)), $path);
        }
        foreach (['/oauth/authorize', '/oauth/connections', '/oauth/token/x', '/token', '/login'] as $path) {
            $this->assertFalse(OAuthServer::csrfSkip($request($path)), $path);
        }

        Configure::write('OAuthServer.routePrefix', '/auth');
        $this->assertTrue(OAuthServer::csrfSkip($request('/auth/token')));
        $this->assertFalse(OAuthServer::csrfSkip($request('/oauth/token')));
    }

    /**
     * @return void
     */
    public function testPageCspIsExtendedOnlyForAnAppLayout(): void
    {
        $this->assertNull(OAuthServer::pageCsp());
        $this->assertNull(OAuthServer::pageCsp(true));

        Configure::write('OAuthServer.consent.layout', 'default');
        $csp = OAuthServer::pageCsp();
        $this->assertSame(
            "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; "
            . "frame-ancestors 'none'; base-uri 'none'",
            $csp,
        );
        $this->assertStringNotContainsString('script-src', (string)$csp);
        $this->assertNull(OAuthServer::pageCsp(true));

        Configure::write('OAuthServer.connections', ['layout' => 'default']);
        $this->assertNotNull(OAuthServer::pageCsp(true));
    }
}
