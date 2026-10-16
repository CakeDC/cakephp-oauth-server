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
    public function testCsrfSkipCoversRequestsWithABearerTokenOfThisServer(): void
    {
        $post = fn(string $path, array $headers = [], array $cookies = []): ServerRequest => new ServerRequest([
            'url' => $path,
            'environment' => ['REQUEST_METHOD' => 'POST'] + $headers,
            'cookies' => $cookies,
        ]);
        $bearer = fn(string $token): array => ['HTTP_AUTHORIZATION' => 'Bearer ' . $token];

        $this->assertTrue(OAuthServer::csrfSkip($post('/api/posts', $bearer('test_at_abc123'))));
        $this->assertTrue(OAuthServer::csrfSkip($post('/mcp', $bearer('test_pat_abc123'))));
        $this->assertTrue(OAuthServer::csrfSkip($post('/mcp', ['HTTP_AUTHORIZATION' => 'bearer test_at_abc==  '])));

        $this->assertFalse(OAuthServer::csrfSkip($post('/api/posts')));
        $this->assertFalse(OAuthServer::csrfSkip($post('/api/posts', $bearer('other_at_abc123'))));
        $this->assertFalse(OAuthServer::csrfSkip($post('/api/posts', $bearer('test_xx_abc123'))));
        $this->assertFalse(OAuthServer::csrfSkip($post('/api/posts', ['HTTP_AUTHORIZATION' => 'Basic test_at_abc'])));
        $this->assertFalse(OAuthServer::csrfSkip($post('/api/posts', $bearer("test_at_abc\nx"))));
        $this->assertFalse(OAuthServer::csrfSkip($post('/api/posts', [], ['PHPSESSID' => 'abc'])));
        // Session pages stay checked, whatever the header says.
        $this->assertFalse(OAuthServer::csrfSkip($post('/oauth/authorize', $bearer('test_at_abc123'))));
        $this->assertFalse(OAuthServer::csrfSkip($post('/oauth/connections', $bearer('test_at_abc123'))));
    }

    /**
     * @return void
     */
    public function testCsrfSkipForABearerTokenAppliesOnlyBelowTheResourcePaths(): void
    {
        $post = fn(string $path, string $base = ''): ServerRequest => (new ServerRequest([
            'url' => $path,
            'environment' => ['REQUEST_METHOD' => 'POST', 'HTTP_AUTHORIZATION' => 'Bearer test_at_abc123'],
        ]))->withAttribute('base', $base);

        // The declared resources are /mcp and /api.
        foreach (['/api', '/api/x', '/api/x/', '//api//x', '/%61pi/x', '/mcp', '/mcp/tools/call'] as $path) {
            $this->assertTrue(OAuthServer::csrfSkip($post($path)), $path);
        }
        foreach (
            ['/account/delete', '/apix', '/apix/me', '/', '/login', '/API/me', '/api/../account/delete',
            '/api/%2e%2e/account/delete', '/mcpx'] as $path
        ) {
            $this->assertFalse(OAuthServer::csrfSkip($post($path)), $path);
        }
        // The base directory is part of the path the resource lives at.
        $this->assertFalse(OAuthServer::csrfSkip($post('/api/me', '/sub')));
    }

    /**
     * @return void
     */
    public function testCsrfNeverSkipsTheSessionPagesWhateverThePathLooksLike(): void
    {
        $post = fn(string $path): ServerRequest => new ServerRequest([
            'url' => $path,
            'environment' => ['REQUEST_METHOD' => 'POST', 'HTTP_AUTHORIZATION' => 'Bearer test_at_abc123'],
        ]);
        Configure::write('OAuthServer.tokenPaths', ['/']);

        foreach (
            ['/oauth/authorize', '/oauth/authorize/', '/oauth/%61uthorize', '/oauth//authorize',
            '/OAuth/Authorize', '/oauth/connections', '/oauth/connections/', '/oauth/./authorize',
            '/oauth/x/../authorize'] as $path
        ) {
            $this->assertFalse(OAuthServer::csrfSkip($post($path)), $path);
        }
        // The token endpoint is skipped with the same normalisation.
        $this->assertTrue(OAuthServer::csrfSkip($post('/oauth/token/')));
        $this->assertTrue(OAuthServer::csrfSkip($post('/oauth//token')));
    }

    /**
     * @return void
     */
    public function testCsrfSkipUsesTokenPathsWhenConfiguredAndAnExplicitArgumentOverRules(): void
    {
        $post = fn(string $path): ServerRequest => new ServerRequest([
            'url' => $path,
            'environment' => ['REQUEST_METHOD' => 'POST', 'HTTP_AUTHORIZATION' => 'Bearer test_at_abc123'],
        ]);

        Configure::write('OAuthServer.tokenPaths', ['/rest']);
        $this->assertTrue(OAuthServer::csrfSkip($post('/rest/x')));
        $this->assertFalse(OAuthServer::csrfSkip($post('/api/x')));
        $this->assertTrue(OAuthServer::csrfSkip($post('/api/x'), ['/api']));
        $this->assertFalse(OAuthServer::csrfSkip($post('/rest/x'), ['/api']));

        Configure::write('OAuthServer.tokenPaths', ['/']);
        $this->assertTrue(OAuthServer::csrfSkip($post('/anything/at/all')));
    }

    /**
     * @return void
     */
    public function testARootResourceDoesNotSkipCsrfEverywhereByItself(): void
    {
        Configure::write('OAuthServer.resources', ['http://localhost' => [
            'name' => 'Whole site',
            'scopes' => ['all' => 'Everything'],
        ]]);
        OAuthServer::reset();
        $request = new ServerRequest([
            'url' => '/account/delete',
            'environment' => ['REQUEST_METHOD' => 'POST', 'HTTP_AUTHORIZATION' => 'Bearer test_at_abc123'],
        ]);

        $this->assertFalse(OAuthServer::csrfSkip($request));
        Configure::write('OAuthServer.tokenPaths', ['/']);
        $this->assertTrue(OAuthServer::csrfSkip($request));
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
