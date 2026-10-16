<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase;

use Cake\Core\Configure;
use Cake\Core\Container;
use Cake\Http\ServerRequest;
use Cake\TestSuite\TestCase;
use Cake\Utility\Security;
use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuthServer\Controller\OAuthController;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\OAuthServerPlugin;
use CakeDC\OAuthServer\Storage\OrmStorage;
use CakeDC\OAuthServer\Test\Support\Fixtures;
use CakeDC\OAuthServer\Test\Support\Routed;
use CakeDC\OAuthServer\TestSuite\OAuthTestTrait;
use ReflectionClass;
use ReflectionMethod;

class OAuthServerTest extends TestCase
{
    use OAuthTestTrait;

    protected array $fixtures = Fixtures::ALL;

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
     * A POST to $path, routed by $template (the path itself when empty; not routed when null).
     *
     * @param string $path The path.
     * @param string|null $token The bearer token, or null for none.
     * @param string|null $template The template of the matched route.
     * @param string $base The base directory.
     * @param array<string, string> $environment More environment.
     * @return \Cake\Http\ServerRequest
     */
    private function post(
        string $path,
        ?string $token = null,
        ?string $template = '',
        string $base = '',
        array $environment = [],
    ): ServerRequest {
        $environment += ['REQUEST_METHOD' => 'POST'];
        if ($token !== null) {
            $environment += ['HTTP_AUTHORIZATION' => 'Bearer ' . $token];
        }

        return Routed::request($path, $template === '' ? $path : $template, ['environment' => $environment])
            ->withAttribute('base', $base);
    }

    /**
     * @return void
     */
    public function testCsrfSkipCoversTheEndpointsClientsCall(): void
    {
        $request = fn(string $path): ServerRequest => new ServerRequest(['url' => $path]);

        foreach (['/oauth/token', '/oauth/register', '/oauth/revoke', '/oauth/introspect'] as $path) {
            $this->assertTrue(OAuthServer::csrfSkip($request($path)), $path);
            // CSRF middleware placed before routing: the endpoints are still skipped.
            $this->assertTrue(OAuthServer::csrfSkip($this->post($path, null, null)), $path);
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
    public function testCsrfSkipCoversTheEndpointsUnderABasePath(): void
    {
        // The routed path is below the base, like the routes the plugin connects.
        foreach (['/oauth/token', '/oauth/register', '/oauth/revoke', '/oauth/introspect'] as $path) {
            $this->assertTrue(OAuthServer::csrfSkip($this->post($path, null, '', '/app')), $path);
        }
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/app/oauth/token', null, '', '/app')));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/oauth/authorize', null, '', '/app')));
    }

    /**
     * @return void
     */
    public function testCsrfSkipCoversRequestsWithAValidBearerTokenOfThisServer(): void
    {
        $api = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $mcp = $this->oauthTokenFor(1, ['content:read'], 'http://localhost/mcp');

        $this->assertTrue(OAuthServer::csrfSkip($this->post('/api/posts', $api, '/api/**')));
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/mcp', $mcp)));
        $this->assertTrue(OAuthServer::csrfSkip(
            $this->post('/mcp', null, '', '', ['HTTP_AUTHORIZATION' => 'bearer ' . $mcp . '  ']),
        ));

        $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/posts', null, '/api/**')));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/posts', 'other_at_abc123', '/api/**')));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/posts', 'test_xx_abc123', '/api/**')));
        $this->assertFalse(OAuthServer::csrfSkip(
            $this->post('/api/posts', null, '/api/**', '', ['HTTP_AUTHORIZATION' => 'Basic ' . $api]),
        ));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/posts', $api . "\nx", '/api/**')));
        $cookie = Routed::request('/api/posts', '/api/**', [
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'cookies' => ['PHPSESSID' => 'abc'],
        ]);
        $this->assertFalse(OAuthServer::csrfSkip($cookie));
        // A token is for one resource: below the other one's path it is not skipped.
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/mcp', $api)));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/posts', $mcp, '/api/**')));
        // Session pages stay checked, whatever the header says.
        Configure::write('OAuthServer.tokenPaths', ['/']);
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/oauth/authorize', $api)));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/oauth/connections', $api)));
    }

    /**
     * @return void
     */
    public function testCsrfSkipNeedsATokenThatValidates(): void
    {
        $suffix = str_repeat('x', 43);
        // The prefix alone is not enough: an access or personal token that is not a live token is checked.
        foreach (['test_at_' . $suffix, 'test_pat_' . $suffix, 'test_at_abc123'] as $garbage) {
            $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/posts', $garbage, '/api/**')), $garbage);
        }
        // A refresh token is never a bearer token.
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/posts', 'test_rt_' . $suffix, '/api/**')));

        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/api/posts', $token, '/api/**')));
        $this->assertNull(
            $this->fetchTable('CakeDC/OAuthServer.OauthTokens')->find()->firstOrFail()->get('last_used_at'),
            'The skip only looks at the token; the authenticator records the use.',
        );

        OAuthServer::server()->tokenRevoker()->revokeAllForSubject('1');
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/posts', $token, '/api/**')));
    }

    /**
     * @return void
     */
    public function testCsrfSkipNeedsTheMatchedRouteBelowThePaths(): void
    {
        $mcp = $this->oauthTokenFor(1, ['content:read'], 'http://localhost/mcp');

        $this->assertTrue(OAuthServer::csrfSkip($this->post('/mcp/tools/call', $mcp, '/mcp/**')));
        // The reviewer's probe: /mcp/account/delete matched by /{tenant}/account/delete.
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/mcp/account/delete', $mcp, '/{tenant}/account/delete')));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/mcp', $mcp, '/{slug}')));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/mcp/x/y', $mcp, '/{controller}/{action}/*')));
        // CSRF middleware placed before routing: no route yet, no skip for a bearer token.
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/mcp', $mcp, null)));

        Configure::write('OAuthServer.tokenPaths', ['/']);
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/mcp/account/delete', $mcp, '/{tenant}/account/delete')));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/mcp', $mcp, null)));
    }

    /**
     * @return void
     */
    public function testCsrfSkipForABearerTokenAppliesOnlyBelowTheResourcePaths(): void
    {
        $api = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $mcp = $this->oauthTokenFor(1, ['content:read'], 'http://localhost/mcp');

        // The declared resources are /mcp and /api; the router would pick their catch-all routes.
        foreach (['/api', '/api/x', '/api/x/', '/%61pi/x'] as $path) {
            $this->assertTrue(OAuthServer::csrfSkip($this->post($path, $api, '/api/**')), $path);
        }
        foreach (['/mcp', '/mcp/tools/call'] as $path) {
            $this->assertTrue(OAuthServer::csrfSkip($this->post($path, $mcp, '/mcp/**')), $path);
        }
        foreach (
            ['/account/delete', '/api//x', '/api%2Fx', '/api%2fx/y', '/apix', '/apix/me', '/', '/login', '/API/me', '/api/../account/delete',
            '/api/%2e%2e/account/delete', '/mcpx'] as $path
        ) {
            $this->assertFalse(OAuthServer::csrfSkip($this->post($path, $api, '/api/**')), $path);
        }
        // The base directory is part of the path the resource lives at.
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/me', $api, '', '/sub')));
    }

    /**
     * @return void
     */
    public function testCsrfNeverSkipsTheSessionPagesWhateverThePathLooksLike(): void
    {
        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        Configure::write('OAuthServer.tokenPaths', ['/']);

        foreach (
            ['/oauth/authorize', '/oauth/authorize/', '/oauth/%61uthorize', '/oauth//authorize', '/oauth%2Fauthorize',
            '/OAuth/Authorize', '/oauth/connections', '/oauth/connections/', '/oauth/./authorize',
            '/oauth/x/../authorize'] as $path
        ) {
            $this->assertFalse(OAuthServer::csrfSkip($this->post($path, $token, '/**')), $path);
        }
        // Control: the same token on another route is skipped.
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/oauth/other', $token, '/**')));
        // The token endpoint is skipped with the same normalisation.
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/oauth/token/')));
        // An encoded slash or an empty segment is not the token endpoint: no skip.
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/oauth//token', $token, '/**')));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/oauth%2Ftoken', $token, '/**')));
    }

    /**
     * @return void
     */
    public function testCsrfSkipUsesTokenPathsWhenConfiguredAndAnExplicitArgumentOverRules(): void
    {
        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');

        Configure::write('OAuthServer.tokenPaths', ['/rest']);
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/rest/x', $token)));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/x', $token)));
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/api/x', $token), ['/api']));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/rest/x', $token), ['/api']));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/x', $token, '/{v}/x'), ['/api']));

        Configure::write('OAuthServer.tokenPaths', ['/']);
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/anything/at/all', $token)));
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
        $request = $this->post('/account/delete', $this->oauthTokenFor(1, ['all'], 'http://localhost'));

        $this->assertFalse(OAuthServer::csrfSkip($request));
        Configure::write('OAuthServer.tokenPaths', ['/']);
        $this->assertTrue(OAuthServer::csrfSkip($request));
    }

    /**
     * @return void
     */
    public function testCsrfSkipNeverThrowsAndSkipsNoBearerRequestWhenTheServerCannotBeBuilt(): void
    {
        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $salt = Security::getSalt();
        Security::setSalt('short');
        OAuthServer::reset();
        try {
            // The derived secret is refused, so the server cannot be built to validate the token.
            $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/posts', $token, '/api/**')));
        } finally {
            Security::setSalt($salt);
            OAuthServer::reset();
        }

        // A configuration that cannot be read at all: the endpoints are routed at the default prefix (they answer
        // 503 there), so they are still skipped; a bearer request is not.
        Configure::write('OAuthServer.routePrefix', 'no slash');
        Configure::write('OAuthServer.tokenPaths', 'not a list');
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/oauth/token')));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/posts', $token, '/api/**')));
    }

    /**
     * @return void
     */
    public function testTheRbacRuleListsTheActionsOfTheController(): void
    {
        $rules = OAuthServer::rbacPermissions();
        $actions = [];
        foreach ((new ReflectionClass(OAuthController::class))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
            if ($method->getDeclaringClass()->getName() === OAuthController::class) {
                $actions[] = $method->getName();
            }
        }

        $this->assertCount(1, $rules);
        $this->assertSame('CakeDC/OAuthServer', $rules[0]['plugin']);
        $this->assertSame('OAuth', $rules[0]['controller']);
        $this->assertTrue($rules[0]['bypassAuth']);
        // Listed one by one: a future action does not inherit the bypass.
        $this->assertSame(
            ['metadata', 'authorize', 'token', 'register', 'revoke', 'introspect', 'connections'],
            $rules[0]['action'],
        );
        $this->assertEqualsCanonicalizing($actions, $rules[0]['action']);
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
