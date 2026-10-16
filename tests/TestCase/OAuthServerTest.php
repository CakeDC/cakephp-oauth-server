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
     * $request as a browser with a session sends it: with the session cookie, in the header and the cookie
     * parameters.
     *
     * @param \Cake\Http\ServerRequest $request The request.
     * @return \Cake\Http\ServerRequest
     */
    private function withCookie(ServerRequest $request): ServerRequest
    {
        $name = (string)session_name();

        return $request->withCookieParams([$name => 'abc'])->withHeader('Cookie', $name . '=abc');
    }

    /**
     * $request with the cookies of the `Cookie` header $header, as the header and as cookie parameters, the way PHP
     * presents them.
     *
     * @param \Cake\Http\ServerRequest $request The request.
     * @param string $header The Cookie header.
     * @return \Cake\Http\ServerRequest
     */
    private function withCookies(ServerRequest $request, string $header): ServerRequest
    {
        $cookies = [];
        foreach (explode(';', $header) as $pair) {
            [$name, $value] = array_pad(explode('=', trim($pair), 2), 2, '');
            if ($name !== '') {
                $cookies[$name] = $value;
            }
        }

        return $request->withCookieParams($cookies)->withHeader('Cookie', $header);
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
    public function testCsrfSkipCoversRequestsWithABearerTokenOfThisServerWhateverElseTheyCarry(): void
    {
        $api = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $mcp = $this->oauthTokenFor(1, ['content:read'], 'http://localhost/mcp');
        $suffix = str_repeat('x', 43);
        $post = fn(string $token, array $environment = []): ServerRequest => $this->post(
            '/api/posts',
            $token,
            '/api/**',
            '',
            $environment,
        );

        // The prefix decides, not the token: a valid one, a made up one, one of another resource. Nothing is looked
        // up; the Token authenticator answers each of them (401 for all but the first). Cookies do not matter.
        foreach ([$api, $mcp, 'test_at_' . $suffix, 'test_pat_' . $suffix, 'test_at_abc123'] as $value) {
            $this->assertTrue(OAuthServer::csrfSkip($post($value)), $value);
            $this->assertTrue(OAuthServer::csrfSkip($this->withCookie($post($value))), $value);
            $this->assertTrue(OAuthServer::csrfSkip($this->withCookies($post($value), 'csrfToken=a; AWSALB=b')), $value);
            $this->assertTrue(OAuthServer::csrfSkip($post($value, ['REMOTE_USER' => 'ada'])), $value);
        }
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/mcp', $mcp)));
        $this->assertTrue(OAuthServer::csrfSkip(
            $this->post('/mcp', null, '', '', ['HTTP_AUTHORIZATION' => 'bearer ' . $mcp . '  ']),
        ));
        $this->assertNull(
            $this->fetchTable('CakeDC/OAuthServer.OauthTokens')->find()->firstOrFail()->get('last_used_at'),
            'The skip only looks at the header; the authenticator records the use.',
        );

        // Not a bearer token of this server: a refresh token, another kind, another server's token, a header that
        // is not one token. The Authorization header alone keeps the check, with a cookie or without.
        foreach (
            ['test_rt_' . $suffix, 'test_xx_abc123', 'other_at_abc123', 'eyJhbGciOiJIUzI1NiJ9.e30.c2ln', $api . "\nx",
            $api . ' x'] as $value
        ) {
            $this->assertFalse(OAuthServer::csrfSkip($post($value)), $value);
            $this->assertFalse(OAuthServer::csrfSkip($this->withCookie($post($value))), $value);
        }
        // Session pages stay checked, whatever the header says.
        Configure::write('OAuthServer.tokenPaths', ['/']);
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/oauth/authorize', $api)));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/oauth/connections', $api)));
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
    public function testCsrfSkipNeverThrowsAndNeverBuildsTheServer(): void
    {
        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $salt = Security::getSalt();
        Security::setSalt('short');
        OAuthServer::reset();
        try {
            // The derived secret is refused, so the server cannot be built; the skip never needs it.
            $this->assertTrue(OAuthServer::csrfSkip($this->withCookie($this->post('/api/posts', $token, '/api/**'))));
            $this->assertTrue(OAuthServer::csrfSkip($this->post('/api/posts', $token, '/api/**')));
            $this->assertTrue(OAuthServer::csrfSkip($this->post('/api/posts', null, '/api/**')));
        } finally {
            Security::setSalt($salt);
            OAuthServer::reset();
        }

        // A configuration that cannot be read at all: the endpoints are routed at the default prefix (they answer
        // 503 there), so they are still skipped; nothing on a resource's routes is.
        Configure::write('OAuthServer.routePrefix', 'no slash');
        Configure::write('OAuthServer.tokenPaths', 'not a list');
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/oauth/token')));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/posts', $token, '/api/**')));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/posts', null, '/api/**')));
    }

    /**
     * @return void
     */
    public function testCsrfSkipSkipsARequestWithoutCredentialsOnTheRoutesOfAResource(): void
    {
        $api = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $post = fn(array $environment = []): ServerRequest => $this->post('/api/posts', null, '/api/**', '', $environment);

        // No Authorization header and no cookie but the CSRF middleware's own: the route answers for itself (an MCP
        // client's discovery starts from such a POST).
        $this->assertTrue(OAuthServer::csrfSkip($post()));
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/mcp', null)));
        foreach (['csrfToken=abc', 'csrfToken=abc;', ' csrfToken=abc ; '] as $header) {
            $this->assertTrue(OAuthServer::csrfSkip($this->withCookies($post(), $header)), $header);
        }
        $this->assertTrue(OAuthServer::csrfSkip($post(['HTTP_COOKIE' => 'csrfToken=abc'])), 'As a header only.');
        $this->assertTrue(OAuthServer::csrfSkip(Routed::request('/api/posts', '/api/**', [
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'cookies' => ['csrfToken' => 'abc'],
        ])), 'As a parameter only.');

        // Any other cookie can be an ambient credential: a session, a remember-me cookie, a load balancer's.
        foreach (['PHPSESSID=abc', 'AWSALB=abc', 'csrfToken=a; AWSALB=b', 'csrfToken=a, AWSALB=b', 'csrftoken=abc', 'abc'] as $header) {
            $this->assertFalse(OAuthServer::csrfSkip($this->withCookies($post(), $header)), $header);
        }
        $this->assertFalse(OAuthServer::csrfSkip($post(['HTTP_COOKIE' => 'PHPSESSID=abc'])), 'A header alone counts.');
        $this->assertFalse(OAuthServer::csrfSkip(Routed::request('/api/posts', '/api/**', [
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'cookies' => ['PHPSESSID' => 'abc'],
        ])), 'A parameter alone counts.');

        // The CSRF middleware's cookie under another name.
        Configure::write('OAuthServer.csrfCookieName', 'XSRF-TOKEN');
        $this->assertTrue(OAuthServer::csrfSkip($this->withCookies($post(), 'XSRF-TOKEN=abc')));
        $this->assertFalse(OAuthServer::csrfSkip($this->withCookies($post(), 'csrfToken=abc')));
        // A setting that is no cookie name leaves no cookie to ignore: every cookie counts.
        Configure::write('OAuthServer.csrfCookieName', ['csrfToken']);
        $this->assertFalse(OAuthServer::csrfSkip($this->withCookies($post(), 'csrfToken=abc')));
        $this->assertTrue(OAuthServer::csrfSkip($post()));
        $this->assertTrue(OAuthServer::csrfSkip($this->withCookies($this->post('/api/posts', $api, '/api/**'), 'a=b')));
        Configure::delete('OAuthServer.csrfCookieName');

        // Any Authorization header but a bearer token of this server keeps the check, and so do credentials PHP or
        // the web server took from the browser.
        foreach (
            [
                ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('ada:secret')],
                ['HTTP_AUTHORIZATION' => 'Negotiate abc'],
                ['HTTP_AUTHORIZATION' => 'Bearerx abc'],
                ['HTTP_AUTHORIZATION' => 'Bearer'],
                ['HTTP_AUTHORIZATION' => 'Bearer other_at_abc123'],
                ['PHP_AUTH_USER' => 'ada'],
                ['PHP_AUTH_DIGEST' => 'username="ada"'],
                ['REMOTE_USER' => 'ada'],
            ] as $environment
        ) {
            $this->assertFalse(OAuthServer::csrfSkip($post($environment)), (string)json_encode($environment));
        }
        $this->assertTrue(
            OAuthServer::csrfSkip($post(['REMOTE_USER' => '', 'PHP_AUTH_USER' => ''])),
            'Empty values are no credential.',
        );

        // Only on the routes of a resource, as routed.
        foreach (
            [
                ['/account/delete', '/account/delete'],
                ['/mcp/account/delete', '/{tenant}/account/delete'],
                ['/mcp', '/{slug}'],
                ['/mcp', null],
                ['/apix', '/apix/**'],
                ['/api%2Fx', '/api/**'],
                ['/api/../account/delete', '/api/**'],
            ] as [$path, $template]
        ) {
            $this->assertFalse(OAuthServer::csrfSkip($this->post($path, null, $template)), $path);
            $this->assertFalse(OAuthServer::csrfSkip($this->post($path, $api, $template)), $path);
        }
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/me', null, '', '/sub')));
        // The $paths argument scopes it like the bearer branch.
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/rest/x', null, '/rest/**'), ['/rest']));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/api/x', null, '/api/**'), ['/rest']));
    }

    /**
     * @return void
     */
    public function testCsrfSkipNeverSkipsTheLogin(): void
    {
        $api = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        Configure::write('OAuthServer.tokenPaths', ['/']);

        foreach (['/oauth/authorize', '/oauth/connections', '/OAuth/Authorize/', '/login', '/LOGIN/'] as $path) {
            $this->assertFalse(OAuthServer::csrfSkip($this->post($path, null, '/**')), $path);
            $this->assertFalse(OAuthServer::csrfSkip($this->post($path, $api, '/**')), $path);
        }
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/account/delete', null, '/**')));
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/account/delete', $api, '/**')));

        // A string URL is the page at its path.
        Configure::write('OAuthServer.login.url', '/users/sign-in?from=oauth');
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/users/sign-in', null, '/**')));
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/users/sign-in', $api, '/**')));
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/login', null, '/**')));

        // An array URL is also every route to the same action: a fallback route, another spelling of the path.
        $routed = fn(string $path, ?string $token, array $params): ServerRequest => $this
            ->post($path, $token, '/{controller}/{action}/*')
            ->withAttribute('params', $params + ['pass' => []]);
        Configure::write('OAuthServer.login.url', [
            'plugin' => 'CakeDC/Users',
            'controller' => 'Users',
            'action' => 'login',
            'prefix' => false,
        ]);
        $login = ['plugin' => 'CakeDC/Users', 'controller' => 'Users', 'action' => 'login'];
        $this->assertFalse(OAuthServer::csrfSkip($routed('/Users/login', null, $login)));
        $this->assertFalse(OAuthServer::csrfSkip($routed('/Users/login', $api, $login)));
        $this->assertFalse(OAuthServer::csrfSkip($routed('/users/LOGIN', null, ['controller' => 'users'] + $login)));
        $this->assertFalse(OAuthServer::csrfSkip($routed('/Users/login/x', null, ['pass' => ['x']] + $login)));
        // Another action, another plugin, a prefixed route: not the login.
        $this->assertTrue(OAuthServer::csrfSkip($routed('/Users/logout', null, ['action' => 'logout'] + $login)));
        $this->assertTrue(OAuthServer::csrfSkip($routed('/Users/login', null, ['plugin' => null] + $login)));
        $this->assertTrue(OAuthServer::csrfSkip($routed('/admin/Users/login', null, ['prefix' => 'Admin'] + $login)));
        // Positional values in the URL array must match too.
        Configure::write('OAuthServer.login.url', ['controller' => 'Pages', 'action' => 'display', 'sign-in']);
        $display = ['plugin' => null, 'controller' => 'Pages', 'action' => 'display'];
        $this->assertFalse(OAuthServer::csrfSkip($routed('/pages/sign-in', null, ['pass' => ['sign-in']] + $display)));
        $this->assertTrue(OAuthServer::csrfSkip($routed('/pages/about', null, ['pass' => ['about']] + $display)));

        // A login whose route cannot be found: no request without a token is skipped (a warning is logged), while
        // a bearer request, which no page on another site can send, still is.
        Configure::write('OAuthServer.login.url', ['_name' => 'no-such-route']);
        $this->assertFalse(OAuthServer::csrfSkip($this->post('/account/delete', null, '/**')));
        $this->assertTrue(OAuthServer::csrfSkip($this->post('/account/delete', $api, '/**')));
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
