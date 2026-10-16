<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Authenticator;

use Authentication\Authenticator\AuthenticationRequiredException;
use Authentication\Identifier\IdentifierCollection;
use Cake\Console\TestSuite\ConsoleIntegrationTestTrait;
use Cake\Core\Configure;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use CakeDC\OAuthServer\Authenticator\TokenAuthenticator;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Test\Support\Fixtures;
use CakeDC\OAuthServer\Test\Support\Routed;
use CakeDC\OAuthServer\TestSuite\OAuthTestTrait;
use InvalidArgumentException;

/**
 * A token is for one resource and works below that resource's path only.
 */
class TokenPathsTest extends TestCase
{
    use ConsoleIntegrationTestTrait;
    use IntegrationTestTrait;
    use OAuthTestTrait;

    protected array $fixtures = Fixtures::ALL;

    protected function setUp(): void
    {
        parent::setUp();
        OAuthServer::reset();
        Configure::delete('TestApp.accountDeleted');
    }

    protected function tearDown(): void
    {
        Configure::delete('TestApp.accountDeleted');
        OAuthServer::reset();
        parent::tearDown();
    }

    public function testATokenForTheApiCannotPostToASessionRoute(): void
    {
        $this->actAsOAuth(1, ['api'], 'http://localhost/api');
        $this->enableCsrfToken();

        $this->post('/account/delete', ['anything' => 'x']);

        $this->assertResponseCode(401);
        $this->assertHeaderContains('WWW-Authenticate', 'Bearer error="invalid_token"');
        $this->assertNull(Configure::read('TestApp.accountDeleted'), 'The action must not run.');
    }

    public function testNoCsrfSkipOutsideTheResourcePath(): void
    {
        // The reviewer's probe: no CSRF token at all. It used to run the action as user 1.
        $this->actAsOAuth(1, ['api'], 'http://localhost/api');

        $this->post('/account/delete', ['anything' => 'x']);

        $this->assertResponseCode(403);
        $this->assertNull(Configure::read('TestApp.accountDeleted'), 'The action must not run.');
    }

    public function testASessionCookieDoesNotRescueATokenOutsideItsPath(): void
    {
        $this->session(['Auth' => ['id' => 1]]);
        $this->actAsOAuth(1, ['api'], 'http://localhost/api');
        $this->enableCsrfToken();

        $this->post('/account/delete', ['anything' => 'x']);

        $this->assertResponseCode(401);
        $this->assertNull(Configure::read('TestApp.accountDeleted'), 'The action must not run.');
    }

    public function testASessionRouteStillWorksWithASessionAndNoToken(): void
    {
        $this->session(['Auth' => ['id' => 1]]);
        $this->enableCsrfToken();

        $this->post('/account/delete', ['anything' => 'x']);

        $this->assertResponseOk();
        $this->assertTrue(Configure::read('TestApp.accountDeleted'));
    }

    public function testTheSameTokenWorksBelowItsResourcePath(): void
    {
        $this->actAsOAuth(1, ['api'], 'http://localhost/api');

        $this->get('/api/me');
        $this->assertResponseOk();
        $this->assertResponseContains('"id":1');

        $this->actAsOAuth(1, ['api'], 'http://localhost/api');
        $this->get('/api/deeper/down');
        $this->assertResponseOk();
        $this->assertResponseContains('"id":1');

        // Trailing slash and duplicate slashes are the same route.
        $this->actAsOAuth(1, ['api'], 'http://localhost/api');
        $this->get('/api/me/');
        $this->assertResponseOk();
    }

    public function testATokenCannotReachASessionRouteWhoseTemplateStartsWithAPlaceholder(): void
    {
        // The reviewer's probe: /{tenant}/account/delete matches /mcp/account/delete with tenant "mcp", a path
        // below the MCP resource. What counts is the route the router picked, and that one is not below /mcp.
        Configure::write('TestApp.tokenAuthenticator', ['resource' => 'http://localhost/mcp']);

        // No CSRF token: the skip no longer applies, so the CSRF check refuses it first.
        $this->actAsOAuth(1, ['content:read'], 'http://localhost/mcp');
        $this->post('/mcp/account/delete', ['x' => '1']);
        $this->assertResponseCode(403);
        $this->assertNull(Configure::read('TestApp.accountDeleted'), 'The action must not run.');

        // With a CSRF token: the authenticator refuses it, outside the resource's routes.
        $this->actAsOAuth(1, ['content:read'], 'http://localhost/mcp');
        $this->enableCsrfToken();
        $this->post('/mcp/account/delete', ['x' => '1']);
        $this->assertResponseCode(401);
        $this->assertHeaderContains('WWW-Authenticate', 'not valid at this address');
        $this->assertNull(Configure::read('TestApp.accountDeleted'), 'The action must not run.');

        // A session cookie does not rescue it either.
        $this->session(['Auth' => ['id' => 1]]);
        $this->actAsOAuth(1, ['content:read'], 'http://localhost/mcp');
        $this->enableCsrfToken();
        $this->post('/mcp/account/delete', ['x' => '1']);
        $this->assertResponseCode(401);
        $this->assertNull(Configure::read('TestApp.accountDeleted'), 'The action must not run.');
    }

    public function testPathsAtTheRootStillCoverARouteThatStartsWithAPlaceholder(): void
    {
        // Accepting the token everywhere is explicit, and then it is accepted on such a route too.
        Configure::write('TestApp.tokenAuthenticator', ['resource' => 'http://localhost/mcp', 'paths' => ['/']]);
        Configure::write('OAuthServer.tokenPaths', ['/']);
        OAuthServer::reset();
        $this->actAsOAuth(1, ['content:read'], 'http://localhost/mcp');

        $this->post('/mcp/account/delete', ['x' => '1']);

        $this->assertResponseOk();
        $this->assertResponseContains('deleted 1');
    }

    public function testAValidTokenInsideItsPathsStillSkipsCsrf(): void
    {
        $this->actAsOAuth(1, ['api'], 'http://localhost/api');

        $this->post('/api/deeper/down', ['x' => '1']);

        $this->assertResponseOk();
        $this->assertResponseContains('"id":1');
    }

    public function testATokenWithTheServersPrefixThatDoesNotValidateGetsTheCsrfCheck(): void
    {
        // The session comes first here, so the session would run the action if CSRF let the request through.
        Configure::write('TestApp.sessionFirst', true);
        Configure::write('OAuthServer.tokenPaths', ['/']);
        OAuthServer::reset();
        $this->session(['Auth' => ['id' => 1]]);
        $this->withOAuthToken('test_at_' . str_repeat('x', 43));

        $this->post('/account/delete', ['x' => '1']);

        $this->assertResponseCode(403);
        $this->assertNull(Configure::read('TestApp.accountDeleted'), 'The action must not run.');

        // A revoked token is no better.
        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $this->exec('oauth token revoke --subject 1');
        $this->session(['Auth' => ['id' => 1]]);
        $this->withOAuthToken($token);
        $this->post('/account/delete', ['x' => '1']);
        $this->assertResponseCode(403);
        $this->assertNull(Configure::read('TestApp.accountDeleted'), 'The action must not run.');
    }

    public function testTheRouteThatMatchedMustBeBelowThePathsToo(): void
    {
        $authenticator = new TokenAuthenticator(new IdentifierCollection(), ['resource' => 'http://localhost/mcp']);
        $token = $this->oauthTokenFor(1, ['content:read'], 'http://localhost/mcp');
        $at = fn(string $url, ?string $template): bool => $authenticator->authenticate(
            Routed::request($url, $template)->withHeader('Authorization', 'Bearer ' . $token),
        )->isValid();

        $this->assertTrue($at('/mcp', '/mcp'));
        $this->assertTrue($at('/mcp/tools/call', '/mcp/**'));
        $this->assertTrue($at('/mcp/items/7', '/mcp/items/{id}'));
        $this->assertFalse($at('/mcp/account/delete', '/{tenant}/account/delete'));
        $this->assertFalse($at('/mcp', '/{slug}'));
        $this->assertFalse($at('/mcp/x', '/{controller}/{action}/*'));
        $this->assertFalse($at('/mcp-x/y', '/mcp-{v}/y'));
        // Authentication before routing: there is no route yet, so the token is outside.
        $this->assertFalse($at('/mcp', null));
        $request = Routed::request('/mcp', null)->withHeader('Authorization', 'Bearer ' . $token);
        $authenticator->authenticate($request);
        try {
            $authenticator->unauthorizedChallenge($request);
            $this->fail('A challenge was expected.');
        } catch (AuthenticationRequiredException $e) {
            $this->assertStringContainsString('not valid at this address', $e->getHeaders()['WWW-Authenticate']);
        }
    }

    public function testAnEncodedSlashCannotSmuggleARouteIntoThePath(): void
    {
        foreach (['/api%2Fx/account/delete', '/api%2fx/account/delete'] as $path) {
            $this->actAsOAuth(1, ['api'], 'http://localhost/api');
            $this->post($path, ['anything' => 'x']);
            $this->assertContains($this->_response->getStatusCode(), [401, 403], $path);
            $this->assertNull(Configure::read('TestApp.accountDeleted'), $path);

            $this->actAsOAuth(1, ['api'], 'http://localhost/api');
            $this->enableCsrfToken();
            $this->post($path, ['anything' => 'x']);
            $this->assertResponseCode(401);
            $this->assertNull(Configure::read('TestApp.accountDeleted'), $path);
            $this->_request = [];
        }
    }

    public function testAnEncodedEndpointPathIsStillCsrfChecked(): void
    {
        foreach (['/oauth%2Ftoken', '/oauth%2Frevoke'] as $path) {
            $this->session(['Auth' => ['id' => 1]]);
            $this->post($path, ['x' => '1']);
            $this->assertResponseCode(403, $path);
        }
    }

    public function testASiblingPathWithTheSamePrefixIsOutside(): void
    {
        $this->actAsOAuth(1, ['api'], 'http://localhost/api');

        $this->get('/apix/me');

        $this->assertResponseCode(401);
        $this->assertHeaderContains('WWW-Authenticate', 'not valid at this address');
    }

    public function testAnonymousRequestsOutsideThePathPassOn(): void
    {
        $this->post('/account/delete');
        $this->assertResponseCode(403);

        $this->enableCsrfToken();
        $this->post('/account/delete');
        $this->assertResponseOk();
    }

    public function testForeignBearerTokensOutsideThePathPassOn(): void
    {
        $this->configRequest(['headers' => ['Authorization' => 'Bearer eyJhbGciOiJIUzI1NiJ9.e30.c2ln']]);
        $this->enableCsrfToken();

        $this->get('/login');

        $this->assertResponseOk();
        $this->assertSame('', $this->_response->getHeaderLine('WWW-Authenticate'));
    }

    public function testThePathsOptionReplacesTheDerivedPath(): void
    {
        $authenticator = new TokenAuthenticator(new IdentifierCollection(), [
            'resource' => 'http://localhost/api',
            'paths' => ['/account', '/api/v2/'],
        ]);
        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        // Each path is matched by a static route of its own.
        $at = fn(string $url): bool => $authenticator->authenticate(
            Routed::request($url, $url)->withHeader('Authorization', 'Bearer ' . $token),
        )->isValid();

        $this->assertTrue($at('/account/delete'));
        $this->assertTrue($at('/api/v2/x'));
        $this->assertFalse($at('/api/me'), 'The default path no longer applies when paths is set.');
        $this->assertFalse($at('/accounts'));
    }

    public function testThePathIncludesTheBaseDirectory(): void
    {
        $authenticator = new TokenAuthenticator(new IdentifierCollection(), ['resource' => 'http://localhost/api']);
        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $request = Routed::request('/api/me', '/api/me')->withHeader('Authorization', 'Bearer ' . $token);

        $this->assertTrue($authenticator->authenticate($request)->isValid());
        // The same routed path under /sub is /sub/api/me, which is not the resource's path /api.
        $this->assertFalse($authenticator->authenticate($request->withAttribute('base', '/sub'))->isValid());
    }

    public function testPathTricksAreOutside(): void
    {
        $authenticator = new TokenAuthenticator(new IdentifierCollection(), ['resource' => 'http://localhost/api']);
        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        // The router would pick the API's catch-all route: only the path decides here.
        $at = fn(string $url): bool => $authenticator->authenticate(
            Routed::request($url, '/api/**')->withHeader('Authorization', 'Bearer ' . $token),
        )->isValid();

        $this->assertTrue($at('/%61pi/me'), 'Percent-encoding is decoded like the router does.');
        $this->assertFalse($at('/api/../account/delete'));
        $this->assertFalse($at('/api/%2e%2e/account/delete'));
        $this->assertFalse($at('/API/me'));
    }

    public function testARootResourceNeedsExplicitPaths(): void
    {
        Configure::write('OAuthServer.resources', ['http://localhost' => [
            'name' => 'Whole site',
            'scopes' => ['all' => 'Everything'],
            'defaultScopes' => ['all'],
        ]]);
        OAuthServer::reset();

        try {
            new TokenAuthenticator(new IdentifierCollection(), []);
            $this->fail('A root resource without paths must be refused.');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('"paths"', $e->getMessage());
            $this->assertStringContainsString('host root', $e->getMessage());
        }

        $authenticator = new TokenAuthenticator(new IdentifierCollection(), ['paths' => ['/']]);
        $token = $this->oauthTokenFor(1, ['all'], 'http://localhost');
        $request = Routed::request('/account/delete', '/{tenant}/account/delete')
            ->withHeader('Authorization', 'Bearer ' . $token);
        $this->assertTrue($authenticator->authenticate($request)->isValid());
    }

    public function testInvalidPathsAreRefused(): void
    {
        foreach ([[], ['api'], [''], [1], ['/a/../b'], 'api'] as $paths) {
            try {
                new TokenAuthenticator(new IdentifierCollection(), ['resource' => 'http://localhost/api', 'paths' => $paths]);
                $this->fail('Refused: ' . json_encode($paths));
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('"paths"', $e->getMessage());
            }
        }
    }
}
