<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Authenticator;

use Authentication\Identifier\IdentifierCollection;
use Cake\Core\Configure;
use Cake\Http\ServerRequest;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use CakeDC\OAuthServer\Authenticator\TokenAuthenticator;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Test\Support\Fixtures;
use CakeDC\OAuthServer\TestSuite\OAuthTestTrait;
use InvalidArgumentException;

/**
 * A token is for one resource and works below that resource's path only.
 */
class TokenPathsTest extends TestCase
{
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
        $at = fn(string $url): bool => $authenticator->authenticate(
            (new ServerRequest(['url' => $url]))->withHeader('Authorization', 'Bearer ' . $token),
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
        $request = (new ServerRequest(['url' => '/api/me']))->withHeader('Authorization', 'Bearer ' . $token);

        $this->assertTrue($authenticator->authenticate($request)->isValid());
        // The same routed path under /sub is /sub/api/me, which is not the resource's path /api.
        $this->assertFalse($authenticator->authenticate($request->withAttribute('base', '/sub'))->isValid());
    }

    public function testPathTricksAreOutside(): void
    {
        $authenticator = new TokenAuthenticator(new IdentifierCollection(), ['resource' => 'http://localhost/api']);
        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $at = fn(string $url): bool => $authenticator->authenticate(
            (new ServerRequest(['url' => $url]))->withHeader('Authorization', 'Bearer ' . $token),
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
        $request = (new ServerRequest(['url' => '/account/delete']))->withHeader('Authorization', 'Bearer ' . $token);
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
