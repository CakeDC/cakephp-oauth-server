<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase;

use Cake\Console\TestSuite\ConsoleIntegrationTestTrait;
use Cake\Core\Configure;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Test\Support\Fixtures;
use CakeDC\OAuthServer\TestSuite\OAuthTestTrait;

/**
 * State-changing requests on a resource's routes, through the test application's middleware: a client whose token
 * stopped working gets the authenticator's 401 with its challenge (the signal to refresh or to sign in again), not
 * the CSRF middleware's 403, whatever cookies it keeps; a request without a token is CSRF checked when it carries
 * a cookie a browser could send by itself.
 */
class CsrfOnResourceRoutesTest extends TestCase
{
    use ConsoleIntegrationTestTrait;
    use IntegrationTestTrait;
    use OAuthTestTrait;

    private const CSRF_MESSAGE = 'Missing or incorrect CSRF cookie type.';

    /**
     * The CSRF middleware's message when the request sends its cookie back but no matching token in the body.
     */
    private const CSRF_MISMATCH = 'CSRF token from either the request body or request headers did not match or is missing.';

    private const MCP_METADATA = 'http://localhost/.well-known/oauth-protected-resource/mcp';

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

    /**
     * Sends the session cookie of a signed in browser with the next requests (IntegrationTestTrait's session()
     * sends none).
     */
    private function withSessionCookie(): void
    {
        $this->cookie((string)session_name(), 'a-browser-session');
    }

    /**
     * GETs $url like a client with a cookie jar and keeps the cookie the CSRF middleware set on the answer, so the
     * next requests send it back.
     */
    private function keepTheCsrfCookieOf(string $url): void
    {
        $this->get($url);
        $this->assertCookieIsSet('csrfToken');
        $cookie = $this->_response->getCookie('csrfToken');
        $this->assertIsArray($cookie);
        $this->cookie('csrfToken', (string)$cookie['value']);
    }

    private function assertRefusedByCsrf(string $message = self::CSRF_MESSAGE): void
    {
        $this->assertResponseCode(403);
        $this->assertResponseContains($message);
    }

    private function assertInvalidToken(string $description): void
    {
        $this->assertResponseCode(401);
        $this->assertHeaderContains('WWW-Authenticate', 'Bearer error="invalid_token"');
        $this->assertHeaderContains('WWW-Authenticate', 'error_description="' . $description . '"');
        $this->assertResponseNotContains(self::CSRF_MESSAGE);
    }

    private function useMcpEndpoint(): void
    {
        Configure::write('TestApp.tokenAuthenticator', [
            'resource' => 'http://localhost/mcp',
            'resourceMetadataUrl' => self::MCP_METADATA,
        ]);
    }

    public function testAnExpiredTokenPostedToAResourceRouteGetsTheChallenge(): void
    {
        $clock = new FrozenClock();
        Configure::write('OAuthServer.services.clock', $clock);
        OAuthServer::reset();
        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $clock->advance(2 * 86400);

        $this->withOAuthToken($token);
        $this->post('/api/me', ['x' => '1']);

        $this->assertInvalidToken('The access token expired.');
    }

    public function testARevokedTokenPostedToAResourceRouteGetsTheChallenge(): void
    {
        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $this->exec('oauth token revoke --subject 1');
        $this->assertExitSuccess();

        $this->withOAuthToken($token);
        $this->post('/api/me', ['x' => '1']);

        $this->assertInvalidToken('The access token was revoked.');
    }

    public function testATokenOfAnotherResourceOrOfADeactivatedOwnerGetsTheChallenge(): void
    {
        $this->actAsOAuth(1, ['content:read'], 'http://localhost/mcp');
        $this->post('/api/deeper/down', ['x' => '1']);
        $this->assertInvalidToken('The access token was issued for another resource.');

        $token = $this->oauthTokenFor(2, ['api'], 'http://localhost/api');
        $this->fetchTable('Users')->updateAll(['active' => false], ['id' => 2]);
        $this->withOAuthToken($token);
        $this->put('/api/me', ['x' => '1']);
        $this->assertInvalidToken('The owner of this access token no longer has access.');

        $this->withOAuthToken('test_at_' . str_repeat('x', 43));
        $this->delete('/api/me');
        $this->assertInvalidToken('The access token is invalid.');
    }

    public function testAClientWithACookieJarLearnsThatItsTokenExpired(): void
    {
        // The MCP Python SDK keeps cookies (httpx): the CSRF cookie the middleware set on an earlier GET goes back
        // with every POST.
        $this->useMcpEndpoint();
        $clock = new FrozenClock();
        Configure::write('OAuthServer.services.clock', $clock);
        OAuthServer::reset();
        $token = $this->oauthTokenFor(1, ['content:read'], 'http://localhost/mcp');
        $this->withOAuthToken($token);
        $this->keepTheCsrfCookieOf('/mcp');
        $this->assertResponseOk();

        $clock->advance(2 * 86400);
        $this->withOAuthToken($token);
        $this->configRequest(['headers' => ['Content-Type' => 'application/json']]);
        $this->post('/mcp', '{"jsonrpc":"2.0","id":3,"method":"tools/list"}');

        $this->assertResponseCode(401);
        $this->assertHeader(
            'WWW-Authenticate',
            'Bearer resource_metadata="' . self::MCP_METADATA . '", error="invalid_token", '
            . 'error_description="The access token expired."',
        );
        $this->assertResponseNotContains(self::CSRF_MESSAGE);
    }

    public function testAClientWithACookieJarLearnsThatItsTokenWasRevoked(): void
    {
        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $this->keepTheCsrfCookieOf('/api/me');
        $this->exec('oauth token revoke --subject 1');

        $this->withOAuthToken($token);
        $this->post('/api/me', ['x' => '1']);

        $this->assertInvalidToken('The access token was revoked.');
    }

    public function testALoadBalancerCookieDoesNotHideTheChallenge(): void
    {
        $clock = new FrozenClock();
        Configure::write('OAuthServer.services.clock', $clock);
        OAuthServer::reset();
        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $clock->advance(2 * 86400);
        $this->cookie('AWSALB', 'a-sticky-session-of-the-load-balancer');

        $this->withOAuthToken($token);
        $this->post('/api/me', ['x' => '1']);

        $this->assertInvalidToken('The access token expired.');
    }

    public function testAPostWithoutTokenOrCookieReachesTheResourceRoute(): void
    {
        $this->post('/api/me', ['x' => '1']);

        // The application's own answer, not the CSRF middleware's.
        $this->assertResponseCode(401);
        $this->assertResponseEquals('{"error":"unauthorized"}');
    }

    public function testAPostWithoutTokenThatSendsBackOnlyTheCsrfCookieReachesTheResourceRoute(): void
    {
        $this->keepTheCsrfCookieOf('/api/me');

        $this->post('/api/me', ['x' => '1']);

        $this->assertResponseCode(401);
        $this->assertResponseEquals('{"error":"unauthorized"}');
    }

    public function testAPostWithoutTokenThatCarriesASessionCookieGetsTheCsrfCheck(): void
    {
        // A browser with a session posts like any session form, with or without the CSRF cookie.
        $this->withSessionCookie();
        $this->post('/api/me', ['x' => '1']);
        $this->assertRefusedByCsrf();

        $this->keepTheCsrfCookieOf('/api/me');
        $this->post('/api/me', ['x' => '1']);
        $this->assertRefusedByCsrf(self::CSRF_MISMATCH);
    }

    public function testMcpDiscoveryStartsFromTheFirstPostWithoutAToken(): void
    {
        // An MCP endpoint protected by the Token authenticator, as in docs/mcp.md: Streamable HTTP sends every
        // message as a POST, and the first one carries no token.
        $this->useMcpEndpoint();
        $this->configRequest(['headers' => ['Content-Type' => 'application/json', 'Accept' => 'application/json']]);

        $this->post('/mcp', '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}');

        $this->assertResponseCode(401);
        $this->assertHeader('WWW-Authenticate', 'Bearer resource_metadata="' . self::MCP_METADATA . '"');
        $this->assertResponseNotContains(self::CSRF_MESSAGE);

        // The same from a client that kept the CSRF cookie of an earlier GET.
        $this->keepTheCsrfCookieOf('/mcp');
        $this->configRequest(['headers' => ['Content-Type' => 'application/json']]);
        $this->post('/mcp', '{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}');
        $this->assertResponseCode(401);
        $this->assertHeader('WWW-Authenticate', 'Bearer resource_metadata="' . self::MCP_METADATA . '"');
    }

    public function testAnMcpClientLearnsThatItsTokenExpired(): void
    {
        $this->useMcpEndpoint();
        $clock = new FrozenClock();
        Configure::write('OAuthServer.services.clock', $clock);
        OAuthServer::reset();
        $token = $this->oauthTokenFor(1, ['content:read'], 'http://localhost/mcp');

        $this->withOAuthToken($token);
        $this->configRequest(['headers' => ['Content-Type' => 'application/json']]);
        $this->post('/mcp', '{"jsonrpc":"2.0","id":2,"method":"tools/list"}');
        $this->assertResponseOk();
        $this->assertResponseContains('"id":1');

        $clock->advance(2 * 86400);
        $this->withOAuthToken($token);
        $this->configRequest(['headers' => ['Content-Type' => 'application/json']]);
        $this->post('/mcp', '{"jsonrpc":"2.0","id":3,"method":"tools/list"}');

        $this->assertResponseCode(401);
        $this->assertHeader(
            'WWW-Authenticate',
            'Bearer resource_metadata="' . self::MCP_METADATA . '", error="invalid_token", '
            . 'error_description="The access token expired."',
        );
    }

    public function testASessionWithAMadeUpTokenOfThisServerGets401AndNeverRunsTheAction(): void
    {
        // Tokens work on every route here, so the session action is on the routes of a resource. The Token
        // authenticator comes first: it answers the token, and the session is never consulted.
        Configure::write('TestApp.tokenAuthenticator', ['resource' => 'http://localhost/api', 'paths' => ['/']]);
        Configure::write('OAuthServer.tokenPaths', ['/']);
        OAuthServer::reset();
        $revoked = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $this->exec('oauth token revoke --subject 1');

        foreach (
            [
                ['test_at_' . str_repeat('x', 43), 'The access token is invalid.'],
                [$revoked, 'The access token was revoked.'],
            ] as [$token, $description]
        ) {
            $this->session(['Auth' => ['id' => 1]]);
            $this->withSessionCookie();
            $this->withOAuthToken($token);
            $this->post('/account/delete', ['x' => '1']);

            $this->assertInvalidToken($description);
            $this->assertNull(Configure::read('TestApp.accountDeleted'), 'The action must not run.');
        }
    }

    public function testASessionCookieWithAValidTokenRunsAsTheTokenOwner(): void
    {
        $this->withSessionCookie();
        $this->actAsOAuth(1, ['api'], 'http://localhost/api');

        $this->post('/api/me', ['x' => '1']);

        $this->assertResponseOk();
        $this->assertResponseContains('"id":1');
    }

    public function testCredentialsABrowserSendsByItselfKeepTheCsrfCheck(): void
    {
        // HTTP Basic credentials, whether PHP sees the header or only PHP_AUTH_USER.
        $this->configRequest(['headers' => ['Authorization' => 'Basic ' . base64_encode('ada:secret')]]);
        $this->post('/api/me', ['x' => '1']);
        $this->assertRefusedByCsrf();

        $this->configRequest(['environment' => ['PHP_AUTH_USER' => 'ada', 'PHP_AUTH_PW' => 'secret']]);
        $this->post('/api/me', ['x' => '1']);
        $this->assertRefusedByCsrf();

        $this->configRequest(['environment' => ['REMOTE_USER' => 'ada']]);
        $this->post('/api/me', ['x' => '1']);
        $this->assertRefusedByCsrf();
    }

    public function testOutsideTheResourceRoutesNothingChanges(): void
    {
        // No token, no cookie: a session route is CSRF checked as before.
        $this->post('/account/delete', ['x' => '1']);
        $this->assertRefusedByCsrf();
        $this->assertNull(Configure::read('TestApp.accountDeleted'), 'The action must not run.');

        // A token of this server on a session route: refused by CSRF, the action never runs.
        $this->withOAuthToken('test_at_' . str_repeat('x', 43));
        $this->post('/account/delete', ['x' => '1']);
        $this->assertRefusedByCsrf();
        $this->assertNull(Configure::read('TestApp.accountDeleted'), 'The action must not run.');
    }

    public function testTheSessionPagesAndTheLoginAreAlwaysCheckedEvenWhenTokensWorkEverywhere(): void
    {
        Configure::write('TestApp.tokenAuthenticator', ['resource' => 'http://localhost/api', 'paths' => ['/']]);
        Configure::write('OAuthServer.tokenPaths', ['/']);
        OAuthServer::reset();

        foreach (['/oauth/authorize', '/oauth/connections', '/login'] as $path) {
            $this->post($path, ['x' => '1']);
            $this->assertRefusedByCsrf();
            $this->withOAuthToken('test_at_' . str_repeat('x', 43));
            $this->post($path, ['x' => '1']);
            $this->assertRefusedByCsrf();
        }

        // Control: another route of the application is skipped without a cookie.
        $this->post('/account/delete', ['x' => '1']);
        $this->assertResponseOk();
        $this->assertResponseEquals('deleted ');
    }

    public function testTheLoginIsRecognisedByTheActionItRoutesTo(): void
    {
        // The fallback routes reach the login action at /Pages/login too.
        Configure::write('TestApp.tokenAuthenticator', ['resource' => 'http://localhost/api', 'paths' => ['/']]);
        Configure::write('OAuthServer.tokenPaths', ['/']);
        OAuthServer::reset();

        foreach (
            [
                ['controller' => 'Pages', 'action' => 'login', 'plugin' => null],
                ['controller' => 'Pages', 'action' => 'login'],
                ['_name' => 'login'],
                '/login',
            ] as $login
        ) {
            Configure::write('OAuthServer.login.url', $login);
            foreach (['/login', '/Pages/login'] as $path) {
                $this->post($path, ['x' => '1']);
                $this->assertRefusedByCsrf();
            }
        }

        // Control: the alias is the login action.
        $this->enableCsrfToken();
        $this->post('/Pages/login', ['x' => '1']);
        $this->assertResponseOk();
        $this->assertResponseEquals('login form');
    }
}
