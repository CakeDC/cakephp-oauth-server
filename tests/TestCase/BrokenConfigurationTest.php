<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase;

use Cake\Console\TestSuite\ConsoleIntegrationTestTrait;
use Cake\Core\Configure;
use Cake\I18n\I18n;
use Cake\Log\Engine\ArrayLog;
use Cake\Log\Log;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use Cake\Utility\Security;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Test\Support\Fixtures;
use CakeDC\OAuthServer\Test\Support\Routed;
use CakeDC\OAuthServer\TestSuite\OAuthTestTrait;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * A broken `OAuthServer` configuration never takes the application down: its pages and `bin/cake` keep working,
 * the plugin's routes answer 503 and log why, and this server's bearer tokens are refused.
 */
class BrokenConfigurationTest extends TestCase
{
    use ConsoleIntegrationTestTrait;
    use IntegrationTestTrait;
    use OAuthTestTrait;

    protected array $fixtures = Fixtures::ALL;

    /**
     * The broken configurations under which the resources or the token paths themselves cannot be read.
     */
    private const UNREADABLE_PATHS = ['issuer', 'resource', 'tokenPaths'];

    private string $settings = '';

    private mixed $baseUrl = null;

    private string $salt = '';

    protected function setUp(): void
    {
        parent::setUp();
        $this->settings = serialize(Configure::read('OAuthServer'));
        $this->baseUrl = Configure::read('App.fullBaseUrl');
        $this->salt = Security::getSalt();
        Log::setConfig('oauth_capture', ['className' => ArrayLog::class, 'scopes' => ['oauth']]);
        OAuthServer::reset();
    }

    protected function tearDown(): void
    {
        Configure::write('OAuthServer', unserialize($this->settings));
        Configure::write('App.fullBaseUrl', $this->baseUrl);
        Security::setSalt($this->salt);
        foreach (['oauth_capture', 'stdout', 'stderr'] as $name) {
            Log::drop($name);
        }
        OAuthServer::reset();
        parent::tearDown();
    }

    /**
     * What the `oauth` scope received.
     */
    private function logged(): string
    {
        $engine = Log::engine('oauth_capture');
        $this->assertInstanceOf(ArrayLog::class, $engine);

        return implode("\n", $engine->read());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function brokenConfigurations(): array
    {
        return [
            'a short salt' => ['salt'],
            'an http App.fullBaseUrl on another host' => ['issuer'],
            'a resource configured as a string' => ['resource'],
            'a tokenPaths that is not a list' => ['tokenPaths'],
            'an unknown users key' => ['users'],
            'a users.resource that is not a string' => ['usersResource'],
            'a services.clock that is not a clock' => ['servicesClock'],
            'an unknown consent key' => ['consent'],
        ];
    }

    private function breakConfiguration(string $how): void
    {
        match ($how) {
            'salt' => Security::setSalt('short'),
            'issuer' => Configure::write('App.fullBaseUrl', 'http://shop.example.com'),
            'resource' => Configure::write('OAuthServer.resources', ['http://localhost/api' => 'Test API']),
            'tokenPaths' => Configure::write('OAuthServer.tokenPaths', 'api'),
            'users' => Configure::write('OAuthServer.users', ['typo' => true]),
            'usersResource' => Configure::write('OAuthServer.users', ['resource' => 5]),
            'servicesClock' => Configure::write('OAuthServer.services', ['clock' => 'not a clock']),
            'consent' => Configure::write('OAuthServer.consent', ['typo' => true]),
        };
        OAuthServer::reset();
    }

    #[DataProvider('brokenConfigurations')]
    public function testTheApplicationKeepsWorking(string $how): void
    {
        $this->breakConfiguration($how);

        $this->get('/login');
        $this->assertResponseOk();
        $this->assertResponseEquals('login form');

        // An anonymous request reaches the application's own API action, which answers for itself.
        $this->get('/api/me');
        $this->assertResponseCode(401);
        $this->assertResponseEquals('{"error":"unauthorized"}');
        $this->assertSame('', $this->logged(), 'Nothing about OAuth happened yet.');
    }

    #[DataProvider('brokenConfigurations')]
    public function testTheMachineEndpointsAnswer503AndLogWhy(string $how): void
    {
        $this->breakConfiguration($how);

        $this->configRequest(['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']]);
        $this->post('/oauth/token', ['grant_type' => 'client_credentials']);

        $this->assertResponseCode(503);
        $this->assertContentType('application/json');
        $this->assertHeader('Cache-Control', 'no-store');
        $this->assertHeader('Retry-After', '300');
        // The CORS headers of the endpoint, so a browser client can read the 503.
        $this->assertHeader('Access-Control-Allow-Origin', '*');
        $this->assertHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, MCP-Protocol-Version');
        $body = (array)json_decode((string)$this->_response->getBody(), true);
        $this->assertSame('temporarily_unavailable', $body['error'] ?? null);
        $this->assertStringNotContainsString('salt', (string)$this->_response->getBody(), 'The reason goes to the log.');
        $this->assertStringContainsString('error: The OAuth endpoint /oauth/token is unavailable', $this->logged());
    }

    #[DataProvider('brokenConfigurations')]
    public function testOauthCheckFailsOnEveryConfigurationTheServerRefuses(string $how): void
    {
        $this->breakConfiguration($how);

        $this->exec('oauth check');

        $this->assertExitError();
        $this->assertOutputContains('[FAIL]');
    }

    public function testACorsPreflightIsAnsweredSoTheBrowserSeesThe503(): void
    {
        $this->breakConfiguration('resource');

        $this->options('/oauth/token');
        $this->assertResponseCode(204);
        $this->assertHeader('Access-Control-Allow-Origin', '*');
        $this->assertHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

        $this->configRequest(['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']]);
        $this->post('/oauth/token', ['grant_type' => 'client_credentials']);
        $this->assertResponseCode(503);
        $this->assertHeader('Access-Control-Allow-Origin', '*');

        // The pages are not called from other origins: no CORS there.
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/connections');
        $this->assertResponseCode(503);
        $this->assertFalse($this->_response->hasHeader('Access-Control-Allow-Origin'));
    }

    #[DataProvider('brokenConfigurations')]
    public function testThePagesAnswer503(string $how): void
    {
        $this->breakConfiguration($how);
        $this->session(['Auth' => ['id' => 1]]);

        $this->get('/oauth/connections');
        $this->assertResponseCode(503);
        $this->assertStringContainsString('/oauth/connections', $this->logged());

        $this->get('/oauth/authorize?response_type=code&client_id=x');
        $this->assertResponseCode(503);
    }

    public function testThePageMessageIsTranslated(): void
    {
        $this->breakConfiguration('salt');
        $this->session(['Auth' => ['id' => 1]]);
        I18n::setLocale('es');
        try {
            $this->get('/oauth/connections');
        } finally {
            I18n::setLocale('en_US');
        }

        $this->assertResponseCode(503);
        // The test application's error page prints the message (CakePHP shows it with debug on).
        $this->assertResponseContains('El servicio de autorización no está disponible en este momento.');
    }

    #[DataProvider('brokenConfigurations')]
    public function testATokenOfThisServerIsRefusedWith401(string $how): void
    {
        $this->breakConfiguration($how);

        $this->configRequest(['headers' => ['Authorization' => 'Bearer test_at_' . str_repeat('x', 43)]]);
        $this->get('/api/me');

        $this->assertResponseCode(401);
        $this->assertHeaderContains('WWW-Authenticate', 'error="invalid_token"');
        $this->assertStringContainsString('error: The Token authenticator refused a bearer token', $this->logged());
        $this->assertStringContainsString(
            // Resolving the resource reads the resources and the issuer; the rest only breaks the server.
            in_array($how, ['resource', 'issuer'], true)
                ? 'its resource and paths cannot be resolved'
                : 'the OAuth server cannot be built',
            $this->logged(),
        );
        $this->assertStringNotContainsString(str_repeat('x', 43), $this->logged());

        // The application still answers its own pages, also for a foreign bearer token.
        $this->configRequest(['headers' => ['Authorization' => 'Bearer eyJhbGciOiJIUzI1NiJ9.e30.c2ln']]);
        $this->get('/api/me');
        $this->assertResponseEquals('{"error":"unauthorized"}');
        $this->get('/login');
        $this->assertResponseOk();
    }

    #[DataProvider('brokenConfigurations')]
    public function testCsrfSkipStillSkipsTheClientEndpointsButNoBearerRequestWithACookie(string $how): void
    {
        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $this->breakConfiguration($how);
        $post = fn(string $path, ?string $bearer, bool $cookie = false): bool => OAuthServer::csrfSkip(Routed::request(
            $path,
            $path === '/api/posts' ? '/api/**' : $path,
            [
                'environment' => ['REQUEST_METHOD' => 'POST'] + ($bearer === null ? [] : [
                    'HTTP_AUTHORIZATION' => 'Bearer ' . $bearer,
                ]),
                'cookies' => $cookie ? [(string)session_name() => 'abc'] : [],
            ],
        ));

        $this->assertTrue($post('/oauth/token', null));
        $this->assertTrue($post('/oauth/revoke', null));
        $this->assertFalse($post('/oauth/authorize', null));
        $this->assertFalse($post('/api/posts', $token, true));
        $this->assertStringContainsString('warning: CSRF protection was not skipped', $this->logged());
        $this->assertStringNotContainsString($token, $this->logged());

        // Without a cookie the token needs no validating, so the request is skipped (the Token authenticator answers
        // 401) as long as the resources and token paths can be read; otherwise nothing is skipped.
        $readable = !in_array($how, self::UNREADABLE_PATHS, true);
        $this->assertSame($readable, $post('/api/posts', $token));
        $this->assertSame($readable, $post('/api/posts', null));
    }

    public function testCsrfSkipBuildsTheServerOnlyForABearerTokenWithACookieWithinTheTokenPaths(): void
    {
        $token = $this->oauthTokenFor(1, ['api'], 'http://localhost/api');
        $this->breakConfiguration('salt');
        $post = fn(string $path, string $template, bool $cookie = true): bool => OAuthServer::csrfSkip(
            Routed::request($path, $template, [
                'environment' => ['REQUEST_METHOD' => 'POST', 'HTTP_AUTHORIZATION' => 'Bearer ' . $token],
                'cookies' => $cookie ? [(string)session_name() => 'abc'] : [],
            ]),
        );

        // Outside the token paths the server is never built, so the broken salt leaves no trace.
        $this->assertFalse($post('/account/delete', '/account/delete'));
        $this->assertFalse($post('/mcp/account/delete', '/{tenant}/account/delete'));
        $this->assertFalse($post('/account/delete', '/account/delete', false));
        // Inside them, without a cookie, nothing needs validating.
        $this->assertTrue($post('/api/posts', '/api/**', false));
        $this->assertSame('', $this->logged());

        // With a cookie the token has to be validated: the server cannot be built, so nothing is skipped.
        $this->assertFalse($post('/api/posts', '/api/**'));
        $this->assertStringContainsString('Security.salt', $this->logged());
        $this->assertStringNotContainsString($token, $this->logged());
    }

    #[DataProvider('brokenConfigurations')]
    public function testABearerPostOnAResourceRouteGets401WhenTheTokenPathsCanBeRead(string $how): void
    {
        $this->breakConfiguration($how);

        $this->configRequest(['headers' => ['Authorization' => 'Bearer test_at_' . str_repeat('x', 43)]]);
        $this->post('/api/me', ['x' => '1']);

        if (in_array($how, self::UNREADABLE_PATHS, true)) {
            // Where the token works cannot be told, so CSRF protection stays on and refuses it first.
            $this->assertResponseCode(403);
            $this->assertResponseContains('Missing or incorrect CSRF cookie type.');
        } else {
            $this->assertResponseCode(401);
            $this->assertHeaderContains('WWW-Authenticate', 'error="invalid_token"');
        }
    }

    public function testATokenPrefixThatCannotBeReadRefusesEveryBearerToken(): void
    {
        Configure::write('OAuthServer.tokenPrefix', 42);
        OAuthServer::reset();

        // Which tokens are this server's cannot be told, so none is passed on to the session.
        $this->configRequest(['headers' => ['Authorization' => 'Bearer eyJhbGciOiJIUzI1NiJ9.e30.c2ln']]);
        $this->get('/api/me');
        $this->assertResponseCode(401);
        $this->assertHeaderContains('WWW-Authenticate', 'error="invalid_token"');

        $this->get('/login');
        $this->assertResponseOk();
    }

    public function testTheEndpointsKeepTheirConfiguredPrefix(): void
    {
        Configure::write('OAuthServer.routePrefix', '/auth');
        $this->breakConfiguration('resource');

        $this->configRequest(['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']]);
        $this->post('/auth/token', ['grant_type' => 'client_credentials']);

        $this->assertResponseCode(503);
    }

    public function testTheMetadataDocumentAnswers503WhenTheIssuerIsBroken(): void
    {
        $this->breakConfiguration('issuer');

        $this->get('/.well-known/oauth-authorization-server');

        $this->assertResponseCode(503);
        $this->assertContentType('application/json');
        $this->assertStringContainsString('App.fullBaseUrl', $this->logged());
    }

    public function testTheCommandLineKeepsWorking(): void
    {
        $this->breakConfiguration('resource');

        $this->exec('cache list');
        $this->assertExitSuccess();

        $this->exec('oauth check');
        $this->assertExitError();
        $this->assertOutputContains('[FAIL] Configuration');
        $this->assertOutputContains('[PASS] Tables');
    }
}
