<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Controller;

use Cake\Cache\Cache;
use Cake\Core\Configure;
use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\ResponseFactory;
use Cake\Http\StreamFactory;
use Cake\Log\Engine\ArrayLog;
use Cake\Log\Log;
use Cake\ORM\TableRegistry;
use Cake\Routing\RouteBuilder;
use Cake\Routing\RouteCollection;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use Cake\Utility\Security;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuth\Server\Http\HttpResponder;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\OAuthServerPlugin;
use CakeDC\OAuthServer\Test\Support\BrokenCacheEngine;
use CakeDC\OAuthServer\Test\Support\Fixtures;
use CakeDC\OAuthServer\Test\Support\Html;

class OAuthControllerTest extends TestCase
{
    use IntegrationTestTrait;

    private const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    protected array $fixtures = Fixtures::ALL;

    private Client $client;

    /**
     * @var array<string, mixed>
     */
    private array $settings = [];

    private mixed $baseUrl = null;

    private mixed $appBase = null;

    protected function setUp(): void
    {
        parent::setUp();
        $this->settings = (array)Configure::read('OAuthServer');
        $this->baseUrl = Configure::read('App.fullBaseUrl');
        $this->appBase = Configure::read('App.base');
        OAuthServer::reset();
        $this->client = OAuthServer::server()->clientRegistrar()
            ->create('Test App', ['https://app.example.com/cb'], false)['client'];
    }

    protected function tearDown(): void
    {
        Configure::write('OAuthServer', $this->settings);
        Configure::write('App.fullBaseUrl', $this->baseUrl);
        Configure::write('App.base', $this->appBase);
        OAuthServer::reset();
        parent::tearDown();
    }

    /**
     * @param array<string, mixed> $changes Settings to add or replace.
     * @return void
     */
    private function configure(array $changes): void
    {
        Configure::write('OAuthServer', $changes + $this->settings);
        OAuthServer::reset();
    }

    private function signIn(int $id = 1): void
    {
        $this->session(['Auth' => ['id' => $id]]);
    }

    /**
     * @param array<string, string> $params Parameters to override.
     * @return string
     */
    private function authorizeUrl(array $params = []): string
    {
        return '/oauth/authorize?' . http_build_query($params + [
            'response_type' => 'code',
            'client_id' => $this->client->clientId,
            'redirect_uri' => 'https://app.example.com/cb',
            'state' => 'st4te',
            'code_challenge' => Pkce::challengeFor(self::VERIFIER),
            'code_challenge_method' => 'S256',
            'scope' => 'content:write',
        ], '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * @return array<string, string>
     */
    private function consentFields(): array
    {
        $this->signIn();
        $this->get($this->authorizeUrl());
        $this->assertResponseOk();

        $fields = Html::hiddenFields((string)$this->_response->getBody(), 'consent_token');
        // The page's CSRF field belongs to that response; each POST below brings its own.
        unset($fields['_csrfToken']);

        return $fields;
    }

    private function code(): string
    {
        $fields = $this->consentFields();
        $this->signIn();
        $this->enableCsrfToken();
        $this->post('/oauth/authorize', $fields + ['decision' => 'approve']);
        parse_str((string)parse_url($this->_response->getHeaderLine('Location'), PHP_URL_QUERY), $params);

        return (string)($params['code'] ?? '');
    }

    /**
     * @param string $code The authorization code.
     * @return array<string, mixed>
     */
    private function exchange(string $code): array
    {
        $this->configRequest(['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']]);
        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'https://app.example.com/cb',
            'code_verifier' => self::VERIFIER,
            'client_id' => $this->client->clientId,
        ]);

        return (array)json_decode((string)$this->_response->getBody(), true);
    }

    /**
     * Posts $body exactly as a browser does: a raw urlencoded body with the CSRF token in a header.
     *
     * @param string $url The URL.
     * @param string $body The raw body.
     * @return void
     */
    private function postRaw(string $url, string $body): void
    {
        $csrf = new CsrfProtectionMiddleware();
        $token = $csrf->createToken();
        $this->signIn();
        $this->cookie('csrfToken', $token);
        $this->configRequest(['headers' => [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'X-CSRF-Token' => $csrf->saltToken($token),
        ]]);
        $this->post($url, $body);
    }

    private function forgetConsents(): void
    {
        // An approved consent is remembered, and the next authorization would skip the page.
        TableRegistry::getTableLocator()->get('CakeDC/OAuthServer.OauthConsents')->deleteAll('1 = 1');
    }

    private function coreCsp(): string
    {
        return (new HttpResponder(new ResponseFactory(), new StreamFactory()))
            ->page('')
            ->getHeaderLine('Content-Security-Policy');
    }

    public function testMetadataSkipsTheHostAuthorizationCheck(): void
    {
        $this->get('/.well-known/oauth-authorization-server');

        $this->assertResponseOk();
        $this->assertContentType('application/json');
        $this->assertResponseContains('"issuer":"http://localhost"');
        $this->assertResponseContains('"token_endpoint":"http://localhost/oauth/token"');
    }

    public function testEveryEndpointAnswersUnderAuthorizationThatRequiresACheck(): void
    {
        // The test app's AuthorizationMiddleware throws for any action that did not check or skip.
        $expected = [
            '/.well-known/oauth-authorization-server' => 200,
            $this->authorizeUrl() => 302,
            '/oauth/token' => 405,
            '/oauth/register' => 405,
            '/oauth/revoke' => 405,
            '/oauth/introspect' => 405,
            '/oauth/connections' => 302,
        ];
        foreach ($expected as $url => $status) {
            $this->get($url);
            $this->assertResponseCode($status, $url);
        }
    }

    public function testAnonymousVisitorsGoToTheLoginWithARelativeReturnUrl(): void
    {
        $this->get($this->authorizeUrl());

        $this->assertResponseCode(302);
        $location = $this->_response->getHeaderLine('Location');
        $this->assertStringStartsWith('/login?redirect=%2Foauth%2Fauthorize%3F', $location);
        parse_str((string)parse_url($location, PHP_URL_QUERY), $query);
        $this->assertStringStartsWith('/oauth/authorize?response_type=code', $query['redirect']);
        $this->assertStringNotContainsString('://', $query['redirect']);
    }

    public function testUnderABasePathTheLoginAndTheConsentFormCarryIt(): void
    {
        // The test dispatcher prepends App.base to the URLs it is given.
        Configure::write('App.base', '/app');
        $this->get($this->authorizeUrl());
        // The login URL gets the base; the return URL stays application-relative, as the login redirect
        // expects (Cake adds the base again when it redirects there).
        $location = $this->_response->getHeaderLine('Location');
        $this->assertStringStartsWith('/app/login?redirect=%2Foauth%2Fauthorize%3F', $location);

        $this->signIn();
        $this->get($this->authorizeUrl());
        $this->assertResponseOk();
        $this->assertMatchesRegularExpression(
            '#<form[^>]*action="/app/oauth/authorize"#',
            (string)$this->_response->getBody(),
        );
    }

    public function testConsentPageAndApproval(): void
    {
        $fields = $this->consentFields();
        $this->assertResponseContains('Test App wants to access Test MCP');
        $this->assertResponseContains('Edit drafts');
        $this->assertArrayHasKey('consent_token', $fields);

        $this->signIn();
        $this->enableCsrfToken();
        $this->post('/oauth/authorize', $fields + ['decision' => 'approve']);

        $this->assertResponseCode(303);
        $this->assertStringStartsWith('https://app.example.com/cb?code=', $this->_response->getHeaderLine('Location'));
        $this->assertStringContainsString('iss=http%3A%2F%2Flocalhost', $this->_response->getHeaderLine('Location'));
    }

    public function testConsentAcrossBodyShapes(): void
    {
        // A raw browser body (the CSRF token in a header).
        $fields = $this->consentFields() + ['decision' => 'approve'];
        $this->postRaw('/oauth/authorize', http_build_query($fields));
        $this->assertResponseCode(303);
        $this->assertStringStartsWith('https://app.example.com/cb?code=', $this->_response->getHeaderLine('Location'));

        // The same through the raw body of an array post that IntegrationTestTrait sends as form data.
        $this->forgetConsents();
        $fields = $this->consentFields() + ['decision' => 'approve'];
        $csrf = new CsrfProtectionMiddleware();
        $token = $csrf->createToken();
        $this->signIn();
        $this->cookie('csrfToken', $token);
        $this->configRequest(['headers' => [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'X-CSRF-Token' => $csrf->saltToken($token),
        ]]);
        $this->post('/oauth/authorize', $fields);
        $this->assertResponseCode(303);

        // A parsed body (the CSRF token as a form field, no content type).
        $this->forgetConsents();
        $fields = $this->consentFields() + ['decision' => 'approve'];
        $this->signIn();
        $this->enableCsrfToken();
        $this->post('/oauth/authorize', $fields);
        $this->assertResponseCode(303);
        $this->assertStringStartsWith('https://app.example.com/cb?code=', $this->_response->getHeaderLine('Location'));
    }

    public function testTheConsentFormIsCsrfProtected(): void
    {
        $fields = $this->consentFields();
        $this->signIn();
        $this->post('/oauth/authorize', $fields + ['decision' => 'approve']);

        $this->assertResponseCode(403);
    }

    public function testClientEndpointsNeedNoCsrfToken(): void
    {
        $tokens = $this->exchange($this->code());

        $this->assertResponseOk();
        $this->assertStringStartsWith('test_at_', $tokens['access_token']);

        $this->configRequest(['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']]);
        $this->post('/oauth/revoke', ['token' => $tokens['refresh_token'], 'client_id' => $this->client->clientId]);
        $this->assertResponseOk();

        $this->configRequest(['headers' => ['Content-Type' => 'application/json']]);
        $this->post('/oauth/register', (string)json_encode([
            'redirect_uris' => ['https://new.example/cb'],
            'token_endpoint_auth_method' => 'none',
        ]));
        $this->assertResponseCode(201);
        $this->assertResponseContains('"client_id"');
    }

    public function testIntrospection(): void
    {
        $created = OAuthServer::server()->clientRegistrar()
            ->create('Gateway', [], true, ['client_credentials'], null, true);
        $tokens = $this->exchange($this->code());

        $this->configRequest(['headers' => [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Authorization' => 'Basic ' . base64_encode($created['client']->clientId . ':' . $created['secret']),
        ]]);
        $this->post('/oauth/introspect', ['token' => $tokens['access_token']]);

        $this->assertResponseOk();
        $this->assertResponseContains('"active":true');
        $this->assertResponseContains('"username":"Ada"');
    }

    public function testConnectionsPage(): void
    {
        $this->exchange($this->code());
        $this->signIn();
        $this->get('/oauth/connections');
        $this->assertResponseOk();
        $this->assertResponseContains('Test App');
        $fields = Html::hiddenFields((string)$this->_response->getBody(), 'family_id');
        unset($fields['_csrfToken']);

        $this->signIn();
        $this->enableCsrfToken();
        $this->post('/oauth/connections', $fields);

        $this->assertResponseCode(303);
        $this->assertHeader('Location', '/oauth/connections');
        $this->signIn();
        $this->get('/oauth/connections');
        $this->assertResponseContains('No application is connected.');
    }

    public function testTheConnectionsRedirectCarriesTheBasePath(): void
    {
        $this->exchange($this->code());
        Configure::write('App.base', '/app');
        $this->signIn();
        $this->get('/oauth/connections');
        $fields = Html::hiddenFields((string)$this->_response->getBody(), 'family_id');
        unset($fields['_csrfToken']);

        $this->signIn();
        $this->enableCsrfToken();
        $this->post('/oauth/connections', $fields);

        $this->assertResponseCode(303);
        $this->assertHeader('Location', '/app/oauth/connections');
    }

    public function testMalformedIdsOnTheConnectionsPageMatchNothing(): void
    {
        // On PostgreSQL, invalid UTF-8 in a query parameter fails the query: it used to answer 500 and log the SQL.
        Log::setConfig('oauth_capture', ['className' => ArrayLog::class, 'scopes' => ['oauth']]);
        try {
            $this->exchange($this->code());
            $this->signIn();
            $this->get('/oauth/connections');
            $fields = Html::hiddenFields((string)$this->_response->getBody(), 'family_id');
            unset($fields['_csrfToken']);

            foreach (["\xFF\xFE", 'not-a-uuid'] as $id) {
                foreach ([['action' => 'revoke_connection', 'family_id' => $id], ['action' => 'revoke_token', 'token_id' => $id]] as $change) {
                    $this->signIn();
                    $this->enableCsrfToken();
                    $this->post('/oauth/connections', $change + $fields);
                    $this->assertResponseCode(303, bin2hex($id));
                }
            }

            $engine = Log::engine('oauth_capture');
            $this->assertInstanceOf(ArrayLog::class, $engine);
            $this->assertSame([], $engine->read());
            $this->signIn();
            $this->get('/oauth/connections');
            $this->assertResponseContains('Test App');
        } finally {
            Log::drop('oauth_capture');
        }
    }

    public function testUnderABasePathAnAnonymousVisitToTheConnectionsPageGoesToTheLoginOnce(): void
    {
        Configure::write('App.base', '/app');

        $this->get('/oauth/connections?tab=tokens');

        // The login URL carries the base once; the return URL stays application-relative.
        $this->assertResponseCode(302);
        $this->assertHeader('Location', '/app/login?redirect=%2Foauth%2Fconnections%3Ftab%3Dtokens');
    }

    public function testUnderABasePathTheClientEndpointsNeedNoCsrfToken(): void
    {
        Configure::write('App.base', '/app');
        $this->configRequest(['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']]);

        $this->post('/oauth/revoke', ['token' => 'unknown', 'client_id' => $this->client->clientId]);

        // The core answers (RFC 7009: 200 for an unknown token), not the CSRF check (403).
        $this->assertResponseOk();
    }

    public function testPersonalTokenWithADottedScopeFromARawBody(): void
    {
        $this->configure([
            'personalTokens' => true,
            'resources' => [
                // The test application's Token authenticator needs its resource declared.
                'http://localhost/api' => ['name' => 'API', 'scopes' => ['api' => 'Use the API']],
                'http://localhost/files' => [
                    'name' => 'Files',
                    'scopes' => ['files.read' => 'Read files', 'files.write' => 'Write files'],
                    'defaultScopes' => ['files.read'],
                ],
            ],
        ]);
        $this->signIn();
        $this->get('/oauth/connections');
        $this->assertResponseOk();
        $fields = Html::hiddenFields((string)$this->_response->getBody(), 'form_token');
        $this->assertSame('create_token', $fields['action']);
        // The checkbox keeps its dotted name (FormHelper would have turned it into brackets).
        $this->assertResponseContains('name="scope:files.read"');

        $body = http_build_query([
            'form_token' => $fields['form_token'],
            'action' => 'create_token',
            'name' => 'CI',
            'resource' => 'http://localhost/files',
            'days' => '5',
            'scope:files.read' => '1',
        ], '', '&', PHP_QUERY_RFC3986);
        $this->postRaw('/oauth/connections', $body);

        $this->assertResponseOk();
        $this->assertResponseContains('test_pat_');
        $tokens = TableRegistry::getTableLocator()->get('CakeDC/OAuthServer.OauthTokens')
            ->find()
            ->where(['type' => 'personal'])
            ->all();
        $this->assertCount(1, $tokens);
        $this->assertSame(['files.read'], $tokens->first()->get('scopes'));
    }

    public function testRateLimitsUseCakeCache(): void
    {
        Cache::clear('default');
        $this->configure(['rateLimit' => ['cache' => 'default', 'token' => [1, 60]]]);
        $headers = ['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']];

        $this->configRequest($headers);
        $this->post('/oauth/token', ['grant_type' => 'x']);
        $this->assertResponseCode(400);
        $this->configRequest($headers);
        $this->post('/oauth/token', ['grant_type' => 'x']);
        $this->assertResponseCode(429);
    }

    public function testRateLimitingFailsOpenWhenTheCacheFails(): void
    {
        Cache::setConfig('oauth_broken', ['className' => BrokenCacheEngine::class]);
        Log::setConfig('oauth_cache_test', ['className' => 'Array', 'scopes' => ['oauth']]);
        try {
            $this->configure(['rateLimit' => ['cache' => 'oauth_broken', 'token' => [1, 60]]]);
            $headers = ['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']];
            foreach ([1, 2] as $attempt) {
                $this->configRequest($headers);
                $this->post('/oauth/token', ['grant_type' => 'x']);
                $this->assertResponseCode(400, 'attempt ' . $attempt);
                $this->assertResponseContains('unsupported_grant_type');
            }
            /** @var \Cake\Log\Engine\ArrayLog $log */
            $log = Log::engine('oauth_cache_test');
            $this->assertStringContainsString(
                'Rate limiting is off for this request: the cache failed (Connection refused).',
                implode("\n", $log->read()),
            );
        } finally {
            Log::drop('oauth_cache_test');
            Cache::drop('oauth_broken');
        }
    }

    public function testIntrospectionHasItsOwnRateLimit(): void
    {
        Cache::clear('default');
        $this->configure(['rateLimit' => ['cache' => 'default', 'token' => [1, 60], 'introspect' => [5, 60]]]);
        $headers = ['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']];
        foreach ([1, 2, 3] as $attempt) {
            $this->configRequest($headers);
            $this->post('/oauth/introspect', ['token' => 'x']);
            $this->assertResponseCode(401, 'attempt ' . $attempt);
        }
        $this->configRequest($headers);
        $this->post('/oauth/token', ['grant_type' => 'x']);
        $this->assertResponseCode(400);
    }

    public function testTheIntrospectLimitOfThePluginConfigurationReachesTheCore(): void
    {
        Cache::clear('default');
        $this->configure(['rateLimit' => ['cache' => 'default', 'introspect' => [2, 60]]]);
        $headers = ['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']];
        foreach ([1, 2] as $attempt) {
            $this->configRequest($headers);
            $this->post('/oauth/introspect', ['token' => 'x']);
            $this->assertResponseCode(401, 'attempt ' . $attempt);
        }
        $this->configRequest($headers);
        $this->post('/oauth/introspect', ['token' => 'x']);
        $this->assertResponseCode(429);
    }

    public function testRateLimitsKeyOnTheRealClientAddress(): void
    {
        Cache::clear('default');
        $this->configure(['rateLimit' => ['cache' => 'default', 'token' => [1, 60]]]);
        $send = function (string $address, array $headers = []): void {
            $this->replaceRequest([
                'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'] + $headers,
                'environment' => ['REMOTE_ADDR' => $address],
            ]);
            $this->post('/oauth/token', ['grant_type' => 'x']);
        };

        $send('203.0.113.7');
        $this->assertResponseCode(400);
        // Forwarding headers do not change the key unless the application trusts its proxies.
        $send('203.0.113.7', ['X-Forwarded-For' => '198.51.100.1', 'X-Real-IP' => '198.51.100.2']);
        $this->assertResponseCode(429);
        // Another address has its own budget.
        $send('203.0.113.8');
        $this->assertResponseCode(400);
    }

    public function testThePluginLayoutKeepsTheCoreSecurityHeaders(): void
    {
        $this->signIn();
        $this->get($this->authorizeUrl());

        $this->assertResponseOk();
        $this->assertHeader('Content-Security-Policy', $this->coreCsp());
        $this->assertHeader('X-Frame-Options', 'DENY');
        $this->assertHeader('Referrer-Policy', 'no-referrer');
        $this->assertHeader('Cache-Control', 'no-store');
    }

    public function testAnApplicationLayoutExtendsOnlyTheStyleImageAndFontSources(): void
    {
        $this->configure(['consent' => ['layout' => 'raw_title']]);
        $this->signIn();
        $this->get($this->authorizeUrl());

        $this->assertResponseOk();
        $csp = $this->_response->getHeaderLine('Content-Security-Policy');
        $this->assertNotSame($this->coreCsp(), $csp);
        $this->assertStringContainsString("style-src 'self' 'unsafe-inline'", $csp);
        $this->assertStringContainsString("img-src 'self' data:", $csp);
        $this->assertStringContainsString("font-src 'self'", $csp);
        // Never weakened: no script execution, no framing, no base tag.
        $this->assertStringContainsString("default-src 'none'", $csp);
        $this->assertStringNotContainsString('script-src', $csp);
        $this->assertStringContainsString("frame-ancestors 'none'", $csp);
        $this->assertStringContainsString("base-uri 'none'", $csp);
        $this->assertHeader('X-Frame-Options', 'DENY');
    }

    public function testErrorPagesAtAuthorizeUseTheConsentLayoutCsp(): void
    {
        $this->configure(['consent' => ['layout' => 'raw_title']]);
        $this->signIn();
        $this->get($this->authorizeUrl(['client_id' => 'unknown']));

        $this->assertResponseCode(400);
        $this->assertStringContainsString(
            "style-src 'self' 'unsafe-inline'",
            $this->_response->getHeaderLine('Content-Security-Policy'),
        );
    }

    public function testTheConnectionsPageUsesItsOwnLayoutCsp(): void
    {
        $this->configure(['connections' => ['enabled' => true, 'layout' => 'raw_title']]);
        $this->signIn();
        $this->get('/oauth/connections');

        $this->assertResponseOk();
        $this->assertStringContainsString(
            "img-src 'self' data:",
            $this->_response->getHeaderLine('Content-Security-Policy'),
        );

        // The consent pages still use the plugin's layout and the core's policy.
        $this->get($this->authorizeUrl());
        $this->assertHeader('Content-Security-Policy', $this->coreCsp());
    }

    public function testErrorPagesAtConnectionsUseTheConsentLayoutCsp(): void
    {
        // Disabled page: the error page renders with the consent layout, whatever the connections layout is.
        $this->configure(['connections' => ['enabled' => false, 'layout' => 'raw_title']]);
        $this->signIn();
        $this->get('/oauth/connections');
        $this->assertResponseCode(404);
        $this->assertHeader('Content-Security-Policy', $this->coreCsp());

        $this->configure(['connections' => ['enabled' => false], 'consent' => ['layout' => 'raw_title']]);
        $this->get('/oauth/connections');
        $this->assertResponseCode(404);
        $this->assertStringContainsString(
            "img-src 'self' data:",
            $this->_response->getHeaderLine('Content-Security-Policy'),
        );
    }

    public function testRoutingDoesNotNeedTheSecret(): void
    {
        $salt = Security::getSalt();
        Security::setSalt('short');
        $collection = new RouteCollection();
        try {
            (new OAuthServerPlugin())->routes(new RouteBuilder($collection, '/'));
        } finally {
            Security::setSalt($salt);
        }

        $paths = array_map(fn($route) => $route->template, $collection->routes());
        $this->assertContains('/.well-known/oauth-authorization-server', $paths);
        $this->assertContains('/oauth/token', $paths);
    }

    public function testAnInvalidConfigurationStillConnectsTheRoutes(): void
    {
        $routes = function (): array {
            $collection = new RouteCollection();
            (new OAuthServerPlugin())->routes(new RouteBuilder($collection, '/'));

            return array_map(fn($route) => $route->template, $collection->routes());
        };

        // No issuer: the metadata document of an issuer without a path, so it answers 503 instead of 404.
        Configure::write('App.fullBaseUrl', false);
        $paths = $routes();
        $this->assertContains('/oauth/token', $paths);
        $this->assertContains('/.well-known/oauth-authorization-server', $paths);

        // The issuer and the route prefix are read on their own when something else is broken.
        Configure::write('App.fullBaseUrl', $this->baseUrl);
        $this->configure(['routePrefix' => '/auth', 'issuer' => 'http://localhost/app', 'tokenPrefix' => 'Not Valid!']);
        Configure::write('OAuthServer.resources', ['http://localhost/api' => 'Test API']);
        $paths = $routes();
        $this->assertContains('/auth/token', $paths);
        $this->assertContains('/auth/connections', $paths);
        $this->assertContains('/.well-known/oauth-authorization-server/app', $paths);

        // A route prefix the core refuses falls back to /oauth.
        $this->configure(['routePrefix' => 'no slash']);
        $this->assertContains('/oauth/token', $routes());
    }
}
