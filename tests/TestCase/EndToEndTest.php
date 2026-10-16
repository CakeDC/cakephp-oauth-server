<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase;

use Cake\Console\TestSuite\ConsoleIntegrationTestTrait;
use Cake\Core\Configure;
use Cake\Log\Log;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Test\Support\FakeDns;
use CakeDC\OAuthServer\Test\Support\FakeTransport;
use CakeDC\OAuthServer\Test\Support\Fixtures;
use CakeDC\OAuthServer\Test\Support\Html;
use CakeDC\OAuthServer\TestSuite\OAuthTestTrait;

class EndToEndTest extends TestCase
{
    use ConsoleIntegrationTestTrait;
    use IntegrationTestTrait;
    use OAuthTestTrait;

    private const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    private const CLAUDE = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
    private const CALLBACK = 'https://claude.ai/api/mcp/auth_callback';

    protected array $fixtures = Fixtures::ALL;

    /**
     * @var array<string, mixed>
     */
    private array $settings = [];

    private FakeTransport $transport;

    protected function setUp(): void
    {
        parent::setUp();
        $this->settings = (array)Configure::read('OAuthServer');
        $transport = $this->transport = new FakeTransport();
        // The shape of the document claude.ai publishes.
        $transport->serve(self::CLAUDE, [
            'client_id' => self::CLAUDE,
            'client_name' => 'Claude',
            'client_uri' => 'https://claude.ai',
            'redirect_uris' => [self::CALLBACK],
            'grant_types' => [
                'authorization_code',
                'refresh_token',
                'urn:ietf:params:oauth:grant-type:jwt-bearer',
            ],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ]);
        Configure::write('OAuthServer.cimd', ['enabled' => true]);
        Configure::write('OAuthServer.services', ['transport' => $transport, 'dns' => new FakeDns()]);
        OAuthServer::reset();
    }

    protected function tearDown(): void
    {
        foreach (['stdout', 'stderr'] as $name) {
            Log::drop($name);
        }
        Configure::write('OAuthServer', $this->settings);
        OAuthServer::reset();
        parent::tearDown();
    }

    private function authorizeQuery(string $clientId, string $redirect): string
    {
        return http_build_query([
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirect,
            'state' => 's',
            'scope' => 'api offline_access',
            'code_challenge' => Pkce::challengeFor(self::VERIFIER),
            'code_challenge_method' => 'S256',
            'resource' => 'http://localhost/api',
        ], '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Walks consent and the code exchange; returns the token response.
     *
     * @return array<string, mixed>
     */
    private function connect(int $userId, string $clientId, string $redirect): array
    {
        $this->session(['Auth' => ['id' => $userId]]);
        $this->get('/oauth/authorize?' . $this->authorizeQuery($clientId, $redirect));
        $this->assertResponseOk();
        $fields = Html::hiddenFields((string)$this->_response->getBody(), 'consent_token');
        unset($fields['_csrfToken']);
        $this->enableCsrfToken();
        $this->post('/oauth/authorize', $fields + ['decision' => 'approve']);
        $location = $this->_response->getHeaderLine('Location');
        $this->assertStringStartsWith($redirect . '?', $location);
        parse_str((string)parse_url($location, PHP_URL_QUERY), $params);
        $this->assertSame('s', $params['state'] ?? null);
        $this->assertSame('http://localhost', $params['iss'] ?? null);
        $this->configRequest(['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']]);
        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'code' => $params['code'] ?? '',
            'redirect_uri' => $redirect,
            'code_verifier' => self::VERIFIER,
            'client_id' => $clientId,
            'resource' => 'http://localhost/api',
        ]);
        $this->assertResponseOk();

        return (array)json_decode((string)$this->_response->getBody(), true);
    }

    /**
     * @return array<string, mixed>
     */
    private function refresh(string $clientId, string $refreshToken): array
    {
        $this->configRequest(['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']]);
        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $clientId,
            'resource' => 'http://localhost/api',
        ]);

        return (array)json_decode((string)$this->_response->getBody(), true);
    }

    private function me(string $token): void
    {
        $this->configRequest(['headers' => ['Authorization' => 'Bearer ' . $token]]);
        $this->get('/api/me');
    }

    /**
     * Posts the first connections-page form carrying $marker, as the signed in person.
     *
     * @param int $userId The person.
     * @param string $marker A hidden field of the form to post.
     * @return void
     */
    private function postConnectionsForm(int $userId, string $marker): void
    {
        $this->session(['Auth' => ['id' => $userId]]);
        $this->get('/oauth/connections');
        $this->assertResponseOk();
        $fields = Html::hiddenFields((string)$this->_response->getBody(), $marker);
        unset($fields['_csrfToken']);
        $this->assertArrayHasKey($marker, $fields);
        $this->enableCsrfToken();
        $this->post('/oauth/connections', $fields);
        $this->assertResponseCode(303);
    }

    /**
     * @return array<string, int>
     */
    private function tokenStates(): array
    {
        $states = ['live' => 0, 'revoked' => 0];
        foreach ($this->fetchTable('CakeDC/OAuthServer.OauthTokens')->find()->all() as $token) {
            $states[$token->get('revoked_at') === null ? 'live' : 'revoked']++;
        }

        return $states;
    }

    public function testClaudeConnectsWithItsMetadataDocument(): void
    {
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/authorize?' . $this->authorizeQuery(self::CLAUDE, self::CALLBACK));
        $this->assertResponseContains('claude.ai wants to access Test API');

        $tokens = $this->connect(1, self::CLAUDE, self::CALLBACK);
        $this->assertStringStartsWith('test_at_', $tokens['access_token']);
        $this->assertStringStartsWith('test_rt_', $tokens['refresh_token']);
        $this->me($tokens['access_token']);
        $this->assertResponseOk();
        $this->assertSame('1', (string)json_decode((string)$this->_response->getBody(), true)['id']);

        $refreshed = $this->refresh(self::CLAUDE, $tokens['refresh_token']);
        $this->assertResponseOk();
        $this->assertNotSame($tokens['access_token'], $refreshed['access_token']);
        $this->assertNotSame($tokens['refresh_token'], $refreshed['refresh_token']);
        $this->me($refreshed['access_token']);
        $this->assertResponseOk();

        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/connections');
        $this->assertResponseContains('claude.ai');
        $this->postConnectionsForm(1, 'family_id');

        $this->me($refreshed['access_token']);
        $this->assertResponseCode(401);
        $this->assertSame(0, $this->tokenStates()['live']);
        $this->refresh(self::CLAUDE, $refreshed['refresh_token']);
        $this->assertResponseCode(400);
        $this->assertResponseContains('invalid_grant');
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/connections');
        $this->assertResponseContains('No application is connected.');

        // The consent went with the connection: the next attempt asks again.
        $this->get('/oauth/authorize?' . $this->authorizeQuery(self::CLAUDE, self::CALLBACK));
        $this->assertResponseOk();
        $this->assertResponseContains('claude.ai wants to access Test API');
    }

    public function testAClaudeCodeStyleLoopbackClientRegistersAndConnects(): void
    {
        $redirect = 'http://127.0.0.1:53682/callback';
        $this->configRequest(['headers' => ['Content-Type' => 'application/json']]);
        $this->post('/oauth/register', (string)json_encode([
            'client_name' => 'Claude Code',
            'redirect_uris' => [$redirect],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ]));
        $this->assertResponseCode(201);
        $registered = (array)json_decode((string)$this->_response->getBody(), true);
        $this->assertSame([$redirect], $registered['redirect_uris']);
        $this->assertArrayNotHasKey('client_secret', $registered);
        $row = $this->fetchTable('CakeDC/OAuthServer.OauthClients')
            ->find()->where(['client_id' => $registered['client_id']])->firstOrFail();
        $this->assertSame('Claude Code', $row->get('name'));

        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/authorize?' . $this->authorizeQuery($registered['client_id'], $redirect));
        // Its name is its own claim: the page names the address the answer goes to.
        $this->assertResponseContains('127.0.0.1 wants to access Test API');
        $this->assertResponseContains('It calls itself <q>Claude Code</q>. Anyone can choose that name.');
        $this->assertResponseNotContains('Claude Code wants');
        $this->assertResponseContains('its name is not verified');
        $this->assertResponseContains('The request comes from 127.0.0.1.');

        $tokens = $this->connect(1, $registered['client_id'], $redirect);
        $this->me($tokens['access_token']);
        $this->assertResponseOk();
        $this->assertSame(['api'], json_decode((string)$this->_response->getBody(), true)['scopes']);

        // Any program on this computer can listen on a loopback port, so the remembered consent does not answer
        // for the next attempt: the person is asked again and told why.
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/authorize?' . $this->authorizeQuery($registered['client_id'], $redirect));
        $this->assertResponseOk();
        $this->assertResponseContains('You approved this application before.');
        $this->connect(1, $registered['client_id'], $redirect);
    }

    public function testRevokingAConnectionDeletesTheCodesNotExchangedYet(): void
    {
        $client = OAuthServer::server()->clientRegistrar()
            ->create('App', ['https://app.example.com/cb'], false)['client'];
        $this->connect(1, $client->clientId, 'https://app.example.com/cb');
        // The consent is remembered for an https client: the next code comes straight back.
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/authorize?' . $this->authorizeQuery($client->clientId, 'https://app.example.com/cb'));
        $this->assertResponseCode(302);
        parse_str((string)parse_url($this->_response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $this->assertNotEmpty($params['code'] ?? null);

        $this->postConnectionsForm(1, 'family_id');

        $this->configRequest(['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']]);
        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'code' => $params['code'],
            'redirect_uri' => 'https://app.example.com/cb',
            'code_verifier' => self::VERIFIER,
            'client_id' => $client->clientId,
            'resource' => 'http://localhost/api',
        ]);
        $this->assertResponseCode(400);
        $this->assertResponseContains('invalid_grant');
        $this->assertSame(0, $this->tokenStates()['live']);
    }

    public function testTheConnectionsPageShowsTheGrantAfterADownScopedRefresh(): void
    {
        $client = OAuthServer::server()->clientRegistrar()
            ->create('App', ['https://app.example.com/cb'], false)['client'];
        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => $client->clientId,
            'redirect_uri' => 'https://app.example.com/cb',
            'state' => 's',
            'scope' => 'content:write offline_access',
            'code_challenge' => Pkce::challengeFor(self::VERIFIER),
            'code_challenge_method' => 'S256',
            'resource' => 'http://localhost/mcp',
        ], '', '&', PHP_QUERY_RFC3986);
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/authorize?' . $query);
        $fields = Html::hiddenFields((string)$this->_response->getBody(), 'consent_token');
        unset($fields['_csrfToken']);
        $this->session(['Auth' => ['id' => 1]]);
        $this->enableCsrfToken();
        $this->post('/oauth/authorize', $fields + ['decision' => 'approve']);
        parse_str((string)parse_url($this->_response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $form = ['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']];
        $this->configRequest($form);
        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'code' => $params['code'] ?? '',
            'redirect_uri' => 'https://app.example.com/cb',
            'code_verifier' => self::VERIFIER,
            'client_id' => $client->clientId,
            'resource' => 'http://localhost/mcp',
        ]);
        $this->assertResponseOk();
        $tokens = (array)json_decode((string)$this->_response->getBody(), true);

        // A refresh that asks for less narrows the new access token only.
        $this->configRequest($form);
        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $tokens['refresh_token'],
            'client_id' => $client->clientId,
            'resource' => 'http://localhost/mcp',
            'scope' => 'content:read',
        ]);
        $this->assertResponseOk();
        $this->assertSame('content:read', json_decode((string)$this->_response->getBody(), true)['scope']);

        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/connections');
        $this->assertResponseOk();
        $this->assertResponseContains('content:write');
    }

    public function testAPersonalTokenNeedsAVisibleName(): void
    {
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/connections');
        $fields = Html::hiddenFields((string)$this->_response->getBody(), 'form_token');
        $this->enableCsrfToken();
        $this->post('/oauth/connections', [
            'form_token' => $fields['form_token'],
            'action' => 'create_token',
            'name' => "CI\u{202E}gnp",
            'resource' => 'http://localhost/api',
            'scope:api' => '1',
            'days' => '7',
        ]);

        $this->assertResponseContains('visible characters');
        $this->assertSame(0, preg_match('/test_pat_[A-Za-z0-9_-]{43}/', (string)$this->_response->getBody()));
        $this->assertSame(['live' => 0, 'revoked' => 0], $this->tokenStates());
    }

    public function testDeactivatedUsersLoseEverything(): void
    {
        $client = OAuthServer::server()->clientRegistrar()
            ->create('App', ['https://app.example.com/cb'], false)['client'];
        $tokens = $this->connect(2, $client->clientId, 'https://app.example.com/cb');
        $this->me($tokens['access_token']);
        $this->assertResponseOk();

        $this->fetchTable('Users')->updateAll(['active' => false], ['id' => 2]);

        $this->me($tokens['access_token']);
        $this->assertResponseCode(401);
        $this->session(['Auth' => ['id' => 2]]);
        $this->get('/oauth/authorize?' . $this->authorizeQuery($client->clientId, 'https://app.example.com/cb'));
        $this->assertRedirectContains('/login?redirect=');
        $this->assertResponseNotContains('wants to access');
        $this->refresh($client->clientId, $tokens['refresh_token']);
        $this->assertResponseCode(400);
        $this->assertResponseContains('invalid_grant');

        // Reactivation brings the person back; the refresh token was not consumed by the refusal.
        $this->fetchTable('Users')->updateAll(['active' => true], ['id' => 2]);
        $refreshed = $this->refresh($client->clientId, $tokens['refresh_token']);
        $this->assertResponseOk();
        $this->me($refreshed['access_token']);
        $this->assertResponseOk();
    }

    public function testAPersonalTokenFromTheConnectionsPage(): void
    {
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/connections');
        $fields = Html::hiddenFields((string)$this->_response->getBody(), 'form_token');
        $this->enableCsrfToken();
        $this->post('/oauth/connections', [
            'form_token' => $fields['form_token'],
            'action' => 'create_token',
            'name' => 'CI',
            'resource' => 'http://localhost/api',
            'scope:api' => '1',
            'days' => '7',
        ]);
        $this->assertResponseOk();
        $this->assertSame(
            1,
            preg_match('/(test_pat_[A-Za-z0-9_-]{43})/', (string)$this->_response->getBody(), $matches),
        );

        $this->me($matches[1]);
        $this->assertResponseOk();
        $this->assertSame('1', (string)json_decode((string)$this->_response->getBody(), true)['id']);
        $this->assertSame(1, $this->tokenStates()['live']);
    }

    public function testABearerTokenIsNotABrowserLogin(): void
    {
        $token = $this->oauthTokenFor(1, [], 'http://localhost/api');
        $client = OAuthServer::server()->clientRegistrar()
            ->create('App', ['https://app.example.com/cb'], false)['client'];

        $this->withOAuthToken($token);
        $this->get('/oauth/authorize?' . $this->authorizeQuery($client->clientId, 'https://app.example.com/cb'));
        // The token is for /api: anywhere else it is judged and refused, never a login.
        $this->assertResponseCode(401);
        $this->assertResponseNotContains('wants to access');
        $this->assertNull($this->_requestSession->read('Auth'));
        $this->assertSame([], $this->fetchTable('CakeDC/OAuthServer.OauthConsents')->find()->all()->toArray());

        $this->withOAuthToken($token);
        $this->get('/oauth/connections');
        $this->assertResponseCode(401);
        $this->assertResponseNotContains('Connected applications');
        $this->assertNull($this->_requestSession->read('Auth'));
    }

    public function testASessionCookieDoesNotHideARevokedBearerToken(): void
    {
        $token = $this->oauthTokenFor(1, [], 'http://localhost/api');
        $this->session(['Auth' => ['id' => 1]]);
        $this->me($token);
        $this->assertResponseOk();

        $this->exec('oauth token revoke --subject 1');
        $this->assertExitSuccess();

        $this->session(['Auth' => ['id' => 1]]);
        $this->me($token);
        $this->assertResponseCode(401);
    }

    public function testASessionCookieWithAValidBearerTokenRunsAsTheTokenOwner(): void
    {
        $token = $this->oauthTokenFor(1, [], 'http://localhost/api');
        // The session says Grace, the token says Ada: the token is checked first and wins.
        $this->session(['Auth' => ['id' => 2]]);
        $this->me($token);

        $this->assertResponseOk();
        $body = (array)json_decode((string)$this->_response->getBody(), true);
        $this->assertSame('1', (string)$body['id']);
        $this->assertSame(['api'], $body['scopes']);
    }

    public function testASessionWithABearerTokenIsNoLoginAtTheConsentPage(): void
    {
        $token = $this->oauthTokenFor(1, [], 'http://localhost/api');
        $client = OAuthServer::server()->clientRegistrar()
            ->create('App', ['https://app.example.com/cb'], false)['client'];

        // The token is presented outside its resource's path: it is judged and refused, never a login.
        $this->session(['Auth' => ['id' => 1]]);
        $this->withOAuthToken($token);
        $this->get('/oauth/authorize?' . $this->authorizeQuery($client->clientId, 'https://app.example.com/cb'));

        $this->assertResponseCode(401);
        $this->assertResponseNotContains('wants to access');
    }

    public function testAValidTokenAcceptedOnEveryRouteIsStillNoLoginOnTheSessionPages(): void
    {
        // A host whose Token authenticator covers every route: the token validates at /oauth/authorize and
        // /oauth/connections, so only the pages themselves stand between it and a browser login.
        Configure::write('TestApp.tokenAuthenticator', ['resource' => 'http://localhost/api', 'paths' => ['/']]);
        Configure::write('OAuthServer.tokenPaths', ['/']);
        OAuthServer::reset();
        $token = $this->oauthTokenFor(1, [], 'http://localhost/api');
        $client = OAuthServer::server()->clientRegistrar()
            ->create('App', ['https://app.example.com/cb'], false)['client'];
        $query = $this->authorizeQuery($client->clientId, 'https://app.example.com/cb');

        // The consent page: the token is accepted here, and the person is still sent to the login.
        $this->withOAuthToken($token);
        $this->get('/oauth/authorize?' . $query);
        $this->assertResponseCode(302);
        $this->assertStringStartsWith('/login?redirect=', $this->_response->getHeaderLine('Location'));
        $this->assertResponseNotContains('wants to access');

        // Approving with valid fields (taken from a real session) and the token: no code, no consent.
        $this->_request = [];
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/authorize?' . $query);
        $this->assertResponseOk();
        $fields = Html::hiddenFields((string)$this->_response->getBody(), 'consent_token');
        unset($fields['_csrfToken']);
        $this->withOAuthToken($token);
        $this->enableCsrfToken();
        $this->post('/oauth/authorize', $fields + ['decision' => 'approve']);
        $this->assertStringNotContainsString('code=', $this->_response->getHeaderLine('Location'));
        $this->assertResponseContains('Your session ended');
        $this->assertSame([], $this->fetchTable('CakeDC/OAuthServer.OauthConsents')->find()->all()->toArray());
        $this->assertSame(0, $this->fetchTable('CakeDC/OAuthServer.OauthAuthorizationCodes')->find()->count());

        // The connections page: the token is accepted here, and the person is still sent to the login.
        $this->_request = [];
        $this->_session = [];
        $this->withOAuthToken($token);
        $this->get('/oauth/connections');
        $this->assertResponseCode(302);
        $this->assertStringStartsWith('/login?redirect=', $this->_response->getHeaderLine('Location'));
        $this->assertResponseNotContains('Connected applications');

        // Creating a personal token with a valid form and the token: nothing is created.
        $this->_request = [];
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/connections');
        $this->assertResponseOk();
        $fields = Html::hiddenFields((string)$this->_response->getBody(), 'form_token');
        $before = $this->fetchTable('CakeDC/OAuthServer.OauthTokens')->find()->count();
        $this->withOAuthToken($token);
        $this->enableCsrfToken();
        $this->post('/oauth/connections', [
            'form_token' => $fields['form_token'],
            'action' => 'create_token',
            'name' => 'Minted with a bearer token',
            'resource' => 'http://localhost/api',
            'scope:api' => '1',
            'days' => '7',
        ]);
        $this->assertSame(0, preg_match('/test_pat_[A-Za-z0-9_-]{43}/', (string)$this->_response->getBody()));
        $this->assertSame($before, $this->fetchTable('CakeDC/OAuthServer.OauthTokens')->find()->count());
    }

    public function testPersonalTokensSwitchedOffStillListAndRevoke(): void
    {
        $token = $this->oauthTokenFor(1, [], 'http://localhost/api');
        $this->me($token);
        $this->assertResponseOk();

        Configure::write('OAuthServer.personalTokens', false);
        OAuthServer::reset();

        // The feature is off, so the token stops working at once, but it stays listed.
        $this->me($token);
        $this->assertResponseCode(401);
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/connections');
        $this->assertResponseOk();
        $this->assertResponseContains('Personal access tokens');
        $this->assertResponseContains('<td>test</td>');
        $this->assertSame(['live' => 1, 'revoked' => 0], $this->tokenStates());

        $this->postConnectionsForm(1, 'token_id');

        $this->assertSame(['live' => 0, 'revoked' => 1], $this->tokenStates());
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/connections');
        $this->assertResponseContains('No application is connected.');
        $this->assertResponseNotContains('Personal access tokens');
    }

    public function testARevokedMetadataDocumentClientStaysRevokedAfterPruning(): void
    {
        $clock = new FrozenClock();
        Configure::write('OAuthServer.services', [
            'transport' => $this->transport,
            'dns' => new FakeDns(),
            'clock' => $clock,
        ]);
        OAuthServer::reset();
        $tokens = $this->connect(1, self::CLAUDE, self::CALLBACK);

        $this->exec('oauth client revoke ' . self::CLAUDE);
        $this->assertExitSuccess();
        // Long enough for the pruner to consider an unused metadata document client.
        $clock->advance(40 * 86400);
        $this->exec('oauth prune');
        $this->assertExitSuccess();

        $row = $this->fetchTable('CakeDC/OAuthServer.OauthClients')
            ->find()->where(['client_id' => self::CLAUDE])->first();
        $this->assertNotNull($row);
        $this->assertNotNull($row->get('revoked_at'));
        $this->assertSame([], $this->fetchTable('CakeDC/OAuthServer.OauthTokens')->find()->all()->toArray());
        $this->me($tokens['access_token']);
        $this->assertResponseCode(401);
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/authorize?' . $this->authorizeQuery(self::CLAUDE, self::CALLBACK));
        $this->assertResponseCode(400);
        $this->assertResponseNotContains('wants to access');
        $this->assertSame('', $this->_response->getHeaderLine('Location'));
    }

    public function testClaudeCodeUsesAnyLoopbackPortFromItsMetadataDocument(): void
    {
        $url = 'https://claude.ai/oauth/claude-code-client-metadata';
        $this->transport->serve($url, [
            'client_id' => $url,
            'client_name' => 'Claude Code',
            'client_uri' => 'https://claude.ai',
            'redirect_uris' => ['http://localhost/callback', 'http://127.0.0.1/callback'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ]);

        // Another port than the registered one.
        $tokens = $this->connect(1, $url, 'http://localhost:54321/callback');
        $this->me($tokens['access_token']);
        $this->assertResponseOk();

        $refused = ['http://localhost:54321/other', 'http://[::1]:54321/callback', 'https://localhost:54321/callback'];
        foreach ($refused as $bad) {
            $this->session(['Auth' => ['id' => 1]]);
            $this->get('/oauth/authorize?' . $this->authorizeQuery($url, $bad));
            $this->assertResponseCode(400, $bad);
            $this->assertResponseNotContains('wants to access');
        }
    }
}
