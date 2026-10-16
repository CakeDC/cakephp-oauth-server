<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase;

use Cake\Console\TestSuite\ConsoleIntegrationTestTrait;
use Cake\Core\Configure;
use Cake\Log\Log;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use CakeDC\OAuth\Server\Grant\Pkce;
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

    protected function setUp(): void
    {
        parent::setUp();
        $this->settings = (array)Configure::read('OAuthServer');
        $transport = new FakeTransport();
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
        // A session left from a page request would authenticate before the token is looked at.
        $this->_session = [];
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
        $this->assertResponseContains('Claude Code wants to access Test API');
        $this->assertResponseContains('its name is not verified');
        $this->assertResponseContains('The request comes from 127.0.0.1.');

        $tokens = $this->connect(1, $registered['client_id'], $redirect);
        $this->me($tokens['access_token']);
        $this->assertResponseOk();
        $this->assertSame(['api'], json_decode((string)$this->_response->getBody(), true)['scopes']);

        // A second connection attempt is remembered: no consent page, the code comes straight back.
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/authorize?' . $this->authorizeQuery($registered['client_id'], $redirect));
        $this->assertRedirectContains($redirect . '?code=');
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
        $this->assertSame(1, preg_match('/(test_pat_[A-Za-z0-9_-]{43})/', (string)$this->_response->getBody(), $matches));

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
        $this->assertRedirectContains('/login?redirect=');
        $this->assertResponseNotContains('wants to access');
        $this->assertSame([], $this->fetchTable('CakeDC/OAuthServer.OauthConsents')->find()->all()->toArray());

        $this->withOAuthToken($token);
        $this->get('/oauth/connections');
        $this->assertRedirectContains('/login');
        $this->assertResponseNotContains('Connected applications');
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

    public function testARevokedClientStaysRevokedAfterPruning(): void
    {
        $client = OAuthServer::server()->clientRegistrar()
            ->create('App', ['https://app.example.com/cb'], false)['client'];
        $tokens = $this->connect(1, $client->clientId, 'https://app.example.com/cb');

        $this->exec('oauth client revoke ' . $client->clientId);
        $this->assertExitSuccess();
        $this->exec('oauth prune');
        $this->assertExitSuccess();

        $row = $this->fetchTable('CakeDC/OAuthServer.OauthClients')
            ->find()->where(['client_id' => $client->clientId])->first();
        $this->assertNotNull($row);
        $this->assertNotNull($row->get('revoked_at'));
        $this->me($tokens['access_token']);
        $this->assertResponseCode(401);
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/authorize?' . $this->authorizeQuery($client->clientId, 'https://app.example.com/cb'));
        $this->assertResponseCode(400);
        $this->assertResponseNotContains('wants to access');
    }
}
