<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\UsersIntegration;

use Cake\Console\TestSuite\ConsoleIntegrationTestTrait;
use Cake\Core\Configure;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Integration\UsersIntegration;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Test\Support\Html;
use CakeDC\OAuthServer\TestSuite\OAuthTestTrait;

class UsersIntegrationTest extends TestCase
{
    use ConsoleIntegrationTestTrait;
    use IntegrationTestTrait;
    use OAuthTestTrait;

    private const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    private string $prefix;

    protected function setUp(): void
    {
        parent::setUp();
        OAuthServer::reset();
        $this->prefix = PluginConfig::fromConfigure()->routePrefix();
        foreach (['OauthConsents', 'OauthTokens', 'OauthAuthorizationCodes', 'OauthClients'] as $table) {
            $this->fetchTable('CakeDC/OAuthServer.' . $table)->deleteAll([]);
        }
        $this->fetchTable('CakeDC/Users.Users')->deleteAll([]);
    }

    protected function tearDown(): void
    {
        Configure::delete('Auth.RbacPolicy.adapter.permissions');
        OAuthServer::reset();
        parent::tearDown();
    }

    /**
     * @return \Cake\Datasource\EntityInterface
     */
    private function createUser(): mixed
    {
        $users = $this->fetchTable('CakeDC/Users.Users');

        return $users->saveOrFail($users->newEntity([
            'username' => 'ada',
            'email' => 'ada@example.com',
            'password' => 'secret-password',
            'active' => true,
            'role' => 'user',
        ], ['accessibleFields' => ['*' => true]]));
    }

    /**
     * @param string $clientId The client.
     * @return string
     */
    private function authorizeQuery(string $clientId): string
    {
        return http_build_query([
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => 'https://app.example.com/cb',
            'code_challenge' => Pkce::challengeFor(self::VERIFIER),
            'code_challenge_method' => 'S256',
            'resource' => 'http://localhost/api',
        ]);
    }

    public function testDefaultsComeFromCakeDcUsers(): void
    {
        $config = PluginConfig::fromConfigure();

        $this->assertSame('CakeDC/Users.Users', $config->userProvider()['table']);
        $this->assertSame('username', $config->userProvider()['displayField']);
        $this->assertSame('CakeDC/Users', $config->login()['url']['plugin'] ?? null);
        $this->assertSame(
            'CakeDC/OAuthServer.OAuthServerToken',
            Configure::read('Auth.Authenticators.OAuthServerToken.className'),
        );
        $this->assertTrue(Configure::read('Auth.Authenticators.OAuthServerToken.skipTwoFactorVerify'));
    }

    public function testTheAuthenticatorValidatesAgainstTheConfiguredUsersResource(): void
    {
        $this->assertSame(
            'http://localhost/api',
            Configure::read('Auth.Authenticators.OAuthServerToken.resource'),
        );
    }

    public function testRbacLetsTheEndpointsThrough(): void
    {
        $this->get('/.well-known/oauth-authorization-server');
        $this->assertResponseOk();

        $this->configRequest(['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']]);
        $this->post($this->prefix . '/token', ['grant_type' => 'x']);
        $this->assertResponseCode(400);
        $this->assertSame(['pass', 'RBAC lets the OAuth endpoints through'], UsersIntegration::rbacReport());
    }

    public function testTheWholeFlowWithACakeDcUsersAccount(): void
    {
        $user = $this->createUser();
        $client = OAuthServer::server()->clientRegistrar()
            ->create('Claude', ['https://app.example.com/cb'], false)['client'];
        $query = $this->authorizeQuery($client->clientId);

        $this->get($this->prefix . '/authorize?' . $query);
        $this->assertRedirectContains('/login?redirect=');

        $this->session(['Auth' => $user]);
        $this->get($this->prefix . '/authorize?' . $query);
        $this->assertResponseOk();
        $this->assertResponseContains('Signed in as ada.');
        $fields = Html::hiddenFields((string)$this->_response->getBody(), 'consent_token');
        unset($fields['_csrfToken']);
        $this->enableCsrfToken();
        $this->post($this->prefix . '/authorize', $fields + ['decision' => 'approve']);
        parse_str((string)parse_url($this->_response->getHeaderLine('Location'), PHP_URL_QUERY), $params);

        $this->configRequest(['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']]);
        $this->post($this->prefix . '/token', [
            'grant_type' => 'authorization_code',
            'code' => $params['code'] ?? '',
            'redirect_uri' => 'https://app.example.com/cb',
            'code_verifier' => self::VERIFIER,
            'client_id' => $client->clientId,
        ]);
        $tokens = (array)json_decode((string)$this->_response->getBody(), true);
        $this->assertArrayHasKey('access_token', $tokens);

        $this->_session = [];
        $this->configRequest(['headers' => ['Authorization' => 'Bearer ' . $tokens['access_token']]]);
        $this->get('/api/me');
        $this->assertResponseOk();
        $this->assertResponseContains((string)$user->get('id'));
    }

    public function testABearerTokenIsNeverABrowserLogin(): void
    {
        $user = $this->createUser();
        $token = $this->oauthTokenFor($user, [], 'http://localhost/api');
        $client = OAuthServer::server()->clientRegistrar()
            ->create('Claude', ['https://app.example.com/cb'], false)['client'];

        $this->withOAuthToken($token);
        $this->get($this->prefix . '/authorize?' . $this->authorizeQuery($client->clientId));
        $this->assertRedirectContains('/login?redirect=');
        $this->assertResponseNotContains('Signed in as');

        $this->withOAuthToken($token);
        $this->get($this->prefix . '/connections');
        $this->assertRedirectContains('/login');
    }

    public function testABearerRequestNeverCreatesASession(): void
    {
        $user = $this->createUser();
        $this->actAsOAuth($user, [], 'http://localhost/api');

        $this->get('/api/me');

        $this->assertResponseOk();
        $this->assertResponseContains((string)$user->get('id'));
        $this->assertNull($this->_requestSession->read('Auth'));
    }

    public function testCheckReportsMissingRbacRules(): void
    {
        // An application that lists its own RBAC rules explicitly leaves the OAuth endpoints out.
        Configure::write('Auth.RbacPolicy.adapter.permissions', [
            ['role' => '*', 'controller' => 'Pages', 'action' => 'me', 'bypassAuth' => true],
        ]);

        $this->exec('oauth check');

        $this->assertOutputContains('[FAIL] RBAC');
    }
}
