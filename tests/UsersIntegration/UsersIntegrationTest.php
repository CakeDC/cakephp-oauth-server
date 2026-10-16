<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\UsersIntegration;

use Cake\Console\TestSuite\ConsoleIntegrationTestTrait;
use Cake\Core\Configure;
use Cake\Http\ServerRequest;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use CakeDC\Auth\Rbac\Rbac;
use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Integration\RbacPermissionsProvider;
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

        // The token is for /api: anywhere else it is judged and refused, never a login.
        $this->withOAuthToken($token);
        $this->get($this->prefix . '/authorize?' . $this->authorizeQuery($client->clientId));
        $this->assertResponseCode(401);
        $this->assertResponseNotContains('Signed in as');
        $this->assertNull($this->_requestSession->read('Auth'));
        $this->assertSame([], $this->_requestSession->read() ?? []);

        $this->withOAuthToken($token);
        $this->get($this->prefix . '/connections');
        $this->assertResponseCode(401);
        $this->assertNull($this->_requestSession->read('Auth'));
        $this->assertSame([], $this->_requestSession->read() ?? []);
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

    /**
     * @param string|null $plugin The plugin of the route.
     * @param string $controller The controller.
     * @param string $action The action.
     * @return \Cake\Http\ServerRequest
     */
    private function routed(?string $plugin, string $controller, string $action): ServerRequest
    {
        return (new ServerRequest(['url' => '/x']))->withAttribute('params', [
            'plugin' => $plugin,
            'controller' => $controller,
            'action' => $action,
            'prefix' => null,
            'pass' => [],
        ]);
    }

    public function testTheRbacProviderOnlyOpensTheOAuthController(): void
    {
        $rbac = new Rbac(['permissions_provider_class' => RbacPermissionsProvider::class]);
        // A role the application's own rules do not mention.
        $user = ['id' => '1', 'role' => 'guest'];

        $this->assertSame(OAuthServer::rbacPermissions()[0], $rbac->getPermissions()[0]);
        $this->assertTrue($rbac->checkPermissions([], $this->routed('CakeDC/OAuthServer', 'OAuth', 'token')));
        $this->assertTrue($rbac->checkPermissions($user, $this->routed('CakeDC/OAuthServer', 'OAuth', 'authorize')));
        $this->assertFalse($rbac->checkPermissions($user, $this->routed(null, 'Articles', 'index')));
        $this->assertFalse($rbac->checkPermissions([], $this->routed(null, 'Articles', 'index')));
        $this->assertFalse($rbac->checkPermissions($user, $this->routed('CakeDC/Users', 'Users', 'profile')));
        $this->assertFalse($rbac->checkPermissions($user, $this->routed(null, 'Pages', 'secret')));
        $this->assertFalse($rbac->checkPermissions($user, $this->routed('CakeDC/OAuthServer', 'Other', 'index')));
        // The rule names the plugin: same controller and action names elsewhere stay closed.
        foreach ([[], $user] as $who) {
            $this->assertFalse($rbac->checkPermissions($who, $this->routed(null, 'OAuth', 'token')));
            $this->assertFalse($rbac->checkPermissions($who, $this->routed('Other', 'OAuth', 'authorize')));
        }
        // The application's own rules survive behind the OAuth rule.
        $this->assertTrue($rbac->checkPermissions($user, $this->routed(null, 'Pages', 'me')));
    }

    public function testTheIntegrationKeepsWhatTheApplicationSet(): void
    {
        $provider = Configure::read('Auth.RbacPolicy.adapter.permissions_provider_class');
        $authenticator = Configure::read('Auth.Authenticators.OAuthServerToken');
        $this->assertSame(RbacPermissionsProvider::class, $provider);

        try {
            Configure::write('Auth.RbacPolicy.adapter.permissions_provider_class', 'Acme\\Mine\\Provider');
            Configure::write('Auth.Authenticators.OAuthServerToken', ['className' => 'Acme\\Mine\\Authenticator']);

            UsersIntegration::apply();

            $this->assertSame(
                'Acme\\Mine\\Provider',
                Configure::read('Auth.RbacPolicy.adapter.permissions_provider_class'),
            );
            $this->assertSame(
                ['className' => 'Acme\\Mine\\Authenticator'],
                Configure::read('Auth.Authenticators.OAuthServerToken'),
            );
        } finally {
            Configure::write('Auth.RbacPolicy.adapter.permissions_provider_class', $provider);
            Configure::write('Auth.Authenticators.OAuthServerToken', $authenticator);
        }
    }

    public function testTheTokenAuthenticatorComesFirst(): void
    {
        $this->assertSame('OAuthServerToken', array_key_first((array)Configure::read('Auth.Authenticators')));
        $this->assertArrayHasKey('Session', (array)Configure::read('Auth.Authenticators'));
    }

    public function testASessionCookieDoesNotHideARevokedBearerToken(): void
    {
        $user = $this->createUser();
        $token = $this->oauthTokenFor($user, [], 'http://localhost/api');
        $this->session(['Auth' => $user]);
        $this->withOAuthToken($token);
        $this->get('/api/me');
        $this->assertResponseOk();

        $this->exec('oauth token revoke --subject ' . $user->get('id'));
        $this->assertExitSuccess();

        $this->session(['Auth' => $user]);
        $this->withOAuthToken($token);
        $this->get('/api/me');
        $this->assertResponseCode(401);
    }

    public function testASessionCookieWithAValidBearerTokenRunsAsTheTokenOwner(): void
    {
        $user = $this->createUser();
        $token = $this->oauthTokenFor($user, [], 'http://localhost/api');
        $users = $this->fetchTable('CakeDC/Users.Users');
        $other = $users->saveOrFail($users->newEntity([
            'username' => 'grace',
            'email' => 'grace@example.com',
            'password' => 'secret-password',
            'active' => true,
            'role' => 'user',
        ], ['accessibleFields' => ['*' => true]]));

        $this->session(['Auth' => $other]);
        $this->withOAuthToken($token);
        $this->get('/api/me');

        $this->assertResponseOk();
        $body = (array)json_decode((string)$this->_response->getBody(), true);
        $this->assertSame((string)$user->get('id'), (string)$body['id']);
        $this->assertSame(['api'], $body['scopes']);
    }

    public function testASessionWithABearerTokenIsNoLoginAtTheConsentPage(): void
    {
        $user = $this->createUser();
        $token = $this->oauthTokenFor($user, [], 'http://localhost/api');
        $client = OAuthServer::server()->clientRegistrar()
            ->create('Claude', ['https://app.example.com/cb'], false)['client'];

        $this->session(['Auth' => $user]);
        $this->withOAuthToken($token);
        $this->get($this->prefix . '/authorize?' . $this->authorizeQuery($client->clientId));

        $this->assertResponseCode(401);
        $this->assertResponseNotContains('Signed in as');
    }

    public function testATokenForTheApiOpensNoCakeDcUsersPage(): void
    {
        $user = $this->createUser();
        $token = $this->oauthTokenFor($user, ['api'], 'http://localhost/api');

        // Reading pages: challenged, the controller never runs.
        foreach (['/profile', '/logout', '/users/change-password'] as $url) {
            $this->withOAuthToken($token);
            $this->get($url);
            $this->assertResponseCode(401, $url);
            $this->assertHeaderContains('WWW-Authenticate', 'Bearer error="invalid_token"');
            $this->assertResponseNotContains('ada@example.com');
        }

        // The reviewer's probe: a state-changing POST with no CSRF token, then with one.
        $before = (string)$this->fetchTable('CakeDC/Users.Users')->get($user->get('id'))->get('password');
        $form = ['password' => 'new-password-123', 'password_confirm' => 'new-password-123'];
        $this->withOAuthToken($token);
        $this->post('/users/change-password', $form);
        $this->assertResponseCode(403);
        $this->withOAuthToken($token);
        $this->enableCsrfToken();
        $this->post('/users/change-password', $form);
        $this->assertResponseCode(401);
        $after = (string)$this->fetchTable('CakeDC/Users.Users')->get($user->get('id'))->get('password');
        $this->assertSame($before, $after, 'The password must not change.');

        // With a session cookie as well, the presented token is still judged.
        $this->session(['Auth' => $user]);
        $this->withOAuthToken($token);
        $this->get('/profile');
        $this->assertResponseCode(401);
    }

    public function testTheAuthenticatorGetsThePathsOfTheUsersResourceOrTheConfiguredOnes(): void
    {
        $authenticator = Configure::read('Auth.Authenticators.OAuthServerToken');
        $original = Configure::read('OAuthServer');
        try {
            // Not set: the authenticator derives /api from its resource.
            $this->assertArrayNotHasKey('paths', $authenticator);

            Configure::delete('Auth.Authenticators.OAuthServerToken');
            Configure::write('OAuthServer.users.paths', ['/api', '/rest/']);
            UsersIntegration::apply();
            $this->assertSame(['/api', '/rest'], Configure::read('Auth.Authenticators.OAuthServerToken.paths'));

            Configure::delete('Auth.Authenticators.OAuthServerToken');
            Configure::delete('OAuthServer.users.paths');
            Configure::write('OAuthServer.tokenPaths', ['/']);
            UsersIntegration::apply();
            $this->assertSame(['/'], Configure::read('Auth.Authenticators.OAuthServerToken.paths'));
        } finally {
            Configure::write('OAuthServer', $original);
            Configure::write('Auth.Authenticators.OAuthServerToken', $authenticator);
        }
    }
}
