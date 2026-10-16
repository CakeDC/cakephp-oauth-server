<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Identity;

use Authentication\Identity;
use Cake\Core\Configure;
use Cake\Datasource\ConnectionManager;
use Cake\Http\ServerRequest;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Identity\OrmUserProvider;
use CakeDC\OAuthServer\Identity\SessionUserContext;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Test\Support\Html;
use CakeDC\OAuthServer\TestSuite\OAuthTestTrait;

/**
 * A users table whose primary key is not called `id`.
 */
class CustomKeyUsersTest extends TestCase
{
    use IntegrationTestTrait;
    use OAuthTestTrait;

    private const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    protected array $fixtures = [
        'plugin.CakeDC/OAuthServer.OauthClients',
        'plugin.CakeDC/OAuthServer.OauthAuthorizationCodes',
        'plugin.CakeDC/OAuthServer.OauthTokens',
        'plugin.CakeDC/OAuthServer.OauthConsents',
    ];

    private string $original = '';

    protected function setUp(): void
    {
        parent::setUp();
        $this->original = serialize(Configure::read('OAuthServer'));
        $connection = ConnectionManager::get('test');
        $connection->execute('DROP TABLE IF EXISTS members');
        $connection->execute(
            'CREATE TABLE members (member_id INT NOT NULL PRIMARY KEY, full_name VARCHAR(100) NOT NULL, ' .
            'active BOOLEAN NOT NULL)',
        );
        $members = $this->fetchTable('Members');
        $members->setPrimaryKey('member_id');
        foreach ([[7, 'Ada', true], [8, 'Grace', true], [9, 'Mallory', false]] as [$id, $name, $active]) {
            $members->saveOrFail($members->newEntity(
                ['member_id' => $id, 'full_name' => $name, 'active' => $active],
                ['accessibleFields' => ['*' => true]],
            ));
        }
        Configure::write('OAuthServer.userProvider', ['table' => 'Members', 'finder' => 'all', 'displayField' => 'full_name']);
        Configure::write('TestApp.identityKey', 'member_id');
        OAuthServer::reset();
    }

    protected function tearDown(): void
    {
        Configure::write('OAuthServer', unserialize($this->original));
        Configure::delete('TestApp.identityKey');
        OAuthServer::reset();
        $this->getTableLocator()->clear();
        ConnectionManager::get('test')->execute('DROP TABLE IF EXISTS members');
        parent::tearDown();
    }

    private function provider(): OrmUserProvider
    {
        return new OrmUserProvider(PluginConfig::fromConfigure()->userProvider());
    }

    public function testTheProviderKnowsTheKeyAndBuildsAnIdentityWithIt(): void
    {
        $provider = $this->provider();
        $this->assertSame('member_id', $provider->keyField());

        $owner = $provider->findBySubject('7');

        $this->assertNotNull($owner);
        $this->assertSame('7', $owner->subject);
        $this->assertSame('Ada', $owner->displayName);
        $this->assertInstanceOf(Identity::class, $owner->identity);
        $this->assertSame('7', (string)$owner->identity->getIdentifier());
        $this->assertNull($provider->findBySubject('1'));
    }

    public function testTheSessionContextReadsTheKeyFromIdentitiesThatCannotTellIt(): void
    {
        $provider = $this->provider();
        $context = new SessionUserContext($provider, '/login', 'redirect', 'identity', $provider->keyField(...));

        // Plain arrays and entities carry the key column.
        $array = (new ServerRequest())->withAttribute('identity', ['member_id' => 8, 'full_name' => 'stale']);
        $this->assertSame('8', $context->currentOwner($array)?->subject);
        $entity = $this->fetchTable('Members')->get(7);
        $this->assertSame('7', $context->currentOwner((new ServerRequest())->withAttribute('identity', $entity))?->subject);
        // An identity that knows its identifier is asked for it.
        $identity = new Identity(['member_id' => 8], ['fieldMap' => ['id' => 'member_id']]);
        $this->assertSame('8', $context->currentOwner((new ServerRequest())->withAttribute('identity', $identity))?->subject);
        // An array that only has `id` is not the key.
        $this->assertNull($context->currentOwner((new ServerRequest())->withAttribute('identity', ['id' => 8])));
    }

    public function testTestTokensForKeyedPeople(): void
    {
        foreach ([7, '7', $this->fetchTable('Members')->get(7), ['member_id' => 7], new Identity(['member_id' => 7], ['fieldMap' => ['id' => 'member_id']])] as $who) {
            $token = $this->oauthTokenFor($who, ['api'], 'http://localhost/api');
            $this->withOAuthToken($token);
            $this->get('/api/me');
            $this->assertResponseOk();
            $this->assertResponseContains('"id":7');
        }
    }

    public function testConsentWorksWithoutALoginLoop(): void
    {
        $client = OAuthServer::server()->clientRegistrar()
            ->create('App', ['https://app.example.com/cb'], false)['client'];
        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => $client->clientId,
            'redirect_uri' => 'https://app.example.com/cb',
            'code_challenge' => Pkce::challengeFor(self::VERIFIER),
            'code_challenge_method' => 'S256',
            'resource' => 'http://localhost/api',
        ]);

        $this->get('/oauth/authorize?' . $query);
        $this->assertRedirectContains('/login?redirect=');

        $this->session(['Auth' => ['member_id' => 7, 'full_name' => 'Ada']]);
        $this->get('/oauth/authorize?' . $query);
        $this->assertResponseOk();
        $this->assertResponseContains('Signed in as Ada.');
        $fields = Html::hiddenFields((string)$this->_response->getBody(), 'consent_token');
        unset($fields['_csrfToken']);
        $this->enableCsrfToken();
        $this->post('/oauth/authorize', $fields + ['decision' => 'approve']);
        parse_str((string)parse_url($this->_response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $this->assertArrayHasKey('code', $params);

        $this->configRequest(['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']]);
        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'code' => $params['code'],
            'redirect_uri' => 'https://app.example.com/cb',
            'code_verifier' => self::VERIFIER,
            'client_id' => $client->clientId,
            'resource' => 'http://localhost/api',
        ]);
        $tokens = (array)json_decode((string)$this->_response->getBody(), true);
        $this->assertArrayHasKey('access_token', $tokens);

        $this->session([]);
        $this->withOAuthToken($tokens['access_token']);
        $this->get('/api/me');
        $this->assertResponseOk();
        $this->assertResponseContains('"id":7');

        // The connections page knows the person as well.
        $this->_request = [];
        $this->session(['Auth' => ['member_id' => 7]]);
        $this->get('/oauth/connections');
        $this->assertResponseOk();
    }
}
