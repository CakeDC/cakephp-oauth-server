<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Identity;

use Authentication\Identity;
use Cake\TestSuite\TestCase;
use CakeDC\OAuth\Server\Client\ApplicationType;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientAuthMethod;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Resource\ProtectedResource;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Identity\OrmUserProvider;
use DateTimeImmutable;

class OrmUserProviderTest extends TestCase
{
    protected array $fixtures = ['plugin.CakeDC/OAuthServer.Users'];

    private function provider(array $settings = []): OrmUserProvider
    {
        return new OrmUserProvider((new PluginConfig(['userProvider' => $settings + ['table' => 'Users']]))->userProvider());
    }

    private function client(): Client
    {
        return new Client('id', 'client', ClientType::Registered, ApplicationType::Web, 'Reports', [], ['client_credentials'], ClientAuthMethod::SecretBasic, new DateTimeImmutable());
    }

    private function resource(): ProtectedResource
    {
        return new ProtectedResource('http://localhost/mcp', 'MCP', ['content:read' => 'Read', 'content:write' => 'Write']);
    }

    public function testFindsActivePeopleAsIdentities(): void
    {
        $owner = $this->provider()->findBySubject('1');

        $this->assertNotNull($owner);
        $this->assertSame('1', $owner->subject);
        $this->assertSame('Ada', $owner->displayName);
        $this->assertInstanceOf(Identity::class, $owner->identity);
        $this->assertSame('ada@example.com', $owner->identity['email']);
        $this->assertNull($this->provider()->findBySubject('3'));
        $this->assertNull($this->provider()->findBySubject('99'));
    }

    public function testCallbacksDecideAuthorizationAndScopes(): void
    {
        $provider = $this->provider([
            'displayField' => 'email',
            'canAuthorize' => fn($identity) => $identity['role'] === 'admin',
            'scopes' => fn($identity, ProtectedResource $resource) => $identity['role'] === 'admin' ? null : ['content:read'],
        ]);
        $ada = $provider->findBySubject('1');
        $grace = $provider->findBySubject('2');
        $this->assertNotNull($ada);
        $this->assertNotNull($grace);

        $this->assertSame('ada@example.com', $ada->displayName);
        $this->assertTrue($provider->canAuthorize($ada, $this->client(), $this->resource()));
        $this->assertFalse($provider->canAuthorize($grace, $this->client(), $this->resource()));
        $this->assertNull($provider->scopesFor($ada, $this->resource()));
        $this->assertSame(['content:read'], $provider->scopesFor($grace, $this->resource()));
    }

    public function testWithoutCallbacksEveryoneMayAuthorizeEverything(): void
    {
        $ada = $this->provider()->findBySubject('1');
        $this->assertNotNull($ada);

        $this->assertTrue($this->provider()->canAuthorize($ada, $this->client(), $this->resource()));
        $this->assertNull($this->provider()->scopesFor($ada, $this->resource()));
        $this->assertNull($this->provider()->forClient($this->client(), $this->resource()));
    }

    public function testClientsActAsTheIdentityTheCallbackReturns(): void
    {
        $provider = $this->provider(['forClient' => fn(Client $client) => $client->clientId === 'client' ? ['id' => 'svc', 'role' => 'bot'] : null]);

        $owner = $provider->forClient($this->client(), $this->resource());

        $this->assertNotNull($owner);
        $this->assertSame('client', $owner->subject);
        $this->assertSame('Reports', $owner->displayName);
        $this->assertSame(SubjectType::Client, $owner->type);
        $this->assertSame(['id' => 'svc', 'role' => 'bot'], $owner->identity);
    }

    public function testSubjectsAreComparedExactly(): void
    {
        $this->assertNull($this->provider()->findBySubject('1abc'));
        $this->assertNull($this->provider()->findBySubject('01'));
        $this->assertNull($this->provider()->findBySubject('1.0'));
        $this->assertSame('1', $this->provider()->findBySubject('1')?->subject);
    }
}
