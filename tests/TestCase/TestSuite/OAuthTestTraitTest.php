<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\TestSuite;

use Authentication\Identity;
use Cake\Core\Configure;
use Cake\ORM\Entity;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Test\Support\Fixtures;
use CakeDC\OAuthServer\TestSuite\OAuthTestTrait;
use InvalidArgumentException;
use LogicException;

class OAuthTestTraitTest extends TestCase
{
    use IntegrationTestTrait;
    use OAuthTestTrait;

    protected array $fixtures = Fixtures::ALL;

    protected function setUp(): void
    {
        parent::setUp();
        OAuthServer::reset();
    }

    protected function tearDown(): void
    {
        OAuthServer::reset();
        parent::tearDown();
    }

    public function testActsAsAPersonOnAProtectedRoute(): void
    {
        $this->actAsOAuth(1, ['api'], 'http://localhost/api');
        $this->get('/api/me');

        $this->assertResponseOk();
        $this->assertResponseContains('"id":1');
        $this->assertResponseContains('"scopes":["api"]');
    }

    public function testNoScopesMeansTheDefaultScopes(): void
    {
        $this->actAsOAuth(1, [], 'http://localhost/api');
        $this->get('/api/me');

        $this->assertResponseContains('"scopes":["api"]');
    }

    public function testAcceptsIdentitiesEntitiesAndArrays(): void
    {
        foreach ([new Identity(['id' => 2]), new Entity(['id' => 2]), ['id' => 2], '2'] as $identity) {
            $this->withOAuthToken($this->oauthTokenFor($identity, [], 'http://localhost/api'));
            $this->get('/api/me');
            $this->assertResponseContains('"id":2');
        }
    }

    public function testTheHeaderAppliesToTheNextRequestOnly(): void
    {
        $this->actAsOAuth(1, [], 'http://localhost/api');
        $this->get('/api/me');
        $this->assertResponseOk();

        $this->get('/api/me');
        $this->assertResponseContains('{"error":"unauthorized"}');
    }

    public function testABearerPostSkipsCsrfAndAnyOtherPostDoesNot(): void
    {
        $this->actAsOAuth(1, [], 'http://localhost/api');
        $this->post('/api/me');
        $this->assertResponseOk();

        $this->post('/api/me');
        $this->assertResponseCode(403);
    }

    public function testASecondTokenReplacesTheFirst(): void
    {
        $first = $this->oauthTokenFor(1, [], 'http://localhost/api');
        $this->withOAuthToken($first);
        $this->actAsOAuth(2, [], 'http://localhost/api');

        $this->get('/api/me');

        $this->assertResponseOk();
        $this->assertResponseContains('"id":2');
    }

    public function testRejectsUnknownResources(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->oauthTokenFor(1, [], 'https://nope.example');
    }

    public function testRejectsAnInactivePerson(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('No active person with id "3"');

        $this->oauthTokenFor(3, [], 'http://localhost/api');
    }

    public function testRejectsAnUnknownPerson(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->oauthTokenFor(999, [], 'http://localhost/api');
    }

    public function testRejectsScopesTheResourceDoesNotHave(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('You cannot grant "admin"');

        $this->oauthTokenFor(1, ['admin'], 'http://localhost/api');
    }

    public function testFailsClearlyWhenPersonalTokensAreDisabled(): void
    {
        $original = Configure::read('OAuthServer');
        Configure::write('OAuthServer.personalTokens', false);
        OAuthServer::reset();
        try {
            $this->expectException(LogicException::class);
            $this->expectExceptionMessage('OAuthServer.personalTokens');

            $this->oauthTokenFor(1, [], 'http://localhost/api');
        } finally {
            Configure::write('OAuthServer', $original);
        }
    }
}
