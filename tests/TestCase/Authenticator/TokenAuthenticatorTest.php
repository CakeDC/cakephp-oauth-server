<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Authenticator;

use Authentication\Identifier\IdentifierCollection;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuthServer\Authenticator\TokenAuthenticator;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Test\Support\Fixtures;
use InvalidArgumentException;

class TokenAuthenticatorTest extends TestCase
{
    use IntegrationTestTrait;

    protected array $fixtures = Fixtures::ALL;

    protected function setUp(): void
    {
        parent::setUp();
        OAuthServer::reset();
    }

    private function personalToken(string $subject = '1', string $resource = 'http://localhost/api', array $scopes = ['api']): string
    {
        $server = OAuthServer::server();
        $target = $server->config()->resources->get($resource);
        $this->assertNotNull($target);

        return $server->tokenIssuer()->issuePersonal($subject, $target, $scopes, 'test', Time::plus($server->clock()->now(), 3600))['value'];
    }

    private function getMe(?string $authorization): void
    {
        if ($authorization !== null) {
            $this->configRequest(['headers' => ['Authorization' => $authorization]]);
        }
        $this->get('/api/me');
    }

    public function testAuthenticatesWithAToken(): void
    {
        $this->getMe('Bearer ' . $this->personalToken());

        $this->assertResponseOk();
        $this->assertResponseContains('"id":1');
        $this->assertResponseContains('"scopes":["api"]');
    }

    public function testInvalidTokensOfThisServerAreChallenged(): void
    {
        $this->getMe('Bearer test_pat_' . str_repeat('x', 43));

        $this->assertResponseCode(401);
        $this->assertHeaderContains('WWW-Authenticate', 'Bearer error="invalid_token"');
    }

    public function testATokenForAnotherResourceIsRefused(): void
    {
        $this->getMe('Bearer ' . $this->personalToken('1', 'http://localhost/mcp', ['content:read']));

        $this->assertResponseCode(401);
        $this->assertHeaderContains('WWW-Authenticate', 'another resource');
    }

    public function testForeignBearerTokensAreNotChallenged(): void
    {
        $this->getMe('Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl');

        $this->assertResponseCode(401);
        $this->assertResponseContains('{"error":"unauthorized"}');
        $this->assertSame('', $this->_response->getHeaderLine('WWW-Authenticate'));
    }

    public function testAnonymousRequestsAreLeftToTheApplication(): void
    {
        $this->getMe(null);

        $this->assertResponseContains('{"error":"unauthorized"}');
    }

    public function testDeactivatedPeopleAreRefused(): void
    {
        $token = $this->personalToken('3');

        $this->getMe('Bearer ' . $token);

        $this->assertResponseCode(401);
        $this->assertHeaderContains('WWW-Authenticate', 'no longer has access');
    }

    public function testABearerRequestNeverBecomesABrowserLogin(): void
    {
        $this->getMe('Bearer ' . $this->personalToken());

        $this->assertResponseOk();
        $this->assertSessionNotHasKey('Auth');
        $this->assertSame([], $this->_response->getHeader('Set-Cookie'));
    }

    public function testABearerTokenIsNotASignedInPersonAtTheConsentPage(): void
    {
        $this->configRequest(['headers' => ['Authorization' => 'Bearer ' . $this->personalToken('1', 'http://localhost/api')]]);
        $client = OAuthServer::server()->clientRegistrar()
            ->create('Test App', ['https://app.example.com/cb'], false)['client'];
        $this->get('/oauth/authorize?' . http_build_query([
            'response_type' => 'code',
            'client_id' => $client->clientId,
            'redirect_uri' => 'https://app.example.com/cb',
            'code_challenge' => Pkce::challengeFor('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
            'code_challenge_method' => 'S256',
            'scope' => 'content:write',
        ], '', '&', PHP_QUERY_RFC3986));

        $this->assertResponseCode(302);
        $this->assertRedirectContains('/login');
    }

    public function testABearerTokenCannotOpenTheConnectionsPage(): void
    {
        $this->configRequest(['headers' => ['Authorization' => 'Bearer ' . $this->personalToken('1', 'http://localhost/api')]]);
        $this->get('/oauth/connections');

        $this->assertResponseCode(302);
        $this->assertRedirectContains('/login');
    }

    public function testAnUndeclaredResourceFailsWhenTheAuthenticatorIsBuilt(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new TokenAuthenticator(new IdentifierCollection(), ['resource' => 'http://localhost/nope']);
    }
}
