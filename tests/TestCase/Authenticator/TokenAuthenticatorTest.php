<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Authenticator;

use Authentication\Authenticator\AuthenticationRequiredException;
use Authentication\Authenticator\Result;
use Authentication\Authenticator\ResultInterface;
use Authentication\Identifier\IdentifierCollection;
use Cake\Core\Configure;
use Cake\Log\Engine\ArrayLog;
use Cake\Log\Log;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use Cake\Utility\Security;
use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuthServer\Authenticator\TokenAuthenticator;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Test\Support\Fixtures;
use CakeDC\OAuthServer\Test\Support\Routed;
use DateTimeImmutable;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;

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

        $this->assertResponseCode(401);
    }

    public function testABearerTokenCannotOpenTheConnectionsPage(): void
    {
        $this->configRequest(['headers' => ['Authorization' => 'Bearer ' . $this->personalToken('1', 'http://localhost/api')]]);
        $this->get('/oauth/connections');

        $this->assertResponseCode(401);
    }

    public function testAnUndeclaredResourceRefusesTheTokensOfThisServer(): void
    {
        // Building the authenticator reads no configuration: a mistake must not break every page.
        $authenticator = new TokenAuthenticator(new IdentifierCollection(), ['resource' => 'http://localhost/nope']);
        $request = Routed::request('/nope/x', '/nope/**');

        $this->assertSame(Result::FAILURE_CREDENTIALS_MISSING, $authenticator->authenticate($request)->getStatus());
        $result = $authenticator->authenticate(
            $request->withHeader('Authorization', 'Bearer ' . $this->personalToken()),
        );
        $this->assertSame(Result::FAILURE_CREDENTIALS_INVALID, $result->getStatus());
        try {
            $authenticator->resolve();
            $this->fail('An undeclared resource must be reported.');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('not declared in OAuthServer.resources', $e->getMessage());
        }
    }

    public function testTheServerIsBuiltOnlyForATokenOfThisServer(): void
    {
        $token = $this->personalToken();
        $salt = Security::getSalt();
        Security::setSalt('short');
        OAuthServer::reset();
        Log::setConfig('oauth_capture', ['className' => ArrayLog::class, 'scopes' => ['oauth']]);
        try {
            $authenticator = new TokenAuthenticator(new IdentifierCollection(), ['resource' => 'http://localhost/api']);
            $at = fn(?string $header): ResultInterface => $authenticator->authenticate(
                $header === null
                    ? Routed::request('/api/me', '/api/me')
                    : Routed::request('/api/me', '/api/me')->withHeader('Authorization', $header),
            );
            $this->assertSame(Result::FAILURE_CREDENTIALS_MISSING, $at(null)->getStatus());
            $this->assertSame(Result::FAILURE_CREDENTIALS_MISSING, $at('Bearer eyJhbGciOiJIUzI1NiJ9.e30.c2ln')->getStatus());
            $engine = Log::engine('oauth_capture');
            $this->assertInstanceOf(ArrayLog::class, $engine);
            $this->assertSame([], $engine->read());

            // The server cannot be built for this token: refused, never passed on, and the reason is logged.
            $result = $at('Bearer ' . $token);
            $this->assertSame(Result::FAILURE_CREDENTIALS_INVALID, $result->getStatus());
            $this->assertStringContainsString('Security.salt', implode("\n", $engine->read()));
            $this->assertStringNotContainsString($token, implode("\n", $engine->read()));
        } finally {
            Security::setSalt($salt);
            Log::drop('oauth_capture');
            OAuthServer::reset();
        }
    }

    public function testTheChallengeIsUncacheableJson(): void
    {
        $this->getMe('Bearer test_pat_' . str_repeat('x', 43));

        $this->assertResponseCode(401);
        $this->assertHeader('Content-Type', 'application/json');
        $this->assertHeader('Cache-Control', 'no-store');
        $this->assertHeader('Pragma', 'no-cache');
    }

    public function testChallengeValuesAreEscaped(): void
    {
        $authenticator = new TokenAuthenticator(new IdentifierCollection(), [
            'resource' => 'http://localhost/api',
            'resourceMetadataUrl' => "https://x.example/a\"b\\c\x01d",
        ]);
        $request = Routed::request('/api/me', '/api/me')
            ->withHeader('Authorization', 'Bearer test_at_' . str_repeat('x', 43));
        $authenticator->authenticate($request);

        try {
            $authenticator->unauthorizedChallenge($request);
            $this->fail('A challenge was expected.');
        } catch (AuthenticationRequiredException $e) {
            $this->assertSame(
                'Bearer resource_metadata="https://x.example/a\\"b\\\\cd", error="invalid_token", '
                . 'error_description="The access token is invalid."',
                $e->getHeaders()['WWW-Authenticate'],
            );
        }
    }

    public function testOnlyThisServersAccessTokensReachTheValidator(): void
    {
        $clock = new class implements ClockInterface {
            public int $calls = 0;

            public function now(): DateTimeImmutable
            {
                $this->calls++;

                return new DateTimeImmutable();
            }
        };
        $settings = Configure::read('OAuthServer');
        Configure::write('OAuthServer.services.clock', $clock);
        OAuthServer::reset();
        try {
            $authenticator = new TokenAuthenticator(new IdentifierCollection(), ['resource' => 'http://localhost/api']);
            $authenticate = fn(string $value) => $authenticator->authenticate(
                Routed::request('/api/me', '/api/me')->withHeader('Authorization', 'Bearer ' . $value),
            );
            $suffix = str_repeat('x', 43);
            $clock->calls = 0;
            foreach (['test_rt_' . $suffix, 'test_cs_' . $suffix, 'test_ac_' . $suffix, 'eyJhbGciOiJIUzI1NiJ9.e30.c2ln'] as $value) {
                $this->assertFalse($authenticate($value)->isValid());
            }
            $this->assertSame(0, $clock->calls);

            // Control: the spy does see a validation.
            $this->assertFalse($authenticate('test_at_' . $suffix)->isValid());
            $this->assertGreaterThan(0, $clock->calls);
        } finally {
            Configure::write('OAuthServer', $settings);
            OAuthServer::reset();
        }
    }

    public function testARenamedIdentityAttributeStillExposesTheToken(): void
    {
        Configure::write('TestApp.identityAttribute', 'principal');
        try {
            $this->getMe('Bearer ' . $this->personalToken());
            $this->assertResponseOk();
            $this->assertResponseContains('"scopes":["api"]');

            $client = OAuthServer::server()->clientRegistrar()
                ->create('Test App', ['https://app.example.com/cb'], false)['client'];
            $this->configRequest(['headers' => ['Authorization' => 'Bearer ' . $this->personalToken()]]);
            $this->get('/oauth/authorize?' . http_build_query([
                'response_type' => 'code',
                'client_id' => $client->clientId,
                'redirect_uri' => 'https://app.example.com/cb',
                'code_challenge' => Pkce::challengeFor('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
                'code_challenge_method' => 'S256',
                'scope' => 'content:write',
            ], '', '&', PHP_QUERY_RFC3986));
            $this->assertResponseCode(401);

            $this->configRequest(['headers' => ['Authorization' => 'Bearer ' . $this->personalToken()]]);
            $this->get('/oauth/connections');
            $this->assertResponseCode(401);
        } finally {
            Configure::delete('TestApp.identityAttribute');
        }
    }
}
