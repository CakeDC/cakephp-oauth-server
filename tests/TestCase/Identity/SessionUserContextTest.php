<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Identity;

use ArrayObject;
use Authentication\AuthenticationService;
use Authentication\Authenticator\AuthenticatorInterface;
use Authentication\Authenticator\HttpBasicAuthenticator;
use Authentication\Authenticator\SessionAuthenticator;
use Authentication\Identifier\IdentifierCollection;
use Authentication\Identity;
use Authorization\AuthorizationService;
use Authorization\IdentityDecorator;
use Authorization\Policy\MapResolver;
use Cake\Http\ServerRequest;
use Cake\Routing\Router;
use Cake\TestSuite\TestCase;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Resource\ProtectedResource;
use CakeDC\OAuth\Server\Token\Token;
use CakeDC\OAuth\Server\Token\TokenType;
use CakeDC\OAuth\Server\Token\ValidatedToken;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Identity\OAuthIdentity;
use CakeDC\OAuthServer\Identity\OrmUserProvider;
use CakeDC\OAuthServer\Identity\SessionUserContext;
use DateTimeImmutable;
use Psr\Http\Message\ServerRequestInterface;

class SessionUserContextTest extends TestCase
{
    protected array $fixtures = ['plugin.CakeDC/OAuthServer.Users'];

    protected function tearDown(): void
    {
        Router::reload();
        parent::tearDown();
    }

    private function context(string|array $loginUrl = '/login'): SessionUserContext
    {
        $provider = new OrmUserProvider((new PluginConfig([]))->userProvider());

        return new SessionUserContext($provider, $loginUrl, 'redirect', 'identity');
    }

    public function testReloadsTheSignedInPerson(): void
    {
        $request = (new ServerRequest())->withAttribute('identity', new Identity(['id' => 2, 'name' => 'stale name']));

        $owner = $this->context()->currentOwner($request);

        $this->assertSame('2', $owner?->subject);
        $this->assertSame('Grace', $owner?->displayName);
    }

    public function testInactiveOrMissingPeopleAreAnonymous(): void
    {
        $this->assertNull($this->context()->currentOwner(new ServerRequest()));
        $this->assertNull($this->context()->currentOwner((new ServerRequest())->withAttribute('identity', new Identity(['id' => 3]))));
    }

    public function testSendsAnonymousVisitorsToTheLoginWithARelativeReturnUrl(): void
    {
        Router::createRouteBuilder('/')->connect('/users/sign-in', ['controller' => 'Users', 'action' => 'login']);

        $response = $this->context(['controller' => 'Users', 'action' => 'login'])
            ->loginResponse(new ServerRequest(), '/oauth/authorize?client_id=a&scope=x y');

        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame('/users/sign-in?redirect=%2Foauth%2Fauthorize%3Fclient_id%3Da%26scope%3Dx%20y', $response->getHeaderLine('Location'));
    }

    private function withProvider(AuthenticatorInterface $provider): ServerRequest
    {
        $service = new class ($provider) extends AuthenticationService {
            public function __construct(private AuthenticatorInterface $provider)
            {
                parent::__construct();
            }

            public function getAuthenticationProvider(): ?AuthenticatorInterface
            {
                return $this->provider;
            }
        };

        return (new ServerRequest())
            ->withAttribute('authentication', $service)
            ->withAttribute('identity', new Identity(['id' => 1]));
    }

    public function testAStatelessAuthenticatorIsNeverABrowserLogin(): void
    {
        $request = $this->withProvider(new HttpBasicAuthenticator(new IdentifierCollection()));

        $this->assertNull($this->context()->currentOwner($request));
        $this->assertSame(302, $this->context()->loginResponse($request, '/oauth/authorize')->getStatusCode());
    }

    public function testASessionAuthenticatorIsABrowserLogin(): void
    {
        $owner = $this->context()->currentOwner($this->withProvider(new SessionAuthenticator(new IdentifierCollection())));

        $this->assertSame('1', $owner?->subject);
    }

    public function testAnArrayLoginUrlIgnoresThePluginOfTheCurrentRequest(): void
    {
        Router::createRouteBuilder('/')->connect('/users/sign-in', ['controller' => 'Users', 'action' => 'login']);
        $current = new ServerRequest(['url' => '/oauth/authorize']);
        $current = $current->withParam('plugin', 'CakeDC/OAuthServer')->withParam('controller', 'Authorize')
            ->withParam('action', 'index');
        Router::setRequest($current);

        $response = $this->context(['controller' => 'Users', 'action' => 'login'])->loginResponse($current, '/x');

        $this->assertSame('/users/sign-in?redirect=%2Fx', $response->getHeaderLine('Location'));
    }

    public function testALoginUrlWithAQueryGetsAnAmpersand(): void
    {
        $response = $this->context('/login?lang=es')->loginResponse(new ServerRequest(), '/x');

        $this->assertSame('/login?lang=es&redirect=%2Fx', $response->getHeaderLine('Location'));
    }

    public function testImpersonationIsNotABrowserLogin(): void
    {
        $provider = new class (new IdentifierCollection()) extends SessionAuthenticator {
            public function isImpersonating(ServerRequestInterface $request): bool
            {
                return true;
            }
        };

        $this->assertNull($this->context()->currentOwner($this->withProvider($provider)));
    }

    public function testBooleanAndFloatIdsAreRefused(): void
    {
        foreach ([true, 1.0] as $id) {
            $request = (new ServerRequest())->withAttribute('identity', new ArrayObject(['id' => $id]));
            $this->assertNull($this->context()->currentOwner($request));
        }
    }

    public function testTheLoginResponseDependsOnTheRequestUrl(): void
    {
        $response = $this->context('/login')->loginResponse(new ServerRequest(), '/oauth/authorize?a=b');

        $this->assertStringEndsWith('redirect=%2Foauth%2Fauthorize%3Fa%3Db', $response->getHeaderLine('Location'));
    }

    public function testAnOAuthIdentityIsNeverASignedInPerson(): void
    {
        $token = new ValidatedToken(
            new Token('id', 'hash', TokenType::Access, 'f', null, '2', SubjectType::User, 'http://localhost/api', ['api'], new DateTimeImmutable()),
            new ResourceOwner('2', 'Grace', null),
            null,
            new ProtectedResource('http://localhost/api', 'API', ['api' => 'Use the API']),
            ['api'],
        );
        $oauth = new OAuthIdentity($token);
        $decorated = new IdentityDecorator(new AuthorizationService(new MapResolver()), $oauth);

        $this->assertNull($this->context()->currentOwner((new ServerRequest())->withAttribute('identity', $oauth)));
        $this->assertNull($this->context()->currentOwner((new ServerRequest())->withAttribute('identity', $decorated)));
    }
}
