<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Identity;

use Authentication\AuthenticationService;
use Authentication\Authenticator\AuthenticatorInterface;
use Authentication\Authenticator\HttpBasicAuthenticator;
use Authentication\Authenticator\SessionAuthenticator;
use Authentication\Identifier\IdentifierCollection;
use Authentication\Identity;
use Cake\Http\ServerRequest;
use Cake\Routing\Router;
use Cake\TestSuite\TestCase;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Identity\OrmUserProvider;
use CakeDC\OAuthServer\Identity\SessionUserContext;

class SessionUserContextTest extends TestCase
{
    protected array $fixtures = ['plugin.CakeDC/OAuthServer.Users'];

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
}
